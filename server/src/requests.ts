import { hostname } from "node:os"
import { Context, Deferred, Effect, Layer } from "effect"
import { resolveExecutable, warningsFor } from "./commands"
import { Config } from "./config"
import { InvalidInput, InvalidTransition, NotFound, TooManyPending, type ExecutorUnavailable } from "./errors"
import { Executor, type ExecuteOutcome } from "./executor"
import { limits, type ApprovalPayload, type Assertion, type ExecResult, type Status } from "./protocol"
import { Store, type StoredRequest } from "./store"

export interface SubmitInput {
  argv: string[]
  cwd: string
  user: string
  uid: number
}

export const challengeFor = (payload: string): string =>
  new Bun.CryptoHasher("sha256").update(payload).digest("base64url")

const randomNonce = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")

const validateSubmit = (input: SubmitInput): Effect.Effect<void, InvalidInput> => {
  const bad = (message: string) => Effect.fail(new InvalidInput({ message }))
  const { argv, cwd, user, uid } = input
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((a) => typeof a !== "string")) return bad("argv must be a non-empty list of strings")
  if (argv[0] === "") return bad("empty command")
  if (argv.length > limits.maxArgs) return bad(`too many arguments (max ${limits.maxArgs})`)
  const bytes = argv.map((a) => Buffer.byteLength(a))
  if (bytes.some((b) => b > limits.maxArgBytes) || bytes.reduce((a, b) => a + b, 0) > limits.maxTotalArgBytes) return bad("command line too long")
  if (argv.some((a) => a.includes("\0"))) return bad("NUL byte in argument")
  if (argv[0] === "sudo") return bad("submit the command without the leading `sudo`")
  if (typeof cwd !== "string" || !cwd.startsWith("/") || cwd.includes("\0") || Buffer.byteLength(cwd) > limits.maxPathBytes) return bad("cwd must be an absolute path")
  if (typeof user !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(user)) return bad("invalid user name")
  if (!Number.isInteger(uid) || uid < 0 || uid > 0xffffffff) return bad("invalid uid")
  return Effect.void
}

const makeService = Effect.gen(function* () {
  const config = yield* Config
  const store = yield* Store
  const executor = yield* Executor
  const host = hostname()
  /** Requests whose execute() call is in flight in this process. */
  const inFlight = new Set<number>()

  const now = () => Date.now()

  const load = (id: number) =>
    Effect.suspend(() => {
      store.expirePending(now())
      const r = store.get(id)
      return r ? Effect.succeed(r) : Effect.fail(new NotFound({ id }))
    })

  const submit = (input: SubmitInput) =>
    Effect.gen(function* () {
      yield* validateSubmit(input)
      const resolved = resolveExecutable(input.argv[0], input.cwd)
      if (!resolved.ok) return yield* new InvalidInput({ message: resolved.message })
      store.expirePending(now())
      if (store.countPending() >= config.requests.maxPending) {
        return yield* new TooManyPending({ max: config.requests.maxPending })
      }
      const createdAt = now()
      const fields = {
        user: input.user,
        uid: input.uid,
        host,
        cwd: input.cwd,
        executable: resolved.path,
        argv: input.argv,
        createdAt,
        expiresAt: createdAt + config.requests.expirationMinutes * 60_000,
        nonce: randomNonce(),
      }
      const stored = store.insert({ ...fields, warnings: warningsFor(resolved.path, input.argv, input.cwd) }, (id) =>
        JSON.stringify({ v: 1, id, ...fields } satisfies ApprovalPayload),
      )
      yield* Effect.logInfo(`request #${stored.id} submitted by ${input.user}: ${JSON.stringify(input.argv)}`)
      return stored
    })

  const ACTIVE: Status[] = ["pending", "approved", "executing"]
  const TERMINAL: Status[] = ["completed", "failed", "uncertain", "denied", "cancelled", "expired"]

  /** Active requests oldest first. max_pending bounds this, so no page is needed. */
  const active = () => store.list({ statuses: ACTIVE, limit: 1000, order: "asc" })

  const list = (opts: { all: boolean }) =>
    Effect.sync(() => {
      store.expirePending(now())
      return opts.all ? store.list({ limit: 50 }) : active()
    })

  /** Active requests are listed separately so finished ones can never push them out. */
  const dashboard = Effect.sync(() => {
    store.expirePending(now())
    return { active: active(), history: store.list({ statuses: TERMINAL, limit: 50 }) }
  })

  const simpleTransition = (id: number, action: string, from: Status[], to: Status, reason: string) =>
    Effect.gen(function* () {
      const r = yield* load(id)
      if (!store.transition(id, from, to, now(), { statusReason: reason })) {
        return yield* new InvalidTransition({ id, status: store.get(id)?.status ?? r.status, action })
      }
      yield* Effect.logInfo(`request #${id} ${to}`)
      return store.get(id)!
    })

  const cancel = (id: number) => simpleTransition(id, "cancel", ["pending"], "cancelled", "cancelled by the requester")
  const deny = (id: number) => simpleTransition(id, "deny", ["pending"], "denied", "denied on the dashboard")

  /** Record a terminal result from the executor (or its ledger). */
  const applyResult = (id: number, result: ExecResult) =>
    result.spawnError
      ? store.transition(id, ["approved", "executing"], "failed", now(), { result, statusReason: result.spawnError })
      : store.transition(id, ["approved", "executing"], "completed", now(), { result, statusReason: null })

  const markUncertain = (id: number, why: string) =>
    store.transition(id, ["approved", "executing"], "uncertain", now(), {
      statusReason: `${why}. The command may or may not have run; it will not be retried. Check the system state before resubmitting.`,
    })

  /**
   * Ask the executor's ledger what happened to an approval whose outcome we
   * did not observe. Never re-sends anything.
   */
  const reconcileOne = (r: StoredRequest): Effect.Effect<void, ExecutorUnavailable> =>
    Effect.gen(function* () {
      const found = yield* executor.lookup(r.nonce)
      // Decide from the stored status, not the caller's snapshot: approve()
      // holds the row it loaded while it was still pending.
      const current = store.get(r.id)
      if (!current || !["approved", "executing"].includes(current.status)) return
      switch (found.state) {
        case "finished":
          if (found.result) applyResult(r.id, found.result)
          break
        case "running":
          store.transition(r.id, ["approved"], "executing", now())
          break
        case "interrupted":
          markUncertain(r.id, "The executor stopped while this command was running")
          break
        case "unknown":
          // The executor never accepted this approval, so nothing ran.
          if (current.status === "approved") {
            store.transition(r.id, ["approved"], "pending", now(), {
              lastError: "approval was not delivered to the executor; approve again",
            })
          } else {
            markUncertain(r.id, "The executor has no record of this run")
          }
          break
      }
    })

  const reconcile = Effect.gen(function* () {
    const stuck = store.list({ statuses: ["approved", "executing"], limit: 100 }).filter((r) => !inFlight.has(r.id))
    for (const r of stuck) {
      yield* reconcileOne(r).pipe(Effect.catchAll((e) => Effect.logWarning(`reconcile #${r.id}: ${e.message}`)))
    }
  })

  const handleOutcome = (r: StoredRequest, outcome: ExecuteOutcome) =>
    Effect.gen(function* () {
      switch (outcome._tag) {
        case "Finished":
          applyResult(r.id, outcome.result)
          yield* Effect.logInfo(`request #${r.id} finished: exit=${outcome.result.exitCode}`)
          return
        case "Rejected": {
          yield* Effect.logWarning(`request #${r.id} approval rejected: ${outcome.code}: ${outcome.message}`)
          if (outcome.code === "replay") return yield* reconcileOne(r)
          const expired = outcome.message.includes("expired")
          store.transition(r.id, ["approved"], expired ? "expired" : "pending", now(), {
            lastError: `${outcome.message}`,
          })
          return
        }
        case "Lost":
          yield* Effect.logWarning(`request #${r.id}: lost connection to executor (started=${outcome.started})`)
          return yield* reconcileOne(r)
      }
    }).pipe(
      Effect.catchAll((e) =>
        // The ledger could not be consulted; the periodic reconciler retries.
        Effect.logWarning(`request #${r.id}: ${e.message}; will reconcile later`),
      ),
    )

  /**
   * Claim the request (pending -> approved) and hand it to the executor.
   * Resolves once the executor has started, refused, or finished, so the
   * dashboard can show progress; execution continues in the background.
   */
  const approve = (id: number, assertion: Assertion | null) =>
    Effect.gen(function* () {
      const r = yield* load(id)
      const t = now()
      if (!store.transition(id, ["pending"], "approved", t, { approvedAt: t, lastError: null }, `AND expires_at > ${t}`)) {
        return yield* new InvalidTransition({ id, status: store.get(id)!.status, action: "approve" })
      }
      const progressed = yield* Deferred.make<void>()
      inFlight.add(id)
      yield* executor
        .execute(r.payload, assertion, () => {
          store.transition(id, ["approved"], "executing", now(), { statusReason: null })
          Effect.runSync(Deferred.succeed(progressed, undefined))
        })
        .pipe(
          Effect.flatMap((outcome) => handleOutcome(r, outcome)),
          Effect.catchAll((e) =>
            Effect.sync(() => {
              store.transition(id, ["approved"], "pending", now(), { lastError: e.message })
            }),
          ),
          Effect.ensuring(
            Effect.sync(() => inFlight.delete(id)).pipe(Effect.zipRight(Deferred.succeed(progressed, undefined))),
          ),
          Effect.forkDaemon,
        )
      yield* Deferred.await(progressed)
      return store.get(id)!
    })

  const sweep = Effect.sync(() => {
    store.expirePending(now())
    store.pruneHistory(now() - config.requests.historyDays * 86_400_000)
  })

  return { submit, get: load, list, dashboard, cancel, deny, approve, reconcile, sweep, executorMode: executor.mode }
})

export class Requests extends Context.Tag("Requests")<Requests, Effect.Effect.Success<typeof makeService>>() {}

export const RequestsLive = Layer.effect(Requests, makeService)
