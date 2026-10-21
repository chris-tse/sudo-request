import { Context, Effect } from "effect"
import { ExecutorUnavailable } from "./errors"
import type { ApprovalPayload, Assertion, ExecResult, ExecuteEvent, LookupResponse, SimpleResponse } from "./protocol"

export type ExecuteOutcome =
  | { _tag: "Rejected"; code: string; message: string }
  | { _tag: "Finished"; result: ExecResult }
  /** The connection dropped before a terminal event. `started` says whether we saw "started". */
  | { _tag: "Lost"; started: boolean }

export interface EnrollInput {
  label: string
  credentialId: string
  clientDataJson: string
  attestationObject: string
}

export interface ExecutorClient {
  readonly mode: "socket" | "mock"
  execute(payload: string, assertion: Assertion | null, onStarted: (startedAt: number) => void): Effect.Effect<ExecuteOutcome, ExecutorUnavailable>
  lookup(nonce: string): Effect.Effect<LookupResponse, ExecutorUnavailable>
  enroll(input: EnrollInput): Effect.Effect<SimpleResponse, ExecutorUnavailable>
  info(): Effect.Effect<SimpleResponse, ExecutorUnavailable>
}

export class Executor extends Context.Tag("Executor")<Executor, ExecutorClient>() {}

/**
 * Opens one connection per call, writes one JSON line, and feeds each
 * response line to `onLine` until it returns a value.
 */
const exchange = <A>(
  socketPath: string,
  request: unknown,
  onLine: (msg: any) => A | undefined,
  onClose: () => A | ExecutorUnavailable,
): Effect.Effect<A, ExecutorUnavailable> =>
  Effect.async<A, ExecutorUnavailable>((resume) => {
    let buffer = Buffer.alloc(0)
    let done = false
    let connected = false
    const finish = (r: A | ExecutorUnavailable) => {
      if (done) return
      done = true
      resume(r instanceof ExecutorUnavailable ? Effect.fail(r) : Effect.succeed(r))
    }
    const sock = Bun.connect({
      unix: socketPath,
      socket: {
        open(s) {
          connected = true
          s.write(JSON.stringify(request) + "\n")
        },
        data(s, chunk) {
          // Split on raw newline bytes before decoding, so a UTF-8 sequence
          // spanning two chunks is decoded whole.
          buffer = Buffer.concat([buffer, chunk])
          let nl: number
          while ((nl = buffer.indexOf(0x0a)) >= 0) {
            const line = buffer.subarray(0, nl).toString("utf8")
            buffer = buffer.subarray(nl + 1)
            let msg: unknown
            try {
              msg = JSON.parse(line)
            } catch {
              continue
            }
            const out = onLine(msg)
            if (out !== undefined) {
              finish(out)
              s.end()
              return
            }
          }
        },
        close() {
          finish(onClose())
        },
        error(_s, err) {
          finish(connected ? onClose() : new ExecutorUnavailable({ message: String(err) }))
        },
      },
    }).catch((err) => finish(new ExecutorUnavailable({ message: `cannot reach executor: ${err?.message ?? err}` })))
    return Effect.promise(() => sock.then((s) => s?.end?.()).catch(() => {}))
  })

export const socketExecutor = (socketPath: string): ExecutorClient => {
  const simple = (req: unknown) =>
    exchange<SimpleResponse>(socketPath, req, (m) => m as SimpleResponse, () =>
      new ExecutorUnavailable({ message: "executor closed the connection" }),
    )
  return {
    mode: "socket",
    execute: (payload, assertion, onStarted) => {
      if (!assertion) return Effect.succeed({ _tag: "Rejected", code: "no_assertion", message: "a passkey approval is required" })
      let started = false
      return exchange<ExecuteOutcome>(
        socketPath,
        { op: "execute", payload, assertion },
        (m: ExecuteEvent) => {
          if (m.event === "started") {
            started = true
            onStarted(m.startedAt)
            return undefined
          }
          if (m.event === "rejected") return { _tag: "Rejected", code: m.code, message: m.message }
          if (m.event === "finished") return { _tag: "Finished", result: m.result }
          return undefined
        },
        () => ({ _tag: "Lost", started }),
      )
    },
    lookup: (nonce) =>
      exchange<LookupResponse>(socketPath, { op: "lookup", nonce }, (m) => m as LookupResponse, () =>
        new ExecutorUnavailable({ message: "executor closed the connection" }),
      ),
    enroll: (input) => simple({ op: "enroll", ...input }),
    info: () => simple({ op: "info" }),
  }
}

/**
 * Development/test executor: never runs anything and never checks approvals.
 * Only selectable through config (`server.executor = "mock"`).
 */
export const mockExecutor = (opts: { delayMs?: number } = {}): ExecutorClient & { executed: ApprovalPayload[] } => {
  const executed: ApprovalPayload[] = []
  return {
    mode: "mock",
    executed,
    execute: (payload, _assertion, onStarted) =>
      Effect.gen(function* () {
        const p = JSON.parse(payload) as ApprovalPayload
        const startedAt = Date.now()
        executed.push(p)
        onStarted(startedAt)
        yield* Effect.sleep(opts.delayMs ?? 300)
        const fail = p.argv[0] === "false"
        return {
          _tag: "Finished",
          result: {
            startedAt,
            finishedAt: Date.now(),
            exitCode: fail ? 1 : 0,
            signal: null,
            timedOut: false,
            stdout: `[mock executor] would run as root in ${p.cwd}:\n${JSON.stringify(p.argv)}\n`,
            stderr: fail ? "[mock executor] simulated failure\n" : "",
            stdoutTruncated: false,
            stderrTruncated: false,
            spawnError: null,
          },
        } satisfies ExecuteOutcome
      }),
    lookup: () => Effect.succeed({ state: "unknown" }),
    enroll: () => Effect.succeed({ ok: true }),
    info: () => Effect.succeed({ ok: true, credentials: 0 }),
  }
}
