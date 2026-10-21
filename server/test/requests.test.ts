import { afterEach, describe, expect, setSystemTime, test } from "bun:test"
import { Effect } from "effect"
import { ExecutorUnavailable } from "../src/errors"
import { mockExecutor, type ExecuteOutcome, type ExecutorClient } from "../src/executor"
import type { ApprovalPayload, LookupResponse } from "../src/protocol"
import { challengeFor } from "../src/requests"
import { makeTestService, submitInput, waitFor } from "./helpers"

afterEach(() => setSystemTime())

/** An executor whose behaviour each test scripts. */
const scripted = (opts: {
  execute?: (onStarted: () => void) => Effect.Effect<ExecuteOutcome, ExecutorUnavailable>
  lookup?: LookupResponse | "unavailable"
}): ExecutorClient & { calls: string[] } => {
  const calls: string[] = []
  return {
    mode: "socket",
    calls,
    execute: (payload, _a, onStarted) => {
      calls.push(payload)
      return opts.execute ? opts.execute(() => onStarted(Date.now())) : Effect.fail(new ExecutorUnavailable({ message: "down" }))
    },
    lookup: () =>
      opts.lookup === "unavailable" || !opts.lookup
        ? Effect.fail(new ExecutorUnavailable({ message: "down" }))
        : Effect.succeed(opts.lookup),
    enroll: () => Effect.succeed({ ok: true }),
    info: () => Effect.succeed({ ok: true, credentials: 1 }),
  }
}

const fakeAssertion = { credentialId: "a", clientDataJson: "b", authenticatorData: "c", signature: "d" }

describe("submission", () => {
  test("valid command is queued as pending with a resolved, immutable payload", async () => {
    const t = makeTestService(mockExecutor())
    const r = await t.ok((s) => s.submit(submitInput(["ls", "-la", "/root"], "/tmp")))
    expect(r.status).toBe("pending")
    expect(r.executable).toMatch(/^\/usr\/bin\/ls$|^\/bin\/ls$/)
    const payload: ApprovalPayload = JSON.parse(r.payload)
    expect(payload).toMatchObject({ v: 1, id: r.id, argv: ["ls", "-la", "/root"], cwd: "/tmp", user: "ctse", uid: 1000 })
    expect(payload.nonce).toMatch(/^[0-9a-f]{64}$/)
    expect(payload.expiresAt - payload.createdAt).toBe(10 * 60_000)
    expect(() => t.store.db.query("UPDATE requests SET payload = 'x' WHERE id = ?").run(r.id)).toThrow(/immutable/)
    expect(() => t.store.db.query("UPDATE requests SET argv = '[]' WHERE id = ?").run(r.id)).toThrow(/immutable/)
  })

  test.each([
    [[], "/", /non-empty/],
    [[""], "/", /empty command/],
    [["ls"], "relative/dir", /absolute/],
    [["ls", "a\0b"], "/", /NUL/],
    [["sudo", "ls"], "/", /leading `sudo`/],
    [["definitely-not-a-real-binary"], "/", /not found/],
    [["/tmp/evil"], "/", /root-controlled|does not exist/],
    [["./evil"], "/home", /root-controlled|does not exist/],
  ] as const)("rejects malformed input %p", async (argv, cwd, message) => {
    const t = makeTestService(mockExecutor())
    const e = await t.err((s) => s.submit(submitInput([...argv], cwd)))
    expect(e._tag).toBe("InvalidInput")
    expect(e.message).toMatch(message)
  })

  test("never consults the caller's PATH", async () => {
    const t = makeTestService(mockExecutor())
    const r = await t.ok((s) => s.submit(submitInput(["env"])))
    expect(["/usr/bin/env", "/bin/env"]).toContain(r.executable)
  })

  test("warns about interpreters and user-writable paths", async () => {
    const t = makeTestService(mockExecutor())
    const r = await t.ok((s) => s.submit(submitInput(["bash", "/tmp/script.sh"])))
    expect(r.warnings.join("\n")).toMatch(/arbitrary code/)
    await Bun.write("/tmp/sr-test-script.sh", "echo hi")
    const r2 = await t.ok((s) => s.submit(submitInput(["bash", "/tmp/sr-test-script.sh"])))
    expect(r2.warnings.join("\n")).toMatch(/writable by a non-root user/)
  })

  test("multiple pending requests coexist, up to max_pending", async () => {
    const t = makeTestService(mockExecutor())
    const ids = []
    for (let i = 0; i < 3; i++) ids.push((await t.ok((s) => s.submit(submitInput(["true"])))).id)
    expect(new Set(ids).size).toBe(3)
    expect((await t.ok((s) => s.list({ all: false }))).map((r) => r.id)).toEqual(ids)
    expect((await t.err((s) => s.submit(submitInput(["true"]))))._tag).toBe("TooManyPending")
  })
})

describe("lifecycle", () => {
  test("cancel works only before execution", async () => {
    const t = makeTestService(mockExecutor({ delayMs: 200 }))
    const a = await t.ok((s) => s.submit(submitInput(["true"])))
    expect((await t.ok((s) => s.cancel(a.id))).status).toBe("cancelled")
    expect((await t.err((s) => s.approve(a.id, null)))._tag).toBe("InvalidTransition")

    const b = await t.ok((s) => s.submit(submitInput(["true"])))
    await t.ok((s) => s.approve(b.id, null))
    const e = await t.err((s) => s.cancel(b.id))
    expect(e.message).toMatch(/already executing; it will not be terminated/)
  })

  test("requests expire and can no longer be approved", async () => {
    const mock = mockExecutor()
    const t = makeTestService(mock)
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    setSystemTime(new Date(Date.now() + 11 * 60_000))
    expect((await t.ok((s) => s.get(r.id))).status).toBe("expired")
    expect((await t.err((s) => s.approve(r.id, null)))._tag).toBe("InvalidTransition")
    expect(mock.executed).toHaveLength(0)
  })

  test("denied requests never execute", async () => {
    const mock = mockExecutor()
    const t = makeTestService(mock)
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    expect((await t.ok((s) => s.deny(r.id))).status).toBe("denied")
    expect((await t.err((s) => s.approve(r.id, null)))._tag).toBe("InvalidTransition")
    expect(mock.executed).toHaveLength(0)
  })

  test("approval executes exactly once and the result is retrievable", async () => {
    const mock = mockExecutor({ delayMs: 50 })
    const t = makeTestService(mock)
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    const results = await Promise.all([t.run((s) => s.approve(r.id, null)), t.run((s) => s.approve(r.id, null))])
    expect(results.filter((x) => x._tag === "Right")).toHaveLength(1)
    await waitFor(() => t.store.get(r.id)!.status === "completed")
    expect(mock.executed).toHaveLength(1)
    const done = await t.ok((s) => s.get(r.id))
    expect(done.result?.exitCode).toBe(0)
    expect(done.result?.stdout).toContain('["true"]')
    expect((await t.err((s) => s.approve(r.id, null)))._tag).toBe("InvalidTransition")
  })

  test("executor rejection returns the request to pending with the reason", async () => {
    const ex = scripted({ execute: () => Effect.succeed({ _tag: "Rejected", code: "verification_failed", message: "signature verification failed" }) })
    const t = makeTestService(ex)
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    const after = await t.ok((s) => s.approve(r.id, fakeAssertion))
    expect(after.status).toBe("pending")
    expect(after.lastError).toMatch(/signature/)
  })

  test("unreachable executor leaves the request pending; nothing is marked as run", async () => {
    const t = makeTestService(scripted({}))
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    const after = await t.ok((s) => s.approve(r.id, fakeAssertion))
    expect(after.status).toBe("pending")
    expect(after.lastError).toMatch(/down/)
  })

  test("connection lost mid-run with an interrupted ledger entry becomes uncertain and is not retried", async () => {
    const ex = scripted({
      execute: (started) => Effect.sync(() => started()).pipe(Effect.as({ _tag: "Lost", started: true } as const)),
      lookup: { state: "interrupted" },
    })
    const t = makeTestService(ex)
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    await t.ok((s) => s.approve(r.id, fakeAssertion))
    await waitFor(() => t.store.get(r.id)!.status === "uncertain")
    expect(t.store.get(r.id)!.statusReason).toMatch(/will not be retried/)
    await t.ok((s) => s.reconcile)
    expect(ex.calls).toHaveLength(1)
  })

  test("after a backend restart, the ledger result is recovered without re-executing", async () => {
    const result = { startedAt: 1, finishedAt: 2, exitCode: 7, signal: null, timedOut: false, stdout: "x", stderr: "", stdoutTruncated: false, stderrTruncated: false, spawnError: null }
    const ex = scripted({ lookup: { state: "finished", result } })
    const t = makeTestService(ex)
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    // Simulate a crash after the executor reported "started".
    t.store.transition(r.id, ["pending"], "executing", Date.now())
    await t.ok((s) => s.reconcile)
    const done = t.store.get(r.id)!
    expect(done.status).toBe("completed")
    expect(done.result?.exitCode).toBe(7)
    expect(ex.calls).toHaveLength(0)
  })

  test("an approval the executor never received goes back to pending on reconcile", async () => {
    const ex = scripted({ lookup: { state: "unknown" } })
    const t = makeTestService(ex)
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    t.store.transition(r.id, ["pending"], "approved", Date.now())
    await t.ok((s) => s.reconcile)
    expect(t.store.get(r.id)!.status).toBe("pending")
  })

  test("a lost connection before start, unknown to the ledger, returns to pending (not uncertain)", async () => {
    const ex = scripted({ execute: () => Effect.succeed({ _tag: "Lost", started: false }), lookup: { state: "unknown" } })
    const t = makeTestService(ex)
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    const after = await t.ok((s) => s.approve(r.id, fakeAssertion))
    expect(after.status).toBe("pending")
    expect(after.lastError).toMatch(/not delivered/)
  })

  test("a lost connection after start, unknown to the ledger, becomes uncertain", async () => {
    const ex = scripted({
      execute: (started) => Effect.sync(() => started()).pipe(Effect.as({ _tag: "Lost", started: true } as const)),
      lookup: { state: "unknown" },
    })
    const t = makeTestService(ex)
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    await t.ok((s) => s.approve(r.id, fakeAssertion))
    expect(t.store.get(r.id)!.status).toBe("uncertain")
  })

  test("old pending requests stay on the dashboard however much history accumulates", async () => {
    const t = makeTestService(mockExecutor())
    const oldest = await t.ok((s) => s.submit(submitInput(["true"])))
    for (let i = 0; i < 55; i++) {
      const r = await t.ok((s) => s.submit(submitInput(["true"])))
      await t.ok((s) => s.deny(r.id))
    }
    const newer = await t.ok((s) => s.submit(submitInput(["true"])))
    const d = await t.ok((s) => s.dashboard)
    expect(d.active.map((r) => r.id)).toEqual([oldest.id, newer.id])
    expect(d.history).toHaveLength(50)
    expect(d.history[0]!.id).toBeGreaterThan(d.history[49]!.id)
    expect((await t.ok((s) => s.list({ all: false }))).map((r) => r.id)).toEqual([oldest.id, newer.id])
  })

  test("challenge is the SHA-256 of the stored payload", async () => {
    const t = makeTestService(mockExecutor())
    const r = await t.ok((s) => s.submit(submitInput(["true"])))
    const expected = new Bun.CryptoHasher("sha256").update(r.payload).digest("base64url")
    expect(challengeFor(r.payload)).toBe(expected)
  })
})
