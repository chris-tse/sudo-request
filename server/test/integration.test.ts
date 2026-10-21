// End to end: Rust CLI -> backend -> Rust executor (unprivileged dev mode),
// with a software passkey standing in for the phone.
//
// Requires `cargo build` first (the `test:all` script at the repo root does this).

import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test"
import { existsSync } from "node:fs"
import { join, resolve } from "node:path"
import type { Subprocess } from "bun"
import { Effect } from "effect"
import { parseConfig } from "../src/config"
import { startApp } from "../src/main"
import { Requests } from "../src/requests"
import { ORIGIN, RP_ID, tempDir, testConfigText, waitFor } from "./helpers"
import { enrollChallenge, SoftAuthenticator } from "./softauth"

setDefaultTimeout(20_000)

const BIN = resolve(import.meta.dir, "../../target/debug")
const CLI = join(BIN, "sudo-request")
const EXECUTOR = join(BIN, "sudo-request-executor")

const dir = tempDir("sr-int-")
const configPath = join(dir, "config.toml")
const config = parseConfig(testConfigText(dir, { executor: "socket", maxPending: 50 }))
let app: Awaited<ReturnType<typeof startApp>>
let executor: Subprocess
let base: string
let phone: SoftAuthenticator

const startExecutor = async () => {
  executor = Bun.spawn([EXECUTOR, "--config", configPath, "serve"], { stderr: "pipe", stdout: "ignore" })
  await waitFor(() => existsSync(config.executor.socket), 5000)
}

const cli = async (...args: string[]) => {
  const p = Bun.spawn([CLI, "--socket", config.server.cliSocket, ...args], { cwd: "/tmp", stdout: "pipe", stderr: "pipe" })
  const [stdout, stderr, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited])
  return { code, stdout, stderr }
}

const api = (path: string, init: RequestInit & { json?: unknown; origin?: string | null } = {}) => {
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (init.origin !== null) headers.Origin = init.origin ?? ORIGIN
  return fetch(base + path, {
    method: init.json !== undefined ? "POST" : "GET",
    headers,
    body: init.json !== undefined ? JSON.stringify(init.json) : undefined,
  })
}

const body = async (r: Response | Promise<Response>): Promise<any> => (await r).json()

const getRequest = async (id: number) => (await body(api(`/api/requests/${id}`))).request

const submit = async (...argv: string[]) => {
  const r = await cli("submit", "--json", "--", ...argv)
  expect(r.code).toBe(0)
  return JSON.parse(r.stdout).request.id as number
}

const approveWith = async (id: number, auth: SoftAuthenticator, opts: { origin?: string; flags?: number; challenge?: string } = {}) => {
  const req = await getRequest(id)
  const assertion = await auth.assert(opts.challenge ?? req.challenge, opts)
  return api(`/api/requests/${id}/approve`, { json: { assertion } })
}

beforeAll(async () => {
  if (!existsSync(CLI) || !existsSync(EXECUTOR)) throw new Error("run `cargo build` first")
  await Bun.write(configPath, testConfigText(dir, { executor: "socket", maxPending: 50 }))
  await startExecutor()
  app = await startApp(config)
  base = `http://127.0.0.1:${app.web.port}`

  const enroll = Bun.spawnSync([EXECUTOR, "--config", configPath, "enroll"])
  const token = enroll.stdout.toString().match(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/)![0]
  phone = await SoftAuthenticator.create(RP_ID, ORIGIN)
  const res = await api("/api/enroll", { json: { label: "test phone", registration: await phone.register(enrollChallenge(token)) } })
  expect(await res.json()).toEqual({ ok: true })
})

afterAll(async () => {
  await app?.stop()
  executor?.kill()
})

describe("end to end", () => {
  test("submit -> approve with passkey -> wait returns output and exit code", async () => {
    const id = await submit("sh", "-c", "echo out; echo err >&2; exit 3")
    expect((await getRequest(id)).status).toBe("pending")
    const status = await cli("status", String(id))
    expect(status.stderr).toContain(`Request #${id}: pending`)

    const res = await approveWith(id, phone)
    expect(res.status).toBe(200)
    const wait = await cli("wait", String(id))
    expect(wait.code).toBe(3)
    expect(wait.stdout).toBe("out\n")
    expect(wait.stderr).toContain("err\n")
    expect(wait.stderr).toContain("completed (exit code 3)")

    // Approving again is refused by the backend...
    expect((await approveWith(id, phone)).status).toBe(409)
  })

  test("the human-readable submit output is agent friendly", async () => {
    const r = await cli("submit", "--", "true")
    expect(r.stdout).toMatch(/^Request #\d+ queued\.\nCommand: true\nExecutable: \/usr\/bin\/true\nStatus: pending\nApproval dashboard: https:\/\//)
  })

  test("`sudo-request -- cmd` is shorthand for submit", async () => {
    const r = await cli("--", "true")
    expect(r.code).toBe(0)
    expect(r.stdout).toContain("queued")
  })

  test("the executor itself rejects a replayed approval", async () => {
    const id = await submit("echo", "once")
    const req = await getRequest(id)
    const assertion = await phone.assert(req.challenge)
    expect((await api(`/api/requests/${id}/approve`, { json: { assertion } })).status).toBe(200)
    await waitFor(() => app.store.get(id)!.status === "completed")

    // Bypass the backend and talk to the executor directly, as a compromised backend could.
    const events = await rawExecutor({
      op: "execute",
      payload: req.payload,
      assertion: {
        credentialId: assertion.id,
        clientDataJson: assertion.response.clientDataJSON,
        authenticatorData: assertion.response.authenticatorData,
        signature: assertion.response.signature,
      },
    })
    expect(events).toEqual([{ event: "rejected", code: "replay", message: "this approval has already been used" }])
  })

  test("unauthenticated, cross-origin and forged approvals never execute", async () => {
    const id = await submit("touch", join(dir, "should-not-exist"))

    expect((await api(`/api/requests/${id}/approve`, { json: {} })).status).toBe(400)
    expect((await api(`/api/requests/${id}/approve`, { json: {}, origin: "https://evil.example" })).status).toBe(403)
    expect((await api(`/api/requests/${id}/approve`, { json: {}, origin: null })).status).toBe(403)

    // A passkey the executor never enrolled (e.g. a virtual authenticator driven by an agent).
    const agent = await SoftAuthenticator.create(RP_ID, ORIGIN)
    let after = await body(approveWith(id, agent))
    expect(after.request.status).toBe("pending")
    expect(after.request.lastError).toMatch(/not enrolled/)

    // The real passkey, but from T3 Code's origin on the same host.
    after = await body(approveWith(id, phone, { origin: "https://pod042.example.ts.net" }))
    expect(after.request.lastError).toMatch(/origin/)

    // The real passkey without Face ID / PIN.
    after = await body(approveWith(id, phone, { flags: 0x01 }))
    expect(after.request.lastError).toMatch(/user verification/)

    // The real passkey, signed for a different request.
    const other = await submit("true")
    after = await body(approveWith(id, phone, { challenge: (await getRequest(other)).challenge }))
    expect(after.request.lastError).toMatch(/challenge/)

    expect(existsSync(join(dir, "should-not-exist"))).toBe(false)
    expect((await cli("cancel", String(id))).code).toBe(0)
    expect((await cli("cancel", String(other))).code).toBe(0)
  })

  test("denied requests never run and wait reports it", async () => {
    const id = await submit("touch", join(dir, "denied"))
    expect((await api(`/api/requests/${id}/deny`, { json: {} })).status).toBe(200)
    const wait = await cli("wait", String(id))
    expect(wait.code).toBe(3)
    expect(wait.stderr).toContain("denied")
    expect(existsSync(join(dir, "denied"))).toBe(false)
  })

  test("the CLI socket has no approve operation", async () => {
    const id = await submit("true")
    const resp = await rawSocket(config.server.cliSocket, { op: "approve", id })
    expect(resp[0]).toMatchObject({ ok: false, error: { code: "invalid_command" } })
    expect((await getRequest(id)).status).toBe("pending")
    await cli("cancel", String(id))
  })

  test("wait --timeout exits 5 while still pending", async () => {
    const id = await submit("true")
    expect((await cli("wait", "--timeout", "1", String(id))).code).toBe(5)
    await cli("cancel", String(id))
  })

  test("an execution interrupted by an executor crash becomes uncertain and is not repeated", async () => {
    const marker = join(dir, "runs")
    const id = await submit("sh", "-c", `echo run >> ${marker}; sleep 5`)
    expect((await approveWith(id, phone)).status).toBe(200)
    await waitFor(() => existsSync(marker))
    executor.kill("SIGKILL")
    await executor.exited
    await startExecutor()
    await Bun.sleep(100)
    await app.runtime.runPromise(Effect.flatMap(Requests, (r) => r.reconcile))
    const r = await getRequest(id)
    expect(r.status).toBe("uncertain")
    expect((await cli("wait", String(id))).code).toBe(4)
    expect(await Bun.file(marker).text()).toBe("run\n")
  })
})

const rawSocket = (path: string, msg: unknown) =>
  new Promise<any[]>((resolveP, reject) => {
    let buf = ""
    Bun.connect({
      unix: path,
      socket: {
        open: (s) => void s.write(JSON.stringify(msg) + "\n"),
        data: (_s, d) => void (buf += d.toString()),
        close: () => resolveP(buf.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))),
        error: (_s, e) => reject(e),
      },
    }).catch(reject)
  })

const rawExecutor = (msg: unknown) => rawSocket(config.executor.socket, msg)
