import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Effect } from "effect"
import { parseConfig, type AppConfig } from "../src/config"
import type { ExecutorClient } from "../src/executor"
import { makeRuntime } from "../src/main"
import { Requests } from "../src/requests"
import { RequestStore } from "../src/store"

export const ORIGIN = "https://pod042.example.ts.net:10000"
export const RP_ID = "pod042.example.ts.net"

export const tempDir = (prefix = "sr-test-") => mkdtempSync(join(tmpdir(), prefix))

type Overrides = { executor?: "mock" | "socket"; executorSocket?: string; origin?: string; rpId?: string; maxPending?: number }

export const testConfig = (dir: string, overrides: Overrides = {}): AppConfig => parseConfig(testConfigText(dir, overrides))

export const testConfigText = (dir: string, overrides: Overrides = {}) => `
[server]
cli_socket = "${dir}/cli.sock"
web_listen = "127.0.0.1:0"
dashboard_url = "${overrides.origin ?? ORIGIN}"
database = "${dir}/requests.sqlite"
executor = "${overrides.executor ?? "mock"}"

[requests]
expiration_minutes = 10
max_pending = ${overrides.maxPending ?? 3}

[webauthn]
rp_id = "${overrides.rpId ?? RP_ID}"
origin = "${overrides.origin ?? ORIGIN}"

[executor]
socket = "${overrides.executorSocket ?? `${dir}/executor.sock`}"
state_dir = "${dir}/executor-state"
timeout_seconds = 30
`

export const makeTestService = (executor: ExecutorClient, configOverrides = {}) => {
  const dir = tempDir()
  const config = testConfig(dir, configOverrides)
  const store = new RequestStore(config.server.database)
  const runtime = makeRuntime(config, store, executor)
  const run = <A, E>(f: (r: Requests["Type"]) => Effect.Effect<A, E>) =>
    runtime.runPromise(Effect.flatMap(Requests, f).pipe(Effect.either))
  const ok = async <A, E>(f: (r: Requests["Type"]) => Effect.Effect<A, E>) => {
    const res = await run(f)
    if (res._tag === "Left") throw new Error(`expected success, got ${JSON.stringify(res.left)}`)
    return res.right
  }
  const err = async <A, E>(f: (r: Requests["Type"]) => Effect.Effect<A, E>) => {
    const res = await run(f)
    if (res._tag === "Right") throw new Error("expected failure")
    return res.left as any
  }
  return { dir, config, store, runtime, run, ok, err }
}

export const submitInput = (argv: string[], cwd = "/") => ({ argv, cwd, user: "ctse", uid: 1000 })

export const waitFor = async (cond: () => boolean, ms = 3000) => {
  const end = Date.now() + ms
  while (!cond()) {
    if (Date.now() > end) throw new Error("timed out waiting")
    await Bun.sleep(10)
  }
}
