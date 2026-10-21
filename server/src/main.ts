import { chmodSync } from "node:fs"
import { Effect, Fiber, Layer, Logger, ManagedRuntime, Schedule } from "effect"
import { startCliServer, removeStaleSocket } from "./cliServer"
import { Config, loadConfig, type AppConfig } from "./config"
import { Executor, mockExecutor, socketExecutor, type ExecutorClient } from "./executor"
import { makeHandler } from "./http"
import { Requests, RequestsLive } from "./requests"
import { RequestStore, Store } from "./store"

export const makeRuntime = (config: AppConfig, store: RequestStore, executor: ExecutorClient) =>
  ManagedRuntime.make(
    RequestsLive.pipe(
      Layer.provideMerge(
        Layer.mergeAll(Layer.succeed(Config, config), Layer.succeed(Store, store), Layer.succeed(Executor, executor)),
      ),
      Layer.provide(Logger.replace(Logger.defaultLogger, Logger.logfmtLogger)),
    ),
  )

export const startApp = async (config: AppConfig, executor: ExecutorClient = executorFor(config)) => {
  await removeStaleSocket(config.server.cliSocket)
  if (config.server.webSocket) await removeStaleSocket(config.server.webSocket)
  const store = new RequestStore(config.server.database)
  const runtime = makeRuntime(config, store, executor)

  const cli = startCliServer(config.server.cliSocket, runtime)

  const fetch = makeHandler((eff) => runtime.runPromise(eff), config)
  let web: ReturnType<typeof Bun.serve>
  if (config.server.webSocket) {
    web = Bun.serve({ unix: config.server.webSocket, fetch })
    // Only our own user and root (tailscaled) can connect.
    chmodSync(config.server.webSocket, 0o600)
  } else {
    const [hostname, port] = config.server.webListen!.split(/:(?=\d+$)/)
    web = Bun.serve({ hostname, port: Number(port), fetch })
  }

  const background = runtime.runFork(
    Effect.flatMap(Requests, (r) =>
      Effect.all([r.sweep, r.reconcile], { discard: true }).pipe(
        Effect.catchAllCause((c) => Effect.logError("background task failed", c)),
        Effect.repeat(Schedule.spaced("5 seconds")),
      ),
    ),
  )

  return {
    runtime,
    store,
    web,
    cli,
    async stop() {
      cli.stop(true)
      web.stop(true)
      await runtime.runPromise(Fiber.interrupt(background))
      await runtime.dispose()
      store.close()
    },
  }
}

const executorFor = (config: AppConfig): ExecutorClient =>
  config.server.executor === "mock" ? mockExecutor() : socketExecutor(config.executor.socket)

if (import.meta.main) {
  const path = process.argv[2] ?? process.env.SUDO_REQUEST_CONFIG ?? "/etc/sudo-request/config.toml"
  const config = await loadConfig(path)
  const app = await startApp(config)
  console.log(
    `sudo-request backend: cli=${config.server.cliSocket} web=${config.server.webSocket ?? config.server.webListen} executor=${config.server.executor} dashboard=${config.server.dashboardUrl}`,
  )
  if (config.server.executor === "mock") {
    console.warn("WARNING: mock executor enabled; approvals are not authenticated and nothing is executed")
  }
  const shutdown = async () => {
    await app.stop()
    process.exit(0)
  }
  process.on("SIGTERM", shutdown)
  process.on("SIGINT", shutdown)
}
