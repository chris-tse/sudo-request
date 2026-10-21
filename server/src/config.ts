import { Context } from "effect"

export interface AppConfig {
  server: {
    cliSocket: string
    /** Unix socket for the dashboard (recommended; Tailscale Serve proxies to it). */
    webSocket: string | null
    /** TCP alternative for development, e.g. "127.0.0.1:4877". */
    webListen: string | null
    dashboardUrl: string
    database: string
    staticDir: string | null
    executor: "socket" | "mock"
    /** Extra origins accepted on state-changing requests (development only). */
    extraOrigins: string[]
  }
  requests: {
    expirationMinutes: number
    maxPending: number
    historyDays: number
  }
  webauthn: {
    rpId: string
    origin: string
  }
  executor: {
    socket: string
  }
}

export class Config extends Context.Tag("Config")<Config, AppConfig>() {}

type Table = Record<string, unknown>

const str = (t: Table, k: string, d?: string): string => {
  const v = t[k] ?? d
  if (typeof v !== "string" || v === "") throw new Error(`config: ${k} must be a non-empty string`)
  return v
}
const optStr = (t: Table, k: string): string | null => {
  const v = t[k]
  if (v === undefined) return null
  if (typeof v !== "string") throw new Error(`config: ${k} must be a string`)
  return v
}
const num = (t: Table, k: string, d: number, min: number, max: number): number => {
  const v = t[k] ?? d
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
    throw new Error(`config: ${k} must be an integer in [${min}, ${max}]`)
  }
  return v
}

export const parseConfig = (text: string): AppConfig => {
  const raw = Bun.TOML.parse(text) as Record<string, Table>
  const server = raw.server ?? {}
  const requests = raw.requests ?? {}
  const webauthn = raw.webauthn ?? {}
  const executor = raw.executor ?? {}

  const mode = str(server, "executor", "socket")
  if (mode !== "socket" && mode !== "mock") throw new Error(`config: server.executor must be "socket" or "mock"`)
  const webSocket = optStr(server, "web_socket")
  const webListen = optStr(server, "web_listen")
  if (!webSocket === !webListen) throw new Error("config: set exactly one of server.web_socket or server.web_listen")
  const origin = str(webauthn, "origin")
  if (!/^https:\/\//.test(origin) && !/^http:\/\/localhost(:\d+)?$/.test(origin)) {
    throw new Error("config: webauthn.origin must be https:// (or http://localhost for development)")
  }
  const extra = server.extra_origins ?? []
  if (!Array.isArray(extra) || extra.some((o) => typeof o !== "string")) {
    throw new Error("config: server.extra_origins must be a list of strings")
  }

  return {
    server: {
      cliSocket: str(server, "cli_socket", "/run/sudo-request/cli.sock"),
      webSocket,
      webListen,
      dashboardUrl: str(server, "dashboard_url", origin),
      database: str(server, "database", "/var/lib/sudo-request/requests.sqlite"),
      staticDir: optStr(server, "static_dir"),
      executor: mode,
      extraOrigins: extra as string[],
    },
    requests: {
      expirationMinutes: num(requests, "expiration_minutes", 10, 1, 24 * 60),
      maxPending: num(requests, "max_pending", 20, 1, 1000),
      historyDays: num(requests, "history_days", 30, 1, 3650),
    },
    webauthn: { rpId: str(webauthn, "rp_id"), origin },
    executor: { socket: str(executor, "socket", "/run/sudo-request-executor/executor.sock") },
  }
}

export const loadConfig = async (path: string): Promise<AppConfig> => parseConfig(await Bun.file(path).text())
