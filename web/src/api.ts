export type Status =
  | "pending"
  | "approved"
  | "executing"
  | "completed"
  | "failed"
  | "uncertain"
  | "denied"
  | "cancelled"
  | "expired"

export interface ExecResult {
  startedAt: number
  finishedAt: number
  exitCode: number | null
  signal: number | null
  timedOut: boolean
  stdout: string
  stderr: string
  stdoutTruncated: boolean
  stderrTruncated: boolean
  spawnError: string | null
}

export interface Request {
  id: number
  status: Status
  user: string
  host: string
  cwd: string
  executable: string
  argv: string[]
  createdAt: number
  expiresAt: number
  statusReason: string | null
  lastError: string | null
  warnings: string[]
  result: ExecResult | null
  payload: string
  challenge: string
  approvedAt: number | null
  updatedAt: number
}

export interface ServerConfig {
  rpId: string
  origin: string
  approval: "passkey" | "mock"
  executorReachable: boolean
  passkeysEnrolled: number | null
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message)
  }
}

const call = async <T>(path: string, body?: unknown): Promise<T> => {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
  })
  const data = await res.json().catch(() => null)
  if (!res.ok) throw new ApiError(res.status, data?.error?.code ?? "error", data?.error?.message ?? res.statusText)
  return data as T
}

export const api = {
  config: () => call<ServerConfig>("/api/config"),
  /** `active` is oldest first; `history` is the newest 50 finished requests. */
  requests: () => call<{ active: Request[]; history: Request[] }>("/api/requests"),
  deny: (id: number) => call<{ request: Request }>(`/api/requests/${id}/deny`, {}).then((r) => r.request),
  approve: (id: number, assertion: unknown) =>
    call<{ request: Request }>(`/api/requests/${id}/approve`, { assertion }).then((r) => r.request),
  enroll: (label: string, registration: unknown) => call<{ ok: true }>("/api/enroll", { label, registration }),
}
