// Mirrors crates/protocol/src/lib.rs. Keep the two in sync.

export const Statuses = [
  "pending",
  "approved",
  "executing",
  "completed",
  "failed",
  "uncertain",
  "denied",
  "cancelled",
  "expired",
] as const
export type Status = (typeof Statuses)[number]

export const isTerminal = (s: Status) =>
  s === "completed" || s === "failed" || s === "uncertain" || s === "denied" || s === "cancelled" ||
  s === "expired"

export const limits = {
  maxArgs: 256,
  maxArgBytes: 4096,
  maxTotalArgBytes: 32 * 1024,
  maxPathBytes: 4096,
  maxLineBytes: 1024 * 1024,
} as const

export interface ApprovalPayload {
  v: 1
  id: number
  nonce: string
  host: string
  user: string
  uid: number
  cwd: string
  executable: string
  argv: string[]
  createdAt: number
  expiresAt: number
}

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

export interface Assertion {
  credentialId: string
  clientDataJson: string
  authenticatorData: string
  signature: string
}

export type ExecuteEvent =
  | { event: "rejected"; code: string; message: string }
  | { event: "started"; startedAt: number }
  | { event: "finished"; result: ExecResult }

export type LedgerState = "unknown" | "running" | "finished" | "interrupted"

export interface LookupResponse {
  state: LedgerState
  result?: ExecResult | null
}

export interface SimpleResponse {
  ok: boolean
  code?: string
  message?: string
  credentials?: number
}

/** What the CLI sees. */
export interface RequestView {
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
}

/** What the dashboard sees: adds the exact approved bytes and the challenge. */
export interface DashboardRequestView extends RequestView {
  payload: string
  challenge: string
  approvedAt: number | null
  updatedAt: number
}
