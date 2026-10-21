import { Database } from "bun:sqlite"
import { Context } from "effect"
import type { DashboardRequestView, ExecResult, RequestView, Status } from "./protocol"

const SCHEMA = `
CREATE TABLE IF NOT EXISTS requests (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  nonce         TEXT NOT NULL UNIQUE,
  payload       TEXT NOT NULL,
  status        TEXT NOT NULL,
  user          TEXT NOT NULL,
  uid           INTEGER NOT NULL,
  host          TEXT NOT NULL,
  cwd           TEXT NOT NULL,
  executable    TEXT NOT NULL,
  argv          TEXT NOT NULL,
  warnings      TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  approved_at   INTEGER,
  status_reason TEXT,
  last_error    TEXT,
  result        TEXT
);
CREATE INDEX IF NOT EXISTS requests_status ON requests(status);
CREATE TABLE IF NOT EXISTS events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id INTEGER NOT NULL,
  at         INTEGER NOT NULL,
  event      TEXT NOT NULL,
  detail     TEXT
);
-- What a human approves never changes after submission. (The executor
-- enforces this independently via the WebAuthn challenge.)
CREATE TRIGGER IF NOT EXISTS requests_immutable
BEFORE UPDATE OF nonce, payload, user, uid, host, cwd, executable, argv, created_at, expires_at ON requests
WHEN OLD.payload <> ''
BEGIN SELECT RAISE(ABORT, 'request is immutable'); END;
`

interface Row {
  id: number
  nonce: string
  payload: string
  status: Status
  user: string
  uid: number
  host: string
  cwd: string
  executable: string
  argv: string
  warnings: string
  created_at: number
  expires_at: number
  updated_at: number
  approved_at: number | null
  status_reason: string | null
  last_error: string | null
  result: string | null
}

export interface StoredRequest {
  id: number
  nonce: string
  payload: string
  status: Status
  user: string
  uid: number
  host: string
  cwd: string
  executable: string
  argv: string[]
  warnings: string[]
  createdAt: number
  expiresAt: number
  updatedAt: number
  approvedAt: number | null
  statusReason: string | null
  lastError: string | null
  result: ExecResult | null
}

const fromRow = (r: Row): StoredRequest => ({
  id: r.id,
  nonce: r.nonce,
  payload: r.payload,
  status: r.status,
  user: r.user,
  uid: r.uid,
  host: r.host,
  cwd: r.cwd,
  executable: r.executable,
  argv: JSON.parse(r.argv),
  warnings: JSON.parse(r.warnings),
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  updatedAt: r.updated_at,
  approvedAt: r.approved_at,
  statusReason: r.status_reason,
  lastError: r.last_error,
  result: r.result ? JSON.parse(r.result) : null,
})

export const toView = (r: StoredRequest): RequestView => ({
  id: r.id,
  status: r.status,
  user: r.user,
  host: r.host,
  cwd: r.cwd,
  executable: r.executable,
  argv: r.argv,
  createdAt: r.createdAt,
  expiresAt: r.expiresAt,
  statusReason: r.statusReason,
  lastError: r.lastError,
  warnings: r.warnings,
  result: r.result,
})

export const toDashboardView = (r: StoredRequest, challenge: string): DashboardRequestView => ({
  ...toView(r),
  payload: r.payload,
  challenge,
  approvedAt: r.approvedAt,
  updatedAt: r.updatedAt,
})

export interface NewRequest {
  user: string
  uid: number
  host: string
  cwd: string
  executable: string
  argv: string[]
  warnings: string[]
  createdAt: number
  expiresAt: number
  nonce: string
}

export interface TransitionFields {
  approvedAt?: number
  statusReason?: string | null
  lastError?: string | null
  result?: ExecResult
}

const fieldColumns: Record<keyof TransitionFields, string> = {
  approvedAt: "approved_at",
  statusReason: "status_reason",
  lastError: "last_error",
  result: "result",
}

export class RequestStore {
  readonly db: Database

  constructor(path: string) {
    this.db = new Database(path, { create: true, strict: true })
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;")
    this.db.exec(SCHEMA)
  }

  close() {
    this.db.close()
  }

  /** Inserts the row, then fills in the payload, which needs the assigned id. */
  insert(req: NewRequest, buildPayload: (id: number) => string): StoredRequest {
    return this.db.transaction(() => {
      const { id } = this.db
        .query<{ id: number }, any>(
          `INSERT INTO requests (nonce, payload, status, user, uid, host, cwd, executable, argv, warnings,
             created_at, expires_at, updated_at)
           VALUES ($nonce, '', 'pending', $user, $uid, $host, $cwd, $executable, $argv, $warnings,
             $createdAt, $expiresAt, $createdAt)
           RETURNING id`,
        )
        .get({
          nonce: req.nonce,
          user: req.user,
          uid: req.uid,
          host: req.host,
          cwd: req.cwd,
          executable: req.executable,
          argv: JSON.stringify(req.argv),
          warnings: JSON.stringify(req.warnings),
          createdAt: req.createdAt,
          expiresAt: req.expiresAt,
        })!
      this.db.query("UPDATE requests SET payload = ? WHERE id = ?").run(buildPayload(id), id)
      this.logEvent(id, req.createdAt, "submitted", JSON.stringify({ argv: req.argv, cwd: req.cwd, user: req.user }))
      return this.get(id)!
    })()
  }

  get(id: number): StoredRequest | null {
    const row = this.db.query<Row, [number]>("SELECT * FROM requests WHERE id = ?").get(id)
    return row ? fromRow(row) : null
  }

  list(opts: { statuses?: Status[]; limit: number; order?: "asc" | "desc" }): StoredRequest[] {
    const order = opts.order === "asc" ? "ASC" : "DESC"
    const rows = opts.statuses
      ? this.db
          .query<Row, any>(
            `SELECT * FROM requests WHERE status IN (${opts.statuses.map(() => "?").join(",")})
             ORDER BY id ${order} LIMIT ?`,
          )
          .all(...opts.statuses, opts.limit)
      : this.db.query<Row, [number]>(`SELECT * FROM requests ORDER BY id ${order} LIMIT ?`).all(opts.limit)
    return rows.map(fromRow)
  }

  countPending(): number {
    return this.db.query<{ n: number }, []>("SELECT COUNT(*) AS n FROM requests WHERE status = 'pending'").get()!.n
  }

  /**
   * Compare-and-set on status. Returns false (and changes nothing) if the
   * request is not currently in one of `from`. This is the only way status
   * changes, so concurrent approvals cannot both succeed.
   */
  transition(id: number, from: Status[], to: Status, now: number, fields: TransitionFields = {}, extraWhere = ""): boolean {
    return this.db.transaction(() => {
      const sets = ["status = $to", "updated_at = $now"]
      const params: Record<string, unknown> = { id, to, now }
      for (const [key, column] of Object.entries(fieldColumns) as [keyof TransitionFields, string][]) {
        const value = fields[key]
        if (value === undefined) continue
        sets.push(`${column} = $${key}`)
        params[key] = key === "result" ? JSON.stringify(value) : value
      }
      from.forEach((s, i) => (params[`from${i}`] = s))
      const res = this.db
        .query(
          `UPDATE requests SET ${sets.join(", ")}
           WHERE id = $id AND status IN (${from.map((_, i) => `$from${i}`).join(",")}) ${extraWhere}`,
        )
        .run(params as any)
      if (res.changes === 1) {
        const detail = fields.statusReason ?? fields.lastError ?? (fields.result ? `exit=${fields.result.exitCode}` : null)
        this.logEvent(id, now, to, detail)
      }
      return res.changes === 1
    })()
  }

  expirePending(now: number): number[] {
    return this.db.transaction(() => {
      const rows = this.db
        .query<{ id: number }, [number, number]>(
          "UPDATE requests SET status = 'expired', updated_at = ? WHERE status = 'pending' AND expires_at <= ? RETURNING id",
        )
        .all(now, now)
      rows.forEach((r) => this.logEvent(r.id, now, "expired", null))
      return rows.map((r) => r.id)
    })()
  }

  pruneHistory(before: number): number {
    return this.db
      .query(
        `DELETE FROM requests WHERE updated_at < ?
         AND status IN ('completed','failed','uncertain','denied','cancelled','expired')`,
      )
      .run(before).changes
  }

  events(id: number) {
    return this.db
      .query<{ at: number; event: string; detail: string | null }, [number]>(
        "SELECT at, event, detail FROM events WHERE request_id = ? ORDER BY id",
      )
      .all(id)
  }

  private logEvent(id: number, at: number, event: string, detail: string | null) {
    this.db.query("INSERT INTO events (request_id, at, event, detail) VALUES (?, ?, ?, ?)").run(id, at, event, detail)
  }
}

export class Store extends Context.Tag("Store")<Store, RequestStore>() {}
