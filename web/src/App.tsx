import { startAuthentication, startRegistration, WebAuthnError } from "@simplewebauthn/browser"
import { useCallback, useEffect, useState } from "react"
import { api, ApiError, type Request, type ServerConfig } from "./api"
import { Command, relative, time, Visible } from "./format"

const POLL_MS = 2000

const describeError = (e: unknown) => {
  if (e instanceof WebAuthnError && e.code === "ERROR_CEREMONY_ABORTED") return "Passkey prompt was cancelled."
  if (e instanceof DOMException && e.name === "NotAllowedError") return "Passkey prompt was cancelled or timed out."
  if (e instanceof ApiError || e instanceof Error) return e.message
  return String(e)
}

const useHashRoute = () => {
  const [hash, setHash] = useState(location.hash)
  useEffect(() => {
    const on = () => setHash(location.hash)
    addEventListener("hashchange", on)
    return () => removeEventListener("hashchange", on)
  }, [])
  return hash.startsWith("#/enroll") ? "enroll" : "home"
}

export const App = () => {
  const route = useHashRoute()
  const [config, setConfig] = useState<ServerConfig | null>(null)
  const [configError, setConfigError] = useState<string | null>(null)

  const loadConfig = useCallback(() => {
    api.config().then(setConfig, (e) => setConfigError(describeError(e)))
  }, [])
  useEffect(loadConfig, [loadConfig])

  if (configError) return <Shell><p className="banner error">Cannot reach the backend: {configError}</p></Shell>
  if (!config) return <Shell><p className="muted">Loading…</p></Shell>
  return (
    <Shell>
      {route === "enroll" ? <Enroll config={config} onDone={loadConfig} /> : <Dashboard config={config} />}
    </Shell>
  )
}

const Shell = ({ children }: { children: React.ReactNode }) => (
  <main>
    <header>
      <a href="#/" className="title">Sudo Requests</a>
    </header>
    {children}
  </main>
)

const Dashboard = ({ config }: { config: ServerConfig }) => {
  const [requests, setRequests] = useState<{ active: Request[]; history: Request[] } | null>(null)
  const [pollError, setPollError] = useState<string | null>(null)
  const [now, setNow] = useState(Date.now())
  const [showHistory, setShowHistory] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setRequests(await api.requests())
      setPollError(null)
    } catch (e) {
      setPollError(describeError(e))
    }
    setNow(Date.now())
  }, [])

  useEffect(() => {
    void refresh()
    const t = setInterval(() => document.visibilityState === "visible" && void refresh(), POLL_MS)
    const tick = setInterval(() => setNow(Date.now()), 1000)
    const onVisible = () => document.visibilityState === "visible" && void refresh()
    document.addEventListener("visibilitychange", onVisible)
    return () => {
      clearInterval(t)
      clearInterval(tick)
      document.removeEventListener("visibilitychange", onVisible)
    }
  }, [refresh])

  const active = requests?.active ?? []
  const recent = requests?.history ?? []
  const recentlyFinished = recent.filter((r) => now - r.updatedAt < 10 * 60_000)
  const history = showHistory ? recent : recentlyFinished

  return (
    <>
      {config.approval === "mock" && (
        <p className="banner warn">Mock executor: approvals are not authenticated and nothing actually runs.</p>
      )}
      {config.approval === "passkey" && !config.executorReachable && (
        <p className="banner error">The privileged executor is not running. Approvals will fail.</p>
      )}
      {config.approval === "passkey" && config.executorReachable && config.passkeysEnrolled === 0 && (
        <p className="banner warn">
          No passkey is enrolled yet. <a href="#/enroll">Enroll this device</a>.
        </p>
      )}
      {pollError && <p className="banner error">Connection problem: {pollError}</p>}

      <h2>Pending <span className="count">{active.length}</span></h2>
      {requests === null ? (
        <p className="muted">Loading…</p>
      ) : active.length === 0 ? (
        <p className="muted empty">Nothing waiting for approval.</p>
      ) : (
        active.map((r) => <RequestCard key={r.id} request={r} config={config} now={now} onChange={refresh} />)
      )}

      {(history.length > 0 || recent.length > 0) && (
        <>
          <h2>
            {showHistory ? "History" : "Recently finished"}
            <button className="link" onClick={() => setShowHistory(!showHistory)}>
              {showHistory ? "show recent" : `show all (${recent.length})`}
            </button>
          </h2>
          {history.map((r) => (
            <RequestCard key={r.id} request={r} config={config} now={now} onChange={refresh} />
          ))}
        </>
      )}
    </>
  )
}

const STATUS_LABEL: Record<Request["status"], string> = {
  pending: "Pending",
  approved: "Starting",
  executing: "Running",
  completed: "Completed",
  failed: "Not run",
  uncertain: "Uncertain",
  denied: "Denied",
  cancelled: "Cancelled",
  expired: "Expired",
}

const RequestCard = ({
  request: r,
  config,
  now,
  onChange,
}: {
  request: Request
  config: ServerConfig
  now: number
  onChange: () => Promise<void>
}) => {
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showDetails, setShowDetails] = useState(false)
  const pending = r.status === "pending" && r.expiresAt > now
  const exitOk = r.result?.exitCode === 0 && !r.result.spawnError

  const act = async (kind: "approve" | "deny") => {
    setBusy(kind)
    setError(null)
    try {
      if (kind === "deny") {
        await api.deny(r.id)
      } else if (config.approval === "mock") {
        await api.approve(r.id, null)
      } else {
        // The challenge is SHA-256 of this exact request; the executor checks
        // the signature against it before running anything.
        const assertion = await startAuthentication({
          optionsJSON: {
            challenge: r.challenge,
            rpId: config.rpId,
            userVerification: "required",
            timeout: 120_000,
            allowCredentials: [],
          },
        })
        const updated = await api.approve(r.id, assertion)
        if (updated.status === "pending" && updated.lastError) setError(updated.lastError)
      }
    } catch (e) {
      setError(describeError(e))
    } finally {
      setBusy(null)
      await onChange()
    }
  }

  const resultClass = r.status === "completed" ? (exitOk ? "ok" : "bad") : ""
  return (
    <article className={`card status-${r.status}`}>
      <div className="card-head">
        <span className="id">#{r.id}</span>
        <span className={`badge ${resultClass}`}>
          {STATUS_LABEL[r.status]}
          {r.status === "completed" && r.result && (r.result.exitCode !== null ? ` · exit ${r.result.exitCode}` : ` · signal ${r.result.signal}`)}
        </span>
      </div>

      <Command argv={r.argv} />

      <dl className="meta">
        <dt>User</dt>
        <dd>{r.user}@{r.host}</dd>
        <dt>Directory</dt>
        <dd className="mono"><Visible text={r.cwd} /></dd>
        {r.executable !== r.argv[0] && (
          <>
            <dt>Runs</dt>
            <dd className="mono"><Visible text={r.executable} /></dd>
          </>
        )}
        <dt>Submitted</dt>
        <dd>{time(r.createdAt)}</dd>
        {r.status === "pending" && (
          <>
            <dt>Expires</dt>
            <dd>{relative(r.expiresAt, now)}</dd>
          </>
        )}
        {r.result && (
          <>
            <dt>Ran</dt>
            <dd>
              {time(r.result.startedAt)} ({((r.result.finishedAt - r.result.startedAt) / 1000).toFixed(1)}s)
            </dd>
          </>
        )}
      </dl>

      {r.warnings.length > 0 && (
        <ul className="warnings">
          {r.warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}

      {r.statusReason && r.status !== "pending" && <p className="reason">{r.statusReason}</p>}
      {(error ?? (r.status === "pending" ? r.lastError : null)) && <p className="banner error">{error ?? r.lastError}</p>}

      {pending && (
        <div className="actions">
          <button className="deny" disabled={busy !== null} onClick={() => act("deny")}>
            {busy === "deny" ? "Denying…" : "Deny"}
          </button>
          <button className="execute" disabled={busy !== null} onClick={() => act("approve")}>
            {busy === "approve" ? "Waiting for passkey…" : "Execute"}
          </button>
        </div>
      )}

      {r.result && <Output result={r.result} />}

      <button className="link" onClick={() => setShowDetails(!showDetails)}>
        {showDetails ? "hide details" : "details"}
      </button>
      {showDetails && (
        <div className="details">
          <p className="muted">Arguments exactly as they will be passed (no shell):</p>
          <ol className="argv">
            {r.argv.map((a, i) => (
              <li key={i} className="mono">
                <Visible text={a} />
              </li>
            ))}
          </ol>
          <p className="muted">Signed payload:</p>
          <pre className="mono small">{r.payload}</pre>
        </div>
      )}
    </article>
  )
}

const Output = ({ result }: { result: NonNullable<Request["result"]> }) => (
  <div className="output">
    {result.spawnError && <p className="banner error">{result.spawnError}</p>}
    {result.timedOut && <p className="banner warn">Timed out and was terminated.</p>}
    {result.stdout && (
      <>
        <h3>stdout{result.stdoutTruncated && " (truncated)"}</h3>
        <pre>{result.stdout}</pre>
      </>
    )}
    {result.stderr && (
      <>
        <h3>stderr{result.stderrTruncated && " (truncated)"}</h3>
        <pre className="stderr">{result.stderr}</pre>
      </>
    )}
    {!result.stdout && !result.stderr && !result.spawnError && <p className="muted">No output.</p>}
  </div>
)

const normaliseToken = (t: string) => t.replace(/[^A-Za-z0-9]/g, "").toUpperCase()

const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")

const Enroll = ({ config, onDone }: { config: ServerConfig; onDone: () => void }) => {
  const [token, setToken] = useState("")
  const [label, setLabel] = useState(/iPhone|iPad/.test(navigator.userAgent) ? "iPhone" : "passkey")
  const [state, setState] = useState<{ kind: "idle" | "busy" | "done" } | { kind: "error"; message: string }>({ kind: "idle" })

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setState({ kind: "busy" })
    try {
      // The code never leaves this page: the executor only stores its hash,
      // and the passkey ceremony signs over that hash as the challenge.
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`sudo-request-enroll:${normaliseToken(token)}`))
      const registration = await startRegistration({
        optionsJSON: {
          challenge: b64url(new Uint8Array(digest)),
          rp: { id: config.rpId, name: "sudo-request" },
          user: { id: b64url(crypto.getRandomValues(new Uint8Array(16))), name: "sudo-request", displayName: "sudo-request approver" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { residentKey: "required", userVerification: "required" },
          attestation: "none",
          timeout: 120_000,
        },
      })
      await api.enroll(label, registration)
      setState({ kind: "done" })
      onDone()
    } catch (err) {
      setState({ kind: "error", message: describeError(err) })
    }
  }

  if (config.approval === "mock") return <p className="banner warn">Enrollment is not used with the mock executor.</p>
  if (state.kind === "done") {
    return (
      <div className="card">
        <p>Passkey enrolled. You can now approve requests.</p>
        <a href="#/" className="button">Go to requests</a>
      </div>
    )
  }
  return (
    <form className="card enroll" onSubmit={submit}>
      <h2>Enroll a passkey</h2>
      <p className="muted">
        In an SSH session (not an agent), run <code>sudo sudo-request-executor enroll</code> and enter the code it prints.
      </p>
      <label>
        Enrollment code
        <input
          value={token}
          onChange={(e) => setToken(e.target.value)}
          autoComplete="off"
          autoCapitalize="characters"
          spellCheck={false}
          placeholder="XXXX-XXXX-XXXX-XXXX"
          required
        />
      </label>
      <label>
        Name for this passkey
        <input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={64} />
      </label>
      {state.kind === "error" && <p className="banner error">{state.message}</p>}
      <button className="execute" disabled={state.kind === "busy" || normaliseToken(token).length !== 16}>
        {state.kind === "busy" ? "Creating passkey…" : "Create passkey"}
      </button>
    </form>
  )
}
