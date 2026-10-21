import { join, normalize } from "node:path"
import { Effect, Either } from "effect"
import { Config, type AppConfig } from "./config"
import { httpStatus, type RequestError } from "./errors"
import { Executor } from "./executor"
import type { Assertion } from "./protocol"
import { challengeFor, Requests } from "./requests"
import { toDashboardView, type StoredRequest } from "./store"

type Run = <A, E>(eff: Effect.Effect<A, E, Requests | Config | Executor>) => Promise<A>

const SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Permissions-Policy": "publickey-credentials-get=(self), publickey-credentials-create=(self)",
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...SECURITY_HEADERS },
  })

const fail = (status: number, code: string, message: string) => json({ error: { code, message } }, status)

const view = (r: StoredRequest) => toDashboardView(r, challengeFor(r.payload))

const isB64url = (v: unknown, max = 64 * 1024): v is string =>
  typeof v === "string" && v.length > 0 && v.length <= max && /^[A-Za-z0-9_-]+=*$/.test(v)

/** Accepts the AuthenticationResponseJSON shape from @simplewebauthn/browser. */
const parseAssertion = (body: any): Assertion | null => {
  const a = body?.assertion
  const r = a?.response
  if (!isB64url(a?.id) || !isB64url(r?.clientDataJSON) || !isB64url(r?.authenticatorData) || !isB64url(r?.signature)) {
    return null
  }
  return { credentialId: a.id, clientDataJson: r.clientDataJSON, authenticatorData: r.authenticatorData, signature: r.signature }
}

/**
 * Every state-changing request must come from the dashboard's own origin.
 * Approvals are additionally bound to a passkey signature that the executor
 * verifies, so this mainly protects deny and enrollment from cross-site posts.
 */
const sameOrigin = (req: Request, config: AppConfig) => {
  const origin = req.headers.get("origin")
  const allowed = [config.webauthn.origin, ...config.server.extraOrigins]
  if (!origin || !allowed.includes(origin)) return false
  const site = req.headers.get("sec-fetch-site")
  if (site && site !== "same-origin") return false
  return (req.headers.get("content-type") ?? "").startsWith("application/json")
}

const readJson = async (req: Request): Promise<any> => {
  const text = await req.text()
  if (text.length > 256 * 1024) throw new Error("body too large")
  return JSON.parse(text)
}

const serveStatic = async (dir: string, pathname: string): Promise<Response> => {
  const rel = normalize(decodeURIComponent(pathname)).replace(/^(\.\.(\/|$))+/, "")
  let file = Bun.file(join(dir, rel))
  if (rel === "/" || !(await file.exists())) file = Bun.file(join(dir, "index.html"))
  if (!(await file.exists())) return new Response("dashboard assets not built", { status: 404 })
  const immutable = rel.startsWith("/assets/")
  return new Response(file, {
    headers: { ...SECURITY_HEADERS, "Cache-Control": immutable ? "public, max-age=31536000, immutable" : "no-cache" },
  })
}

export const makeHandler = (run: Run, config: AppConfig) => {
  const handleError = (e: unknown) => {
    const err = e as RequestError
    if (err && typeof err === "object" && "_tag" in err) return fail(httpStatus(err), err._tag, err.message)
    console.error(e)
    return fail(500, "internal", "internal error")
  }
  const attempt = async <A>(eff: Effect.Effect<A, RequestError, Requests | Config | Executor>, ok: (a: A) => Response) => {
    const result = await run(Effect.either(eff))
    return Either.isRight(result) ? ok(result.right) : handleError(result.left)
  }

  return async (req: Request): Promise<Response> => {
    const url = new URL(req.url)
    const path = url.pathname
    try {
      if (!path.startsWith("/api/")) {
        if (req.method !== "GET" && req.method !== "HEAD") return fail(405, "method", "method not allowed")
        if (!config.server.staticDir) return new Response("no static_dir configured", { status: 404 })
        return serveStatic(config.server.staticDir, path)
      }

      if (req.method === "GET") {
        if (path === "/api/config") {
          const info = await run(
            Effect.flatMap(Executor, (x) => x.info()).pipe(Effect.either),
          )
          return json({
            rpId: config.webauthn.rpId,
            origin: config.webauthn.origin,
            approval: config.server.executor === "mock" ? "mock" : "passkey",
            executorReachable: Either.isRight(info),
            passkeysEnrolled: Either.isRight(info) ? (info.right.credentials ?? 0) : null,
          })
        }
        if (path === "/api/requests") {
          return attempt(Effect.flatMap(Requests, (r) => r.dashboard), (d) =>
            json({ active: d.active.map(view), history: d.history.map(view) }),
          )
        }
        const m = path.match(/^\/api\/requests\/(\d+)$/)
        if (m) return attempt(Effect.flatMap(Requests, (r) => r.get(Number(m[1]))), (r) => json({ request: view(r) }))
        return fail(404, "not_found", "no such endpoint")
      }

      if (req.method !== "POST") return fail(405, "method", "method not allowed")
      if (!sameOrigin(req, config)) return fail(403, "forbidden_origin", "cross-origin request refused")
      const body = await readJson(req).catch(() => null)
      if (body === null) return fail(400, "bad_request", "invalid JSON body")

      const action = path.match(/^\/api\/requests\/(\d+)\/(approve|deny)$/)
      if (action) {
        const id = Number(action[1])
        if (action[2] === "deny") return attempt(Effect.flatMap(Requests, (r) => r.deny(id)), (r) => json({ request: view(r) }))
        const assertion = parseAssertion(body)
        if (!assertion && config.server.executor !== "mock") {
          return fail(400, "assertion_required", "approval requires a passkey assertion")
        }
        return attempt(Effect.flatMap(Requests, (r) => r.approve(id, assertion)), (r) => json({ request: view(r) }))
      }

      if (path === "/api/enroll") {
        const r = body?.registration?.response
        const id = body?.registration?.id
        if (!isB64url(id) || !isB64url(r?.clientDataJSON) || !isB64url(r?.attestationObject)) {
          return fail(400, "bad_request", "invalid registration response")
        }
        const label = typeof body.label === "string" ? body.label.slice(0, 64) : "passkey"
        const result = await run(
          Effect.flatMap(Executor, (x) =>
            x.enroll({ label, credentialId: id, clientDataJson: r.clientDataJSON, attestationObject: r.attestationObject }),
          ).pipe(Effect.either),
        )
        if (Either.isLeft(result)) return fail(503, "executor_unavailable", result.left.message)
        return result.right.ok
          ? json({ ok: true })
          : fail(400, result.right.code ?? "enroll_failed", result.right.message ?? "enrollment failed")
      }

      return fail(404, "not_found", "no such endpoint")
    } catch (e) {
      return handleError(e)
    }
  }
}
