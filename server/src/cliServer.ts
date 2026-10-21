import { chmodSync, existsSync, lstatSync, unlinkSync } from "node:fs"
import { Effect, type ManagedRuntime } from "effect"
import { errorCode, type RequestError } from "./errors"
import { limits } from "./protocol"
import { Requests } from "./requests"
import { toView } from "./store"
import { Config } from "./config"

type Runtime = ManagedRuntime.ManagedRuntime<Requests | Config, never>

const parseId = (v: unknown) => (Number.isSafeInteger(v) && (v as number) > 0 ? (v as number) : null)

/** Handles one CLI message. Exported for tests. */
export const handleCliMessage = (msg: any) =>
  Effect.gen(function* () {
    const requests = yield* Requests
    const config = yield* Config
    const dashboardUrl = config.server.dashboardUrl
    switch (msg?.op) {
      case "submit": {
        const r = yield* requests.submit({ argv: msg.argv, cwd: msg.cwd, user: msg.user, uid: msg.uid })
        return { ok: true, request: toView(r), dashboardUrl }
      }
      case "status":
      case "cancel": {
        const id = parseId(msg.id)
        if (id === null) return { ok: false, error: { code: "invalid_command", message: "id must be a positive integer" } }
        const r = msg.op === "status" ? yield* requests.get(id) : yield* requests.cancel(id)
        return { ok: true, request: toView(r) }
      }
      case "list": {
        const rs = yield* requests.list({ all: msg.all === true })
        return { ok: true, requests: rs.map(toView), dashboardUrl }
      }
      default:
        // There is deliberately no "approve" operation on this socket.
        return { ok: false, error: { code: "invalid_command", message: `unknown op ${JSON.stringify(msg?.op)}` } }
    }
  }).pipe(
    Effect.catchAll((e: RequestError) => Effect.succeed({ ok: false, error: { code: errorCode(e), message: e.message } })),
  )

const isListening = (path: string) =>
  Bun.connect({ unix: path, socket: { data() {}, open(s) { s.end() } } }).then(
    () => true,
    () => false,
  )

/** Removes a socket file left by a previous run, but never one that is still in use. */
const removeStaleSocket = async (path: string) => {
  if (!existsSync(path)) return
  if (!lstatSync(path).isSocket()) throw new Error(`${path} exists and is not a socket`)
  if (await isListening(path)) throw new Error(`${path} is in use; is another sudo-request backend running?`)
  unlinkSync(path)
}

export const startCliServer = (path: string, runtime: Runtime, mode = 0o666) => {
  const server = Bun.listen<{ buf: Buffer; done: boolean }>({
    unix: path,
    socket: {
      open(s) {
        s.data = { buf: Buffer.alloc(0), done: false }
      },
      data(s, chunk) {
        if (s.data.done) return
        // Accumulate bytes: decoding each chunk separately would mangle a
        // multi-byte character split across two reads.
        s.data.buf = Buffer.concat([s.data.buf, chunk])
        const nl = s.data.buf.indexOf(0x0a)
        if (nl < 0 && s.data.buf.length > limits.maxLineBytes) {
          s.data.done = true
          s.end(JSON.stringify({ ok: false, error: { code: "invalid_command", message: "message too large" } }) + "\n")
          return
        }
        if (nl < 0) return
        s.data.done = true
        let msg: unknown
        try {
          msg = JSON.parse(s.data.buf.subarray(0, nl).toString("utf8"))
        } catch {
          s.end(JSON.stringify({ ok: false, error: { code: "invalid_command", message: "malformed JSON" } }) + "\n")
          return
        }
        runtime
          .runPromise(handleCliMessage(msg))
          .catch((e) => ({ ok: false, error: { code: "internal", message: String(e) } }))
          .then((resp) => s.end(JSON.stringify(resp) + "\n"))
      },
      error() {},
    },
  })
  // Any local user may *queue* a request; approval happens elsewhere.
  chmodSync(path, mode)
  return server
}

export { removeStaleSocket }
