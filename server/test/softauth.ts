// A software WebAuthn authenticator (ES256) for tests. Produces the same JSON
// shapes as @simplewebauthn/browser.

const b64url = (b: Uint8Array | ArrayBuffer) => Buffer.from(b instanceof ArrayBuffer ? new Uint8Array(b) : b).toString("base64url")
const sha256 = (data: Uint8Array | string) => new Uint8Array(new Bun.CryptoHasher("sha256").update(data).digest())
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) (out.set(p, o), (o += p.length))
  return out
}

type Cbor = number | string | Uint8Array | Map<Cbor, Cbor>
const cborHead = (major: number, n: number) => {
  if (n < 24) return Uint8Array.of((major << 5) | n)
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n)
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff)
  return Uint8Array.of((major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
}
const cbor = (v: Cbor): Uint8Array => {
  if (typeof v === "number") return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v)
  if (typeof v === "string") {
    const b = new TextEncoder().encode(v)
    return concat(cborHead(3, b.length), b)
  }
  if (v instanceof Uint8Array) return concat(cborHead(2, v.length), v)
  return concat(cborHead(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)]))
}

const derInt = (b: Uint8Array) => {
  let i = 0
  while (i < b.length - 1 && b[i] === 0) i++
  let x = b.slice(i)
  if (x[0]! & 0x80) x = concat(Uint8Array.of(0), x)
  return concat(Uint8Array.of(0x02, x.length), x)
}
const rawToDer = (raw: Uint8Array) => {
  const body = concat(derInt(raw.slice(0, 32)), derInt(raw.slice(32)))
  return concat(Uint8Array.of(0x30, body.length), body)
}

export class SoftAuthenticator {
  private constructor(
    private keys: CryptoKeyPair,
    readonly id: Uint8Array,
    readonly rpId: string,
    readonly origin: string,
  ) {}

  static async create(rpId: string, origin: string) {
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
    return new SoftAuthenticator(keys as CryptoKeyPair, crypto.getRandomValues(new Uint8Array(16)), rpId, origin)
  }

  get credentialId() {
    return b64url(this.id)
  }

  private authData(flags: number, extra = new Uint8Array()) {
    return concat(sha256(this.rpId), Uint8Array.of(flags), new Uint8Array(4), extra)
  }

  async register(challenge: Uint8Array) {
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", this.keys.publicKey))
    const cose = new Map<Cbor, Cbor>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, raw.slice(1, 33)],
      [-3, raw.slice(33, 65)],
    ])
    const extra = concat(new Uint8Array(16), Uint8Array.of(0, this.id.length), this.id, cbor(cose))
    const att = cbor(new Map<Cbor, Cbor>([["fmt", "none"], ["attStmt", new Map()], ["authData", this.authData(0x45, extra)]]))
    const clientData = JSON.stringify({ type: "webauthn.create", challenge: b64url(challenge), origin: this.origin, crossOrigin: false })
    return {
      id: this.credentialId,
      rawId: this.credentialId,
      type: "public-key",
      response: { clientDataJSON: b64url(new TextEncoder().encode(clientData)), attestationObject: b64url(att) },
    }
  }

  async assert(challengeB64: string, opts: { origin?: string; flags?: number } = {}) {
    const clientData = new TextEncoder().encode(
      JSON.stringify({ type: "webauthn.get", challenge: challengeB64, origin: opts.origin ?? this.origin, crossOrigin: false }),
    )
    const authData = this.authData(opts.flags ?? 0x05)
    const sig = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.keys.privateKey, concat(authData, sha256(clientData))),
    )
    return {
      id: this.credentialId,
      rawId: this.credentialId,
      type: "public-key",
      response: { clientDataJSON: b64url(clientData), authenticatorData: b64url(authData), signature: b64url(rawToDer(sig)) },
    }
  }
}

export const enrollChallenge = (token: string) =>
  sha256(`sudo-request-enroll:${token.replace(/[^A-Za-z0-9]/g, "").toUpperCase()}`)
