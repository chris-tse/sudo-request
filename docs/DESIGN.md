# Design

## Goal

An agent says a command needs sudo. The user tells it to submit. The user opens a
private dashboard, taps Execute, confirms with Face ID, and the agent continues.

## Processes and identities

```text
 ctse (agent + human share this account)
 ┌──────────────────────┐
 │ sudo-request (CLI)   │──NDJSON──▶ /run/sudo-request/cli.sock (0666)
 └──────────────────────┘                   │
                                            ▼
 sudo-request (system user, no login, no capabilities)
 ┌────────────────────────────────────────────────────┐
 │ sudo-request-server (Bun + Effect)                 │
 │  • SQLite queue  /var/lib/sudo-request (0700)      │
 │  • dashboard + API on /run/sudo-request/web.sock   │◀── tailscaled (root) ◀── phone
 │    (0600)                                          │    https://pod042…:10000
 └──────────────────────┬─────────────────────────────┘
                        │ NDJSON, {payload, assertion}
                        ▼ /run/sudo-request-executor/executor.sock
                          (root:sudo-request 0660 + SO_PEERCRED = sudo-request)
 root
 ┌────────────────────────────────────────────────────┐
 │ sudo-request-executor (Rust)                       │
 │  • enrolled passkeys + ledger                      │
 │    /var/lib/sudo-request-executor (0700)           │
 │  • verifies WebAuthn assertion, claims nonce,      │
 │    runs argv with a clean env                      │
 └────────────────────────────────────────────────────┘
```

The backend runs under its own system user, not `ctse`. That is what keeps
the agent from reading or altering the queue, the dashboard assets (which are
root-owned under `/opt`), or the executor socket. The backend holds **no secret
that can authorize execution**. The only approval credential is the private key
inside the phone's passkey.

## Request lifecycle

```text
pending ──deny──▶ denied
   │ ──cancel──▶ cancelled   (CLI; only while pending)
   │ ──timeout─▶ expired     (default 10 min; also enforced by the executor)
   │
   └─approve (passkey)─▶ approved ──executor started──▶ executing ──▶ completed (exit code / signal)
                            │                              │
                            │ executor refused or          └──executor died──▶ uncertain (never retried)
                            │ unreachable: back to
                            │ pending, with the error
                            └──executable refused or spawn failed──▶ failed (known not to have run)
```

- Every status change is a compare-and-set `UPDATE … WHERE status IN (…)`
  in SQLite, so two concurrent approvals cannot both proceed.
- A trigger makes the approved fields (payload, argv, cwd, executable, user,
  timestamps, nonce) immutable once written.
- `approved` is held only while the backend is talking to the executor. If
  the connection drops, the backend asks the executor ledger (`lookup`) what
  happened instead of resending. The ledger answers `unknown` (never claimed,
  so the request goes back to pending), `running`, `finished` (the result is
  recovered), or `interrupted` (the request becomes uncertain).
- On restart, the backend's reconciler (every 5 seconds) handles any
  `approved` or `executing` rows the same way. The executor runs with
  `KillMode=process`, so restarting it does not kill a command halfway
  through. The run is recorded as interrupted.

## Approval protocol

1. When a request is submitted, the backend serializes the request once to a JSON
   string, the **payload**:
   `{v, id, nonce, host, user, uid, cwd, executable, argv, createdAt, expiresAt}`.
2. The dashboard asks the passkey to sign with `challenge = SHA-256(payload)`
   and `userVerification = "required"`.
3. The backend forwards `{payload, assertion}` to the executor.
4. The executor:
   1. parses the payload with `deny_unknown_fields`, so there is no
      `approved: true` field to smuggle in;
   2. checks the version, nonce format, host name, limits, timestamps, and expiry;
   3. finds the credential among the passkeys it enrolled, then verifies
      `clientDataJSON.type == "webauthn.get"`, the challenge, the origin
      (including `:10000`), the `rpIdHash`, the UP and UV flags, the signature
      counter, and the ES256 signature;
   4. creates `ledger/<nonce>.claim` with `O_EXCL` and fsyncs it. If the file
      already exists, the request is rejected as a replay;
   5. requires the executable's resolved path, and every parent directory, to be
      root-owned and not writable by group or others;
   6. runs the command: no shell, `env_clear()` plus a minimal environment, stdin
      `/dev/null`, its own process group, a timeout (SIGTERM, then SIGKILL),
      and 1 MiB caps on stdout and stderr;
   7. writes `ledger/<nonce>.result` and streams `started` then `finished`.

The executor executes what it parses from the same bytes that were hashed, so
nothing is re-canonicalized between what was displayed, what was signed, and
what runs.

WebAuthn parsing is about 200 lines in `crates/executor/src/webauthn.rs`, on top of
RustCrypto `p256`/`sha2` and `ciborium`. No cryptography is implemented by hand.
`webauthn-rs` was considered. It manages its own random challenges and pulls in
OpenSSL, while this design needs the challenge to be a hash of the request.
Only ES256 is accepted, which is what iCloud Keychain and Android passkeys use.

## Passkey enrollment

Enrollment is the other place an agent could insert itself, for example by
registering a virtual authenticator from a headless browser. It is therefore
gated by root:

1. Over SSH, run `sudo sudo-request-executor enroll`. It prints a single-use code
   valid for 15 minutes (about 79 bits) and stores only
   `SHA-256("sudo-request-enroll:" + code)`.
2. On the phone, `/#/enroll` computes the same hash locally and uses it as the
   registration challenge, so the code never leaves the phone.
3. The executor checks the challenge, origin, rpId, and UV, extracts the
   P-256 key from the attestation, stores it, and deletes the token.

Manage passkeys with `sudo sudo-request-executor passkeys list|remove <id>`.

## Networking

- `https://pod042.porpoise-banjo.ts.net` (443) → T3 Code: **unchanged**.
- `https://pod042.porpoise-banjo.ts.net:8443` → existing service: **unchanged**.
- `https://pod042.porpoise-banjo.ts.net:10000` → `unix:/run/sudo-request/web.sock`: **new**.

Tailscale Serve offers HTTPS only on 443, 8443, and 10000, so 10000 is the
remaining port. Path routing under T3 Code's origin (`/sudo`) was rejected.
The dashboard would share an origin with T3 Code's front end, which runs from
files the agent can edit, and that code could then drive the dashboard. A
different port is a different origin, and the executor's exact-origin check
enforces this boundary even though passkeys are scoped to the host name.

A custom domain (for example `sudo.example.com`) would need private DNS pointing at
the tailnet IP and a certificate for that name, such as Let's Encrypt DNS-01. It
works, but it is not needed. A Tailscale Services virtual hostname is
another option for later. Changing hostnames later means re-enrolling the
passkey, because passkeys are bound to the rpId.

## Why these choices

- **No signing key in the backend** (unlike the reference project
  `douglasjordan2/sudo-approve`, whose hub signs directives with Ed25519).
  Here the phone's passkey signature *is* the directive, so stealing the
  backend's files or database gives no ability to run anything. This does
  **not** make the backend untrusted. It serves the page that shows you the
  command and picks the challenge, so a compromised backend could display one
  command while asking you to sign another (see SECURITY.md, "Trusted
  components"). The defense against the agent is that the backend runs as a
  separate user the agent cannot control.
- **Passkey per approval rather than a login session.** It removes session
  cookies, CSRF tokens, and session theft as concerns, and it is what lets the
  root executor verify the human independently. The cost is one Face ID per
  Execute, which is the intended UX anyway.
- **Unix sockets everywhere.** File permissions and `SO_PEERCRED` give local
  access control for free, and no localhost port exists that the agent could
  bind if the backend is down.
- **Shared protocol crate.** `crates/protocol` holds the wire types used by both
  Rust binaries, which are compiled and installed separately with different
  owners. The TypeScript side mirrors it in `server/src/protocol.ts`.
- **Effect is used where it helps:** typed errors (`NotFound`,
  `InvalidTransition`, …), the executor client as a swappable service (socket
  or mock), the forked execution fiber with a `Deferred` for "has the executor
  started?", and the scheduled sweeper and reconciler. Storage and HTTP stay
  plain.
- **Polling** every 2 seconds, paused while the tab is hidden. That is enough for
  a handful of requests a day.

## Follow-up work

Feature plans and host verification tasks are tracked in [GitHub issues](https://github.com/chris-tse/sudo-request/issues). The [initial audit and resolution](https://github.com/chris-tse/sudo-request/issues/8) records the implementation review.
