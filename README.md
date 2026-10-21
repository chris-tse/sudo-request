# sudo-request

Approve privileged commands for a coding agent from your phone.

```text
agent:  sudo-request submit -- ufw allow 22/tcp
        Request #42 queued.
        Approval dashboard: https://pod042.porpoise-banjo.ts.net:10000

you:    open the dashboard → review → Execute → Face ID

agent:  sudo-request wait 42        # prints stdout/stderr, exits with the command's code
```

Nothing intercepts `sudo`. The agent uses `sudo-request` only when you tell it to.
Submission never blocks, and nothing runs until you approve that exact
request with your passkey.

## Components

| Piece | Language | Runs as | Does |
|---|---|---|---|
| `sudo-request` | Rust | the agent's user (`ctse`) | Queues requests, reports status and output |
| `sudo-request-server` | Bun + Effect | `sudo-request` (system user) | Queue (SQLite), dashboard, approval coordination |
| dashboard | React | your phone's browser | Shows requests and performs the passkey ceremony |
| `sudo-request-executor` | Rust | root | Verifies the passkey signature itself, runs the command once |

The executor does not trust the backend. It runs a command only when given a
WebAuthn assertion that meets all of these conditions:

- It comes from a passkey you enrolled from a root shell.
- Its challenge is the SHA-256 hash of the exact request bytes, which include the
  executable, arguments, working directory, a nonce, and the expiry.
- Face ID or a PIN was used (the user-verification flag is set).
- It came from the dashboard's exact origin.

Each approval is claimed in a root-owned ledger before the process starts, so
it can never run twice.

See [docs/DESIGN.md](docs/DESIGN.md) for the architecture and plan and
[docs/SECURITY.md](docs/SECURITY.md) for the threat model and its limits.

## CLI

```text
sudo-request submit [--json] -- <command> [args...]   # queue, exit immediately
sudo-request -- <command> [args...]                   # same as submit
sudo-request status [--json] <id>
sudo-request wait [--json] [--timeout SECONDS] <id>
sudo-request cancel <id>                              # only before execution starts
sudo-request list [--all]
```

Commands are passed as an argument array. No shell is involved, and the
executable is resolved against the system `PATH` (`/usr/local/sbin:...:/bin`),
never yours.

Exit codes: `wait` and `status` on a completed request exit with the command's
own code. Otherwise: 1 is an error, 2 is a usage error, 3 means denied, cancelled
or expired, 4 means it failed to start or the outcome is uncertain, 5 means
`--timeout` elapsed, and 6 means the backend is unreachable.

## Development

Everything runs unprivileged.

```bash
scripts/test.sh                     # Rust + backend unit and end-to-end tests, type checks

# Dashboard against a mock executor (nothing runs, no passkey):
(cd web && bun install && bun run build)
bun server/src/main.ts dev/mock.toml           # http://localhost:4877
cargo run -q --bin sudo-request -- --socket dev/run/cli.sock submit -- ufw status
```

The end-to-end test (`server/test/integration.test.ts`) drives the real Rust
CLI and executor in unprivileged mode. A software authenticator stands in for the
phone. The test covers enrollment, approval, output, replay, forged and
cross-origin approvals, denial, and crash recovery.

## Installing on pod042

Read [docs/SECURITY.md](docs/SECURITY.md) first. Installing creates a
root service.

```bash
scripts/build.sh                    # as ctse
sudo deploy/install.sh              # creates the user, installs to /opt, enables services
sudo tailscale serve --bg --https=10000 unix:/run/sudo-request/web.sock
sudo sudo-request-executor enroll   # from SSH, then open https://<host>:10000/#/enroll on the phone
```

Uninstall with `sudo deploy/uninstall.sh [--purge]` and
`sudo tailscale serve --https=10000 off`.

## Agent instructions

Optional text to add to `AGENTS.md`: [docs/AGENTS-snippet.md](docs/AGENTS-snippet.md).
