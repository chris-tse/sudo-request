# Security model

sudo-request is a convenience tool with a real approval step. It is **not**
a sandbox for a hostile agent. Whoever approves a command is running it as root.

## What it guarantees

1. Submitting runs nothing. The CLI socket has no approve operation.
2. Approval needs a signature from a passkey that you enrolled from a root
   shell, made with Face ID or a PIN, over the SHA-256 hash of that exact request.
3. The root executor verifies that signature itself. Nothing runs without
   it, no matter what the backend's database or API say.
4. An approval executes at most once (a ledger claim made with `O_EXCL` before
   spawning), and only before the request expires.
5. If the command or arguments change after signing, the challenge no longer matches.
6. Only the backend's uid can connect to the executor socket (file mode plus
   `SO_PEERCRED`).
7. There is no shell, the environment is clean, `PATH` is the system path, and
   the executable must be root-controlled.
8. If anything cannot be verified, nothing runs. An unknown outcome is shown as
   `uncertain` and is never retried.

## Trusted components

The passkey proves *that you signed a specific request*. It cannot prove
*what the screen showed you* while you signed. The page is served by the
backend, which also picks the challenge. A compromised backend could display
`ufw status` while asking your passkey to sign a different queued request.
During enrollment, it could swap in a public key it controls, because
the registration data is not signed in a way that binds the key to the
enrollment code.

So the backend and the dashboard it serves are **trusted for presentation**.
They are protected from the agent by OS isolation: a separate `sudo-request`
user, root-owned assets, and a socket the agent cannot bind or reach. They are
not protected by cryptography. Every protection below assumes the backend
runs uncompromised as `sudo-request`. Closing this gap would need a second
display that the backend does not control, such as a root-rendered
confirmation over SSH. A trusted fingerprint check could protect enrollment,
but would not protect command presentation. This deployment trusts the backend
for both tasks.

## The seven questions (before enabling root execution)

**1. Process architecture.** There are three processes: the CLI (short-lived),
the backend (persistent, unprivileged), and the executor (persistent, root). The
backend and executor communicate only over Unix sockets. The dashboard is
reachable only through Tailscale Serve on port 10000. See DESIGN.md for the
diagram.

**2. Linux identities.**

| Process | User |
|---|---|
| CLI | `ctse` (or any local user) |
| Backend | `sudo-request`: a system user with no shell and an empty capability set, under systemd hardening |
| Executor | `root` |
| tailscaled | `root` (already the case) |

Binaries and dashboard assets are root-owned under `/opt/sudo-request`. Config
is root-owned and mode 0644, and holds no secrets.

**3. Human authentication.** Each Execute tap triggers a WebAuthn ceremony
with `userVerification: "required"`, which means Face ID on the iPhone. There is
no session and no cookie. Enrolling a passkey requires a one-time code that only
`sudo sudo-request-executor enroll` can create.

**4. Authorization of privileged execution.** The executor checks the assertion
against its own root-owned list of enrolled public keys and recomputes the
challenge from the payload bytes it is about to run. It also checks the origin,
rpId, UV flag, expiry, host, and replay ledger. The backend's opinion of whether
a request is approved carries no weight.

**5. Preventing agent self-approval.**

| What the agent could try | What stops it |
|---|---|
| An "approve" op over the CLI socket | It does not exist |
| `POST /api/requests/:id/approve` with no or fake assertion | 400 from the backend, and signature failure at the executor anyway |
| Driving the dashboard with Playwright or T3's preview browser | No access to the phone's private key. A virtual authenticator creates a key the executor never enrolled |
| Enrolling its own passkey | Needs the code printed in your root shell |
| Connecting to the executor socket | `root:sudo-request 0660` plus a peer-uid check |
| Editing the queue DB, dashboard JS, executor keys, or ledger | Owned by other users (`sudo-request` with mode 0700, or root) |
| Binding the dashboard's port while the backend is down | The backend listens on a root/`sudo-request`-only Unix socket, not a port |
| Getting a passkey signature through T3 Code's page (same host, :443) | The executor requires origin `…:10000`. The browser sets the origin, not the page |
| Replaying an earlier approval | The nonce is already claimed in the ledger |
| Changing the binary after approval | The executable chain must be root-owned and not writable by group or others |
| **Repointing Tailscale Serve :10000 to its own fake dashboard** | **Requires an operator account; disabled on pod042. See limitation 1** |

**6. Preserving the existing Tailscale endpoint.** The only change is adding
`--https=10000`. The routes on 443 (T3 Code at `127.0.0.1:3773`) and 8443 are
not touched. The installer does not run any `tailscale` command; you do.

**7. Remaining limitations.** See below.

## Limitations

### 1. Tailscale operator (fixed on pod042 2026-10-21)

**Status:** `ctse` was removed as Tailscale operator during setup.
`tailscale debug prefs` no longer shows an `OperatorUser`. Keep it that way. The
risk below returns if anyone runs `tailscale set --operator=ctse` again.

While a user is the operator, any process running as that user, including the agent,
can run `tailscale serve` and `tailscale funnel`. An agent could repoint
`:10000` at its own server. You would then see a familiar
command at the real URL, while the page asks your passkey to sign the hash of a
*different* request the agent had queued. Face ID shows the site, not
the command, so nothing on the phone would look wrong.

**Fix:** `sudo tailscale set --operator=`. After that, changing Tailscale
config needs sudo. You can do it over SSH, or through sudo-request itself. Agents
that currently manage `tailscale serve` for you would lose that ability. This is
the one change I recommend making before enabling root execution.

### 2. The agent shares the human administrator's account

T3 Code, and so the agent, runs as `ctse`, who is in the `sudo` group. This
tool cannot protect *other* ways of getting root through that account. For
example, the agent can edit `~/.bashrc`, put a fake `sudo` early in `PATH`, or alias
`sudo` to capture your password the next time you SSH in as ctse and
type it. That includes when you run `sudo sudo-request-executor enroll`.

sudo-request reduces how often you type your password in a ctse session, but
it does not close this gap. Options for separating administrator access are
tracked in [issue #11](https://github.com/chris-tse/sudo-request/issues/11).

### 3. Approved commands are fully trusted

- `bash script.sh`, `python3 x.py`, `apt install ./pkg.deb`, and
  `systemctl start some.service` run code the request doesn't show. A
  file in a user-writable place can change between approval and execution.
  The dashboard flags interpreters, arguments that point at user-writable or
  uninspectable paths, and invisible or control characters. These are warnings,
  not blocks.
- Read the whole command. An agent can queue a near-duplicate
  (`ufw allow 2222/tcp`) next to the one you expect. Each Execute button
  signs only its own card.
- Package managers, `systemctl`, and `modprobe` have broad effects by nature.

### 4. Other notes

- **The requesting user is reported by the CLI, not verified.** Bun cannot read
  `SO_PEERCRED`. The field is informational only, and execution is always as
  root with `SUDO_USER` set to that value. Tracking verification in [issue #9](https://github.com/chris-tse/sudo-request/issues/9).
- **Viewing and denying** need tailnet access but no passkey, so any tailnet
  device can see commands and their output. Use Tailscale ACLs if other people
  share the tailnet. Denying is equivalent to the CLI's cancel.
- **Command output** is visible to the requesting agent (via `wait`) and on the
  dashboard. Do not approve commands that print secrets you do not want the
  agent to see.
- **Timeouts:** 15 minutes by default, after which the process group gets
  SIGTERM and, 5 seconds later, SIGKILL, even if the direct child has already
  exited. A descendant that left the group (via `setsid` or daemonizing) is not
  killed. Commands get no TTY and no stdin, so anything interactive fails. Use
  `-y` flags.
- **Ledger growth:** claims and results are kept in
  `/var/lib/sudo-request-executor/ledger`. They are small, but are not pruned yet. Tracking cleanup in [issue #6](https://github.com/chris-tse/sudo-request/issues/6).
- **Passkeys are bound to the host name.** Renaming the machine or tailnet requires
  re-enrolling.
