#!/usr/bin/env bash
# One-shot deployment for pod042. Build first as your normal user, then:
#
#   scripts/build.sh
#   sudo ./setup.sh
#
# Steps:
#   1. Install binaries, config, system user and systemd services (deploy/install.sh).
#   2. Publish the dashboard on https://<host>:10000 via Tailscale Serve.
#      Existing routes on :443 (T3 Code) and :8443 are left alone.
#   3. Optionally remove ctse as Tailscale operator (asks first; see docs/SECURITY.md).
#   4. Open a 15-minute passkey enrollment window and print the code.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run with: sudo $0" >&2
  exit 1
fi
cd "$(dirname "$0")"

echo "### 1/4 install"
deploy/install.sh >/tmp/sudo-request-install.log 2>&1 || { cat /tmp/sudo-request-install.log; exit 1; }
sed -n '1,/^Installed/p' /tmp/sudo-request-install.log

for _ in $(seq 50); do
  [[ -S /run/sudo-request/web.sock ]] && break
  sleep 0.1
done
if [[ ! -S /run/sudo-request/web.sock ]]; then
  echo "backend did not start; see: journalctl -u sudo-request -u sudo-request-executor" >&2
  exit 1
fi

echo "### 2/4 tailscale serve :10000"
if tailscale serve status 2>/dev/null | grep -q ':10000'; then
  if tailscale serve status | grep -A1 ':10000' | grep -q 'unix:/run/sudo-request/web.sock'; then
    echo "    already configured"
  else
    echo "port 10000 is already served by something else; not changing it:" >&2
    tailscale serve status >&2
    exit 1
  fi
else
  tailscale serve --bg --https=10000 unix:/run/sudo-request/web.sock
fi
tailscale serve status

echo "### 3/4 tailscale operator"
operator="$(tailscale debug prefs 2>/dev/null | sed -n 's/.*"OperatorUser": *"\([^"]*\)".*/\1/p')"
if [[ -n "$operator" ]]; then
  echo "    '$operator' can change Tailscale Serve without sudo, so an agent running as"
  echo "    '$operator' could repoint the dashboard URL. Removing it means future"
  echo "    'tailscale serve' changes need sudo (or a sudo-request)."
  read -r -p "    Remove '$operator' as Tailscale operator? [y/N] " answer
  if [[ "$answer" =~ ^[Yy]$ ]]; then
    tailscale set --operator=
    echo "    removed"
  else
    echo "    kept (see docs/SECURITY.md, limitation 1)"
  fi
else
  echo "    no operator set"
fi

echo "### 4/4 passkey enrollment"
EXECUTOR=(/opt/sudo-request/bin/sudo-request-executor --config /etc/sudo-request/config.toml)
if "${EXECUTOR[@]}" passkeys list | grep -q "No passkeys enrolled"; then
  "${EXECUTOR[@]}" enroll
else
  echo "    a passkey is already enrolled; to add another: sudo ${EXECUTOR[*]} enroll"
fi

echo
echo "Done. Try it:  sudo-request submit -- ufw status verbose"
