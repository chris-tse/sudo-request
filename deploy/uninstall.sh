#!/usr/bin/env bash
# Remove sudo-request.
#
#   sudo deploy/uninstall.sh           # keep request history, passkeys and ledger
#   sudo deploy/uninstall.sh --purge   # also delete data, config and the system user
#
# Does not touch Tailscale; remove the dashboard route yourself with:
#   sudo tailscale serve --https=10000 off
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

systemctl disable --now sudo-request.service sudo-request-executor.service 2>/dev/null || true
rm -f /etc/systemd/system/sudo-request.service /etc/systemd/system/sudo-request-executor.service
systemctl daemon-reload

rm -f /usr/local/bin/sudo-request /usr/local/sbin/sudo-request-executor
rm -rf /opt/sudo-request

if [[ "${1:-}" == "--purge" ]]; then
  rm -rf /var/lib/sudo-request /var/lib/sudo-request-executor /etc/sudo-request
  userdel sudo-request 2>/dev/null || true
  echo "Purged."
else
  echo "Removed. Data kept in /var/lib/sudo-request, /var/lib/sudo-request-executor and /etc/sudo-request."
fi
