#!/usr/bin/env bash
# Install sudo-request from dist/ (run scripts/build.sh first).
#
#   sudo deploy/install.sh
#
# Creates the `sudo-request` system user, installs root-owned binaries and
# assets under /opt/sudo-request, writes /etc/sudo-request/config.toml if it
# does not exist, and enables both systemd services.
#
# It does NOT touch Tailscale, sudoers, or any existing service. The
# Tailscale Serve command is printed at the end for you to run.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
DIST=dist
for f in sudo-request sudo-request-executor sudo-request-server web/index.html; do
  [[ -e "$DIST/$f" ]] || { echo "missing $DIST/$f; run scripts/build.sh as your normal user first" >&2; exit 1; }
done

HOSTNAME_FQDN="${SUDO_REQUEST_HOSTNAME:-$(tailscale status --self --json 2>/dev/null | sed -n 's/.*"DNSName": *"\([^"]*\)\.".*/\1/p' | head -1)}"
if [[ -z "$HOSTNAME_FQDN" ]]; then
  echo "could not determine the Tailscale hostname; set SUDO_REQUEST_HOSTNAME=host.tailnet.ts.net" >&2
  exit 1
fi

echo "==> system user"
if ! id sudo-request >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /var/lib/sudo-request --shell /usr/sbin/nologin sudo-request
fi

echo "==> binaries and dashboard (root-owned, so the agent's account cannot alter them)"
install -d -o root -g root -m 0755 /opt/sudo-request /opt/sudo-request/bin
install -o root -g root -m 0755 "$DIST/sudo-request" "$DIST/sudo-request-executor" "$DIST/sudo-request-server" /opt/sudo-request/bin/
rm -rf /opt/sudo-request/web.new
cp -r "$DIST/web" /opt/sudo-request/web.new
chown -R root:root /opt/sudo-request/web.new
chmod -R u=rwX,go=rX /opt/sudo-request/web.new
rm -rf /opt/sudo-request/web
mv /opt/sudo-request/web.new /opt/sudo-request/web
ln -sf /opt/sudo-request/bin/sudo-request /usr/local/bin/sudo-request
# Admin subcommands (enroll, passkeys); useful only as root, since the state they touch is root-owned.
ln -sf /opt/sudo-request/bin/sudo-request-executor /usr/local/sbin/sudo-request-executor

echo "==> config"
install -d -o root -g root -m 0755 /etc/sudo-request
if [[ ! -e /etc/sudo-request/config.toml ]]; then
  sed "s/@HOSTNAME@/$HOSTNAME_FQDN/g" deploy/config.toml > /etc/sudo-request/config.toml
  chown root:root /etc/sudo-request/config.toml
  chmod 0644 /etc/sudo-request/config.toml
else
  echo "    keeping existing /etc/sudo-request/config.toml"
fi

echo "==> systemd"
install -o root -g root -m 0644 deploy/sudo-request.service deploy/sudo-request-executor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sudo-request-executor.service sudo-request.service
systemctl restart sudo-request-executor.service sudo-request.service

cat <<EOF

Installed. Remaining manual steps:

1. Publish the dashboard on the tailnet (port 10000; T3 Code's :443 and :8443 are untouched):

     sudo tailscale serve --bg --https=10000 unix:/run/sudo-request/web.sock

2. Enroll your phone's passkey, from an SSH session (not an agent):

     sudo sudo-request-executor enroll

   then open https://$HOSTNAME_FQDN:10000/#/enroll on the phone and enter the code.

3. Strongly recommended, see docs/SECURITY.md: remove ctse as Tailscale operator so an
   agent running as ctse cannot repoint the dashboard URL:

     sudo tailscale set --operator=
EOF
