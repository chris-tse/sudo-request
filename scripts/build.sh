#!/usr/bin/env bash
# Build all release artifacts into dist/. Runs unprivileged.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf dist
mkdir -p dist

cargo build --release --locked
cp target/release/sudo-request target/release/sudo-request-executor dist/

(cd web && bun install --frozen-lockfile && bun run build)
cp -r web/dist dist/web

(cd server && bun install --frozen-lockfile && bun build src/main.ts --compile --outfile ../dist/sudo-request-server)

echo "Built:"
ls -l dist
