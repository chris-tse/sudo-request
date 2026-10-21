#!/usr/bin/env bash
# Full unprivileged test suite: Rust unit tests, backend unit + end-to-end tests, type checks.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo test
cargo build
(cd server && bun run typecheck && bun test)
(cd web && bun run typecheck)
