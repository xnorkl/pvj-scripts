#!/usr/bin/env bash
# Usage: ./tests/test-compose.sh [windows]   # needs docker compose; 'windows' profile needs a KVM Linux host
set -euo pipefail
cd "$(dirname "$0")/.."
profile=${1:-}
args=(-f tests/compose.yml)
[[ $profile == windows ]] && args+=(--profile windows)
docker compose "${args[@]}" up --build --abort-on-container-exit --exit-code-from runner
code=$?
docker compose "${args[@]}" down -v >/dev/null 2>&1 || true
exit $code
