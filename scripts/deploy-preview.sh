#!/usr/bin/env bash
# Upload the current tree as a preview version (never production):
#   https://preview-lucasgundry.lucas-gundry.workers.dev
# Runs check.sh first and stops on any failure. Wrangler runs in a
# throwaway container; ~/.cloudflare_env is mounted read-only and is the
# only credential it sees. Production is `wrangler versions deploy`,
# which this script never runs.
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/check.sh
[ "$(stat -c '%a' "$HOME/.cloudflare_env")" = 600 ] || { echo "~/.cloudflare_env must be mode 600" >&2; exit 2; }
rev=$(git rev-parse --short HEAD)
dirty=$(git status --porcelain | grep -q . && echo "+uncommitted" || true)
docker run --rm \
  -v "$PWD":/src:ro -v "$HOME/.cloudflare_env":/run/cf_env:ro \
  -e WRANGLER_SEND_METRICS=false -e HOME=/tmp \
  node:22-slim sh -c "cp -r /src /tmp/site && cd /tmp/site && set -a && . /run/cf_env && set +a &&
    npx -y wrangler@4.151.0 versions upload --preview-alias preview --message 'preview $rev$dirty'" \
  2>&1 | grep -vE '^npm (notice|warn)'
