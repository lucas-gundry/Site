#!/usr/bin/env bash
# Send 100% of production traffic to a version already uploaded by
# deploy-preview.sh:
#   scripts/deploy-production.sh <version-id>
# Lucas runs this by hand. Claude never runs it (sprint rules in
# ~/homelab/CLAUDE.md); the agent and TTY checks below are a seatbelt for
# that rule, not a security boundary.
#
# Order: refuse in an agent shell -> version ID shape -> on main, clean,
# same as origin/main -> check.sh -> the version's upload message names
# this commit (and not "+uncommitted") -> type "deploy" -> deploy.
# Wrangler runs in a throwaway container, as in deploy-preview.sh;
# ~/.cloudflare_env is mounted read-only and is the only credential it sees.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "deploy-production: $*" >&2; exit 2; }

[ -z "${CLAUDECODE:-}${AI_AGENT:-}" ] || die "refusing to run in an AI agent's shell; Lucas runs this by hand"
[ -t 0 ] || die "needs a terminal (it asks for confirmation)"

[ $# -eq 1 ] || die "usage: scripts/deploy-production.sh <version-id> (from deploy-preview.sh's output)"
id=$1
[[ "$id" =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] || die "not a version ID: $id"

[ "$(git branch --show-current)" = main ] || die "check out main first"
[ -z "$(git status --porcelain)" ] || die "uncommitted changes; commit or remove them first"
git fetch -q origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main differs from origin/main; push or pull first"

./scripts/check.sh

[ "$(stat -c '%a' "$HOME/.cloudflare_env")" = 600 ] || die "~/.cloudflare_env must be mode 600"
rev=$(git rev-parse --short HEAD)

wrangler() {
  docker run --rm \
    -v "$PWD":/src:ro -v "$HOME/.cloudflare_env":/run/cf_env:ro \
    -e WRANGLER_SEND_METRICS=false -e HOME=/tmp \
    node:22-slim sh -c "cp -r /src /tmp/site && cd /tmp/site && set -a && . /run/cf_env && set +a &&
      npx -y wrangler@4.151.0 $*" \
    2>&1 | grep -vE '^npm (notice|warn)'
}

echo "== Version $id"
view=$(wrangler versions view "$id")
echo "$view"
# deploy-preview.sh uploads with the message "preview <commit>[+uncommitted]".
echo "$view" | grep -qE "preview ${rev}([^+0-9a-f]|$)" \
  || die "this version wasn't uploaded from commit $rev with a clean tree; run deploy-preview.sh on main first"

read -r -p "Send 100% of production traffic to $id (commit $rev)? Type deploy: " answer
[ "$answer" = deploy ] || die "not deployed"

wrangler versions deploy "$id@100%" --yes --message "production-$rev"
echo "Deployed $id (commit $rev). Check the live URLs."
