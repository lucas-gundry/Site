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
# this commit (and not "+uncommitted") -> type "deploy" -> deploy -> wait
# until production serves every file of this version (exit 3 if not).
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

# Wait until production serves this version. A version switch takes a few
# minutes to reach every Cloudflare server; purging the cache doesn't speed
# it up. Each version has its own address that serves exactly its files, so
# compare every served file's ETag there with production's. All files, not
# just Home: a deploy that doesn't touch Home would otherwise pass at once.
# Exit 3: deployed, but not confirmed live (nothing is rolled back).
ver="https://${id:0:8}-lucasgundry.lucas-gundry.workers.dev"
prod="https://lucasgundry.com"
etag() { curl -sIL --max-time 10 "$1" 2>/dev/null | tr -d '\r' | awk 'tolower($1)=="etag:"{e=$2} END{print e}' || true; }
# Every path starts with "/" so Home ("/") isn't lost as an empty word.
paths=$(git ls-files public | grep -v '_headers$' | sed 's|^public||; s|index\.html$||')
declare -A want
for p in $paths; do
  want[$p]=$(etag "$ver$p")
  [ -n "${want[$p]}" ] || { echo "deploy-production: deployed, but $ver$p has no ETag; check the live URLs by hand" >&2; exit 3; }
done
echo "== Waiting for production to serve $id (${#want[@]} files, up to 10 minutes)"
for try in $(seq 1 40); do
  stale=()
  for p in $paths; do [ "$(etag "$prod$p")" = "${want[$p]}" ] || stale+=("$p"); done
  if [ ${#stale[@]} -eq 0 ]; then
    echo "Live: production serves $id (commit $rev), all ${#want[@]} files match."
    exit 0
  fi
  echo "  $(date +%T): ${#stale[@]} of ${#want[@]} files not updated yet"
  sleep 15
done
echo "deploy-production: deployed $id, but after 10 minutes production still differs on:" >&2
printf '  %s\n' "${stale[@]}" >&2
exit 3
