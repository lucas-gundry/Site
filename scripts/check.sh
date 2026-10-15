#!/usr/bin/env bash
# Pre-push checks for the site. Run before every push; any hit blocks it.
#   1. gitleaks over the working tree and history
#   2. a grep for private lab details that a secret scanner wouldn't flag
#   3. internal links point at files that exist
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0

if command -v gitleaks >/dev/null; then
  gitleaks dir --no-banner --redact . || fail=1
  if git rev-parse --verify -q HEAD >/dev/null; then
    gitleaks git --no-banner --redact . || fail=1
  fi
else
  echo "FAIL: gitleaks not installed" >&2; fail=1
fi

# Private details: Okta org, lab hostnames and container names, account
# names, IP addresses, UUIDs (event IDs), ping URLs, personal email.
patterns=(
  'integrator-[0-9]+' 'okta(preview)?\.com/' '-admin\.okta'
  '\blabby\b' '\bes01\b' 'elastic-es01' 'fleet-server' 'kibana_rules'
  '\blab-(analyst|admin)\b' 'analyst-read' '\bdaddio\b' '\belastic_env\b' '_env\b'
  '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
  'hc-ping\.com' '@gmail\.com' 'bionic\.lucasgundry' 'localhost:[0-9]+'
)
files=$(git ls-files --cached --others --exclude-standard | grep -vE '^(scripts/check\.sh|\.gitignore)$')
for p in "${patterns[@]}"; do
  hits=$(echo "$files" | xargs -r grep -nEi -- "$p" 2>/dev/null)
  if [ -n "$hits" ]; then echo "FAIL private detail /$p/:"; echo "$hits"; fail=1; fi
done

# Internal links: every href="/..." must resolve to a file under public/.
for f in $(echo "$files" | grep '^public/.*\.html$'); do
  for h in $(grep -oE 'href="/[^"#]*"' "$f" | sed -E 's/href="\/(.*)"/\1/'); do
    t="$h"; [ -z "$t" ] || [[ "$t" == */ ]] && t="${t}index.html"
    [ -e "public/$t" ] || { echo "FAIL broken link in $f: /$h"; fail=1; }
  done
done

[ $fail -eq 0 ] && echo "All checks passed." || echo "Checks FAILED: fix before pushing."
exit $fail
