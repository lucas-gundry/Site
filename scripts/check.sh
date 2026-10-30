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
# names, IP addresses, UUIDs (event IDs), ping URLs, personal email, and
# AWS identifiers (12-digit account IDs, the Identity Center start URL,
# the Terraform state bucket's real name). Patterns are shapes, never the
# real values, so this file can't leak them itself.
patterns=(
  '\b[0-9]{12}\b' '\bd-[0-9a-z]{10}\b' 'awsapps\.com' 'bionic-tfstate-[0-9a-f]{6,}'
  'integrator-[0-9]+' 'okta(preview)?\.com/' '-admin\.okta'
  '\blabby\b' '\bes01\b' 'elastic-es01' 'fleet-server' 'kibana_rules'
  '\blab-(analyst|admin)\b' 'analyst-read' '\bdaddio\b' '\belastic_env\b' '_env\b'
  '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
  'hc-ping\.com' '@gmail\.com' 'bionic\.lucasgundry' 'localhost:[0-9]+'
)
files=$(git ls-files --cached --others --exclude-standard | grep -vE '^(scripts/check\.sh|\.gitignore)$')
for p in "${patterns[@]}"; do
  scope=$files
  # scripts/ isn't served and names its own credential file; every other
  # pattern, and gitleaks, still cover it.
  [ "$p" = '_env\b' ] && scope=$(echo "$files" | grep -v '^scripts/')
  hits=$(echo "$scope" | xargs -r grep -nEi -- "$p" 2>/dev/null)
  if [ -n "$hits" ]; then echo "FAIL private detail /$p/:"; echo "$hits"; fail=1; fi
done

# Binary images: the same patterns over their embedded strings, and no
# metadata at all (EXIF, XMP, PNG text chunks can carry hostnames, paths,
# GPS, or the camera owner). SVGs are text and covered by the grep above.
for img in $(echo "$files" | grep -Ei '\.(png|jpe?g|gif|webp|avif|ico)$'); do
  s=$(strings -n 4 "$img")
  for p in "${patterns[@]}"; do
    echo "$s" | grep -qEi -- "$p" && { echo "FAIL private detail /$p/ inside $img"; fail=1; }
  done
  echo "$s" | grep -qE 'Exif|<x:xmpmeta|http://ns\.adobe\.com/xap|tEXt|iTXt|zTXt' \
    && { echo "FAIL metadata in $img: strip it (e.g. exiftool -all= or re-export)"; fail=1; }
done

# PDFs (the resume): the same patterns over the extracted text and the raw
# bytes, and no identifying metadata. The info fields and XMP can carry an
# author, the source file's name and path, or the editing app's account.
# Producer is allowed: it names only the PDF library.
pdfs=$(echo "$files" | grep -Ei '\.pdf$')
if [ -n "$pdfs" ] && ! command -v pdftotext >/dev/null; then
  echo "FAIL: poppler-utils (pdftotext, pdfinfo) not installed; can't check PDFs" >&2; fail=1
else
  for pdf in $pdfs; do
    t=$(pdftotext -q "$pdf" - 2>/dev/null; strings -n 4 "$pdf")
    for p in "${patterns[@]}"; do
      echo "$t" | grep -qEi -- "$p" && { echo "FAIL private detail /$p/ inside $pdf"; fail=1; }
    done
    info=$(pdfinfo "$pdf" 2>/dev/null | grep -E '^(Author|Creator|Title|Subject|Keywords):' | grep -vE ':\s*$')
    [ -z "$info" ] || { echo "FAIL metadata in $pdf: strip it"; echo "$info" | sed 's/^/  /'; fail=1; }
    pdfinfo -meta "$pdf" 2>/dev/null | grep -q '<x:xmpmeta' \
      && { echo "FAIL XMP metadata in $pdf: strip it"; fail=1; }
  done
fi

# Internal links: every href="/..." must resolve to a file under public/.
for f in $(echo "$files" | grep '^public/.*\.html$'); do
  for h in $(grep -oE 'href="/[^"#]*"' "$f" | sed -E 's/href="\/(.*)"/\1/'); do
    t="$h"; [ -z "$t" ] || [[ "$t" == */ ]] && t="${t}index.html"
    [ -e "public/$t" ] || { echo "FAIL broken link in $f: /$h"; fail=1; }
  done
done

[ $fail -eq 0 ] && echo "All checks passed." || echo "Checks FAILED: fix before pushing."
exit $fail
