# lucasgundry.com

Static site, no build step and no JavaScript. Served as static assets by
the Cloudflare Worker `lucasgundry` (config in `wrangler.jsonc`). Only
`public/` is served.

- Preview: `scripts/deploy-preview.sh` runs the checks, then uploads a
  version to https://preview-lucasgundry.lucas-gundry.workers.dev. It
  never deploys production.
- Production: `wrangler versions deploy`, only with Lucas's OK.

- Pages are plain HTML in `public/`; shared styles in `public/assets/style.css`.
- `public/_headers` sets the security headers (CSP, HSTS, and others).
- Before every push: `scripts/check.sh` (gitleaks, a grep for private lab
  details, image metadata, internal links). Any failure blocks the push.
- Write-ups show evidence as text: proof blocks rebuilt from real output
  with private details replaced, inline SVG diagrams, and CSS-only replays
  (radio buttons; no script, so the CSP stays `default-src 'none'`).

## Release safety

Two scripts guard what reaches the public site:

- [`scripts/check.sh`](scripts/check.sh) runs before every push and every
  deploy. It runs gitleaks over the files and the history, searches for
  private details a secret scanner wouldn't flag, checks images and the PDF
  for metadata, and confirms internal links resolve. The script holds only
  pattern shapes. Real names stay in a git-ignored file, so the check can't
  leak what it looks for.
- [`scripts/deploy-production.sh`](scripts/deploy-production.sh) is run by
  hand. It deploys only a clean `main` that matches `origin/main`, re-runs the
  checks, and confirms the version was uploaded from that exact commit. It
  then asks for a typed confirmation and waits until production serves every
  file of the new version. It also refuses to run in an AI agent's shell;
  that's a seatbelt, not a security boundary.

Preview locally: run `python3 -m http.server -d public` and open the address it prints.
