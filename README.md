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

Preview locally: run `python3 -m http.server -d public` and open the address it prints.
