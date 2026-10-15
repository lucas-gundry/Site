# lucasgundry.com

Static site, no build step and no JavaScript. Hosted on Cloudflare Pages:
`main` deploys to lucasgundry.com, every other branch gets a preview URL.

- Pages are plain HTML; shared styles in `assets/style.css`.
- `_headers` sets the security headers (CSP, HSTS, and others) on Cloudflare Pages.
- Before every push: `scripts/check.sh` (gitleaks, a grep for private lab
  details, internal links). Any failure blocks the push.

Preview locally: run `python3 -m http.server` here and open the address it prints.
