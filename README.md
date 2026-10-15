# lucasgundry.com

Static site, no build step and no JavaScript. Served as static assets by
the Cloudflare Worker `lucasgundry` (Workers Builds, config in
`wrangler.jsonc`): a push to `main` deploys production, and every other
branch uploads a version with its own preview URL. Only `public/` is served.

- Pages are plain HTML in `public/`; shared styles in `public/assets/style.css`.
- `public/_headers` sets the security headers (CSP, HSTS, and others).
- Before every push: `scripts/check.sh` (gitleaks, a grep for private lab
  details, internal links). Any failure blocks the push.

Preview locally: run `python3 -m http.server -d public` and open the address it prints.
