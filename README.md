# takeover-check

> A subdomain takeover fingerprint checker — finds dangling CNAMEs that point at deleted cloud/hosting resources an attacker can re-register, with evidence and remediation for every result.

![CI](https://github.com/MrVempiree/takeover-check/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)

## Why this matters

When a team deletes a GitHub Pages site, a Heroku app, an S3 bucket or a Shopify store but forgets the DNS record, the subdomain keeps pointing at the service — and anyone can often claim the deleted resource name and serve their own content on the victim's subdomain. That means phishing pages, cookie/session theft and reputation damage on a domain the owner still trusts. takeover-check finds those records before attackers do.

## Features

- **Evidence-based classification** — every subdomain is labelled `vulnerable`, `claimed` or `unknown`, always with the evidence that produced the verdict (matched fingerprint text, NXDOMAIN, HTTP status).
- **Bundled fingerprint dataset** — 15 well-known services (GitHub Pages, GitLab Pages, Heroku, Amazon S3, Microsoft Azure, Netlify, Vercel, Shopify, Fastly, Bitbucket, Surge, Pantheon, Ghost, Tumblr, Fly.io), following the conventions of the public "Can I take over XYZ" research catalogue.
- **Two detection modes** — HTTP body signatures of deleted resources, plus dangling (NXDOMAIN) CNAME detection for services where a non-resolving target is itself the signal.
- **Careful matching** — label-boundary CNAME suffix matching, so `user.github.io` matches GitHub Pages but `notgithub.io` does not.
- **Three report formats** — terminal, JSON and Markdown (Markdown includes a results table and per-finding remediation).
- **Zero dependencies** — standard library only; DNS and HTTP layers are injectable, so the classifier is fully unit-tested offline.

## Installation

```bash
git clone https://github.com/MrVempiree/takeover-check.git
cd takeover-check
pip install .
```

## Usage

```bash
# A few subdomains
takeover-check blog.example.com shop.example.com old.example.com

# A whole subdomain inventory (e.g. from your recon), JSON output
takeover-check --file subdomains.txt --format json -o results.json

# Markdown report for a ticket / client deliverable
takeover-check --file subdomains.txt --format markdown -o report.md
```

The exit code is `1` when any vulnerable subdomain is found (use `--no-fail` to always exit `0`), so it can gate CI or a cron-driven DNS audit.

## Sample output

```text
[VULNERABLE] blog.example.com
    CNAME:    user.github.io
    Service:  GitHub Pages
    Evidence: GitHub Pages returned its unclaimed-resource signature
              (HTTP 404): "There isn't a GitHub Pages site here"
    Fix:      Remove the dangling DNS record immediately, or re-create
              the resource on the service under your own account. Audit
              DNS for other records pointing at the same service.

[CLAIMED] www.example.com
    CNAME:    site.netlify.app
    Service:  Netlify
    Evidence: CNAME points to Netlify and the service responds
              (HTTP 200) without an unclaimed-resource signature.

2 checked, 1 vulnerable.
```

## How it works

1. Resolve each subdomain's CNAME record.
2. Match the CNAME target against the fingerprint dataset (label-boundary suffix match).
3. If the target no longer resolves and the service is known to be claimable in that state → **vulnerable**.
4. Otherwise fetch the subdomain over HTTP and compare the body against the service's "resource deleted" signature → **vulnerable** on a match, **claimed** when the service answers normally.
5. Anything else is **unknown** and reported with the reason, for manual review — the tool never guesses.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## ⚠️ Authorised use only

takeover-check is a security assessment tool. Run it **only** against domains you own or have explicit, written permission to assess (for example, in-scope bug-bounty assets). The author accepts no liability for misuse.

## Author

Created by **Lavish Gangwar** ([MrVempiree](https://github.com/MrVempiree)) — Cybersecurity Researcher & Web Pentester.

## License

MIT — see [LICENSE](LICENSE).
