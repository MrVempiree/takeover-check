# Contributing to takeover-check

Thanks for helping improve takeover-check. This tool exists for **authorised**
security testing and defence: only ever check domains you own or have
explicit written permission to test.

## Getting set up

```bash
git clone https://github.com/MrVempiree/takeover-check.git
cd takeover-check
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Python 3.9+ is required. The test suite runs fully offline — DNS and HTTP
behaviour is mocked, never queried against live third-party domains.

## How the code is organised

- `takeover_check/fingerprints.py` and `takeover_check/data/` — the
  dangling-service fingerprints (CNAME patterns and response signatures)
- `takeover_check/checker.py` — the checking logic
- `takeover_check/report.py` — result formatting
- `takeover_check/cli.py` — command-line interface (`takeover-check`)
- `tests/test_checker.py`, `tests/test_fingerprints_reports_cli.py`

## Adding a fingerprint for a new service

This is the most valuable kind of contribution. A good fingerprint entry has:

1. The service name and the CNAME suffix its customers point at.
2. The exact response signature of an **unclaimed** resource (error text,
   status code, or NXDOMAIN behaviour) — quoted from the provider's own
   error page, not guessed.
3. A note on false-positive risk: services whose unclaimed state looks like a
   normal page need extra care and a stricter signature.

Add the entry in the existing data format, and add tests covering a
claimed resource (no finding), an unclaimed one (finding), and an unrelated
domain (no finding). If you cannot verify the unclaimed signature against
the provider's documentation or your own test resource on that provider, say
so in the PR — unverified fingerprints get parked, not merged.

## Pull requests

- One fingerprint or one fix per PR, with the source of the signature in the
  description.
- All tests must pass (`pytest` green) and new behaviour must be covered by
  tests.
- Examples use `example.com` and your own test subdomains only.

## Reporting bugs

Open an issue with the command you ran, the domain type involved (sanitise
real domains you do not own), and the result you expected.
