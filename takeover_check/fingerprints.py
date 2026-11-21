"""Bundled fingerprint dataset of dangling-service signatures.

The dataset follows the conventions of public subdomain-takeover research
(notably the community-maintained "Can I take over XYZ" catalogue): each
entry names a service, the CNAME suffixes that point at it, the HTTP body
signature the service returns when the underlying resource has been
deleted, and whether a non-resolving (NXDOMAIN) CNAME target is itself a
takeover signal for that service.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

DATA_FILE = Path(__file__).parent / "data" / "fingerprints.json"


@dataclass
class Fingerprint:
    service: str
    cname_suffixes: List[str]
    http_fingerprints: List[str]
    nxdomain_vulnerable: bool
    notes: str = ""

    def matches_cname(self, cname: str) -> bool:
        """Label-boundary suffix match: 'user.github.io' matches 'github.io',
        and 'bucket.s3-website-us-east-1.amazonaws.com' matches the partial
        label 's3-website', while 'notgithub.io' matches neither."""
        target = "." + cname.rstrip(".").lower()
        return any(("." + suffix.lower()) in target
                   for suffix in self.cname_suffixes)

    def match_body(self, body: str) -> Optional[str]:
        """Return the matched HTTP fingerprint string, if any."""
        for fingerprint in self.http_fingerprints:
            if fingerprint in body:
                return fingerprint
        return None


def load_fingerprints(path: Optional[Path] = None) -> List[Fingerprint]:
    with open(path or DATA_FILE, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return [Fingerprint(**entry) for entry in raw]


def match_service(cname: str,
                  fingerprints: List[Fingerprint]) -> Optional[Fingerprint]:
    for fingerprint in fingerprints:
        if fingerprint.matches_cname(cname):
            return fingerprint
    return None
