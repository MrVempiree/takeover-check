"""Subdomain takeover classification logic.

For each subdomain the checker resolves its CNAME, matches the target
against the bundled fingerprint dataset, and then classifies it:

- ``vulnerable`` — the CNAME points at a takeover-prone service AND the
  service answers with its "resource deleted" signature (or the CNAME
  target no longer resolves for services where that alone is the signal);
- ``claimed`` — the CNAME points at a known service that responds
  normally, i.e. the resource still exists;
- ``unknown`` — no CNAME, an unrecognised target, or an inconclusive
  result that needs manual review.

DNS and HTTP are injectable callables so the classifier is fully testable
offline with mocked resolution and responses.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .fingerprints import Fingerprint, load_fingerprints, match_service

HttpGetFn = Callable[[str], Tuple[int, str]]


class SystemResolver:
    """DNS resolution built on the standard library."""

    def cname(self, host: str) -> Optional[str]:
        try:
            _, aliases, _ = socket.gethostbyname_ex(host)
        except (socket.gaierror, UnicodeError):
            return None
        return aliases[0] if aliases else None

    def resolves(self, host: str) -> bool:
        try:
            socket.getaddrinfo(host.rstrip("."), None)
            return True
        except (socket.gaierror, UnicodeError):
            return False


def http_get(host: str, timeout: int = 10) -> Tuple[int, str]:
    """Fetch http://<host>/ and return (status, body). (0, '') on failure."""
    req = urllib.request.Request(f"http://{host}/",
                                 headers={"User-Agent": "takeover-check/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read(8192).decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body
    except Exception:
        return 0, ""


@dataclass
class Result:
    subdomain: str
    cname: Optional[str]
    service: Optional[str]
    status: str  # vulnerable | claimed | unknown
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "subdomain": self.subdomain,
            "cname": self.cname,
            "service": self.service,
            "status": self.status,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


REMEDIATION_VULNERABLE = (
    "Remove the dangling DNS record immediately, or re-create the resource "
    "on the service under your own account. Audit DNS for other records "
    "pointing at the same service."
)
REMEDIATION_CLAIMED = (
    "No action needed — the service resource still exists. Re-check if the "
    "resource is ever deleted."
)
REMEDIATION_UNKNOWN = (
    "Review manually: confirm the CNAME target is still in use, and remove "
    "the record if the service is no longer used."
)


def check_subdomain(subdomain: str, resolver,
                    http_get_fn: HttpGetFn,
                    fingerprints: List[Fingerprint]) -> Result:
    cname = resolver.cname(subdomain)
    if not cname:
        return Result(subdomain, None, None, "unknown",
                      "No CNAME record found for this subdomain.",
                      REMEDIATION_UNKNOWN)

    entry = match_service(cname, fingerprints)
    if entry is None:
        return Result(subdomain, cname, None, "unknown",
                      f"CNAME points to {cname}, which does not match any "
                      "known takeover-prone service in the dataset.",
                      REMEDIATION_UNKNOWN)

    if not resolver.resolves(cname):
        if entry.nxdomain_vulnerable:
            return Result(
                subdomain, cname, entry.service, "vulnerable",
                f"CNAME target {cname} ({entry.service}) no longer resolves "
                "(NXDOMAIN). The name can be registered by an attacker.",
                REMEDIATION_VULNERABLE)
        return Result(
            subdomain, cname, entry.service, "unknown",
            f"CNAME target {cname} ({entry.service}) does not resolve, but "
            "this service is not normally claimable via NXDOMAIN alone — "
            "verify manually.",
            REMEDIATION_UNKNOWN)

    status, body = http_get_fn(subdomain)
    matched = entry.match_body(body)
    if matched:
        return Result(
            subdomain, cname, entry.service, "vulnerable",
            f"{entry.service} returned its unclaimed-resource signature "
            f"(HTTP {status}): \"{matched}\"",
            REMEDIATION_VULNERABLE)

    return Result(
        subdomain, cname, entry.service, "claimed",
        f"CNAME points to {entry.service} and the service responds "
        f"(HTTP {status}) without an unclaimed-resource signature.",
        REMEDIATION_CLAIMED)


def check_subdomains(subdomains: List[str], resolver=None,
                     http_get_fn: Optional[HttpGetFn] = None,
                     fingerprints: Optional[List[Fingerprint]] = None
                     ) -> List[Result]:
    if resolver is None:
        resolver = SystemResolver()
    if http_get_fn is None:
        http_get_fn = http_get
    if fingerprints is None:
        fingerprints = load_fingerprints()
    return [check_subdomain(sub, resolver, http_get_fn, fingerprints)
            for sub in subdomains]
