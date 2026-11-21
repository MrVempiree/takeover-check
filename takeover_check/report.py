"""Report rendering for takeover-check: terminal, JSON and Markdown."""

from __future__ import annotations

import json
from typing import List

from .checker import Result

STATUS_LABEL = {"vulnerable": "VULNERABLE", "claimed": "CLAIMED",
                "unknown": "UNKNOWN"}


def to_json(results: List[Result]) -> str:
    payload = {
        "tool": "takeover-check",
        "checked": len(results),
        "vulnerable": sum(1 for r in results if r.status == "vulnerable"),
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2)


def to_markdown(results: List[Result]) -> str:
    lines = ["# takeover-check report", ""]
    if not results:
        lines.append("No subdomains were checked.")
        return "\n".join(lines) + "\n"
    vulnerable = sum(1 for r in results if r.status == "vulnerable")
    lines.append(f"**{len(results)} checked — {vulnerable} vulnerable**")
    lines.append("")
    lines.append("| Subdomain | CNAME | Service | Status | Evidence |")
    lines.append("|---|---|---|---|---|")
    for r in results:
        lines.append(
            f"| {r.subdomain} | {r.cname or '-'} | {r.service or '-'} | "
            f"{STATUS_LABEL[r.status]} | {r.evidence} |")
    lines.append("")
    for r in results:
        if r.status == "vulnerable":
            lines.append(f"## {r.subdomain} — remediation")
            lines.append("")
            lines.append(r.remediation)
            lines.append("")
    return "\n".join(lines)


def to_terminal(results: List[Result]) -> str:
    if not results:
        return "[*] No subdomains were checked."
    out = []
    for r in results:
        out.append(f"[{STATUS_LABEL[r.status]}] {r.subdomain}")
        out.append(f"    CNAME:    {r.cname or '-'}")
        out.append(f"    Service:  {r.service or '-'}")
        out.append(f"    Evidence: {r.evidence}")
        if r.status == "vulnerable":
            out.append(f"    Fix:      {r.remediation}")
        out.append("")
    vulnerable = sum(1 for r in results if r.status == "vulnerable")
    out.append(f"{len(results)} checked, {vulnerable} vulnerable.")
    return "\n".join(out)
