"""Command-line interface for takeover-check."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import report
from .checker import check_subdomains


def load_subdomains(args: argparse.Namespace) -> List[str]:
    subdomains = list(args.subdomains or [])
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    subdomains.append(line)
    return subdomains


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="takeover-check",
        description="Check subdomains for dangling CNAMEs that allow "
                    "subdomain takeover. Authorised testing only — check "
                    "domains you own or have explicit permission to assess.",
    )
    parser.add_argument("subdomains", nargs="*",
                        help="Subdomain(s) to check")
    parser.add_argument("-f", "--file",
                        help="File with one subdomain per line")
    parser.add_argument("--format", choices=["terminal", "json", "markdown"],
                        default="terminal", help="Report format")
    parser.add_argument("-o", "--output", help="Write the report to a file")
    parser.add_argument("--no-fail", action="store_true",
                        help="Always exit 0, even when vulnerable "
                             "subdomains are found")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    subdomains = load_subdomains(args)
    if not subdomains:
        parser.error("no subdomains given (pass names or --file)")

    results = check_subdomains(subdomains)

    if args.format == "json":
        output = report.to_json(results)
    elif args.format == "markdown":
        output = report.to_markdown(results)
    else:
        output = report.to_terminal(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
    else:
        print(output)

    vulnerable = any(r.status == "vulnerable" for r in results)
    return 1 if (vulnerable and not args.no_fail) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
