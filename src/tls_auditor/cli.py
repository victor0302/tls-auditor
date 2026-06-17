from __future__ import annotations

import argparse
import json
import ssl
import sys
from dataclasses import asdict

from .probe import CertBasics, Endpoint, fetch_cert

OUTPUT_CHOICES: tuple[str, ...] = ("text", "json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-auditor",
        description="Audit the TLS configuration of a target host.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="Connect and dump cert basics.")
    audit.add_argument("target", help="Target as host or host:port (default port 443).")
    audit.add_argument("--timeout", type=float, default=10.0, help="Connect timeout in seconds.")
    audit.add_argument("--output", choices=OUTPUT_CHOICES, default="text")
    return parser


def format_cert(cert: CertBasics, output: str) -> str:
    if output == "json":
        return json.dumps(asdict(cert), indent=2)
    lines = [
        f"Subject:    {cert.subject.get('commonName', '?')}",
        f"Issuer:     {cert.issuer.get('commonName', '?')}",
        f"Not before: {cert.not_before}",
        f"Not after:  {cert.not_after}",
        f"SAN:        {', '.join(cert.san) if cert.san else '(none)'}",
    ]
    return "\n".join(lines)


def run_audit(target: str, timeout: float, output: str) -> int:
    try:
        endpoint = Endpoint.parse(target)
    except ValueError:
        print(f"error: could not parse target {target!r}", file=sys.stderr)
        return 2
    try:
        cert = fetch_cert(endpoint, timeout=timeout)
    except (OSError, ssl.SSLError) as exc:
        print(f"error: failed to fetch certificate for {target}: {exc}", file=sys.stderr)
        return 1
    print(format_cert(cert, output))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        return run_audit(args.target, args.timeout, args.output)
    return 2


if __name__ == "__main__":
    sys.exit(main())
