from __future__ import annotations

import argparse
import ssl
import sys

from .chain import analyze as analyze_chain
from .output import _coerce_audit_inputs, render_json, render_text
from .probe import Endpoint, fetch_cert
from .protocols import probe as probe_protocols

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
    audit.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors in text output."
    )
    audit.add_argument(
        "--no-protocols",
        action="store_true",
        help="Skip TLS protocol version probing.",
    )
    return parser


def _load_grade():
    try:
        from .scoring import grade  # noqa: PLC0415
        return grade
    except ImportError:
        return None


def run_audit(target: str, timeout: float, output: str, *, color: bool, probe_p: bool) -> int:
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

    protocols = probe_protocols(endpoint, timeout=timeout) if probe_p else ()
    chain = analyze_chain(cert, endpoint.host)
    grade_fn = _load_grade()
    grade = grade_fn(protocols=protocols, chain=chain, ciphers=()) if grade_fn else None

    result = _coerce_audit_inputs(
        host=endpoint.host,
        port=endpoint.port,
        cert=cert,
        protocols=protocols,
        chain=chain,
        ciphers=(),
        grade=grade,
    )

    if output == "json":
        print(render_json(result))
    else:
        print(render_text(result, color=color))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        return run_audit(
            args.target,
            args.timeout,
            args.output,
            color=not args.no_color,
            probe_p=not args.no_protocols,
        )
    return 2


if __name__ == "__main__":
    sys.exit(main())
