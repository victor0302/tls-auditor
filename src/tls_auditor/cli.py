import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-auditor",
        description="Audit the TLS configuration of a target host.",
    )
    parser.add_argument("target", nargs="?", help="Target as host or host:port.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print(f"tls-auditor: scaffolding only; nothing to audit yet for {args.target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
