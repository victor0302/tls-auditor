# tls-auditor — progress notes

Running log of what's been built and why. Append-only.

## 2026-06-17 — Issue #1: scaffolding

Laid down the project skeleton so the rest of the tickets have somewhere to land.

- `pyproject.toml` with PEP 621 metadata, a `tls-auditor` console script entry point
- `src/` layout: `src/tls_auditor/` package, version string, `cli.py`
- `tests/` with a passing smoke test
- ruff + pytest pinned via the `[dev]` extra

Decisions:
- **`src/` layout over flat layout.** Tests import the installed package — catches "works in-tree, breaks on install" early.
- **setuptools, not hatch/poetry.** Stdlib-adjacent, zero ceremony.
- **ruff rules: `E, F, I, UP, B`.** Lint + import sort + modernizers + bugbear.

## 2026-06-17 — Issue #2: `audit` subcommand

First real I/O: connect to a host over TLS and print the basics of the served cert.

- `tls-auditor audit <host:port>` (port defaults to 443)
- Uses stdlib `ssl` + `socket` — no third-party deps
- Prints subject CN, issuer CN, notBefore, notAfter, and SAN DNS entries
- `--timeout` (default 10s) and `--output {text,json}`
- Exit `0` success, `1` connection / TLS failure, `2` bad input
- Verified live against `example.com:443`

Decisions:
- **Stdlib only.** Pulling in `cryptography` or `pyOpenSSL` would buy richer parsing, but `ssl.getpeercert()` is enough for what #2 asks for and keeps `pip install` instant.
- **Probe lives in its own module (`probe.py`).** Later tickets (protocol versions, cipher checks, chain analysis) will all hang off the same connect-and-inspect primitive — separating it from CLI plumbing now avoids a refactor later.
- **`Endpoint` is a frozen dataclass.** Cheap value type with parsing on the class itself — `Endpoint.parse("host:port")` reads better than a free function and is trivial to test.
- **Connection failures exit `1`, bad input exits `2`.** Same convention as the sibling tools — keeps the suite consistent.
- **Tests mock `fetch_cert`.** Live `example.com:443` is the manual smoke test; unit tests can't assume network.

## Open follow-ups (tracked as issues)

- #3 probe supported TLS protocol versions
- #4 certificate chain analysis: expiry, SAN, issuer, self-signed
- #5 detect weak cipher suites
- #6 scoring / grade (A+ to F)
- #7 output formats: text + JSON (fill in real bodies)
- #8 GitHub Actions: lint + test workflow
