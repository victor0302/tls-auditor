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

## 2026-06-20 — Issue #3: TLS protocol probe

`src/tls_auditor/protocols.py`. One TLS handshake per protocol version (1.0 / 1.1 / 1.2 / 1.3), with `minimum_version == maximum_version` pinned to each.

- `probe(endpoint, timeout)` returns `list[ProtocolResult(name, supported, insecure, error)]`
- TLS 1.0 and 1.1 always carry `insecure=True` regardless of whether the server accepts them
- Deprecation warnings from setting deprecated `TLSVersion` enum members are suppressed *inside* the probe — the *result* (server accepted them) is the actual signal
- Handshake errors are captured into `result.error`, not raised
- Verified live against `example.com:443`: 1.2/1.3 supported, 1.0/1.1 unsupported (Python's own client refuses to send them now)

Decisions:
- **One context per probe.** It's tempting to reuse a single context and just flip min/max — but mocking and reasoning are both simpler when each probe is hermetic.
- **Insecure flag is independent of `supported`.** A server that doesn't speak 1.0 still gets `insecure=True` in the row — the meaning is "this protocol is unsafe to use", not "this server is unsafe". Output rendering decides whether to grey out the row.
- **Errors stored, not raised.** "TLS 1.0 handshake failed" is the *answer*, not an exception. Treating it as an exception means callers have to catch four of them; storing it lets the caller print a clean matrix.
- **Suppress `DeprecationWarning` at the assignment.** Python warns when you *use* a deprecated TLSVersion enum value. We are deliberately using them — passing the warning to the user would be noise.

## 2026-06-20 — Issue #4: certificate chain analysis

`src/tls_auditor/chain.py`. Pure analysis on top of `CertBasics` — no new I/O. The reason it's its own module: I want to be able to feed it a cert from anywhere (live probe, stored PEM, test fixture) without changing the analyzer.

- `analyze(cert, hostname, now=None)` returns `ChainAnalysis(expired, expires_soon, days_until_expiry, self_signed, hostname_matches, san, warnings, errors)`
- Expiry warning threshold: 30 days
- Self-signed = subject == issuer (both compared as dicts)
- Hostname match: SAN first, CN fallback, case-insensitive, wildcards via `fnmatch`
- `now` is injectable — every "expiry" test in the suite uses a fixed clock

Decisions:
- **`now` is a parameter.** Time-dependent tests that read `datetime.now()` are how flaky CI happens. One parameter, default to `datetime.now(UTC)`, problem permanently solved.
- **Warnings and errors are separate tuples.** Callers (especially #6, scoring) want different weights for "self-signed" (deduct points) and "expired" (fail outright). One mixed list would force string-matching to recover the distinction.
- **`fnmatch` for wildcard matching.** `*.example.com` matches `api.example.com` but not `example.com` — exactly the right semantics for SAN wildcards. No need for a custom matcher.
- **SAN before CN, CN as fallback.** Modern certs put hostnames in SAN; CN-only certs are legacy. Both are still in the wild, so the fallback is real, but SAN is the source of truth when it exists.
- **No cryptographic chain validation.** This module doesn't verify the chain back to a root — that's `ssl`'s job and it already happened at handshake time. We're analyzing what the handshake returned.

## 2026-06-20 — Issue #5: weak cipher detection

`src/tls_auditor/ciphers.py`. Two halves: a pure `classify()` function for unit-testing the rules, and an `enumerate_ciphers()` that does the live cipher-by-cipher handshake.

- Weak-suite tokens: `RC4`, `3DES`, `DES-`, `NULL`, `EXPORT`, `EXP-`, `MD5` — each match contributes its own reason string
- TLS 1.2 suites without forward secrecy (anything not starting with `ECDHE` / `DHE` / `TLS_AES` / `TLS_CHACHA`) flagged with `"no forward secrecy"`
- TLS 1.3 exempt from the PFS check — every 1.3 cipher suite is PFS by construction
- `enumerate_ciphers()` walks a candidate list, attempts a single-cipher handshake at TLS 1.2 *and* TLS 1.3, and records what the server actually negotiated
- Pinning to `set_ciphers(<single>)` can fail at the local OpenSSL level (unsupported cipher names); those are silently skipped — what matters is what the *server* accepts
- Stdlib only

Decisions:
- **Two surfaces, not one.** `classify()` is pure and gets all the rule coverage; `enumerate_ciphers()` is glue that calls handshakes. Splitting them means tests don't need a TLS server and the live function stays small.
- **Each weak token contributes its own reason.** A cipher that's RC4 *and* MD5 is more broken than one with just RC4; the reason list lets a scoring pass weight that. Joining them into "RC4+MD5+EXP-" loses that.
- **Both `EXPORT` and `EXP-` tokens.** OpenSSL has used both spellings over the years (`EXP-RC4-MD5`, `EXP1024-RC4-SHA`); matching both is one line and avoids missing legitimate export ciphers.
- **Reuse `set_ciphers(<single>)` instead of negotiating freely.** The standard "list of accepted ciphers" technique. Yes, it's many handshakes — but each is fast and the *only* way to know what the server would actually negotiate.
- **TLS 1.3 separate code path.** TLS 1.3 cipher suite names (`TLS_AES_256_GCM_SHA384`) don't match the OpenSSL 1.2 grammar; the PFS prefix check would false-positive without the `TLS_AES` / `TLS_CHACHA` allowlist.
- **Local pinning failures swallowed.** If the local OpenSSL doesn't ship `EXP-RC4-MD5`, that's not a server problem — the candidate just isn't testable from this client.

## Open follow-ups (tracked as issues)

- #6 scoring / grade (A+ to F) — will consume protocols + chain + ciphers
- #7 output formats: text + JSON (fill in real bodies)
- #8 GitHub Actions: lint + test workflow
