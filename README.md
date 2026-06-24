# tls-auditor

Audit the TLS configuration of a target host.

## Install

```bash
pip install -e ".[dev]"
```

## Run

```bash
tls-auditor <host:port>
```

## Develop

```bash
ruff check .
pytest
```

## Grading rubric

The `grade(protocols, chain, ciphers)` function in `tls_auditor.scoring` rolls a probe into a single SSL-Labs-style letter grade.

Starts at a 100-point score and applies:

| Condition | Effect |
| --- | --- |
| Cert expired | Hard `F` |
| No TLS protocol versions accepted | Hard `F` |
| Hostname does not match SAN/CN | Caps at `F` |
| Self-signed cert | -30 points |
| Cert expires in ≤30 days | -10 points |
| TLS 1.0 or 1.1 supported | Caps at `C` |
| TLS 1.3 not supported | -10 points |
| Each weak cipher accepted | -10 (capped at -40) |

Final score → grade: ≥95 `A+`, ≥85 `A`, ≥75 `B`, ≥65 `C`, ≥50 `D`, else `F`.
