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

## Output formats

### Text

Section-by-section: grade at the top, then certificate, chain, protocols, and ciphers (when present). ANSI colors per severity; `--no-color` to disable. `--no-protocols` skips the protocol probe.

### JSON

```json
{
  "host": "example.com",
  "port": 443,
  "grade": {"grade": "A+", "score": 100, "reasons": []},
  "certificate": {"subject": {...}, "issuer": {...}, "san": [...],
                   "not_before": "...", "not_after": "..."},
  "chain": {"expired": false, "expires_soon": false, "days_until_expiry": 90,
             "self_signed": false, "hostname_matches": true,
             "warnings": [], "errors": [], "san": [...]},
  "protocols": [{"name": "TLSv1.2", "supported": true, "insecure": false, "error": null}],
  "ciphers": [{"name": "...", "protocol": "TLSv1.3", "weak_reasons": [], "is_weak": false}]
}
```

Stable field names — safe to consume from CI.
