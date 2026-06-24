# tls-auditor

[![CI](https://github.com/victor0302/tls-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/victor0302/tls-auditor/actions/workflows/ci.yml)

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
