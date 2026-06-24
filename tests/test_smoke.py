import json
from unittest.mock import patch

import pytest

from tls_auditor import __version__
from tls_auditor.cli import build_parser, main
from tls_auditor.probe import CertBasics, Endpoint


def test_version():
    assert __version__ == "0.1.0"


def test_parser_requires_subcommand():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_parser_audit_defaults():
    args = build_parser().parse_args(["audit", "example.com:443"])
    assert args.command == "audit"
    assert args.target == "example.com:443"
    assert args.timeout == 10.0
    assert args.output == "text"


def test_endpoint_parse_with_port():
    assert Endpoint.parse("example.com:8443") == Endpoint("example.com", 8443)


def test_endpoint_parse_default_port():
    assert Endpoint.parse("example.com") == Endpoint("example.com", 443)


def _sample_cert() -> CertBasics:
    return CertBasics(
        subject={"commonName": "example.com"},
        issuer={"commonName": "Test CA"},
        san=["example.com", "www.example.com"],
        not_before="Jan  1 00:00:00 2025 GMT",
        not_after="Jan  1 00:00:00 2030 GMT",
    )


def test_main_renders_text(capsys):
    with patch("tls_auditor.cli.fetch_cert", return_value=_sample_cert()), \
         patch("tls_auditor.cli.probe_protocols", return_value=()):
        rc = main(["audit", "example.com:443", "--no-color", "--no-protocols"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Subject:    example.com" in out
    assert "Grade:" in out


def test_main_renders_json(capsys):
    with patch("tls_auditor.cli.fetch_cert", return_value=_sample_cert()), \
         patch("tls_auditor.cli.probe_protocols", return_value=()):
        rc = main(["audit", "example.com:443", "--output", "json", "--no-protocols"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["host"] == "example.com"
    assert payload["port"] == 443
    assert payload["certificate"]["subject"]["commonName"] == "example.com"
    assert "grade" in payload


def test_main_handles_connection_failure(capsys):
    with patch("tls_auditor.cli.fetch_cert", side_effect=OSError("nope")):
        rc = main(["audit", "example.com:443"])
    assert rc == 1
    assert "failed to fetch certificate" in capsys.readouterr().err
