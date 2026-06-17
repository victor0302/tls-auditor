import json
from unittest.mock import patch

import pytest

from tls_auditor import __version__
from tls_auditor.cli import build_parser, format_cert, main
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
        not_after="Jan  1 00:00:00 2026 GMT",
    )


def test_format_cert_text():
    out = format_cert(_sample_cert(), "text")
    assert "Subject:    example.com" in out
    assert "Issuer:     Test CA" in out
    assert "www.example.com" in out


def test_format_cert_json():
    payload = json.loads(format_cert(_sample_cert(), "json"))
    assert payload["subject"]["commonName"] == "example.com"
    assert "www.example.com" in payload["san"]


def test_main_uses_mocked_probe(capsys):
    with patch("tls_auditor.cli.fetch_cert", return_value=_sample_cert()):
        rc = main(["audit", "example.com:443"])
    assert rc == 0
    assert "Subject:    example.com" in capsys.readouterr().out


def test_main_handles_connection_failure(capsys):
    with patch("tls_auditor.cli.fetch_cert", side_effect=OSError("nope")):
        rc = main(["audit", "example.com:443"])
    assert rc == 1
    assert "failed to fetch certificate" in capsys.readouterr().err
