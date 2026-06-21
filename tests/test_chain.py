from datetime import datetime, timedelta, timezone

from tls_auditor.chain import analyze
from tls_auditor.probe import CertBasics


def _cert(not_after, *, san=("example.com",), issuer=None, cn="example.com"):
    return CertBasics(
        subject={"commonName": cn},
        issuer=issuer or {"commonName": "Test CA"},
        san=list(san),
        not_before="Jan  1 00:00:00 2024 GMT",
        not_after=not_after,
    )


def test_valid_long_lived_cert():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    result = analyze(_cert("Jan  1 00:00:00 2030 GMT"), "example.com", now=now)
    assert not result.expired
    assert not result.expires_soon
    assert not result.self_signed
    assert result.hostname_matches
    assert result.warnings == ()
    assert result.errors == ()


def test_expired_cert_is_error():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    result = analyze(_cert("Jan  1 00:00:00 2025 GMT"), "example.com", now=now)
    assert result.expired
    assert any("expired" in e for e in result.errors)


def test_expires_soon_is_warning():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    in_15_days = (now + timedelta(days=15)).strftime("%b %d %H:%M:%S %Y GMT")
    result = analyze(_cert(in_15_days), "example.com", now=now)
    assert not result.expired
    assert result.expires_soon
    assert any("expires in" in w for w in result.warnings)


def test_self_signed_flagged():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = _cert(
        "Jan  1 00:00:00 2030 GMT",
        issuer={"commonName": "example.com"},
    )
    result = analyze(cert, "example.com", now=now)
    assert result.self_signed
    assert any("self-signed" in w for w in result.warnings)


def test_hostname_mismatch_is_error():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = _cert("Jan  1 00:00:00 2030 GMT", san=("foo.example.com",), cn="foo.example.com")
    result = analyze(cert, "bar.example.com", now=now)
    assert not result.hostname_matches
    assert any("does not match" in e for e in result.errors)


def test_wildcard_san_matches():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = _cert("Jan  1 00:00:00 2030 GMT", san=("*.example.com",), cn="*.example.com")
    assert analyze(cert, "api.example.com", now=now).hostname_matches


def test_cn_fallback_when_no_san():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = _cert("Jan  1 00:00:00 2030 GMT", san=(), cn="example.com")
    assert analyze(cert, "example.com", now=now).hostname_matches


def test_case_insensitive_hostname_match():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = _cert("Jan  1 00:00:00 2030 GMT", san=("Example.COM",), cn="Example.COM")
    assert analyze(cert, "EXAMPLE.com", now=now).hostname_matches
