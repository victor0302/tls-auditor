from datetime import datetime, timezone

from tls_auditor.chain import analyze
from tls_auditor.ciphers import classify
from tls_auditor.probe import CertBasics
from tls_auditor.protocols import ProtocolResult
from tls_auditor.scoring import grade


def _cert(not_after="Jan  1 00:00:00 2030 GMT", *, self_signed=False, host_ok=True):
    cn = "example.com" if host_ok else "other.example.com"
    issuer = {"commonName": cn} if self_signed else {"commonName": "Test CA"}
    san = ("example.com",) if host_ok else ("other.example.com",)
    return CertBasics(
        subject={"commonName": cn},
        issuer=issuer,
        san=list(san),
        not_before="Jan  1 00:00:00 2024 GMT",
        not_after=not_after,
    )


_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_GOOD_PROTOS = [
    ProtocolResult("TLSv1", False, True),
    ProtocolResult("TLSv1.1", False, True),
    ProtocolResult("TLSv1.2", True, False),
    ProtocolResult("TLSv1.3", True, False),
]


def test_clean_modern_setup_is_a_plus():
    ch = analyze(_cert(), "example.com", now=_NOW)
    cipher_results = [classify("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2")]
    g = grade(_GOOD_PROTOS, ch, cipher_results)
    assert g.grade == "A+"
    assert g.score >= 95


def test_expired_cert_is_f():
    ch = analyze(_cert("Jan  1 00:00:00 2025 GMT"), "example.com", now=_NOW)
    g = grade(_GOOD_PROTOS, ch, [])
    assert g.grade == "F"
    assert "expired" in g.reasons[0]


def test_hostname_mismatch_drops_to_f():
    ch = analyze(_cert(host_ok=False), "example.com", now=_NOW)
    g = grade(_GOOD_PROTOS, ch, [])
    assert g.grade == "F"


def test_self_signed_loses_points_but_not_to_f():
    ch = analyze(_cert(self_signed=True), "example.com", now=_NOW)
    g = grade(_GOOD_PROTOS, ch, [])
    assert g.grade in ("B", "C")
    assert any("self-signed" in r for r in g.reasons)


def test_legacy_tls_caps_at_c():
    protos = [
        ProtocolResult("TLSv1", True, True),
        ProtocolResult("TLSv1.1", True, True),
        ProtocolResult("TLSv1.2", True, False),
        ProtocolResult("TLSv1.3", True, False),
    ]
    ch = analyze(_cert(), "example.com", now=_NOW)
    g = grade(protos, ch, [])
    assert g.grade in ("C", "D")
    assert any("legacy TLS" in r for r in g.reasons)


def test_weak_cipher_pulls_grade_down():
    ch = analyze(_cert(), "example.com", now=_NOW)
    cipher_results = [
        classify("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2"),
        classify("ECDHE-RSA-RC4-SHA", "TLSv1.2"),
    ]
    clean = grade(_GOOD_PROTOS, ch, cipher_results[:1])
    weak = grade(_GOOD_PROTOS, ch, cipher_results)
    assert weak.score < clean.score
    assert any("weak cipher" in r for r in weak.reasons)


def test_no_supported_protocols_is_f():
    protos = [
        ProtocolResult(p, False, p in ("TLSv1", "TLSv1.1"))
        for p in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
    ]
    ch = analyze(_cert(), "example.com", now=_NOW)
    g = grade(protos, ch, [])
    assert g.grade == "F"


def test_grade_with_only_chain():
    ch = analyze(_cert(), "example.com", now=_NOW)
    g = grade(None, ch, None)
    assert g.grade in ("A", "A+")


def test_grade_with_nothing_is_a_plus():
    g = grade()
    assert g.grade == "A+"
    assert g.score == 100