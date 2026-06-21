from unittest.mock import patch

from tls_auditor.ciphers import classify, enumerate_ciphers
from tls_auditor.probe import Endpoint


def test_rc4_flagged():
    s = classify("ECDHE-RSA-RC4-SHA", "TLSv1.2")
    assert s.is_weak and "uses RC4" in s.weak_reasons


def test_3des_flagged():
    s = classify("DES-CBC3-SHA", "TLSv1.2")
    assert s.is_weak
    assert any("3DES" in r or "DES-" in r for r in s.weak_reasons)


def test_null_flagged():
    s = classify("NULL-MD5", "TLSv1.2")
    assert s.is_weak
    assert "uses NULL" in s.weak_reasons
    assert "uses MD5" in s.weak_reasons


def test_export_flagged():
    s = classify("EXP-RC4-MD5", "TLSv1.2")
    assert s.is_weak and "uses EXP-" in s.weak_reasons


def test_no_forward_secrecy_flagged_in_tls12():
    s = classify("AES256-GCM-SHA384", "TLSv1.2")
    assert s.is_weak and "no forward secrecy" in s.weak_reasons


def test_forward_secrecy_safe_in_tls12():
    s = classify("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2")
    assert not s.is_weak


def test_tls13_ciphers_not_flagged_for_pfs():
    s = classify("TLS_AES_256_GCM_SHA384", "TLSv1.3")
    assert not s.is_weak


def test_enumerate_uses_provided_candidates_and_skips_misses():
    def fake_handshake(endpoint, cipher, version, timeout):
        return cipher if cipher in {"ECDHE-RSA-AES256-GCM-SHA384", "RC4-SHA"} else None

    with patch("tls_auditor.ciphers._try_handshake", side_effect=fake_handshake):
        results = enumerate_ciphers(
            Endpoint("example.com", 443),
            timeout=1,
            ciphers=["ECDHE-RSA-AES256-GCM-SHA384", "RC4-SHA", "NOPE-CIPHER"],
        )
    names = {r.name for r in results}
    assert "ECDHE-RSA-AES256-GCM-SHA384" in names
    assert "RC4-SHA" in names
    assert "NOPE-CIPHER" not in names
    weak = {r.name for r in results if r.is_weak}
    assert "RC4-SHA" in weak
    assert "ECDHE-RSA-AES256-GCM-SHA384" not in weak
