import json
from dataclasses import dataclass

from tls_auditor.ciphers import classify
from tls_auditor.output import (
    StubGrade,
    _coerce_audit_inputs,
    render_json,
    render_text,
)
from tls_auditor.probe import CertBasics
from tls_auditor.protocols import ProtocolResult


def _cert():
    return CertBasics(
        subject={"commonName": "example.com"},
        issuer={"commonName": "Test CA"},
        san=["example.com"],
        not_before="Jan  1 00:00:00 2025 GMT",
        not_after="Jan  1 00:00:00 2030 GMT",
    )


@dataclass(frozen=True)
class _G:
    grade: str
    score: int
    reasons: tuple[str, ...] = ()


def test_text_includes_grade_at_top():
    result = _coerce_audit_inputs(
        host="example.com",
        port=443,
        cert=_cert(),
        grade=_G("A+", 100),
    )
    out = render_text(result, color=False)
    assert out.splitlines()[0].startswith("Grade: A+")


def test_text_color_toggle():
    result = _coerce_audit_inputs(
        host="example.com", port=443, cert=_cert(), grade=_G("F", 0)
    )
    assert "\x1b[" in render_text(result, color=True)
    assert "\x1b[" not in render_text(result, color=False)


def test_text_renders_protocol_section():
    result = _coerce_audit_inputs(
        host="example.com",
        port=443,
        protocols=[
            ProtocolResult("TLSv1.2", True, False),
            ProtocolResult("TLSv1", True, True),
        ],
        grade=_G("C", 70),
    )
    out = render_text(result, color=False)
    assert "Protocols" in out
    assert "TLSv1.2" in out
    assert "TLSv1" in out


def test_text_renders_cipher_section():
    result = _coerce_audit_inputs(
        host="example.com",
        port=443,
        ciphers=[classify("ECDHE-RSA-RC4-SHA", "TLSv1.2")],
        grade=_G("D", 60),
    )
    out = render_text(result, color=False)
    assert "Ciphers" in out
    assert "RC4" in out


def test_json_schema():
    result = _coerce_audit_inputs(
        host="example.com",
        port=443,
        cert=_cert(),
        protocols=[ProtocolResult("TLSv1.2", True, False)],
        ciphers=[classify("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2")],
        grade=_G("A+", 100, ("clean run",)),
    )
    payload = json.loads(render_json(result))
    assert payload["host"] == "example.com"
    assert payload["port"] == 443
    assert payload["grade"] == {"grade": "A+", "score": 100, "reasons": ["clean run"]}
    assert payload["certificate"]["subject"]["commonName"] == "example.com"
    assert payload["protocols"][0]["name"] == "TLSv1.2"
    assert payload["ciphers"][0]["name"] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert payload["ciphers"][0]["is_weak"] is False


def test_stub_grade_defaults():
    g = StubGrade()
    assert g.grade == "A+"
    assert g.score == 100
    assert g.reasons == ()
