from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Protocol

from .chain import ChainAnalysis
from .ciphers import CipherStatus
from .probe import CertBasics
from .protocols import ProtocolResult

ANSI_RESET = "\x1b[0m"
ANSI_BY_GRADE: dict[str, str] = {
    "A+": "\x1b[1;32m",
    "A": "\x1b[32m",
    "B": "\x1b[36m",
    "C": "\x1b[33m",
    "D": "\x1b[35m",
    "F": "\x1b[1;31m",
}
ANSI_OK = "\x1b[32m"
ANSI_WARN = "\x1b[33m"
ANSI_BAD = "\x1b[31m"


class _GradeLike(Protocol):
    @property
    def grade(self) -> str: ...
    @property
    def score(self) -> int: ...
    @property
    def reasons(self) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class StubGrade:
    grade: str = "A+"
    score: int = 100
    reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class AuditResult:
    host: str
    port: int
    cert: CertBasics | None
    protocols: tuple[ProtocolResult, ...]
    chain: ChainAnalysis | None
    ciphers: tuple[CipherStatus, ...]
    grade: _GradeLike


def render_text(result: AuditResult, *, color: bool = True) -> str:
    def c(text: str, ansi: str) -> str:
        return f"{ansi}{text}{ANSI_RESET}" if color else text

    grade_color = ANSI_BY_GRADE.get(result.grade.grade, "")
    lines: list[str] = [
        c(f"Grade: {result.grade.grade}  (score {result.grade.score})", grade_color),
        f"Target: {result.host}:{result.port}",
        "",
    ]
    if result.grade.reasons:
        lines.append("Reasons:")
        for r in result.grade.reasons:
            lines.append(f"  - {r}")
        lines.append("")

    if result.cert is not None:
        lines.append("Certificate")
        lines.append(f"  Subject:    {result.cert.subject.get('commonName', '?')}")
        lines.append(f"  Issuer:     {result.cert.issuer.get('commonName', '?')}")
        lines.append(f"  Not before: {result.cert.not_before}")
        lines.append(f"  Not after:  {result.cert.not_after}")
        san = ", ".join(result.cert.san) if result.cert.san else "(none)"
        lines.append(f"  SAN:        {san}")
        lines.append("")

    if result.chain is not None:
        lines.append("Chain")
        for w in result.chain.warnings:
            lines.append(f"  {c('warn', ANSI_WARN)}  {w}")
        for e in result.chain.errors:
            lines.append(f"  {c('err ', ANSI_BAD)}  {e}")
        if not (result.chain.warnings or result.chain.errors):
            lines.append(f"  {c('ok  ', ANSI_OK)}  no issues")
        lines.append("")

    if result.protocols:
        lines.append("Protocols")
        for p in result.protocols:
            tag = "ok  "
            ansi = ANSI_OK
            if p.supported and p.insecure:
                tag, ansi = "bad ", ANSI_BAD
            elif not p.supported and p.insecure:
                tag, ansi = "ok  ", ANSI_OK
            elif not p.supported:
                tag, ansi = "—   ", ANSI_RESET
            note = "supported" if p.supported else (p.error or "not supported")
            lines.append(f"  {c(tag, ansi)}  {p.name:<8} {note}")
        lines.append("")

    if result.ciphers:
        lines.append("Ciphers")
        for cs in result.ciphers:
            ansi = ANSI_BAD if cs.is_weak else ANSI_OK
            tag = "bad " if cs.is_weak else "ok  "
            why = f" ({', '.join(cs.weak_reasons)})" if cs.weak_reasons else ""
            lines.append(f"  {c(tag, ansi)}  {cs.protocol}  {cs.name}{why}")
        lines.append("")

    return "\n".join(lines).rstrip("\n")


def render_json(result: AuditResult) -> str:
    payload = {
        "host": result.host,
        "port": result.port,
        "grade": {
            "grade": result.grade.grade,
            "score": result.grade.score,
            "reasons": list(result.grade.reasons),
        },
        "certificate": (
            None
            if result.cert is None
            else {
                "subject": result.cert.subject,
                "issuer": result.cert.issuer,
                "san": list(result.cert.san),
                "not_before": result.cert.not_before,
                "not_after": result.cert.not_after,
            }
        ),
        "chain": (
            None
            if result.chain is None
            else {
                **{k: v for k, v in asdict(result.chain).items() if k not in {"san"}},
                "san": list(result.chain.san),
            }
        ),
        "protocols": [
            {
                "name": p.name,
                "supported": p.supported,
                "insecure": p.insecure,
                "error": p.error,
            }
            for p in result.protocols
        ],
        "ciphers": [
            {
                "name": c.name,
                "protocol": c.protocol,
                "weak_reasons": list(c.weak_reasons),
                "is_weak": c.is_weak,
            }
            for c in result.ciphers
        ],
    }
    return json.dumps(payload, indent=2)


def _coerce_audit_inputs(
    host: str,
    port: int,
    cert: CertBasics | None = None,
    protocols: Iterable[ProtocolResult] | None = None,
    chain: ChainAnalysis | None = None,
    ciphers: Iterable[CipherStatus] | None = None,
    grade: _GradeLike | None = None,
) -> AuditResult:
    return AuditResult(
        host=host,
        port=port,
        cert=cert,
        protocols=tuple(protocols or ()),
        chain=chain,
        ciphers=tuple(ciphers or ()),
        grade=grade or StubGrade(),
    )
