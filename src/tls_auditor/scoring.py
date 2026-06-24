from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .chain import ChainAnalysis
from .ciphers import CipherStatus
from .protocols import ProtocolResult

GRADES: tuple[str, ...] = ("A+", "A", "B", "C", "D", "F")


@dataclass(frozen=True)
class Grade:
    grade: str
    score: int
    reasons: tuple[str, ...]


def grade(
    protocols: Iterable[ProtocolResult] | None = None,
    chain: ChainAnalysis | None = None,
    ciphers: Iterable[CipherStatus] | None = None,
) -> Grade:
    score = 100
    reasons: list[str] = []
    cap: int | None = None

    protocols = list(protocols or ())
    ciphers = list(ciphers or ())

    if chain is not None:
        if chain.expired:
            return Grade(grade="F", score=0, reasons=("certificate expired",))
        if not chain.hostname_matches:
            cap = 0  # F
            reasons.append("hostname does not match cert SAN/CN")
        if chain.self_signed:
            score -= 30
            reasons.append("self-signed certificate")
        if chain.expires_soon:
            score -= 10
            reasons.append(f"certificate expires in {chain.days_until_expiry} days")

    supported = {p.name for p in protocols if p.supported}
    if "TLSv1" in supported or "TLSv1.1" in supported:
        if cap is None or cap > _grade_to_score("C"):
            cap = _grade_to_score("C")
        reasons.append("legacy TLS (1.0 or 1.1) supported")
    if "TLSv1.3" not in supported and supported:
        score -= 10
        reasons.append("TLS 1.3 not supported")
    if not supported and protocols:
        return Grade(grade="F", score=0, reasons=("no TLS protocol versions accepted",))

    weak_ciphers = [c for c in ciphers if c.is_weak]
    if weak_ciphers:
        score -= min(40, 10 * len(weak_ciphers))
        names = ", ".join(sorted({c.name for c in weak_ciphers})[:3])
        reasons.append(f"weak cipher(s) accepted: {names}")

    if cap is not None:
        score = min(score, cap)
    score = max(0, min(100, score))
    return Grade(grade=_score_to_grade(score), score=score, reasons=tuple(reasons))


def _grade_to_score(g: str) -> int:
    return {"A+": 95, "A": 90, "B": 80, "C": 70, "D": 60, "F": 0}[g]


def _score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"
