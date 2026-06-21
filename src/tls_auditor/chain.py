from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import datetime, timezone

from .probe import CertBasics

EXPIRY_WARNING_DAYS = 30


@dataclass(frozen=True)
class ChainAnalysis:
    expired: bool
    expires_soon: bool
    days_until_expiry: int
    self_signed: bool
    hostname_matches: bool
    san: tuple[str, ...]
    warnings: tuple[str, ...]
    errors: tuple[str, ...]


def _parse_cert_time(value: str) -> datetime:
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _hostname_matches(hostname: str, san: tuple[str, ...], cn: str | None) -> bool:
    candidates: list[str] = list(san)
    if cn and cn not in candidates:
        candidates.append(cn)
    host = hostname.lower().rstrip(".")
    for entry in candidates:
        pattern = entry.lower().rstrip(".")
        if fnmatch.fnmatch(host, pattern):
            return True
    return False


def analyze(cert: CertBasics, hostname: str, now: datetime | None = None) -> ChainAnalysis:
    now = now or datetime.now(timezone.utc)
    not_after = _parse_cert_time(cert.not_after)
    delta_days = (not_after - now).days
    expired = not_after < now
    expires_soon = (not expired) and delta_days <= EXPIRY_WARNING_DAYS
    self_signed = bool(cert.subject) and cert.subject == cert.issuer
    matches = _hostname_matches(hostname, tuple(cert.san), cert.subject.get("commonName"))

    warnings: list[str] = []
    errors: list[str] = []

    if expired:
        errors.append(f"certificate expired on {cert.not_after}")
    elif expires_soon:
        warnings.append(f"certificate expires in {delta_days} days ({cert.not_after})")

    if self_signed:
        warnings.append("certificate is self-signed (subject == issuer)")

    if not matches:
        errors.append(f"hostname {hostname!r} does not match certificate SAN/CN")

    return ChainAnalysis(
        expired=expired,
        expires_soon=expires_soon,
        days_until_expiry=delta_days,
        self_signed=self_signed,
        hostname_matches=matches,
        san=tuple(cert.san),
        warnings=tuple(warnings),
        errors=tuple(errors),
    )
