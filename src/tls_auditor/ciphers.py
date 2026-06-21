from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass

from .probe import Endpoint

WEAK_TOKENS: tuple[str, ...] = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "EXP-", "MD5")
_FORWARD_SECRECY_PREFIXES: tuple[str, ...] = ("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA")


@dataclass(frozen=True)
class CipherStatus:
    name: str
    protocol: str
    weak_reasons: tuple[str, ...]

    @property
    def is_weak(self) -> bool:
        return bool(self.weak_reasons)


def _weak_reasons(cipher_name: str, protocol: str) -> tuple[str, ...]:
    reasons: list[str] = []
    upper = cipher_name.upper()
    for token in WEAK_TOKENS:
        if token in upper:
            reasons.append(f"uses {token}")
    if protocol == "TLSv1.2" and not any(
        upper.startswith(p) for p in _FORWARD_SECRECY_PREFIXES
    ):
        reasons.append("no forward secrecy")
    return tuple(reasons)


def _candidate_ciphers() -> list[str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:COMPLEMENTOFALL")
    except ssl.SSLError:
        ctx.set_ciphers("DEFAULT")
    return [c["name"] for c in ctx.get_ciphers()]


def _try_handshake(
    endpoint: Endpoint,
    cipher: str,
    protocol_version: ssl.TLSVersion,
    timeout: float,
) -> str | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            ctx.minimum_version = protocol_version
            ctx.maximum_version = protocol_version
        except (ValueError, OSError):
            return None
    try:
        ctx.set_ciphers(cipher)
    except ssl.SSLError:
        return None
    try:
        with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=endpoint.host) as tls:
                negotiated = tls.cipher()
    except (OSError, ssl.SSLError):
        return None
    return negotiated[0] if negotiated else None


def enumerate_ciphers(
    endpoint: Endpoint,
    timeout: float = 3.0,
    ciphers: list[str] | None = None,
) -> list[CipherStatus]:
    candidates = ciphers if ciphers is not None else _candidate_ciphers()
    accepted: list[CipherStatus] = []
    seen: set[tuple[str, str]] = set()

    for protocol_name, version in (
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ):
        for cipher in candidates:
            negotiated = _try_handshake(endpoint, cipher, version, timeout)
            if not negotiated:
                continue
            key = (negotiated, protocol_name)
            if key in seen:
                continue
            seen.add(key)
            accepted.append(
                CipherStatus(
                    name=negotiated,
                    protocol=protocol_name,
                    weak_reasons=_weak_reasons(negotiated, protocol_name),
                )
            )
    return accepted


def classify(name: str, protocol: str) -> CipherStatus:
    return CipherStatus(name=name, protocol=protocol, weak_reasons=_weak_reasons(name, protocol))
