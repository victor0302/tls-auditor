from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass

from .probe import Endpoint

PROTOCOLS: tuple[tuple[str, ssl.TLSVersion], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)
INSECURE_PROTOCOLS: frozenset[str] = frozenset({"TLSv1", "TLSv1.1"})


@dataclass(frozen=True)
class ProtocolResult:
    name: str
    supported: bool
    insecure: bool
    error: str | None = None


def _probe_one(
    endpoint: Endpoint, name: str, version: ssl.TLSVersion, timeout: float
) -> ProtocolResult:
    insecure = name in INSECURE_PROTOCOLS
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, OSError) as exc:
        return ProtocolResult(name=name, supported=False, insecure=insecure, error=str(exc))

    try:
        with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=endpoint.host) as tls:
                negotiated = tls.version()
    except (OSError, ssl.SSLError) as exc:
        return ProtocolResult(name=name, supported=False, insecure=insecure, error=str(exc))

    return ProtocolResult(name=name, supported=negotiated == name, insecure=insecure)


def probe(endpoint: Endpoint, timeout: float = 5.0) -> list[ProtocolResult]:
    return [_probe_one(endpoint, name, version, timeout) for name, version in PROTOCOLS]
