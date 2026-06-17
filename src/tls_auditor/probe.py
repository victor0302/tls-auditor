from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int

    @classmethod
    def parse(cls, target: str) -> Endpoint:
        if ":" in target:
            host, _, port_s = target.rpartition(":")
            return cls(host, int(port_s))
        return cls(target, 443)


@dataclass(frozen=True)
class CertBasics:
    subject: dict[str, str]
    issuer: dict[str, str]
    san: list[str]
    not_before: str
    not_after: str


def _flatten(name_tuple) -> dict[str, str]:
    out: dict[str, str] = {}
    for rdn in name_tuple or ():
        for k, v in rdn:
            out[k] = v
    return out


def fetch_cert(endpoint: Endpoint, timeout: float) -> CertBasics:
    ctx = ssl.create_default_context()
    with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=endpoint.host) as tls:
            cert = tls.getpeercert()
    san = [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"]
    return CertBasics(
        subject=_flatten(cert.get("subject")),
        issuer=_flatten(cert.get("issuer")),
        san=san,
        not_before=cert.get("notBefore", ""),
        not_after=cert.get("notAfter", ""),
    )
