import ssl
from unittest.mock import MagicMock, patch

from tls_auditor.probe import Endpoint
from tls_auditor.protocols import INSECURE_PROTOCOLS, ProtocolResult, probe


def test_probe_reports_each_protocol():
    negotiations = {
        ssl.TLSVersion.TLSv1: None,
        ssl.TLSVersion.TLSv1_1: None,
        ssl.TLSVersion.TLSv1_2: "TLSv1.2",
        ssl.TLSVersion.TLSv1_3: "TLSv1.3",
    }

    def wrap_socket(self, sock, server_hostname):
        negotiated = negotiations.get(self.maximum_version)
        if negotiated is None:
            raise ssl.SSLError("handshake failed")
        tls = MagicMock()
        tls.__enter__.return_value = tls
        tls.version.return_value = negotiated
        tls.__exit__.return_value = False
        return tls

    def create_connection(addr, timeout):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False
        return sock

    with patch.object(ssl.SSLContext, "wrap_socket", wrap_socket), \
         patch("socket.create_connection", create_connection):
        results = probe(Endpoint("example.com", 443), timeout=1)

    by_name = {r.name: r for r in results}
    assert by_name["TLSv1.2"].supported and not by_name["TLSv1.2"].insecure
    assert by_name["TLSv1.3"].supported and not by_name["TLSv1.3"].insecure
    assert not by_name["TLSv1"].supported and by_name["TLSv1"].insecure
    assert not by_name["TLSv1.1"].supported and by_name["TLSv1.1"].insecure


def test_unsupported_version_pinning_returns_error():
    fake_prop = property(
        lambda self: None,
        lambda self, v: (_ for _ in ()).throw(ValueError("nope")),
    )
    with patch.object(ssl.SSLContext, "minimum_version", new=fake_prop):
        results = probe(Endpoint("example.com", 443), timeout=1)
    assert all(not r.supported for r in results)
    assert all(r.error == "nope" for r in results)


def test_insecure_set_is_v10_and_v11():
    assert INSECURE_PROTOCOLS == {"TLSv1", "TLSv1.1"}


def test_result_is_frozen_dataclass():
    r = ProtocolResult(name="TLSv1.2", supported=True, insecure=False)
    try:
        r.supported = False  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("ProtocolResult should be frozen")
