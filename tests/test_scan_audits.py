import socket
import urllib.error
import urllib.request

import pytest

from services.scan_service import audit_ftp, audit_http_basic, audit_redis, detect_device_type


def test_ftp_timeout_returns_skipped(monkeypatch):
    import ftplib

    def timeout(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(ftplib.FTP, "connect", timeout)
    assert audit_ftp("192.0.2.1")["status"] == "skipped"


def test_ftp_530_is_an_explicit_authentication_rejection(monkeypatch):
    import ftplib

    class RejectingFTP:
        def connect(self, *args, **kwargs):
            pass

        def login(self, *args, **kwargs):
            raise ftplib.error_perm("530 Login incorrect")

        def close(self):
            pass

    monkeypatch.setattr(ftplib, "FTP", RejectingFTP)
    result = audit_ftp("192.0.2.1", custom_credentials=[("user", "bad")], use_defaults=False)
    assert result["status"] == "safe"


@pytest.mark.parametrize(
    "reply",
    [
        "530 Account disabled by policy",
        "530 Authentication failed because TLS is required",
        "534 Authentication failed because TLS is required",
        "534 Policy requires SSL",
        "550 Requested action not taken",
    ],
)
def test_ftp_non_auth_permanent_errors_are_skipped(monkeypatch, reply):
    import ftplib

    class PolicyFTP:
        def connect(self, *args, **kwargs):
            pass

        def login(self, *args, **kwargs):
            raise ftplib.error_perm(reply)

        def close(self):
            pass

    monkeypatch.setattr(ftplib, "FTP", PolicyFTP)
    result = audit_ftp("192.0.2.1", custom_credentials=[("user", "bad")], use_defaults=False)
    assert result["status"] == "skipped"


def test_redis_timeout_returns_skipped(monkeypatch):
    class TimeoutSocket:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            raise socket.timeout("timed out")

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: TimeoutSocket())
    assert audit_redis("192.0.2.1")["status"] == "skipped"


def test_redis_auth_uses_resp_for_passwords_with_spaces(monkeypatch):
    sent = []

    class RedisSocket:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            pass

        def sendall(self, payload):
            sent.append(payload)

        def recv(self, size):
            return b"-WRONGPASS invalid username-password pair\r\n"

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: RedisSocket())
    result = audit_redis(
        "192.0.2.1", custom_passwords=["pass word"], use_defaults=False
    )
    assert result["status"] == "safe"
    assert sent == [b"*2\r\n$4\r\nAUTH\r\n$9\r\npass word\r\n"]


def test_http_basic_timeout_during_credentials_returns_skipped(monkeypatch):
    calls = 0

    def urlopen(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise urllib.error.HTTPError(
                "http://example",
                401,
                "Unauthorized",
                {"WWW-Authenticate": 'Basic realm="test"'},
                None,
            )
        raise socket.timeout("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    result = audit_http_basic(
        "192.0.2.1", custom_credentials=[("admin", "admin")], use_defaults=False
    )
    assert result["status"] == "skipped"


def test_http_basic_is_safe_only_after_explicit_rejections(monkeypatch):
    def reject(*args, **kwargs):
        raise urllib.error.HTTPError(
            "http://example",
            401,
            "Unauthorized",
            {"WWW-Authenticate": 'Basic realm="test"'},
            None,
        )

    monkeypatch.setattr(urllib.request, "urlopen", reject)
    result = audit_http_basic(
        "192.0.2.1", custom_credentials=[("admin", "bad")], use_defaults=False
    )
    assert result["status"] == "safe"


def test_http_basic_non_basic_401_is_skipped_without_sending_credentials(monkeypatch):
    calls = 0

    def reject(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise urllib.error.HTTPError(
            "http://example",
            401,
            "Unauthorized",
            {"WWW-Authenticate": 'Digest realm="test"'},
            None,
        )

    monkeypatch.setattr(urllib.request, "urlopen", reject)
    result = audit_http_basic(
        "192.0.2.1", custom_credentials=[("admin", "secret")], use_defaults=False
    )
    assert result["status"] == "skipped"
    assert calls == 1


def test_http_basic_closes_successful_response(monkeypatch):
    class Response:
        code = 200
        closed = False

        def close(self):
            self.closed = True

    response = Response()
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: response)
    assert audit_http_basic("192.0.2.1")["status"] == "safe"
    assert response.closed is True


def test_filtered_ports_do_not_affect_device_type():
    ports = [{"port": 554, "state": "filtered"}, {"port": 9100, "state": "closed"}]
    assert detect_device_type("generic-host", "generic vendor", ports) not in {"Camera", "Printer"}
