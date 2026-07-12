import socket

from services.scan_service import audit_ftp, audit_redis, detect_device_type


def test_ftp_timeout_returns_skipped(monkeypatch):
    import ftplib

    def timeout(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(ftplib.FTP, "connect", timeout)
    assert audit_ftp("192.0.2.1")["status"] == "skipped"


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


def test_filtered_ports_do_not_affect_device_type():
    ports = [{"port": 554, "state": "filtered"}, {"port": 9100, "state": "closed"}]
    assert detect_device_type("generic-host", "generic vendor", ports) not in {"Camera", "Printer"}
