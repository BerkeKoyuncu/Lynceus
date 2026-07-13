import socket
import urllib.error
import urllib.request

import pytest

from services.scan_service import audit_ftp, audit_http_basic, audit_redis, detect_device_type
from models import Asset, db
from services.topology_service import classify_device, get_network_topology
import services.topology_service as topology_service


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
    assert detect_device_type("generic-host", "generic vendor", ports) not in {"IP Camera", "Printer"}


@pytest.mark.parametrize(
    ("hostname", "vendor", "ports", "expected"),
    [
        (
            "",
            "ZTE",
            [
                {"port": 53, "state": "open", "service": "domain"},
                {"port": 80, "state": "open", "service": "http"},
                {"port": 139, "state": "open", "service": "netbios-ssn"},
                {"port": 445, "state": "open", "service": "microsoft-ds"},
            ],
            "Router",
        ),
        (
            "office-pc",
            "Dell",
            [{"port": 445, "state": "open", "service": "microsoft-ds"}],
            "Workstation",
        ),
        (
            "core-switch",
            "Cisco Systems",
            [{"port": 161, "state": "open", "service": "snmp"}],
            "Switch",
        ),
        (
            "db-server",
            "Supermicro",
            [{"port": 5432, "state": "open", "service": "postgresql"}],
            "Server",
        ),
        (
            "lobby-camera",
            "Generic",
            [{"port": 554, "state": "open", "service": "rtsp"}],
            "IP Camera",
        ),
        (
            "meeting-phone",
            "Yealink",
            [{"port": 5060, "state": "open", "service": "sip"}],
            "IP Phone",
        ),
        (
            "unlabelled",
            "Generic Vendor",
            [{"port": 80, "state": "open", "service": "http"}],
            "Unknown",
        ),
    ],
)
def test_device_type_uses_combined_evidence(hostname, vendor, ports, expected):
    assert detect_device_type(hostname, vendor, ports) == expected


def test_scan_and_topology_use_the_same_classifier():
    ports = [
        {"port": 53, "state": "open", "service": "domain"},
        {"port": 445, "state": "open", "service": "microsoft-ds"},
    ]
    scan_type = detect_device_type("", "ZTE", ports)
    topology_type = classify_device(
        "192.168.1.1",
        "00:11:22:33:44:55",
        "",
        "ZTE",
        ports,
    )
    assert scan_type == topology_type == "Router"


def test_gateway_signal_overrides_ambiguous_endpoint_ports():
    assert classify_device(
        "192.168.1.1",
        "00:11:22:33:44:55",
        "generic-host",
        "Generic Vendor",
        [{"port": 445, "state": "open", "service": "microsoft-ds"}],
        is_gateway=True,
    ) == "Router"


def test_topology_merges_inventory_asset_with_default_gateway(app, monkeypatch):
    monkeypatch.setattr(topology_service, "detect_default_gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(topology_service, "get_system_arp_table", lambda: [])

    with app.app_context():
        gateway_asset = Asset(
            name="Office Modem",
            ip_address="192.168.1.1",
            mac_address="00:11:22:33:44:55",
            mac_vendor="Generic Router Vendor",
            device_type="Router",
            criticality="High",
        )
        db.session.add(gateway_asset)
        db.session.commit()

        topology = get_network_topology([gateway_asset])

    ip_nodes = [
        node
        for node in topology["nodes"]
        if node.get("ip") == "192.168.1.1"
        or node.get("details", {}).get("ip") == "192.168.1.1"
    ]
    assert len(ip_nodes) == 1
    assert ip_nodes[0]["id"] == "host_192.168.1.1"
    assert ip_nodes[0]["details"]["network_role"] == "Default Gateway"
    assert any(
        edge["from"] == "host_192.168.1.1"
        and edge["to"] == "subnet_192.168.1.0/24"
        for edge in topology["edges"]
    )
