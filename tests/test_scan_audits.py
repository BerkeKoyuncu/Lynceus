import socket
import urllib.error
import urllib.request

import pytest

from services.scan_service import audit_ftp, audit_http_basic, audit_redis, detect_device_type
from models import Asset, db
from services.topology_service import classify_device, get_network_topology
import services.topology_service as topology_service


# Verify that ftp timeout returns skipped behaves as expected.
def test_ftp_timeout_returns_skipped(monkeypatch):
    import ftplib

    # Handle the timeout operation.
    def timeout(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(ftplib.FTP, "connect", timeout)
    assert audit_ftp("192.0.2.1")["status"] == "skipped"


# Verify that ftp 530 is an explicit authentication rejection behaves as expected.
def test_ftp_530_is_an_explicit_authentication_rejection(monkeypatch):
    import ftplib

    # Group the state and behavior for RejectingFTP.
    class RejectingFTP:
        # Handle the connect operation.
        def connect(self, *args, **kwargs):
            pass

        # Handle the login operation.
        def login(self, *args, **kwargs):
            raise ftplib.error_perm("530 Login incorrect")

        # Handle the close operation.
        def close(self):
            pass

    monkeypatch.setattr(ftplib, "FTP", RejectingFTP)
    result = audit_ftp("192.0.2.1", custom_credentials=[("user", "bad")], use_defaults=False)
    assert result["status"] == "safe"


# Verify that ftp non auth permanent errors are skipped behaves as expected.
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

    # Group the state and behavior for PolicyFTP.
    class PolicyFTP:
        # Handle the connect operation.
        def connect(self, *args, **kwargs):
            pass

        # Handle the login operation.
        def login(self, *args, **kwargs):
            raise ftplib.error_perm(reply)

        # Handle the close operation.
        def close(self):
            pass

    monkeypatch.setattr(ftplib, "FTP", PolicyFTP)
    result = audit_ftp("192.0.2.1", custom_credentials=[("user", "bad")], use_defaults=False)
    assert result["status"] == "skipped"


# Verify that redis timeout returns skipped behaves as expected.
def test_redis_timeout_returns_skipped(monkeypatch):
    # Group the state and behavior for TimeoutSocket.
    class TimeoutSocket:
        # Handle the settimeout operation.
        def settimeout(self, timeout):
            pass

        # Handle the connect operation.
        def connect(self, address):
            raise socket.timeout("timed out")

        # Handle the close operation.
        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: TimeoutSocket())
    assert audit_redis("192.0.2.1")["status"] == "skipped"


# Verify that redis auth uses resp for passwords with spaces behaves as expected.
def test_redis_auth_uses_resp_for_passwords_with_spaces(monkeypatch):
    sent = []

    # Group the state and behavior for RedisSocket.
    class RedisSocket:
        # Handle the settimeout operation.
        def settimeout(self, timeout):
            pass

        # Handle the connect operation.
        def connect(self, address):
            pass

        # Handle the sendall operation.
        def sendall(self, payload):
            sent.append(payload)

        # Handle the recv operation.
        def recv(self, size):
            return b"-WRONGPASS invalid username-password pair\r\n"

        # Handle the close operation.
        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: RedisSocket())
    result = audit_redis(
        "192.0.2.1", custom_passwords=["pass word"], use_defaults=False
    )
    assert result["status"] == "safe"
    assert sent == [b"*2\r\n$4\r\nAUTH\r\n$9\r\npass word\r\n"]


# Verify that http basic timeout during credentials returns skipped behaves as expected.
def test_http_basic_timeout_during_credentials_returns_skipped(monkeypatch):
    calls = 0

    # Handle the urlopen operation.
    def urlopen(*args, **kwargs):
        nonlocal calls
        calls += 1
        # Handle the branch where calls == 1 evaluates to true.
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


# Verify that http basic is safe only after explicit rejections behaves as expected.
def test_http_basic_is_safe_only_after_explicit_rejections(monkeypatch):
    # Handle the reject operation.
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


# Verify that http basic non basic 401 is skipped without sending credentials behaves as expected.
def test_http_basic_non_basic_401_is_skipped_without_sending_credentials(monkeypatch):
    calls = 0

    # Handle the reject operation.
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


# Verify that http basic closes successful response behaves as expected.
def test_http_basic_closes_successful_response(monkeypatch):
    # Group the state and behavior for Response.
    class Response:
        code = 200
        closed = False

        # Handle the close operation.
        def close(self):
            self.closed = True

    response = Response()
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: response)
    assert audit_http_basic("192.0.2.1")["status"] == "safe"
    assert response.closed is True


# Verify that filtered ports do not affect device type behaves as expected.
def test_filtered_ports_do_not_affect_device_type():
    ports = [{"port": 554, "state": "filtered"}, {"port": 9100, "state": "closed"}]
    assert detect_device_type("generic-host", "generic vendor", ports) not in {"IP Camera", "Printer"}


# Verify that device type uses combined evidence behaves as expected.
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


# Verify that scan and topology use the same classifier behaves as expected.
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


# Verify that gateway signal overrides ambiguous endpoint ports behaves as expected.
def test_gateway_signal_overrides_ambiguous_endpoint_ports():
    assert classify_device(
        "192.168.1.1",
        "00:11:22:33:44:55",
        "generic-host",
        "Generic Vendor",
        [{"port": 445, "state": "open", "service": "microsoft-ds"}],
        is_gateway=True,
    ) == "Router"


# Verify that topology merges inventory asset with default gateway behaves as expected.
def test_topology_merges_inventory_asset_with_default_gateway(app, monkeypatch):
    monkeypatch.setattr(topology_service, "detect_default_gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(topology_service, "get_system_arp_table", lambda: [])

    # Manage app.app_context() within this scoped block.
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
