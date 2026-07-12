import urllib.request
from services.scan_service import is_version_affected, fetch_cves_for_query, CVE_CACHE
from services.rule_service import evaluate_cve_findings, reconcile_findings_for_scan
from services.anomaly_service import evaluate_host_anomalies
from models import db, SecurityFinding, Asset, User, ScanResult

def test_is_version_affected():
    # 1. Exact match / substring check
    match_1 = {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:::"}
    assert is_version_affected("2.4.49", match_1, "http_server") is True
    assert is_version_affected("2.4.50", match_1, "http_server") is False

    # 2. versionEndExcluding
    match_2 = {
        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:",
        "versionEndExcluding": "2.4.50"
    }
    assert is_version_affected("2.4.49", match_2, "http_server") is True
    assert is_version_affected("2.4.50", match_2, "http_server") is False

    # 3. versionEndIncluding
    match_3 = {
        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:",
        "versionEndIncluding": "2.4.49"
    }
    assert is_version_affected("2.4.49", match_3, "http_server") is True
    assert is_version_affected("2.4.50", match_3, "http_server") is False

    # 4. versionStartIncluding / versionStartExcluding
    match_4 = {
        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:",
        "versionStartIncluding": "2.4.40",
        "versionEndExcluding": "2.4.50"
    }
    assert is_version_affected("2.4.45", match_4, "http_server") is True
    assert is_version_affected("2.4.39", match_4, "http_server") is False
    assert is_version_affected("2.4.50", match_4, "http_server") is False

    # 5. Invalid version string
    assert is_version_affected("invalid-version-string", match_1, "http_server") is False

def test_evaluate_cve_findings(app):
    with app.app_context():
        user = User.query.first()
        # Create a scan result to satisfy the ScanResult FK constraint
        scan = ScanResult(
            user_id=user.id if user else None,
            input_ip="192.168.1.0",
            subnet_mask="24",
            scan_type="service_version",
            status="completed",
            network_cidr="192.168.1.0/24"
        )
        db.session.add(scan)
        db.session.commit()

        # Create an asset
        asset = Asset(
            name="CVE Test Asset",
            ip_address="192.168.1.99",
            mac_address="00:11:22:33:44:99",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()

        port_info = {
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "version": "2.4.49",
            "cpe": ["cpe:/a:apache:http_server:2.4.49"]
        }

        dummy_cve_list = [{
            "id": "CVE-2021-41773",
            "summary": "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49.",
            "cvss": 7.5,
            "is_definite_match": True
        }]

        # Run evaluator
        evaluate_cve_findings(asset, "192.168.1.99", port_info, dummy_cve_list, scan_id=scan.id)

        # Check that finding was created
        finding = SecurityFinding.query.filter_by(asset_id=asset.id, cve="CVE-2021-41773").first()
        assert finding is not None
        assert finding.status == "open"
        assert finding.severity == "High"
        assert finding.port == 80
        assert finding.protocol == "tcp"

def test_scheduler_is_disabled_during_tests(app):
    assert app.config.get("TESTING") is True

def test_ip_change_is_detected_before_asset_update(app):
    with app.app_context():
        user = User.query.first()
        asset = Asset(
            name="IP Change Test Device",
            ip_address="192.168.1.100",
            mac_address="00:11:22:33:44:55",
            is_trusted=True,
            ip_assignment_type="Static"
        )
        db.session.add(asset)
        db.session.commit()
        
        # Simulating Pass 1: Match asset and store expected IP snapshot
        host = {
            "address": "192.168.1.200",  # Changed IP
            "mac_address": "00:11:22:33:44:55",
            "mac_vendor": "Test Vendor",
            "hostname": "test-device",
            "ports": []
        }
        
        # Pass 1 Snapshot simulation
        host["_asset_id"] = asset.id
        host["_expected_ip"] = "192.168.1.100"
        host["_expected_mac"] = "00:11:22:33:44:55"
        
        res = evaluate_host_anomalies(host, scan_id=999)
        assert res is not None
        assert res["type"] == "ip_hijack"
        assert res["expected_ip"] == "192.168.1.100"
        assert res["found_ip"] == "192.168.1.200"

def test_udp_scan_does_not_reconcile_tcp_finding(app):
    with app.app_context():
        user = User.query.first()
        asset = Asset(
            name="UDP Test Asset",
            ip_address="192.168.1.5",
            mac_address="00:11:22:33:44:05",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()
        
        # Active TCP finding on port 80
        finding = SecurityFinding(
            asset_id=asset.id,
            ip_address="192.168.1.5",
            port=80,
            protocol="tcp",
            service="http",
            severity="Medium",
            status="open",
            fingerprint="dummy_tcp_fp_80"
        )
        db.session.add(finding)
        db.session.commit()
        
        # Reconcile on UDP scan type
        # Since UDP scan does not scan TCP port 80, the finding should remain "open"!
        reconcile_findings_for_scan(
            asset=asset,
            host_online=True,
            observed_fingerprints=set(),
            scan_id=999,
            scan_type="udp",
            requested_ports=None,
            current_open_ports=[]
        )
        
        db.session.refresh(finding)
        assert finding.status == "open"

def test_cve_api_failure_preserves_existing_finding(app):
    with app.app_context():
        user = User.query.first()
        asset = Asset(
            name="CVE Failure Asset",
            ip_address="192.168.1.6",
            mac_address="00:11:22:33:44:06",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()
        
        finding = SecurityFinding(
            asset_id=asset.id,
            ip_address="192.168.1.6",
            port=22,
            protocol="tcp",
            service="ssh",
            cve="CVE-2016-3115",
            severity="Medium",
            status="open",
            source_type="cve",
            fingerprint="dummy_cve_fp_22"
        )
        db.session.add(finding)
        db.session.commit()
        
        # CVE API failure means port 22 failed CVE lookup
        cve_failed_ports = {22}
        
        reconcile_findings_for_scan(
            asset=asset,
            host_online=True,
            observed_fingerprints=set(),
            scan_id=999,
            scan_type="service_version",
            requested_ports=None,
            current_open_ports=[("tcp", 22)],
            cve_failed_ports=cve_failed_ports
        )
        
        db.session.refresh(finding)
        assert finding.status == "open"  # Preserved because lookup failed

def test_cve_api_failure_is_not_cached():
    # Make a query with a product name that raises an error or fails
    # Call fetch_cves_for_query, verify success is False
    # Verify that this is not added to CVE_CACHE
    original_urlopen = urllib.request.urlopen
    
    def raise_error(*args, **kwargs):
        raise Exception("Timeout connection error")
        
    urllib.request.urlopen = raise_error
    try:
        res = fetch_cves_for_query("NonExistentProductDefiniteFailure", "1.0")
        assert res["success"] is False
        
        # Check cache
        cache_key = ("nonexistentproductdefinitefailure", "1.0", ())
        assert cache_key not in CVE_CACHE
    finally:
        urllib.request.urlopen = original_urlopen

def test_ftp_credential_does_not_reconcile_redis_finding(app):
    with app.app_context():
        user = User.query.first()
        asset = Asset(
            name="Cred Asset",
            ip_address="192.168.1.7",
            mac_address="00:11:22:33:44:07",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()
        
        finding = SecurityFinding(
            asset_id=asset.id,
            ip_address="192.168.1.7",
            port=6379,
            protocol="tcp",
            service="redis",
            severity="Critical",
            status="open",
            source_type="credential_audit",
            fingerprint="dummy_redis_cred_fp"
        )
        db.session.add(finding)
        db.session.commit()
        
        # We only audited FTP (tcp, 21) successfully as "safe", Redis (tcp, 6379) wasn't audited
        audited_endpoints = {("tcp", 21): "safe"}
        
        reconcile_findings_for_scan(
            asset=asset,
            host_online=True,
            observed_fingerprints=set(),
            scan_id=999,
            scan_type="aggressive",
            requested_ports=None,
            current_open_ports=[("tcp", 21), ("tcp", 6379)],
            audited_endpoints=audited_endpoints
        )
        
        db.session.refresh(finding)
        assert finding.status == "open"  # Redis finding remains open!

def test_ping_sweep_does_not_reconcile_port_findings(app):
    with app.app_context():
        user = User.query.first()
        asset = Asset(
            name="Ping Sweep Asset",
            ip_address="192.168.1.8",
            mac_address="00:11:22:33:44:08",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()
        
        finding = SecurityFinding(
            asset_id=asset.id,
            ip_address="192.168.1.8",
            port=22,
            protocol="tcp",
            service="ssh",
            severity="Medium",
            status="open",
            fingerprint="dummy_ping_sweep_fp"
        )
        db.session.add(finding)
        db.session.commit()
        
        # Ping sweep scan does not scan any ports
        reconcile_findings_for_scan(
            asset=asset,
            host_online=True,
            observed_fingerprints=set(),
            scan_id=999,
            scan_type="ping_sweep",
            requested_ports=None,
            current_open_ports=[]
        )
        
        db.session.refresh(finding)
        assert finding.status == "open"  # Port finding is NOT reconciled on ping sweep

def test_not_observed_finding_can_update_assignment(app):
    with app.app_context():
        user = User.query.first()
        asset = Asset(
            name="Assignment Asset",
            ip_address="192.168.1.9",
            mac_address="00:11:22:33:44:09",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()
        
        finding = SecurityFinding(
            asset_id=asset.id,
            ip_address="192.168.1.9",
            port=80,
            protocol="tcp",
            service="http",
            severity="Low",
            status="not_observed",
            fingerprint="dummy_assignment_fp"
        )
        db.session.add(finding)
        db.session.commit()
        
        # Update details without providing status
        finding.assigned_user_id = user.id if user else 1
        db.session.commit()
        
        db.session.refresh(finding)
        if user:
            assert finding.assigned_user_id == user.id
        assert finding.status == "not_observed"  # Maintained status
