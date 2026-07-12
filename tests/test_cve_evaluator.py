import urllib.request
import json
import threading
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

def test_scheduler_thread_not_started(app):
    # Verify that run_scheduler_loop background daemon thread is not active
    threads = [t.name for t in threading.enumerate()]
    assert not any("run_scheduler_loop" in t_name for t_name in threads)

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

def test_not_observed_finding_can_update_assignment_via_route(app, client):
    with app.app_context():
        user = User.query.filter_by(email="admin@test.com").first()
        user_id = user.id
        
        # Create asset and finding
        asset = Asset(
            name="Route Assign Asset",
            ip_address="192.168.1.99",
            mac_address="00:11:22:33:44:aa",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()
        
        finding = SecurityFinding(
            asset_id=asset.id,
            ip_address="192.168.1.99",
            port=80,
            protocol="tcp",
            service="http",
            severity="Low",
            status="not_observed",
            fingerprint="route_assignment_fp"
        )
        db.session.add(finding)
        db.session.commit()
        finding_id = finding.id

    # Programmatically log in as the seeded admin user using session_transaction
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True

    # Post update
    response = client.post(
        f"/findings/{finding_id}/update",
        data={
            "assigned_user_id": str(user_id),
            "remediation_note": "Assigned remediation step."
        },
        follow_redirects=True
    )
    assert b"Finding details updated successfully." in response.data
    assert response.status_code == 200

    # Verify
    with app.app_context():
        f = db.session.get(SecurityFinding, finding_id)
        assert f.assigned_user_id == user_id
        # Status should still be not_observed!
        assert f.status == "not_observed"

def test_reconciliation_filtered_states(app):
    with app.app_context():
        asset = Asset(
            name="Filtered State Asset",
            ip_address="192.168.1.111",
            mac_address="00:11:22:33:44:bb",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()

        finding = SecurityFinding(
            asset_id=asset.id,
            ip_address="192.168.1.111",
            port=443,
            protocol="tcp",
            service="https",
            severity="High",
            status="open",
            fingerprint="filtered_state_fp"
        )
        db.session.add(finding)
        db.session.commit()

        # Reconcile when port is filtered / open|filtered
        reconcile_findings_for_scan(
            asset=asset,
            host_online=True,
            observed_fingerprints=set(),
            scan_id=999,
            scan_type="detailed",
            requested_ports=None,
            current_open_ports=[],
            endpoint_states={("tcp", 443): "filtered"}
        )

        db.session.refresh(finding)
        # Should remain open since filtered is inconclusive!
        assert finding.status == "open"

        # Reconcile when port is closed
        reconcile_findings_for_scan(
            asset=asset,
            host_online=True,
            observed_fingerprints=set(),
            scan_id=999,
            scan_type="detailed",
            requested_ports=None,
            current_open_ports=[],
            endpoint_states={("tcp", 443): "closed"}
        )

        db.session.refresh(finding)
        assert finding.status == "not_observed"

def test_execute_scan_e2e_serialization(app, monkeypatch):
    # Mock run_nmap_scan
    def mock_scan(*args, **kwargs):
        return {
            "success": True,
            "command": "nmap ...",
            "output": "<xml>...</xml>",
            "scanned_endpoints": [("tcp", 22), ("tcp", 80)],
            "hosts": [
                {
                    "address": "192.168.1.100",
                    "status": "up",
                    "hostname": "test-host",
                    "mac_address": "00:11:22:33:44:55",
                    "mac_vendor": "Test Vendor",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "product": "OpenSSH",
                            "version": "7.2p2",
                            "cpe": ["cpe:/a:openbsd:openssh:7.2p2"]
                        },
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                            "product": "Apache httpd",
                            "version": "2.4.49",
                            "cpe": ["cpe:/a:apache:http_server:2.4.49"]
                        }
                    ]
                }
            ]
        }
    monkeypatch.setattr("services.scan_service.run_nmap_scan", mock_scan)

    # Mock fetch_cves_for_query to return success and some dummy cves
    def mock_fetch(*args, **kwargs):
        return {
            "success": True,
            "cves": [
                {
                    "id": "CVE-2021-41773",
                    "cvss": 7.5,
                    "summary": "Path traversal",
                    "is_definite_match": True
                }
            ]
        }
    monkeypatch.setattr("services.scan_service.fetch_cves_for_query", mock_fetch)

    with app.app_context():
        user = User.query.first()
        scan = ScanResult(
            user_id=user.id if user else None,
            input_ip="192.168.1.100",
            subnet_mask="32",
            scan_type="service_version",
            status="pending",
            network_cidr="192.168.1.100/32",
            audit_credentials=False
        )
        db.session.add(scan)
        db.session.commit()

        # Run execute_scan
        from services.scan_service import execute_scan
        execute_scan(app, scan.id, audit_credentials=False)

        # Check status and result data serialization
        db.session.refresh(scan)
        assert scan.status == "completed"
        assert scan.result_data is not None
        
        # Verify JSON loads successfully without serialization errors
        res_data = json.loads(scan.result_data)
        assert "hosts" in res_data
        hosts = res_data["hosts"]
        assert len(hosts) == 1
        
        # Verify internal keys (like sets and tuple keys) were cleaned up and do not exist in the serialized json
        host = hosts[0]
        assert "_cve_failed_ports" not in host
        assert "_audited_endpoints" not in host
        assert "_asset_id" not in host
        assert "is_new_rogue" not in host

def test_migration_upgrade_downgrade():
    import tempfile
    import os
    from app import create_app
    from flask_migrate import upgrade, downgrade

    db_fd, db_path = tempfile.mkstemp()
    try:
        app = create_app({
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
            "START_SCHEDULER": False
        })
        
        with app.app_context():
            # Run upgrade to head
            upgrade()
            
            # Run downgrade by one step (to 3f235f89c673)
            downgrade(revision="-1")
            
            # Run upgrade back to head
            upgrade()
    finally:
        os.close(db_fd)
        try:
            os.unlink(db_path)
        except OSError:
            pass
