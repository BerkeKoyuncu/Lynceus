from services.scan_service import is_version_affected, fetch_cves_for_query
from services.rule_service import evaluate_cve_findings
from models import db, SecurityFinding, Asset

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
        evaluate_cve_findings(asset, "192.168.1.99", port_info, dummy_cve_list, scan_id=123)

        # Check that finding was created
        finding = SecurityFinding.query.filter_by(asset_id=asset.id, cve="CVE-2021-41773").first()
        assert finding is not None
        assert finding.status == "open"
        assert finding.severity == "High"
        assert finding.port == 80
