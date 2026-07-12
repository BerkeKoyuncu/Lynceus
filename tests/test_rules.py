from models import db, User, SecurityRule, SecurityFinding, Asset
from services.rule_service import (
    calculate_finding_fingerprint,
    evaluate_rules_for_host,
    reconcile_findings_for_scan,
    seed_default_rules,
)

def test_seed_default_rules(app):
    with app.app_context():
        # Get test admin
        admin = User.query.filter_by(is_admin=True).first()
        seed_default_rules(admin.id)
        
        # Verify rules seeded
        rules_count = SecurityRule.query.filter_by(user_id=admin.id).count()
        assert rules_count > 0
        
        telnet_rule = SecurityRule.query.filter_by(user_id=admin.id, name="Disable Telnet Service").first()
        assert telnet_rule is not None

def test_evaluate_rules_for_host(app):
    with app.app_context():
        admin = User.query.filter_by(is_admin=True).first()
        seed_default_rules(admin.id)
        
        # Create a critical asset
        asset = Asset(
            name="Production Server",
            ip_address="192.168.1.15",
            mac_address="00:11:22:33:44:aa",
            criticality="Critical",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()
        
        # Scanned host exposing Telnet (port 23)
        host = {
            "address": "192.168.1.15",
            "hostname": "prod-server",
            "ports": [
                {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet", "version": "1.0"}
            ]
        }
        
        # Evaluate rules
        evaluate_rules_for_host(host, asset, admin.id)
        
        # Check if SecurityFinding was generated for Telnet exposure
        finding = SecurityFinding.query.filter_by(asset_id=asset.id, port=23).first()
        assert finding is not None
        assert finding.severity in ["High", "Critical"]
        assert "telnet" in finding.service


def test_redis_rule_finding_is_preserved_when_audit_is_skipped(app):
    with app.app_context():
        admin = User.query.filter_by(is_admin=True).first()
        seed_default_rules(admin.id)
        rule = SecurityRule.query.filter_by(
            user_id=admin.id, name="Redis Unauthenticated Access"
        ).one()
        asset = Asset(name="Redis", ip_address="192.0.2.10", criticality="High")
        db.session.add(asset)
        db.session.flush()
        fingerprint = calculate_finding_fingerprint(
            asset.ip_address, 6379, "redis", "rule", rule.id
        )
        finding = SecurityFinding(
            asset_id=asset.id,
            ip_address=asset.ip_address,
            port=6379,
            protocol="tcp",
            service="redis",
            severity="Critical",
            status="open",
            source_type="rule",
            source_rule_id=rule.id,
            fingerprint=fingerprint,
        )
        db.session.add(finding)
        db.session.commit()

        host = {
            "address": asset.ip_address,
            "ports": [{
                "port": 6379,
                "protocol": "tcp",
                "state": "open",
                "service": "redis",
                "credential_audit": {"status": "skipped", "message": "timeout"},
            }],
        }
        original_scan_id = finding.scan_id
        preserved = evaluate_rules_for_host(host, asset, admin.id, scan_id=999)
        db.session.refresh(finding)
        assert finding.scan_id == original_scan_id
        assert preserved == {fingerprint}

        reconcile_findings_for_scan(
            asset=asset,
            host_online=True,
            observed_fingerprints=preserved,
            scan_id=999,
            scan_type="detailed",
            requested_ports="6379",
            current_open_ports=[("tcp", 6379)],
            endpoint_states={("tcp", 6379): "open"},
        )
        db.session.refresh(finding)
        assert finding.status == "open"
