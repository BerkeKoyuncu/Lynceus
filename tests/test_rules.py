from models import db, User, SecurityRule, SecurityFinding, Asset
from services.rule_service import seed_default_rules, evaluate_rules_for_host

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
