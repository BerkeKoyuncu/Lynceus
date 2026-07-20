from datetime import datetime, timedelta, timezone

from models import Asset, HoneypotLog, SecurityAnomaly, SecurityFinding, User, db
from services.risk_service import calculate_asset_risk, calculate_network_risk_score


def test_clean_critical_asset_has_zero_risk(app):
    with app.app_context():
        asset = Asset(
            name="Clean Critical Asset",
            ip_address="192.0.2.1",
            criticality="Critical",
            is_trusted=True,
        )
        db.session.add(asset)
        db.session.commit()

        risk = calculate_asset_risk(asset)

        assert risk["score"] == 0
        assert risk["level"] == "Low"
        assert risk["criticality_multiplier"] == 1.15


def test_asset_risk_respects_severity_and_review_confidence(app):
    with app.app_context():
        asset = Asset(ip_address="192.0.2.2", criticality="Medium", is_trusted=True)

        low_open = SecurityFinding(
            ip_address=asset.ip_address,
            port=80,
            severity="Low",
            status="open",
        )
        critical_review = SecurityFinding(
            ip_address=asset.ip_address,
            port=443,
            severity="Critical",
            status="needs_review",
        )
        critical_open = SecurityFinding(
            ip_address=asset.ip_address,
            port=22,
            severity="Critical",
            status="open",
        )

        assert calculate_asset_risk(asset, [low_open], [])["score"] == 3
        assert calculate_asset_risk(asset, [critical_review], [])["score"] == 20
        assert calculate_asset_risk(asset, [critical_open], [])["score"] == 50


def test_rogue_device_does_not_double_charge_untrusted_state(app):
    with app.app_context():
        asset = Asset(ip_address="192.0.2.3", criticality="Medium", is_trusted=False)
        anomaly = SecurityAnomaly(
            anomaly_type="rogue_device",
            ip_address=asset.ip_address,
            description="Unknown device",
            confidence_score="Medium",
        )

        risk = calculate_asset_risk(asset, [], [anomaly])

        assert risk["anomaly_score"] == 15
        assert risk["trust_score"] == 0
        assert risk["score"] == 15


def test_network_risk_uses_asset_concentration_instead_of_linear_sum(app):
    with app.app_context():
        for index in range(4):
            asset = Asset(
                name=f"Asset {index}",
                ip_address=f"198.51.100.{index + 1}",
                criticality="Medium",
                is_trusted=True,
            )
            db.session.add(asset)
            db.session.flush()
            db.session.add(
                SecurityFinding(
                    asset_id=asset.id,
                    ip_address=asset.ip_address,
                    port=443,
                    severity="Critical",
                    status="open",
                )
            )
        db.session.commit()
        admin = User.query.filter_by(email="admin@test.com").first()

        risk = calculate_network_risk_score(admin.id)

        assert risk["components"]["evidence"] == 50
        assert risk["components"]["breadth"] == 6
        assert risk["score"] == 56
        assert [asset["score"] for asset in risk["assets"]] == [50, 50, 50, 50]


def test_single_critical_finding_keeps_network_below_high_threshold(app):
    with app.app_context():
        asset = Asset(
            name="Single Finding Asset",
            ip_address="198.51.100.20",
            criticality="Medium",
            is_trusted=True,
        )
        db.session.add(asset)
        db.session.flush()
        db.session.add(
            SecurityFinding(
                asset_id=asset.id,
                ip_address=asset.ip_address,
                port=443,
                severity="Critical",
                status="open",
            )
        )
        db.session.commit()
        admin = User.query.filter_by(email="admin@test.com").first()

        risk = calculate_network_risk_score(admin.id)

        assert risk["score"] == 50
        assert risk["level"] == "Medium"


def test_network_risk_only_counts_recent_unique_honeypot_sources(app):
    with app.app_context():
        old_timestamp = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2)
        db.session.add(
            HoneypotLog(
                ip_address="203.0.113.1",
                path="/old",
                created_at=old_timestamp,
            )
        )
        db.session.add_all([
            HoneypotLog(ip_address="203.0.113.2", path="/first"),
            HoneypotLog(ip_address="203.0.113.2", path="/second"),
        ])
        db.session.commit()
        admin = User.query.filter_by(email="admin@test.com").first()

        risk = calculate_network_risk_score(admin.id)

        assert risk["components"]["intrusions"] == 2
        assert risk["score"] == 2
