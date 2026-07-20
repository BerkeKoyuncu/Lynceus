from datetime import datetime

from models import Asset, SecurityAnomaly, SecurityFinding, User, db


def _login(client, user_id):
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True


def test_admin_can_bulk_update_finding_status(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@test.com").first()
        findings = [
            SecurityFinding(
                ip_address=f"192.0.2.{index}",
                port=443,
                service="https",
                status="open",
                acceptance_expiry=datetime(2030, 1, 1),
            )
            for index in range(1, 4)
        ]
        db.session.add_all(findings)
        db.session.commit()
        admin_id = admin.id
        selected_ids = [findings[0].id, findings[1].id]
        unselected_id = findings[2].id

    _login(client, admin_id)
    response = client.post(
        "/findings/bulk-update",
        data={
            "finding_ids": [str(finding_id) for finding_id in selected_ids],
            "bulk_status": "resolved",
            "filter_status": "open",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Successfully updated 2 selected findings." in response.data

    with app.app_context():
        for finding_id in selected_ids:
            finding = db.session.get(SecurityFinding, finding_id)
            assert finding.status == "resolved"
            assert finding.acceptance_expiry is None
        assert db.session.get(SecurityFinding, unselected_id).status == "open"


def test_bulk_finding_update_rejects_system_managed_status(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@test.com").first()
        finding = SecurityFinding(
            ip_address="192.0.2.10",
            port=22,
            service="ssh",
            status="open",
        )
        db.session.add(finding)
        db.session.commit()
        admin_id = admin.id
        finding_id = finding.id

    _login(client, admin_id)
    response = client.post(
        "/findings/bulk-update",
        data={"finding_ids": [str(finding_id)], "bulk_status": "not_observed"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Invalid status selected." in response.data
    with app.app_context():
        assert db.session.get(SecurityFinding, finding_id).status == "open"


def test_admin_can_bulk_update_asset_trust(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@test.com").first()
        assets = [
            Asset(name="Asset A", ip_address="198.51.100.10", is_trusted=False),
            Asset(name="Asset B", ip_address="198.51.100.11", is_trusted=False),
        ]
        db.session.add_all(assets)
        db.session.flush()
        anomalies = [
            SecurityAnomaly(
                anomaly_type="rogue_device",
                ip_address=asset.ip_address,
                description="Unknown device",
                is_resolved=False,
            )
            for asset in assets
        ]
        db.session.add_all(anomalies)
        db.session.commit()
        admin_id = admin.id
        asset_ids = [asset.id for asset in assets]
        anomaly_ids = [anomaly.id for anomaly in anomalies]

    _login(client, admin_id)
    response = client.post(
        "/admin/assets/bulk-trust",
        data={
            "asset_ids": [str(asset_id) for asset_id in asset_ids],
            "trust_status": "trusted",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Successfully marked 2 selected assets as trusted." in response.data

    with app.app_context():
        assert all(db.session.get(Asset, asset_id).is_trusted for asset_id in asset_ids)
        assert all(db.session.get(SecurityAnomaly, anomaly_id).is_resolved for anomaly_id in anomaly_ids)

    response = client.post(
        "/admin/assets/bulk-trust",
        data={"asset_ids": [str(asset_ids[0])], "trust_status": "untrusted"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(Asset, asset_ids[0]).is_trusted is False
        assert db.session.get(Asset, asset_ids[1]).is_trusted is True


def test_bulk_action_controls_render_for_admin(app, client):
    with app.app_context():
        admin = User.query.filter_by(email="admin@test.com").first()
        db.session.add(Asset(name="Rendered Asset", ip_address="203.0.113.20"))
        db.session.add(
            SecurityFinding(
                ip_address="203.0.113.20",
                port=80,
                service="http",
                status="open",
            )
        )
        db.session.commit()
        admin_id = admin.id

    _login(client, admin_id)

    findings_response = client.get("/findings")
    assert findings_response.status_code == 200
    assert b'id="bulk-findings-form"' in findings_response.data
    assert b'class="finding-checkbox"' in findings_response.data

    assets_response = client.get("/admin/assets")
    assert assets_response.status_code == 200
    assert b'id="bulk-trust-btn"' in assets_response.data
    assert b'id="bulk-untrust-btn"' in assets_response.data
