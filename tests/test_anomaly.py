from models import db, Asset, SecurityAnomaly, AssetObservation
from services.anomaly_service import evaluate_host_anomalies

# Verify that rogue device detection behaves as expected.
def test_rogue_device_detection(app):
    # Manage app.app_context() within this scoped block.
    with app.app_context():
        # Scanned host is completely unknown
        host = {
            "address": "192.168.1.50",
            "mac_address": "00:aa:bb:cc:dd:ee",
            "mac_vendor": "Test Vendor",
            "hostname": "unknown-host",
            "ports": []
        }
        res = evaluate_host_anomalies(host, scan_id=99)
        assert res is not None
        assert res["type"] == "rogue_device"
        assert res["confidence_score"] == "Medium"
        
        # Verify in database
        anomaly = SecurityAnomaly.query.filter_by(anomaly_type="rogue_device").first()
        assert anomaly is not None
        assert anomaly.ip_address == "192.168.1.50"

# Verify that mac spoofing detection behaves as expected.
def test_mac_spoofing_detection(app):
    # Manage app.app_context() within this scoped block.
    with app.app_context():
        # Create a trusted asset
        asset = Asset(
            name="Trusted Server",
            ip_address="192.168.1.10",
            mac_address="00:11:22:33:44:55",
            is_trusted=True
        )
        db.session.add(asset)
        db.session.commit()
        
        # Scanned host has the same IP but different MAC address (MAC Spoofing)
        host = {
            "address": "192.168.1.10",
            "mac_address": "00:aa:bb:cc:dd:ee",
            "mac_vendor": "Spoofer",
            "hostname": "server-host",
            "ports": []
        }
        res = evaluate_host_anomalies(host, scan_id=100)
        assert res is not None
        assert res["type"] == "mac_spoofing"
        # Confirm it flagged a MAC spoofing anomaly
        anomaly = SecurityAnomaly.query.filter_by(anomaly_type="mac_spoofing").first()
        assert anomaly is not None
        assert anomaly.confidence_score in ["High", "Medium", "Low"]
