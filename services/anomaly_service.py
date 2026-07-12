import hashlib
from datetime import datetime, timezone, timedelta
from models import db, Asset, AssetObservation, SecurityAnomaly


def _anomaly_exists(anomaly_type, ip_address, mac_address, hours=24):
    """
    Returns True if an unresolved anomaly of the same type, IP, and MAC
    was already recorded within the last `hours` hours.
    """
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    return SecurityAnomaly.query.filter(
        SecurityAnomaly.anomaly_type == anomaly_type,
        SecurityAnomaly.ip_address == ip_address,
        SecurityAnomaly.mac_address == mac_address,
        SecurityAnomaly.is_resolved == False,
        SecurityAnomaly.created_at >= since
    ).first() is not None

def get_ports_hash(ports_list):
    """
    Computes a stable hash from a list of open ports.
    """
    if not ports_list:
        return "empty"
    # Extract port numbers, sort them, and compute SHA-256
    port_ids = []
    for p in ports_list:
        p_num = p.get("port")
        if p_num:
            port_ids.append(str(p_num))
    sorted_ports = ",".join(sorted(port_ids))
    return hashlib.sha256(sorted_ports.encode()).hexdigest()

def record_observation(asset_id, scan_id, ip_address, mac_address, hostname, vendor, operating_system, open_ports):
    """
    Saves a single asset observation snapshot.
    """
    ports_hash = get_ports_hash(open_ports)
    observation = AssetObservation(
        asset_id=asset_id,
        scan_id=scan_id,
        ip_address=ip_address,
        mac_address=mac_address.strip().lower() if mac_address else None,
        hostname=hostname,
        vendor=vendor,
        operating_system=operating_system,
        open_ports_hash=ports_hash,
        observed_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    db.session.add(observation)
    db.session.commit()
    return observation

def evaluate_host_anomalies(host, scan_id):
    """
    Evaluates potential security anomalies for a scanned host based on historical observations.
    Returns a dict containing the anomaly details and confidence score if an anomaly is detected.
    """
    ip = host.get("address")
    mac = host.get("mac_address", "").strip().lower() if host.get("mac_address") else None
    vendor = host.get("mac_vendor")
    hostname = host.get("hostname")
    ports = host.get("ports", [])
    
    # Check if a new rogue device was identified in Pass 1 (fallback for direct/test calls)
    is_new_rogue = host.get("is_new_rogue")
    if is_new_rogue is None:
        asset_check = None
        if mac:
            asset_check = Asset.query.filter(Asset.mac_address.ilike(mac)).first()
        if not asset_check:
            asset_check = Asset.query.filter_by(ip_address=ip).first()
        is_new_rogue = (asset_check is None)

    if is_new_rogue:
        desc = f"New unknown device detected on the network: IP {ip}, MAC {mac or 'N/A'} ({vendor or 'Unknown'})."
        if not _anomaly_exists("rogue_device", ip, mac):
            anomaly = SecurityAnomaly(
                anomaly_type="rogue_device",
                ip_address=ip,
                mac_address=mac,
                description=desc,
                confidence_score="Medium"
            )
            db.session.add(anomaly)
            db.session.commit()
        return {
            "type": "rogue_device",
            "description": desc,
            "confidence_score": "Medium"
        }

    # 1. Look for existing asset
    asset_match = None
    if mac:
        asset_match = Asset.query.filter(Asset.mac_address.ilike(mac)).first()
    if not asset_match:
        asset_match = Asset.query.filter_by(ip_address=ip).first()

    if not asset_match:
        return None

    # Evaluate anomalies FIRST before saving the current observation
    anomaly_result = None

    # 2. Check for MAC Spoofing (Expected IP matches scanned IP, but MAC changed)
    if asset_match.ip_address == ip and asset_match.mac_address and mac and asset_match.mac_address.lower() != mac:
        old_mac = asset_match.mac_address.lower()
        
        # Query observation history: has the new MAC been seen on this IP before?
        # Note: We filter out observations from the current scan session to compare against history!
        past_matching_observations = AssetObservation.query.filter_by(
            ip_address=ip,
            mac_address=mac
        ).filter(AssetObservation.scan_id != scan_id).count()
        
        # Check if the old MAC is still active on another IP in the current scan session
        # We check if there's an observation for the old MAC in this scan_id
        old_mac_active_elsewhere = AssetObservation.query.filter_by(
            scan_id=scan_id,
            mac_address=old_mac
        ).filter(AssetObservation.ip_address != ip).first()

        # Check for rapid randomization/flapping in the last 48 hours (excluding current scan)
        two_days_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2)
        unique_macs_on_ip = db.session.query(AssetObservation.mac_address).filter(
            AssetObservation.ip_address == ip,
            AssetObservation.observed_at >= two_days_ago,
            AssetObservation.scan_id != scan_id
        ).distinct().count()

        confidence = "High"
        reason = "Potential MAC Spoofing!"
        
        if old_mac_active_elsewhere:
            # Both old MAC and new MAC are active at the same time on different IPs
            confidence = "High"
            reason = "Active conflict: Expected MAC is active on another IP, while this IP was claimed by a new MAC."
        elif unique_macs_on_ip > 3:
            # Frequent changes on this IP suggest MAC Randomization or virtual machine churn
            confidence = "Low"
            reason = "Frequent MAC variations on this IP (likely MAC randomization or dynamic environment)."
        elif past_matching_observations > 0:
            # We've seen this IP-MAC mapping before, so it's probably legitimate lease changes or multi-NIC device
            confidence = "Low"
            reason = "Known historical IP-MAC mapping detected."
        elif asset_match.ip_assignment_type == "DHCP":
            # DHCP client changed IP/MAC mapping and old client is gone
            confidence = "Medium"
            reason = "DHCP lease changed to a new MAC; old client inactive."

        desc = f"IP address {ip} has changed its MAC address from {asset_match.mac_address} to {mac}. {reason}"
        if not _anomaly_exists("mac_spoofing", ip, mac):
            anomaly = SecurityAnomaly(
                anomaly_type="mac_spoofing",
                ip_address=ip,
                mac_address=mac,
                description=desc,
                confidence_score=confidence
            )
            db.session.add(anomaly)
            db.session.commit()
        anomaly_result = {
            "type": "mac_spoofing",
            "expected_mac": asset_match.mac_address,
            "found_mac": mac,
            "description": desc,
            "confidence_score": confidence
        }

    # 3. Check for IP Hijacking (MAC is same, but IP address changed)
    elif asset_match.mac_address and mac and asset_match.mac_address.lower() == mac and asset_match.ip_address != ip:
        old_ip = asset_match.ip_address
        
        # Check if the new IP is currently claimed by another active device in inventory
        conflicting_asset = Asset.query.filter_by(ip_address=ip).filter(Asset.mac_address != mac).first()
        
        confidence = "Medium"
        reason = "IP address changed."
        
        if asset_match.ip_assignment_type == "Static":
            # Static IP device changing IP is anomalous
            confidence = "High"
            reason = "Static IP device migrated to a new IP."
        elif conflicting_asset:
            # Hijacked an IP address of another known active client!
            confidence = "High"
            reason = "MAC address claimed an IP address active on another device."
        elif asset_match.ip_assignment_type == "DHCP":
            # Normal DHCP lease renewal
            confidence = "Low"
            reason = "Standard DHCP lease renewal / migration."

        desc = f"MAC address {mac} ({vendor or 'Unknown'}) changed its IP address from {old_ip} to {ip}. {reason}"
        if not _anomaly_exists("ip_hijack", ip, mac):
            anomaly = SecurityAnomaly(
                anomaly_type="ip_hijack",
                ip_address=ip,
                mac_address=mac,
                description=desc,
                confidence_score=confidence
            )
            db.session.add(anomaly)
            db.session.commit()
        anomaly_result = {
            "type": "ip_hijack",
            "expected_ip": old_ip,
            "found_ip": ip,
            "description": desc,
            "confidence_score": confidence
        }
        
    return anomaly_result
