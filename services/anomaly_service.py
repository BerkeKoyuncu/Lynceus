import hashlib
from datetime import datetime, timezone, timedelta
from models import db, Asset, AssetObservation, SecurityAnomaly


# Handle the anomaly exists operation.
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

# Retrieve ports hash.
def get_ports_hash(ports_list):
    """
    Computes a stable hash from a list of ports including port number, protocol, and state.
    """
    # Handle the branch where not ports_list evaluates to true.
    if not ports_list:
        return "empty"
    # Extract endpoint details, sort them, and compute SHA-256
    port_ids = []
    # Iterate over ports_list and bind each item to p.
    for p in ports_list:
        p_num = p.get("port")
        # Handle the branch where p_num evaluates to true.
        if p_num:
            proto = (p.get("protocol") or "tcp").lower()
            state = (p.get("state") or "open").lower()
            port_ids.append(f"{p_num}/{proto}:{state}")
    sorted_ports = ",".join(sorted(port_ids))
    return hashlib.sha256(sorted_ports.encode()).hexdigest()

# Handle the record observation operation.
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

# Handle the evaluate host anomalies operation.
def evaluate_host_anomalies(host, scan_id):
    """
    Evaluates potential security anomalies for a scanned host based on historical observations.
    Returns a dict containing the anomaly details and confidence score if an anomaly is detected.
    """
    ip = host.get("address")
    mac = host.get("mac_address", "").strip().lower() if host.get("mac_address") else None
    vendor = host.get("mac_vendor")
    hostname = host.get("hostname")
    
    # Check if a new rogue device was identified in Pass 1 (fallback for direct/test calls)
    is_new_rogue = host.get("is_new_rogue")
    # Handle the branch where is_new_rogue is None evaluates to true.
    if is_new_rogue is None:
        asset_check = None
        # Handle the branch where mac evaluates to true.
        if mac:
            asset_check = Asset.query.filter(Asset.mac_address.ilike(mac)).first()
        # Handle the branch where not asset_check evaluates to true.
        if not asset_check:
            asset_check = Asset.query.filter_by(ip_address=ip).first()
        is_new_rogue = (asset_check is None)

    # Handle the branch where is_new_rogue evaluates to true.
    if is_new_rogue:
        desc = f"New unknown device detected on the network: IP {ip}, MAC {mac or 'N/A'} ({vendor or 'Unknown'})."
        # Handle the branch where not _anomaly_exists('rogue_device', ip, mac) evaluates to true.
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

    # Retrieve snapshot values
    expected_ip = host.get("_expected_ip")
    expected_mac = host.get("_expected_mac")
    asset_id = host.get("_asset_id")
    
    # If no snapshot, look up from DB as fallback (for standalone tests)
    if expected_ip is None and expected_mac is None and asset_id is None:
        asset_check = None
        # Handle the branch where mac evaluates to true.
        if mac:
            asset_check = Asset.query.filter(Asset.mac_address.ilike(mac)).first()
        # Handle the branch where not asset_check evaluates to true.
        if not asset_check:
            asset_check = Asset.query.filter_by(ip_address=ip).first()
        # Handle the branch where asset_check evaluates to true.
        if asset_check:
            expected_ip = asset_check.ip_address
            expected_mac = asset_check.mac_address
            asset_id = asset_check.id
            ip_assignment_type = asset_check.ip_assignment_type
        # Handle the fallback branch when the preceding condition does not match.
        else:
            return None
    # Handle the fallback branch when the preceding condition does not match.
    else:
        # Get ip_assignment_type from the asset in DB
        asset_db = db.session.get(Asset, asset_id)
        ip_assignment_type = asset_db.ip_assignment_type if asset_db else "DHCP"

    # Evaluate anomalies
    anomaly_result = None

    # 2. Check for MAC Spoofing (Expected IP matches scanned IP, but MAC changed)
    # i.e., scanned IP matches expected IP, but scanned MAC != expected MAC
    if expected_ip == ip and expected_mac and mac and expected_mac.lower() != mac:
        old_mac = expected_mac.lower()
        
        # Has the new MAC been seen on this IP before?
        past_matching_observations = AssetObservation.query.filter_by(
            ip_address=ip,
            mac_address=mac
        ).filter(AssetObservation.scan_id != scan_id).count()
        
        # Check if the old MAC is still active on another IP in the current scan session
        old_mac_active_elsewhere = AssetObservation.query.filter_by(
            scan_id=scan_id,
            mac_address=old_mac
        ).filter(AssetObservation.ip_address != ip).first()

        # Check for rapid randomization/flapping in the last 48 hours
        two_days_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2)
        unique_macs_on_ip = db.session.query(AssetObservation.mac_address).filter(
            AssetObservation.ip_address == ip,
            AssetObservation.observed_at >= two_days_ago,
            AssetObservation.scan_id != scan_id
        ).distinct().count()

        confidence = "High"
        reason = "Potential MAC Spoofing!"
        
        # Handle the branch where old_mac_active_elsewhere evaluates to true.
        if old_mac_active_elsewhere:
            confidence = "High"
            reason = "Active conflict: Expected MAC is active on another IP, while this IP was claimed by a new MAC."
        # Handle the branch where unique_macs_on_ip > 3 evaluates to true.
        elif unique_macs_on_ip > 3:
            confidence = "Low"
            reason = "Frequent MAC variations on this IP (likely MAC randomization or dynamic environment)."
        # Handle the branch where past_matching_observations > 0 evaluates to true.
        elif past_matching_observations > 0:
            confidence = "Low"
            reason = "Known historical IP-MAC mapping detected."
        # Handle the branch where ip_assignment_type == 'DHCP' evaluates to true.
        elif ip_assignment_type == "DHCP":
            confidence = "Medium"
            reason = "DHCP lease changed to a new MAC; old client inactive."

        desc = f"IP address {ip} has changed its MAC address from {expected_mac} to {mac}. {reason}"
        # Handle the branch where not _anomaly_exists('mac_spoofing', ip, mac) evaluates to true.
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
            "expected_mac": expected_mac,
            "found_mac": mac,
            "description": desc,
            "confidence_score": confidence
        }

    # 3. Check for IP Hijacking (MAC is same, but IP address changed)
    elif expected_mac and mac and expected_mac.lower() == mac and expected_ip != ip:
        old_ip = expected_ip
        
        conflicting_asset = Asset.query.filter_by(ip_address=ip).filter(Asset.mac_address != mac).first()
        
        confidence = "Medium"
        reason = "IP address changed."
        
        # Handle the branch where ip_assignment_type == 'Static' evaluates to true.
        if ip_assignment_type == "Static":
            confidence = "High"
            reason = "Static IP device migrated to a new IP."
        # Handle the branch where conflicting_asset evaluates to true.
        elif conflicting_asset:
            confidence = "High"
            reason = "MAC address claimed an IP address active on another device."
        # Handle the branch where ip_assignment_type == 'DHCP' evaluates to true.
        elif ip_assignment_type == "DHCP":
            confidence = "Low"
            reason = "Standard DHCP lease renewal / migration."

        desc = f"MAC address {mac} ({vendor or 'Unknown'}) changed its IP address from {old_ip} to {ip}. {reason}"
        # Handle the branch where not _anomaly_exists('ip_hijack', ip, mac) evaluates to true.
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
