import ipaddress
import ssl
import socket
import json
from datetime import datetime, timezone
from models import db, SecurityRule, SecurityFinding, SecurityAnomaly, Asset, SystemSetting, HoneypotLog, HoneypotBlockedIP

def get_ssl_expiry_days(ip, port):
    """
    Connects to the given IP and port, fetches the SSL certificate,
    and returns the number of days left until expiration.
    """
    try:
        cert_pem = ssl.get_server_certificate((ip, port), timeout=2)
        from cryptography import x509
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
        if hasattr(cert_obj, "not_valid_after_utc"):
            expiry_date = cert_obj.not_valid_after_utc
        else:
            expiry_date = cert_obj.not_valid_after.replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        days_left = (expiry_date - now).days
        return days_left
    except Exception:
        return None

def is_ip_in_subnet(ip, subnet_cidr):
    """
    Checks if an IP address resides in a given subnet CIDR.
    """
    try:
        if subnet_cidr == "*":
            return True
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet_cidr, strict=False)
    except Exception:
        return False

def seed_default_rules(user_id):
    """
    Seeds standard security rules for a user if they don't already exist.
    """
    existing = SecurityRule.query.filter_by(user_id=user_id).first()
    if existing:
        return

    default_rules = [
        SecurityRule(
            user_id=user_id,
            name="Disable Telnet Service",
            severity="High",
            scope="*",
            port_service_condition="port:23,service:telnet",
            asset_criticality_condition="*",
            exception_list="",
            remediation_text="Telnet transmits credentials in plain text. Disable Telnet and migrate to SSH (Port 22) for secure administration.",
            enabled=True
        ),
        SecurityRule(
            user_id=user_id,
            name="Disable Plaintext FTP Service",
            severity="Medium",
            scope="*",
            port_service_condition="port:21,service:ftp",
            asset_criticality_condition="*",
            exception_list="",
            remediation_text="FTP transmits credentials and data in plain text. Migrate to SFTP or FTPS for secure file transfers.",
            enabled=True
        ),
        SecurityRule(
            user_id=user_id,
            name="Restrict RDP Access",
            severity="High",
            scope="*",
            port_service_condition="port:3389,service:ms-wbt-server",
            asset_criticality_condition="*",
            exception_list="",
            remediation_text="Remote Desktop Protocol (RDP) should not be exposed globally. Restrict access to designated management subnets or configure exceptions.",
            enabled=True
        ),
        SecurityRule(
            user_id=user_id,
            name="Redis Unauthenticated Access",
            severity="Critical",
            scope="*",
            port_service_condition="port:6379,service:redis",
            asset_criticality_condition="*",
            exception_list="",
            remediation_text="Redis is accessible without authentication or uses weak credentials. Configure strong passwords or bind Redis to localhost/secure subnet.",
            enabled=True
        ),
        SecurityRule(
            user_id=user_id,
            name="Unknown Service on Critical Asset",
            severity="High",
            scope="*",
            port_service_condition="service:unknown",
            asset_criticality_condition="Critical,High",
            exception_list="",
            remediation_text="An unrecognized or undocumented service was detected on a critical asset. Identify the service and configure/block it accordingly.",
            enabled=True
        ),
        SecurityRule(
            user_id=user_id,
            name="Expiring TLS Certificate",
            severity="Medium",
            scope="*",
            port_service_condition="port:443,port:8443,service:https",
            asset_criticality_condition="*",
            exception_list="",
            remediation_text="An SSL/TLS certificate is expiring within 30 days. Renew the certificate to avoid service interruptions.",
            enabled=True
        ),
        SecurityRule(
            user_id=user_id,
            name="New Open Port Detected",
            severity="High",
            scope="*",
            port_service_condition="new_port",
            asset_criticality_condition="*",
            exception_list="",
            remediation_text="A new open port has been detected on the network asset that was not active in previous scans. Verify if this change is authorized.",
            enabled=True
        )
    ]
    
    for rule in default_rules:
        db.session.add(rule)
    db.session.commit()

def calculate_finding_fingerprint(ip_address, port, service, source_type, source_id_or_cve):
    import hashlib
    raw_str = f"{ip_address}:{port}:{service or ''}:{source_type}:{source_id_or_cve or ''}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

def evaluate_rules_for_host(host, asset, user_id, prev_ports=None, scan_id=None):
    """
    Evaluates active security rules against a scanned host's details.
    Creates or updates SecurityFinding records, auto-reopening them if needed.
    """
    ip = host.get("address")
    mac = host.get("mac_address", "").strip().lower() if host.get("mac_address") else ""
    ports = host.get("ports", [])
    
    # Load all active security rules for the user
    rules = SecurityRule.query.filter_by(user_id=user_id, enabled=True).all()
    
    for rule in rules:
        # 1. Check exception list (IP or MAC)
        exceptions = [x.strip().lower() for x in rule.exception_list.split(",") if x.strip()] if rule.exception_list else []
        if ip.lower() in exceptions or mac in exceptions:
            continue
            
        # 2. Check scope
        if rule.scope and rule.scope != "*":
            if not is_ip_in_subnet(ip, rule.scope):
                continue
                
        # 3. Check asset criticality condition
        criticalities = [c.strip().lower() for c in rule.asset_criticality_condition.split(",") if c.strip()] if rule.asset_criticality_condition else []
        if "*" not in criticalities and asset.criticality.lower() not in criticalities:
            continue
            
        # 4. Check rule conditions
        matched = False
        evidence = ""
        matched_port = None
        matched_service = None
        matched_version = None
        
        conditions = [c.strip().lower() for c in rule.port_service_condition.split(",") if c.strip()] if rule.port_service_condition else []
        
        # Check "new_port" condition
        if "new_port" in conditions:
            if prev_ports is not None:
                current_port_nums = [int(p.get("port") or 0) for p in ports]
                for cp in current_port_nums:
                    if cp not in prev_ports:
                        matched = True
                        matched_port = cp
                        evidence = f"New port {cp} was detected. It was not open in previous scans."
                        # Find service info for this port
                        for pinfo in ports:
                            if int(pinfo.get("port") or 0) == cp:
                                matched_service = pinfo.get("service")
                                matched_version = pinfo.get("version")
                                break
                        break

        if not matched:
            for pinfo in ports:
                p_num = int(pinfo.get("port") or 0)
                service = (pinfo.get("service") or "").lower()
                version = pinfo.get("version")
                
                # Check port/service matching conditions
                for cond in conditions:
                    if cond.startswith("port:"):
                        cond_port = int(cond.split(":")[1])
                        if p_num == cond_port:
                            matched = True
                            matched_port = p_num
                            matched_service = service
                            matched_version = version
                            evidence = f"Port condition matched: Port {p_num} is open."
                    elif cond.startswith("service:"):
                        cond_svc = cond.split(":")[1]
                        if cond_svc == "unknown":
                            if service in ["unknown", "disabled", "-", ""] or "unknown" in service:
                                matched = True
                                matched_port = p_num
                                matched_service = service
                                matched_version = version
                                evidence = f"Service condition matched: Unrecognized service on port {p_num}."
                        elif cond_svc in service:
                            matched = True
                            matched_port = p_num
                            matched_service = service
                            matched_version = version
                            evidence = f"Service condition matched: Service '{service}' is open on port {p_num}."

                # Special case: Redis anonymous auth check
                if matched and rule.name == "Redis Unauthenticated Access":
                    # If this port is 6379 or service is redis, check credential audit results
                    audit_res = pinfo.get("credential_audit")
                    if audit_res and audit_res.get("status") == "vulnerable":
                        evidence = f"Redis instance on port {p_num} allows anonymous login or has default passwords: {audit_res.get('message')}"
                    else:
                        # If not audited yet or audited safe, we don't mark as critical anonymous unless audited
                        if p_num == 6379:
                            evidence = "Redis port 6379 is open. Check credential settings to verify authentication status."
                
                # Special case: TLS certificate check
                if matched and rule.name == "Expiring TLS Certificate":
                    # Call get_ssl_expiry_days
                    days_left = get_ssl_expiry_days(ip, p_num)
                    if days_left is not None and days_left <= 30:
                        evidence = f"TLS Certificate on port {p_num} is expiring in {days_left} days."
                    else:
                        matched = False  # Not expiring or couldn't fetch

                if matched:
                    break

        if matched:
            # Create or update SecurityFinding record
            fp = calculate_finding_fingerprint(ip, matched_port or 0, matched_service, "rule", rule.id)
            
            existing_finding = SecurityFinding.query.filter_by(
                asset_id=asset.id,
                fingerprint=fp
            ).first()
            
            if not existing_finding:
                existing_finding = SecurityFinding.query.filter_by(
                    asset_id=asset.id,
                    ip_address=ip,
                    port=matched_port or 0,
                    service=matched_service or "unknown",
                    source_type="rule",
                    source_rule_id=rule.id
                ).first()
            
            if existing_finding:
                existing_finding.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
                existing_finding.evidence = evidence
                existing_finding.version = matched_version
                existing_finding.fingerprint = fp
                existing_finding.scan_id = scan_id
                
                reopen = False
                if existing_finding.status == "resolved":
                    reopen = True
                elif existing_finding.status == "accepted_risk":
                    if existing_finding.acceptance_expiry and datetime.now(timezone.utc).replace(tzinfo=None) > existing_finding.acceptance_expiry:
                        reopen = True
                
                if reopen:
                    existing_finding.status = "open"
            else:
                new_finding = SecurityFinding(
                    asset_id=asset.id,
                    ip_address=ip,
                    port=matched_port or 0,
                    service=matched_service or "unknown",
                    version=matched_version,
                    severity=rule.severity,
                    evidence=evidence,
                    status="open",
                    remediation_note=rule.remediation_text,
                    first_seen=datetime.now(timezone.utc).replace(tzinfo=None),
                    last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
                    source_type="rule",
                    source_rule_id=rule.id,
                    scan_id=scan_id,
                    fingerprint=fp
                )
                db.session.add(new_finding)
            db.session.commit()

def evaluate_cve_findings(asset, ip_address, port_info, cve_list, scan_id=None):
    """
    Saves external CVE scan results into the SecurityFinding table.
    """
    p_num = int(port_info.get("port") or 0)
    service = port_info.get("service") or "unknown"
    version = port_info.get("version") or ""
    
    for cve in cve_list:
        cve_id = cve.get("id")
        cvss = cve.get("cvss")
        summary = cve.get("summary")
        is_definite = cve.get("is_definite_match", False)
        
        status = "open" if is_definite else "needs_review"
        
        # Map CVSS to severity
        if cvss is None:
            severity = "Medium"
        elif cvss >= 9.0:
            severity = "Critical"
        elif cvss >= 7.0:
            severity = "High"
        elif cvss >= 4.0:
            severity = "Medium"
        else:
            severity = "Low"

        fp = calculate_finding_fingerprint(ip_address, p_num, service, "cve", cve_id)

        existing_finding = SecurityFinding.query.filter_by(
            asset_id=asset.id,
            fingerprint=fp
        ).first()

        if not existing_finding:
            existing_finding = SecurityFinding.query.filter_by(
                asset_id=asset.id,
                ip_address=ip_address,
                port=p_num,
                cve=cve_id
            ).first()

        if existing_finding:
            existing_finding.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
            existing_finding.fingerprint = fp
            existing_finding.scan_id = scan_id
            
            reopen = False
            if existing_finding.status == "resolved":
                reopen = True
            elif existing_finding.status == "accepted_risk":
                if existing_finding.acceptance_expiry and datetime.now(timezone.utc).replace(tzinfo=None) > existing_finding.acceptance_expiry:
                    reopen = True
            
            if reopen:
                existing_finding.status = status
        else:
            new_finding = SecurityFinding(
                asset_id=asset.id,
                ip_address=ip_address,
                port=p_num,
                service=service,
                version=version,
                cve=cve_id,
                cvss=cvss,
                severity=severity,
                evidence=f"Vulnerability {cve_id} detected on service {service} (version: {version}).\nDescription: {summary}",
                status=status,
                remediation_note="Apply the latest software updates and vendor security patches for this service version.",
                first_seen=datetime.now(timezone.utc).replace(tzinfo=None),
                last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
                source_type="cve",
                scan_id=scan_id,
                fingerprint=fp
            )
            db.session.add(new_finding)
    db.session.commit()

def calculate_network_risk_score(user_id):
    """
    Calculates the dynamic security risk score (0-100) based on actual findings,
    anomalies, untrusted devices, and honeypot configuration.
    """
    risk_score = 0
    risk_factors = []

    # 1. Unresolved Security Findings
    findings = SecurityFinding.query.filter(SecurityFinding.status.in_(["open", "needs_review"])).all()
    findings_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        severity = f.severity or "Medium"
        if severity in findings_by_severity:
            findings_by_severity[severity] += 1
            
    findings_score = (
        (findings_by_severity["Critical"] * 25) +
        (findings_by_severity["High"] * 15) +
        (findings_by_severity["Medium"] * 5) +
        (findings_by_severity["Low"] * 1)
    )
    risk_score += findings_score

    if findings_by_severity["Critical"] > 0:
        risk_factors.append({
            "severity": "critical",
            "message": f"{findings_by_severity['Critical']} unresolved Critical vulnerability finding(s) detected."
        })
    if findings_by_severity["High"] > 0:
        risk_factors.append({
            "severity": "high",
            "message": f"{findings_by_severity['High']} unresolved High vulnerability finding(s) detected."
        })
    if findings_by_severity["Medium"] > 0:
        risk_factors.append({
            "severity": "medium",
            "message": f"{findings_by_severity['Medium']} unresolved Medium vulnerability finding(s) detected."
        })

    # 2. Unresolved Security Anomalies
    anomalies = SecurityAnomaly.query.filter_by(is_resolved=False).all()
    anomalies_by_conf = {"High": 0, "Medium": 0, "Low": 0}
    for a in anomalies:
        conf = a.confidence_score or "High"
        if conf in anomalies_by_conf:
            anomalies_by_conf[conf] += 1
            
    anomalies_score = (
        (anomalies_by_conf["High"] * 20) +
        (anomalies_by_conf["Medium"] * 10) +
        (anomalies_by_conf["Low"] * 5)
    )
    risk_score += anomalies_score

    if anomalies_by_conf["High"] > 0:
        risk_factors.append({
            "severity": "high",
            "message": f"{anomalies_by_conf['High']} unresolved High-confidence anomaly/anomalies detected."
        })
    if anomalies_by_conf["Medium"] > 0:
        risk_factors.append({
            "severity": "medium",
            "message": f"{anomalies_by_conf['Medium']} unresolved Medium-confidence anomaly/anomalies detected."
        })

    # 3. Untrusted Inventory Assets
    untrusted_count = Asset.query.filter_by(is_trusted=False).count()
    if untrusted_count > 0:
        risk_score += min(untrusted_count * 2, 10)
        risk_factors.append({
            "severity": "medium",
            "message": f"{untrusted_count} devices in inventory are marked as Untrusted."
        })

    # 4. Global Settings Risk Check
    setting = SystemSetting.query.filter_by(user_id=user_id).first()
    if setting:
        if not setting.honeypot_active:
            risk_score += 10
            risk_factors.append({
                "severity": "low",
                "message": "Honeypot system is disabled (reduced intrusion detection capability)."
            })
        if not setting.smtp_server or not setting.smtp_sender or not setting.alert_recipient:
            risk_score += 5
            risk_factors.append({
                "severity": "low",
                "message": "Email notifications (SMTP) not configured. Security alerts won't be sent."
            })

    # 5. Recent Honeypot Intrusion Logs
    recent_honeypot_hits = HoneypotLog.query.count()
    if recent_honeypot_hits > 0:
        hits_score = min(recent_honeypot_hits * 2, 10)
        risk_score += hits_score
        risk_factors.append({
            "severity": "medium",
            "message": f"{recent_honeypot_hits} intrusion attempts logged on decoy endpoints."
        })

    # Cap risk score
    risk_score = min(max(risk_score, 0), 100)

    # Determine risk level properties
    if risk_score >= 70:
        level = "High"
        color = "var(--error-text)"
        bg = "var(--error-bg)"
    elif risk_score >= 35:
        level = "Medium"
        color = "var(--warning-text)"
        bg = "var(--warning-bg)"
    else:
        level = "Low"
        color = "var(--success-text)"
        bg = "var(--success-bg)"

    return {
        "score": risk_score,
        "level": level,
        "color": color,
        "bg": bg,
        "factors": risk_factors
    }
