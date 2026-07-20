import ipaddress
import ssl
import socket
import json
from datetime import datetime, timezone
from models import db, SecurityRule, SecurityFinding

# Retrieve ssl expiry days.
def get_ssl_expiry_days(ip, port):
    """
    Connects to the given IP and port, fetches the SSL certificate,
    and returns the number of days left until expiration.
    """
    # Run this block with structured exception handling.
    try:
        cert_pem = ssl.get_server_certificate((ip, port), timeout=2)
        from cryptography import x509
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
        # Handle the branch where hasattr(cert_obj, 'not_valid_after_utc') evaluates to true.
        if hasattr(cert_obj, "not_valid_after_utc"):
            expiry_date = cert_obj.not_valid_after_utc
        # Handle the fallback branch when the preceding condition does not match.
        else:
            expiry_date = cert_obj.not_valid_after.replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        days_left = (expiry_date - now).days
        return days_left
    # Handle an exception raised by the preceding protected block.
    except Exception:
        return None

# Determine whether ip in subnet.
def is_ip_in_subnet(ip, subnet_cidr):
    """
    Checks if an IP address resides in a given subnet CIDR.
    """
    # Run this block with structured exception handling.
    try:
        # Handle the branch where subnet_cidr == '*' evaluates to true.
        if subnet_cidr == "*":
            return True
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet_cidr, strict=False)
    # Handle an exception raised by the preceding protected block.
    except Exception:
        return False

# Handle the seed default rules operation.
def seed_default_rules(user_id):
    """
    Seeds standard security rules for a user if they don't already exist.
    """
    existing = SecurityRule.query.filter_by(user_id=user_id).first()
    # Handle the branch where existing evaluates to true.
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
    
    # Iterate over default_rules and bind each item to rule.
    for rule in default_rules:
        db.session.add(rule)
    db.session.commit()

# Handle the calculate finding fingerprint operation.
def calculate_finding_fingerprint(ip_address, port, service, source_type, source_id_or_cve, protocol="tcp"):
    import hashlib
    proto = (protocol or "tcp").lower().strip()
    raw_str = f"{ip_address}:{proto}:{port}:{service or ''}:{source_type}:{source_id_or_cve or ''}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


# Handle the inconclusive rule fingerprints operation.
def _inconclusive_rule_fingerprints(asset_id, ip, port, protocol, rule_id):
    existing_findings = SecurityFinding.query.filter(
        SecurityFinding.asset_id == asset_id,
        SecurityFinding.ip_address == ip,
        SecurityFinding.port == port,
        SecurityFinding.protocol == protocol,
        SecurityFinding.source_type == "rule",
        SecurityFinding.source_rule_id == rule_id,
        SecurityFinding.status.in_(["open", "needs_review"]),
    ).all()
    return {
        finding.fingerprint
        for finding in existing_findings
        if finding.fingerprint
    }

# Handle the evaluate rules for host operation.
def evaluate_rules_for_host(host, asset, user_id, prev_ports=None, scan_id=None):
    """
    Evaluates active security rules against a scanned host's details.
    Creates or updates SecurityFinding records, auto-reopening them if needed.
    """
    ip = host.get("address")
    mac = host.get("mac_address", "").strip().lower() if host.get("mac_address") else ""
    ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
    preserved_fingerprints = set()
    
    # Load all active security rules for the user
    rules = SecurityRule.query.filter_by(user_id=user_id, enabled=True).all()
    
    # Iterate over rules and bind each item to rule.
    for rule in rules:
        # 1. Check exception list (IP or MAC)
        exceptions = [x.strip().lower() for x in rule.exception_list.split(",") if x.strip()] if rule.exception_list else []
        # Handle the branch where ip.lower() in exceptions or mac in exceptions evaluates to true.
        if ip.lower() in exceptions or mac in exceptions:
            continue
            
        # 2. Check scope
        if rule.scope and rule.scope != "*":
            # Handle the branch where not is_ip_in_subnet(ip, rule.scope) evaluates to true.
            if not is_ip_in_subnet(ip, rule.scope):
                continue
                
        # 3. Check asset criticality condition
        criticalities = [c.strip().lower() for c in rule.asset_criticality_condition.split(",") if c.strip()] if rule.asset_criticality_condition else []
        # Handle the branch where '*' not in criticalities and asset.criticality.lower() not in criticalities evaluates to true.
        if "*" not in criticalities and asset.criticality.lower() not in criticalities:
            continue
            
        # 4. Check rule conditions
        matched = False
        evidence = ""
        matched_port = None
        matched_service = None
        matched_version = None
        
        conditions = [c.strip().lower() for c in rule.port_service_condition.split(",") if c.strip()] if rule.port_service_condition else []
        
        # Check "new_port" condition — detect ALL new ports, not just the first
        if "new_port" in conditions:
            # Handle the branch where prev_ports is not None evaluates to true.
            if prev_ports is not None:
                legacy_prev_ports = {p for p in prev_ports if isinstance(p, int)}
                tuple_prev_ports = {p for p in prev_ports if isinstance(p, tuple)}
                
                # Iterate over ports and bind each item to pinfo.
                for pinfo in ports:
                    cp_num = int(pinfo.get("port") or 0)
                    cp_proto = (pinfo.get("protocol") or "tcp").lower()
                    
                    is_new = False
                    # Handle the branch where (cp_proto, cp_num) not in tuple_prev_ports evaluates to true.
                    if (cp_proto, cp_num) not in tuple_prev_ports:
                        # Handle the branch where not tuple_prev_ports and cp_num not in legacy_prev_ports evaluates to true.
                        if not tuple_prev_ports and cp_num not in legacy_prev_ports:
                            is_new = True
                        # Handle the branch where tuple_prev_ports evaluates to true.
                        elif tuple_prev_ports:
                            is_new = True
                            
                    # Handle the branch where is_new evaluates to true.
                    if is_new:
                        new_service = pinfo.get("service")
                        new_version = pinfo.get("version_display") or pinfo.get("version")
                        new_evidence = f"New port {cp_num}/{cp_proto} was detected. It was not open in previous scans."
                        new_fp = calculate_finding_fingerprint(ip, cp_num, new_service, "rule", rule.id, protocol=cp_proto)
                        existing_new = SecurityFinding.query.filter_by(asset_id=asset.id, fingerprint=new_fp).first()
                        # Handle the branch where not existing_new evaluates to true.
                        if not existing_new:
                            existing_new = SecurityFinding.query.filter_by(
                                asset_id=asset.id, ip_address=ip, port=cp_num,
                                protocol=cp_proto, source_type="rule", source_rule_id=rule.id
                            ).first()
                        # Handle the branch where existing_new evaluates to true.
                        if existing_new:
                            existing_new.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
                            existing_new.evidence = new_evidence
                            existing_new.fingerprint = new_fp
                            existing_new.scan_id = scan_id
                            # Handle the branch where existing_new.status in {'resolved', 'not_observed'} evaluates to true.
                            if existing_new.status in {"resolved", "not_observed"}:
                                existing_new.status = "open"
                        # Handle the fallback branch when the preceding condition does not match.
                        else:
                            db.session.add(SecurityFinding(
                                asset_id=asset.id, ip_address=ip, port=cp_num, protocol=cp_proto,
                                service=new_service or "unknown", version=new_version,
                                severity=rule.severity, evidence=new_evidence, status="open",
                                remediation_note=rule.remediation_text,
                                first_seen=datetime.now(timezone.utc).replace(tzinfo=None),
                                last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
                                source_type="rule", source_rule_id=rule.id,
                                scan_id=scan_id, fingerprint=new_fp
                            ))
                db.session.commit()
            continue  # new_port rule handled above; skip the regular matched block

        # Handle the branch where not matched evaluates to true.
        if not matched:
            matched_protocol = "tcp"
            # Iterate over ports and bind each item to pinfo.
            for pinfo in ports:
                p_num = int(pinfo.get("port") or 0)
                service = (pinfo.get("service") or "").lower()
                version = pinfo.get("version")
                
                # Check port/service matching conditions
                for cond in conditions:
                    # Handle the branch where cond.startswith('port:') evaluates to true.
                    if cond.startswith("port:"):
                        # Run this block with structured exception handling.
                        try:
                            cond_port = int(cond.split(":")[1])
                        # Handle an exception raised by the preceding protected block.
                        except (ValueError, IndexError):
                            continue
                        # Handle the branch where p_num == cond_port evaluates to true.
                        if p_num == cond_port:
                            matched = True
                            matched_port = p_num
                            matched_service = service
                            matched_version = version
                            matched_protocol = (pinfo.get("protocol") or "tcp").lower()
                            evidence = f"Port condition matched: Port {p_num} is open."
                    # Handle the branch where cond.startswith('service:') evaluates to true.
                    elif cond.startswith("service:"):
                        cond_svc = cond.split(":")[1]
                        # Handle the branch where cond_svc == 'unknown' evaluates to true.
                        if cond_svc == "unknown":
                            # Handle the branch where service in ['unknown', 'disabled', '-', ''] or 'unknown' in service evaluates to true.
                            if service in ["unknown", "disabled", "-", ""] or "unknown" in service:
                                matched = True
                                matched_port = p_num
                                matched_service = service
                                matched_version = version
                                matched_protocol = (pinfo.get("protocol") or "tcp").lower()
                                evidence = f"Service condition matched: Unrecognized service on port {p_num}."
                        # Handle the branch where cond_svc in service evaluates to true.
                        elif cond_svc in service:
                            matched = True
                            matched_port = p_num
                            matched_service = service
                            matched_version = version
                            matched_protocol = (pinfo.get("protocol") or "tcp").lower()
                            evidence = f"Service condition matched: Service '{service}' is open on port {p_num}."

                # Special case: Redis anonymous auth check
                if matched and rule.name == "Redis Unauthenticated Access":
                    # Check if a credential audit finding was already created for this host and port to prevent double risk score calculation
                    existing_cred_finding = SecurityFinding.query.filter_by(
                        asset_id=asset.id,
                        ip_address=ip,
                        port=p_num,
                        protocol=matched_protocol,
                        source_type="credential_audit",
                        status="open"
                    ).first()
                    # Handle the branch where existing_cred_finding evaluates to true.
                    if existing_cred_finding:
                        matched = False
                        continue

                    audit_res = pinfo.get("credential_audit")
                    audit_status = audit_res.get("status") if audit_res else None
                    # Handle the branch where audit_status == 'vulnerable' evaluates to true.
                    if audit_status == "vulnerable":
                        evidence = (
                            f"Redis authentication weakness confirmed on port {p_num}: "
                            f"{audit_res.get('message')}"
                        )
                    # Handle the branch where audit_status == 'safe' evaluates to true.
                    elif audit_status == "safe":
                        matched = False
                        continue
                    # Handle the fallback branch when the preceding condition does not match.
                    else:
                        preserved_fingerprints.update(
                            _inconclusive_rule_fingerprints(
                                asset.id, ip, p_num, matched_protocol, rule.id
                            )
                        )
                        # Missing/skipped audits are inconclusive, so preserve an
                        # active finding without creating a new one.
                        matched = False
                        continue
                
                # Special case: TLS certificate check
                if matched and rule.name == "Expiring TLS Certificate":
                    # Call get_ssl_expiry_days
                    days_left = get_ssl_expiry_days(ip, p_num)
                    # Handle the branch where days_left is not None and days_left <= 30 evaluates to true.
                    if days_left is not None and days_left <= 30:
                        evidence = f"TLS Certificate on port {p_num} is expiring in {days_left} days."
                    # Handle the branch where days_left is None evaluates to true.
                    elif days_left is None:
                        # Evaluation was inconclusive. Preserve an existing finding
                        # by recording it as observed in this scan; reconciliation
                        # must not interpret an external-service failure as safety.
                        preserved_fingerprints.update(
                            _inconclusive_rule_fingerprints(
                                asset.id, ip, p_num, matched_protocol, rule.id
                            )
                        )
                        matched = False
                    # Handle the fallback branch when the preceding condition does not match.
                    else:
                        matched = False  # Certificate was evaluated and is not expiring

                # Handle the branch where matched evaluates to true.
                if matched:
                    break

        # Handle the branch where matched evaluates to true.
        if matched:
            # Create or update SecurityFinding record
            fp = calculate_finding_fingerprint(ip, matched_port or 0, matched_service, "rule", rule.id, protocol=matched_protocol)
            
            existing_finding = SecurityFinding.query.filter_by(
                asset_id=asset.id,
                fingerprint=fp
            ).first()
            
            # Handle the branch where not existing_finding evaluates to true.
            if not existing_finding:
                existing_finding = SecurityFinding.query.filter_by(
                    asset_id=asset.id,
                    ip_address=ip,
                    port=matched_port or 0,
                    protocol=matched_protocol,
                    service=matched_service or "unknown",
                    source_type="rule",
                    source_rule_id=rule.id
                ).first()
            
            # Handle the branch where existing_finding evaluates to true.
            if existing_finding:
                existing_finding.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
                existing_finding.evidence = evidence
                existing_finding.version = matched_version
                existing_finding.fingerprint = fp
                existing_finding.scan_id = scan_id
                
                reopen = False
                # Handle the branch where existing_finding.status in {'resolved', 'not_observed'} evaluates to true.
                if existing_finding.status in {"resolved", "not_observed"}:
                    reopen = True
                # Handle the branch where existing_finding.status == 'accepted_risk' evaluates to true.
                elif existing_finding.status == "accepted_risk":
                    # Handle the branch where existing_finding.acceptance_expiry and datetime.now(timezone.utc).replace(tzinfo=None) > existing_finding.a... evaluates to true.
                    if existing_finding.acceptance_expiry and datetime.now(timezone.utc).replace(tzinfo=None) > existing_finding.acceptance_expiry:
                        reopen = True
                
                # Handle the branch where reopen evaluates to true.
                if reopen:
                    existing_finding.status = "open"
            # Handle the fallback branch when the preceding condition does not match.
            else:
                new_finding = SecurityFinding(
                    asset_id=asset.id,
                    ip_address=ip,
                    port=matched_port or 0,
                    protocol=matched_protocol,
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

    return preserved_fingerprints

# Handle the evaluate cve findings operation.
def evaluate_cve_findings(asset, ip_address, port_info, cve_list, scan_id=None):
    """
    Saves external CVE scan results into the SecurityFinding table.
    """
    p_num = int(port_info.get("port") or 0)
    protocol = (port_info.get("protocol") or "tcp").lower()
    service = port_info.get("service") or "unknown"
    version = port_info.get("version_display") or port_info.get("version") or ""
    
    # Iterate over cve_list and bind each item to cve.
    for cve in cve_list:
        cve_id = cve.get("id")
        cvss = cve.get("cvss")
        summary = cve.get("summary")
        is_definite = cve.get("is_definite_match", False)
        
        status = "open" if is_definite else "needs_review"
        
        # Map CVSS to severity
        if cvss is None:
            severity = "Medium"
        # Handle the branch where cvss >= 9.0 evaluates to true.
        elif cvss >= 9.0:
            severity = "Critical"
        # Handle the branch where cvss >= 7.0 evaluates to true.
        elif cvss >= 7.0:
            severity = "High"
        # Handle the branch where cvss >= 4.0 evaluates to true.
        elif cvss >= 4.0:
            severity = "Medium"
        # Handle the fallback branch when the preceding condition does not match.
        else:
            severity = "Low"

        fp = calculate_finding_fingerprint(ip_address, p_num, service, "cve", cve_id, protocol=protocol)

        existing_finding = SecurityFinding.query.filter_by(
            asset_id=asset.id,
            fingerprint=fp
        ).first()

        # Handle the branch where not existing_finding evaluates to true.
        if not existing_finding:
            existing_finding = SecurityFinding.query.filter_by(
                asset_id=asset.id,
                ip_address=ip_address,
                port=p_num,
                protocol=protocol,
                cve=cve_id
            ).first()

        # Handle the branch where existing_finding evaluates to true.
        if existing_finding:
            existing_finding.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
            existing_finding.fingerprint = fp
            existing_finding.scan_id = scan_id
            
            reopen = False
            # Handle the branch where existing_finding.status in {'resolved', 'not_observed'} evaluates to true.
            if existing_finding.status in {"resolved", "not_observed"}:
                reopen = True
            # Handle the branch where existing_finding.status == 'accepted_risk' evaluates to true.
            elif existing_finding.status == "accepted_risk":
                # Handle the branch where existing_finding.acceptance_expiry and datetime.now(timezone.utc).replace(tzinfo=None) > existing_finding.a... evaluates to true.
                if existing_finding.acceptance_expiry and datetime.now(timezone.utc).replace(tzinfo=None) > existing_finding.acceptance_expiry:
                    reopen = True
            
            # Handle the branch where reopen evaluates to true.
            if reopen:
                existing_finding.status = status
        # Handle the fallback branch when the preceding condition does not match.
        else:
            new_finding = SecurityFinding(
                asset_id=asset.id,
                ip_address=ip_address,
                port=p_num,
                protocol=protocol,
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

# Validate rule conditions.
def validate_rule_conditions(port_service_condition, scope, severity, criticality_condition):
    """
    Validates a security rule's fields before saving.
    Returns (True, None) on success or (False, error_message) on failure.
    """
    import ipaddress as _ip
    valid_severities = ["Low", "Medium", "High", "Critical"]
    # Handle the branch where severity not in valid_severities evaluates to true.
    if severity not in valid_severities:
        return False, f"Severity must be one of: {', '.join(valid_severities)}."

    # Handle the branch where scope and scope != '*' evaluates to true.
    if scope and scope != "*":
        # Run this block with structured exception handling.
        try:
            _ip.ip_network(scope, strict=False)
        # Handle an exception raised by the preceding protected block.
        except ValueError:
            return False, f"Scope '{scope}' is not a valid CIDR range or '*'."

    valid_criticalities = {"*", "low", "medium", "high", "critical"}
    # Handle the branch where criticality_condition evaluates to true.
    if criticality_condition:
        parts = [c.strip().lower() for c in criticality_condition.split(",") if c.strip()]
        invalid = [p for p in parts if p not in valid_criticalities]
        # Handle the branch where invalid evaluates to true.
        if invalid:
            return False, f"Invalid criticality values: {', '.join(invalid)}. Use Low, Medium, High, Critical, or *."

    # Handle the branch where not port_service_condition or not port_service_condition.strip() evaluates to true.
    if not port_service_condition or not port_service_condition.strip():
        return False, "Port/service condition cannot be empty."

    allowed_special = {"new_port"}
    tokens = [t.strip().lower() for t in port_service_condition.split(",") if t.strip()]
    # Iterate over tokens and bind each item to token.
    for token in tokens:
        # Handle the branch where token in allowed_special evaluates to true.
        if token in allowed_special:
            continue
        # Handle the branch where token.startswith('port:') evaluates to true.
        if token.startswith("port:"):
            # Run this block with structured exception handling.
            try:
                port_num = int(token.split(":")[1])
                # Handle the branch where not 1 <= port_num <= 65535 evaluates to true.
                if not (1 <= port_num <= 65535):
                    return False, f"Port number {port_num} out of valid range (1–65535)."
            # Handle an exception raised by the preceding protected block.
            except (ValueError, IndexError):
                return False, f"Invalid port condition '{token}'. Use format port:NUMBER (e.g. port:22)."
        # Handle the branch where token.startswith('service:') evaluates to true.
        elif token.startswith("service:"):
            svc = token.split(":", 1)[1].strip()
            # Handle the branch where not svc evaluates to true.
            if not svc:
                return False, "Service condition requires a non-empty service name (e.g. service:ssh)."
        # Handle the fallback branch when the preceding condition does not match.
        else:
            return False, f"Unknown condition token '{token}'. Valid tokens: new_port, port:N, service:name."

    return True, None


# Handle the reconcile findings for scan operation.
def reconcile_findings_for_scan(asset, host_online, observed_fingerprints, scan_id, 
                                scan_type, requested_ports, audit_credentials=False, 
                                credential_ids=None, current_open_ports=None,
                                cve_failed_ports=None, audited_endpoints=None,
                                scanned_endpoints=None, endpoint_states=None,
                                current_ports_info=None,
                                confirmed_unaffected_cves=None):
    """
    After a scan, marks findings that were not observed in this scan as 'not_observed'.
    Only does this if the host was seen online (status='up') during the scan.
    """
    # Handle the branch where not host_online evaluates to true.
    if not host_online:
        return

    # Handle the branch where current_open_ports is None evaluates to true.
    if current_open_ports is None:
        current_open_ports = []
        
    # Handle the branch where cve_failed_ports is None evaluates to true.
    if cve_failed_ports is None:
        cve_failed_ports = set()

    # Handle the branch where confirmed_unaffected_cves is None evaluates to true.
    if confirmed_unaffected_cves is None:
        confirmed_unaffected_cves = {}
        
    # Handle the branch where audited_endpoints is None evaluates to true.
    if audited_endpoints is None:
        audited_endpoints = {}

    # Handle the branch where endpoint_states is None evaluates to true.
    if endpoint_states is None:
        endpoint_states = {}
        # Handle the branch where current_open_ports evaluates to true.
        if current_open_ports:
            # Iterate over current_open_ports and bind each item to item.
            for item in current_open_ports:
                # Handle the branch where isinstance(item, tuple) evaluates to true.
                if isinstance(item, tuple):
                    endpoint_states[(item[0].lower(), int(item[1]))] = "open"
                # Handle the fallback branch when the preceding condition does not match.
                else:
                    endpoint_states[("tcp", int(item))] = "open"

    # Build set of open endpoints: (protocol, port)
    # If the caller passed a set/list of tuples, use it. Otherwise construct assuming 'tcp'
    current_open_endpoints = set()
    # Iterate over current_open_ports and bind each item to item.
    for item in current_open_ports:
        # Handle the branch where isinstance(item, tuple) evaluates to true.
        if isinstance(item, tuple):
            current_open_endpoints.add((item[0].lower(), int(item[1])))
        # Handle the fallback branch when the preceding condition does not match.
        else:
            current_open_endpoints.add(("tcp", int(item)))

    # Parse scanned_endpoints into a set of (protocol, port)
    scanned_endpoints_set = set()
    # Handle the branch where scanned_endpoints evaluates to true.
    if scanned_endpoints:
        # Iterate over scanned_endpoints and bind each item to (proto, p).
        for proto, p in scanned_endpoints:
            scanned_endpoints_set.add((proto.lower(), int(p)))

    # Helper to check if a specific endpoint was scanned
    def is_endpoint_scanned(protocol, port):
        # Handle the branch where scan_type == 'ping_sweep' evaluates to true.
        if scan_type == "ping_sweep":
            return False

        proto_lower = (protocol or "tcp").lower()
        
        # If we have actual scanned endpoints from XML scaninfo, use it
        if scanned_endpoints_set:
            return (proto_lower, port) in scanned_endpoints_set

        # Fallback to estimation based on scan type and requested_ports
        if requested_ports and requested_ports.strip():
            tokens = [t.strip().lower() for t in requested_ports.split(",") if t.strip()]
            # Iterate over tokens and bind each item to token.
            for token in tokens:
                token_proto = None
                # Handle the branch where token.startswith('t:') evaluates to true.
                if token.startswith("t:"):
                    token_proto = "tcp"
                    token = token[2:]
                # Handle the branch where token.startswith('u:') evaluates to true.
                elif token.startswith("u:"):
                    token_proto = "udp"
                    token = token[2:]
                
                # If token has a specific protocol, verify it matches
                if token_proto and token_proto != proto_lower:
                    continue
                    
                # Handle the branch where '-' in token evaluates to true.
                if "-" in token:
                    # Run this block with structured exception handling.
                    try:
                        start, end = token.split("-")
                        # Handle the branch where int(start) <= port <= int(end) evaluates to true.
                        if int(start) <= port <= int(end):
                            return True
                    # Handle an exception raised by the preceding protected block.
                    except ValueError:
                        continue
                # Handle the fallback branch when the preceding condition does not match.
                else:
                    # Run this block with structured exception handling.
                    try:
                        # Handle the branch where int(token) == port evaluates to true.
                        if int(token) == port:
                            return True
                    # Handle an exception raised by the preceding protected block.
                    except ValueError:
                        continue
            return False
        # Handle the fallback branch when the preceding condition does not match.
        else:
            # Default Nmap scan behavior
            NMAP_TOP_100 = {
                7, 9, 13, 21, 22, 23, 25, 37, 53, 79, 80, 81, 88, 110, 111, 113, 119, 123, 
                135, 139, 143, 179, 199, 389, 443, 444, 445, 465, 513, 514, 515, 540, 554, 
                587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 
                1433, 1720, 1723, 1755, 1900, 2000, 2049, 2121, 2717, 3000, 3128, 3306, 
                3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 
                5666, 5800, 5900, 6000, 6001, 6667, 8000, 8008, 8080, 8081, 8443, 8888, 
                9100, 9999, 32768, 49152, 49153, 49154, 49155, 49156, 49157
            }
            # Handle the branch where scan_type in ['fast', 'quick'] evaluates to true.
            if scan_type in ["fast", "quick"]:
                return proto_lower == "tcp" and port in NMAP_TOP_100
            # Handle the branch where scan_type == 'udp' evaluates to true.
            elif scan_type == "udp":
                common_udp = {
                    53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 
                    520, 631, 1434, 1900, 4500, 5353, 5355
                }
                return proto_lower == "udp" and (port in common_udp or port < 1024)
            # Handle the fallback branch when the preceding condition does not match.
            else:
                # Default TCP scan
                if proto_lower != "tcp":
                    return False
                common_high_tcp = {
                    1433, 1521, 2049, 3000, 3128, 3306, 3389, 4899, 5000, 5432, 
                    5666, 5900, 6379, 8000, 8080, 8081, 8443, 8888, 9000, 9092, 9100
                }
                return port < 1024 or port in common_high_tcp

    active_findings = SecurityFinding.query.filter(
        SecurityFinding.asset_id == asset.id,
        SecurityFinding.status.in_(["open", "needs_review"])
    ).all()

    # Iterate over active_findings and bind each item to finding.
    for finding in active_findings:
        finding_protocol = (finding.protocol or "tcp").lower()
        # Handle the branch where finding.fingerprint and finding.fingerprint not in observed_fingerprints evaluates to true.
        if finding.fingerprint and finding.fingerprint not in observed_fingerprints:
            # If the endpoint wasn't even scanned, we can't assume anything about it!
            if not is_endpoint_scanned(finding_protocol, finding.port):
                continue

            # Check if the port has an explicit scanned state
            state = endpoint_states.get((finding_protocol, finding.port))
            
            # If the state is inconclusive (filtered or open|filtered), we must not close it
            if state in ["filtered", "open|filtered", "closed|filtered", "unfiltered"]:
                continue

            # If the state is "open", we only close it if the condition for its source type is met
            if state == "open":
                # Port is still open, check based on source type
                if finding.source_type == "cve":
                    # Only reconcile if version detection ran in this scan and CVE search succeeded
                    if scan_type in ["service_version", "detailed", "aggressive", "vuln"]:
                        endpoint = (finding_protocol, finding.port)
                        # Handle the branch where endpoint not in cve_failed_ports and finding.port not in cve_failed_ports evaluates to true.
                        if endpoint not in cve_failed_ports and finding.port not in cve_failed_ports:
                            unaffected = {
                                cve_id.upper()
                                for cve_id in confirmed_unaffected_cves.get(endpoint, set())
                            }
                            # Handle the branch where finding.cve and finding.cve.upper() in unaffected evaluates to true.
                            if finding.cve and finding.cve.upper() in unaffected:
                                finding.status = "not_observed"
                # Handle the branch where finding.source_type == 'credential_audit' evaluates to true.
                elif finding.source_type == "credential_audit":
                    # Only reconcile if the audit completed successfully and marked the port as "safe"
                    audit_status = audited_endpoints.get((finding_protocol, finding.port))
                    # Handle the branch where audit_status == 'safe' evaluates to true.
                    if audit_status == "safe":
                        finding.status = "not_observed"
                # Handle the fallback branch when the preceding condition does not match.
                else:
                    # Other types (rules, etc.) on open ports can be reconciled because rule matching ran
                    finding.status = "not_observed"
            # Handle the branch where state == 'closed' evaluates to true.
            elif state == "closed":
                # If state is explicitly "closed"
                finding.status = "not_observed"
            # Handle the fallback branch when the preceding condition does not match.
            else:
                # If state is None (e.g., port fell under extraports and is not explicitly open/closed in ports list),
                # do NOT change the status to not_observed.
                continue

    db.session.commit()


# Handle the calculate network risk score operation.
def calculate_network_risk_score(user_id=None):
    """Compatibility wrapper for the central risk service."""
    from services.risk_service import calculate_network_risk_score as calculate

    return calculate(user_id)
