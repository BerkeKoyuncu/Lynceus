import os
import copy
import json
import socket
import time
import urllib.request
import urllib.error
import smtplib
import threading
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import current_app
from sqlalchemy.orm import sessionmaker

from models import db, User, ScanResult, ScanSchedule, SystemSetting, Asset, ScanCredential, SecurityFinding, SecurityAnomaly
from scanner import (
    ScanOwnershipLost,
    allow_scan_process_start,
    end_scan_process_attempt,
    run_nmap_scan,
)
from services.anomaly_service import evaluate_host_anomalies, record_observation
from services.rule_service import evaluate_rules_for_host, evaluate_cve_findings, seed_default_rules, reconcile_findings_for_scan
from services.email_service import send_notification_email_async

# Mapping for common services to NVD vendors/products
VENDOR_PRODUCT_MAP = {
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "dropbear": ("matt_johnston", "dropbear"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "vsftpd project": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd_project", "proftpd"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "samba": ("samba", "samba"),
    "cups": ("openprinting", "cups"),
    "microsoft iis": ("microsoft", "iis"),
    "iis": ("microsoft", "iis"),
    "tomcat": ("apache", "tomcat"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "bind": ("isc", "bind"),
    "werkzeug": ("pallets", "werkzeug"),
    "werkzeug httpd": ("pallets", "werkzeug"),
    "vmware-auth": ("vmware", "workstation")
}

CVE_CACHE = {}
CVE_CACHE_TTL_SECONDS = 300


def _cache_time():
    return time.monotonic()

def parse_version(v_str):
    import re
    # Extract digit sequences
    nums = re.findall(r'\d+', v_str)
    return tuple(int(x) for x in nums) if nums else ()


def _parse_comparable_version(value):
    """Parse only the leading product version, excluding distro/banner suffixes."""
    import re

    text = (value or "").replace("\\", "")
    match = re.search(r"\d+(?:\.\d+)*(?:p\d+)?", text, re.IGNORECASE)
    if not match:
        return ()
    suffix = text[match.end():].lstrip()
    if re.match(r"^[-_.]?(?:alpha|beta|rc|pre|preview|dev|snapshot)\d*\b", suffix, re.IGNORECASE):
        return ()
    parsed = [int(part) for part in re.findall(r"\d+", match.group(0))]
    while len(parsed) > 1 and parsed[-1] == 0:
        parsed.pop()
    return tuple(parsed)


def _cpe_identity(criteria):
    parts = (criteria or "").split(":")
    if len(parts) > 5 and parts[:3] == ["cpe", "2.3", "a"]:
        return (
            "a",
            parts[3].replace("\\", "").lower(),
            parts[4].replace("\\", "").lower(),
        )
    if len(parts) > 4 and parts[0] == "cpe" and parts[1].startswith("/a"):
        return (
            "a",
            parts[2].replace("\\", "").lower(),
            parts[3].replace("\\", "").lower(),
        )
    return None


def _iter_cpe_matches(value):
    if isinstance(value, dict):
        if "criteria" in value:
            yield value
        for nested in value.values():
            yield from _iter_cpe_matches(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _iter_cpe_matches(nested)


def _has_unsupported_cpe_logic(value):
    if isinstance(value, dict):
        if value.get("negate") is True:
            return True
        operator = value.get("operator")
        if operator is not None and str(operator).upper() != "OR":
            return True
        return any(_has_unsupported_cpe_logic(nested) for nested in value.values())
    if isinstance(value, list):
        return any(_has_unsupported_cpe_logic(nested) for nested in value)
    return False


def _cpe_version_state(user_version, match_obj, api_vendor, api_product):
    """Return affected/unaffected/unknown for one product CPE match."""
    expected_identity = ("a", api_vendor.lower(), api_product.lower())
    if _cpe_identity(match_obj.get("criteria")) != expected_identity:
        return "unknown"
    if match_obj.get("vulnerable", True) is not True:
        return "unknown"

    user_parsed = _parse_comparable_version(user_version)
    if not user_parsed:
        return "unknown"

    parts = match_obj.get("criteria", "").split(":")
    cpe_version = parts[5] if len(parts) > 5 and parts[1] == "2.3" else None
    if parts and len(parts) > 4 and parts[1].startswith("/a"):
        cpe_version = parts[4]
    if cpe_version and cpe_version not in {"*", "-"}:
        cpe_parsed = _parse_comparable_version(cpe_version)
        if not cpe_parsed:
            return "unknown"
        return "affected" if user_parsed == cpe_parsed else "unaffected"

    boundaries = {
        "versionEndIncluding": lambda boundary: user_parsed <= boundary,
        "versionEndExcluding": lambda boundary: user_parsed < boundary,
        "versionStartIncluding": lambda boundary: user_parsed >= boundary,
        "versionStartExcluding": lambda boundary: user_parsed > boundary,
    }
    parsed_boundaries = {}
    for key in boundaries:
        if key in match_obj:
            parsed_boundaries[key] = _parse_comparable_version(match_obj[key])
            if not parsed_boundaries[key]:
                return "unknown"
    for key, boundary in parsed_boundaries.items():
        if not boundaries[key](boundary):
            return "unaffected"
    return "affected"

def is_version_affected(user_ver, match_obj, api_product):
    cpe_uri = match_obj.get("criteria", "")
    
    # Check if this criteria matches our product
    if api_product not in cpe_uri.lower():
        return False
        
    parts = cpe_uri.split(":")
    if len(parts) > 5:
        cpe_ver = parts[5]
        if cpe_ver != "*" and cpe_ver != "-":
            # Exact or substring comparison
            clean_user = user_ver.lower().replace("p", "").replace("v", "")
            clean_cpe = cpe_ver.lower().replace("p", "").replace("v", "")
            if clean_user not in clean_cpe and clean_cpe not in clean_user:
                return False
  
    user_parsed = parse_version(user_ver)
    if not user_parsed:
        # Cannot parse version — mark as needs_review, not confirmed
        return False
  
    # Check boundaries
    if "versionEndIncluding" in match_obj:
        end_parsed = parse_version(match_obj["versionEndIncluding"])
        if end_parsed and user_parsed > end_parsed:
            return False
            
    if "versionEndExcluding" in match_obj:
        end_parsed = parse_version(match_obj["versionEndExcluding"])
        if end_parsed and user_parsed >= end_parsed:
            return False
            
    if "versionStartIncluding" in match_obj:
        start_parsed = parse_version(match_obj["versionStartIncluding"])
        if start_parsed and user_parsed < start_parsed:
            return False
            
    if "versionStartExcluding" in match_obj:
        start_parsed = parse_version(match_obj["versionStartExcluding"])
        if start_parsed and user_parsed <= start_parsed:
            return False
            
    return True

def fetch_cves_for_query(product, version=None, cpe_list=None):
    """
    Queries the CIRCL CVE API for a service and version, using CPE list to extract accurate vendor/product fields if available.
    Returns: {"success": True/False, "cves": [...], "error": ...}
    """
    if not product or product == "-":
        return {"success": True, "cves": []}
        
    version_clean = version.strip() if version else ""
    product_clean = product.lower().strip()
    
    cache_key = (product_clean, version_clean, tuple(cpe_list) if cpe_list else ())
    if cache_key in CVE_CACHE:
        cached = CVE_CACHE[cache_key]
        if isinstance(cached, dict) and "result" in cached and "expires_at" in cached:
            if cached["expires_at"] > _cache_time():
                return copy.deepcopy(cached["result"])
            CVE_CACHE.pop(cache_key, None)
            cached = None
        if cached is None:
            pass
        elif isinstance(cached, dict):
            return copy.deepcopy(cached)
        else:
            return {"success": True, "cves": copy.deepcopy(cached)}

    cpe_vendor = None
    cpe_product = None
    cpe_version = None

    if cpe_list:
        for cpe_str in cpe_list:
            if not cpe_str:
                continue
            parts = cpe_str.split(":")
            if len(parts) >= 4:
                # 2.3 format: cpe:2.3:a:vendor:product:version:...
                if parts[0] == "cpe" and parts[1] == "2.3" and parts[2] == "a" and len(parts) >= 5:
                    cpe_vendor = parts[3]
                    cpe_product = parts[4]
                    cpe_version = parts[5] if len(parts) > 5 else None
                    break
                # 2.2 format: cpe:/a:vendor:product:version
                elif parts[0] == "cpe" and parts[1].startswith("/a") and len(parts) >= 4:
                    cpe_vendor = parts[2]
                    cpe_product = parts[3]
                    cpe_version = parts[4] if len(parts) > 4 else None
                    break

    # Prioritize CPE version if available and valid
    if cpe_version and cpe_version not in ["*", "-"]:
        target_version = cpe_version
    else:
        target_version = version_clean

    if cpe_vendor and cpe_product:
        vendor, api_product = cpe_vendor, cpe_product
    else:
        vendor, api_product = VENDOR_PRODUCT_MAP.get(product_clean, (product_clean, product_clean))

    request_succeeded = False
    all_items = []
    first_error = None
    
    # Try querying using the parsed/cpe vendor and product
    url = f"https://vulnerability.circl.lu/api/search/{vendor}/{api_product}"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Lynceus Vulnerability Scanner"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
        all_items = data.get("results", {}).get("nvd", []) + data.get("results", {}).get("cvelistv5", [])
        request_succeeded = True
    except Exception as e:
        first_error = str(e)

    # Fallback to string query parsing if CPE-based search failed or returned no items
    if (not request_succeeded or not all_items) and cpe_list:
        vendor, api_product = VENDOR_PRODUCT_MAP.get(product_clean, (product_clean, product_clean))
        url = f"https://vulnerability.circl.lu/api/search/{vendor}/{api_product}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Lynceus Vulnerability Scanner"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
            all_items = data.get("results", {}).get("nvd", []) + data.get("results", {}).get("cvelistv5", [])
            request_succeeded = True
        except Exception as e:
            if not first_error:
                first_error = str(e)

    if not request_succeeded:
        return {"success": False, "cves": [], "error": first_error or "API query failed"}

    try:
        seen_cves = set()
        filtered_cves = []
        confirmed_unaffected_cves = set()
        inconclusive_cves = set()
        product_confirmed = False

        for item in all_items:
            if not isinstance(item, list) or len(item) < 2:
                continue

            cve_id = item[0].upper()
            if cve_id in seen_cves:
                continue
            cve_record = item[1]

            descriptions = cve_record.get("containers", {}).get("cna", {}).get("descriptions", [])
            summary = "No description available."
            for desc in descriptions:
                if desc.get("lang") == "en":
                    summary = desc.get("value")
                    break

            cvss_score = None
            metrics = cve_record.get("containers", {}).get("cna", {}).get("metrics", [])
            for metric in metrics:
                for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                    if key in metric:
                        score = metric[key].get("baseScore")
                        if score is not None:
                            cvss_score = score
                            break
                if cvss_score is not None:
                    break

            # Check if version is affected. Only explicit, parseable CPE range
            # evidence may be emitted as confirmed-unaffected.
            is_affected = True
            is_definite = False
            if target_version:
                is_affected = False
                cpe_nodes = cve_record.get("containers", {}).get("cna", {}).get("cpeApplicability", [])
                product_matches = [
                    match for match in _iter_cpe_matches(cpe_nodes)
                    if _cpe_identity(match.get("criteria"))
                    == ("a", vendor.lower(), api_product.lower())
                ]

                if product_matches:
                    product_confirmed = True
                    if _has_unsupported_cpe_logic(cpe_nodes):
                        states = ["unknown"]
                    else:
                        states = [
                            _cpe_version_state(
                                target_version, match, vendor, api_product
                            )
                            for match in product_matches
                        ]
                    if "affected" in states:
                        is_affected = True
                        is_definite = True
                    elif states and all(state == "unaffected" for state in states):
                        if cve_id not in inconclusive_cves:
                            confirmed_unaffected_cves.add(cve_id)
                    else:
                        inconclusive_cves.add(cve_id)
                        confirmed_unaffected_cves.discard(cve_id)
                else:
                    # CPE not found, check description as fallback
                    if api_product in summary.lower():
                        is_affected = True
                        is_definite = False
                    else:
                        is_affected = False
                    inconclusive_cves.add(cve_id)
                    confirmed_unaffected_cves.discard(cve_id)
            else:
                is_affected = True
                is_definite = False

            if is_affected:
                confirmed_unaffected_cves.discard(cve_id)
                seen_cves.add(cve_id)
                filtered_cves.append({
                    "id": cve_id,
                    "summary": summary,
                    "cvss": cvss_score,
                    "is_definite_match": is_definite
                })

        filtered_cves.sort(key=lambda x: x["cvss"] if x["cvss"] is not None else -1, reverse=True)
        filtered_cves = filtered_cves[:15]
        result = {
            "success": True,
            "lookup_success": True,
            "product_confirmed": product_confirmed,
            "version_confirmed": product_confirmed and bool(_parse_comparable_version(target_version)),
            "cves": filtered_cves,
            "affected_cves": [cve["id"] for cve in filtered_cves],
            "confirmed_unaffected_cves": sorted(confirmed_unaffected_cves),
        }
        CVE_CACHE[cache_key] = {
            "expires_at": _cache_time() + CVE_CACHE_TTL_SECONDS,
            "result": copy.deepcopy(result),
        }
        return copy.deepcopy(result)
    except Exception as e:
        return {"success": False, "cves": [], "error": str(e)}

def create_credential_audit_finding(asset, ip_address, port_info, audit_res, scan_id=None):
    """
    Creates or updates a SecurityFinding for a confirmed weak-credential vulnerability.
    source_type = 'credential_audit'
    """
    from services.rule_service import calculate_finding_fingerprint
    p_num = int(port_info.get("port") or 0)
    protocol = (port_info.get("protocol") or "tcp").lower()
    service = port_info.get("service") or "unknown"
    version = port_info.get("version_display") or port_info.get("version") or ""
    message = audit_res.get("message", "Weak or default credentials confirmed.")

    fp = calculate_finding_fingerprint(ip_address, p_num, service, "credential_audit", service, protocol=protocol)

    existing = SecurityFinding.query.filter_by(
        asset_id=asset.id, fingerprint=fp
    ).first()
    if not existing:
        existing = SecurityFinding.query.filter_by(
            asset_id=asset.id, ip_address=ip_address, port=p_num,
            protocol=protocol, source_type="credential_audit"
        ).first()

    if existing:
        existing.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
        existing.evidence = message
        existing.fingerprint = fp
        existing.scan_id = scan_id
        if existing.status in {"resolved", "not_observed"}:
            existing.status = "open"
    else:
        new_finding = SecurityFinding(
            asset_id=asset.id,
            ip_address=ip_address,
            port=p_num,
            protocol=protocol,
            service=service,
            version=version,
            severity="Critical",
            evidence=message,
            status="open",
            remediation_note="Change or disable default/weak credentials immediately. Restrict service access via firewall rules.",
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None),
            last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
            source_type="credential_audit",
            scan_id=scan_id,
            fingerprint=fp
        )
        db.session.add(new_finding)
    db.session.commit()

def _is_ftp_auth_rejection(error):
    import re

    message = str(error).strip().lower()
    reply_code = re.match(r"^(\d{3})\b", message)
    if reply_code and reply_code.group(1) != "530":
        return False
    policy_markers = (
        "tls",
        "ssl",
        "policy",
        "account disabled",
        "account expired",
        "not allowed",
    )
    if any(marker in message for marker in policy_markers):
        return False
    return any(
        phrase in message
        for phrase in (
            "login incorrect",
            "cannot log in",
            "not logged in",
            "authentication failed",
            "authentication failure",
            "invalid password",
            "invalid credentials",
        )
    )


def audit_ftp(ip, port=21, custom_credentials=None, use_defaults=True):
    credentials = []
    if custom_credentials:
        credentials.extend(custom_credentials)
    if use_defaults:
        credentials.extend([
            ("anonymous", "anonymous@domain.com"),
            ("admin", "admin"),
            ("root", "root"),
            ("user", "password")
        ])
    import ftplib
    rejected = 0
    for username, password in credentials:
        ftp = None
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=2)
            ftp.login(username, password)
            return {"status": "vulnerable", "message": f"Weak credentials confirmed for user '{username}'."}
        except ftplib.error_perm as error:
            if _is_ftp_auth_rejection(error):
                rejected += 1
            else:
                return {"status": "skipped", "message": f"FTP credential audit could not complete: {error}"}
        except (OSError, EOFError, ftplib.Error) as error:
            return {"status": "skipped", "message": f"FTP credential audit could not complete: {error}"}
        finally:
            if ftp is not None:
                try:
                    ftp.close()
                except OSError:
                    pass
    if credentials and rejected == len(credentials):
        return {"status": "safe", "message": "FTP rejected all tested credentials"}
    return {"status": "skipped", "message": "No FTP credentials were available to test"}

def _redis_command(*parts):
    encoded_parts = [str(part).encode("utf-8") for part in parts]
    chunks = [f"*{len(encoded_parts)}\r\n".encode()]
    for part in encoded_parts:
        chunks.append(f"${len(part)}\r\n".encode())
        chunks.append(part + b"\r\n")
    return b"".join(chunks)


def audit_redis(ip, port=6379, custom_passwords=None, use_defaults=True):
    passwords = []
    if custom_passwords:
        passwords.extend(custom_passwords)
    if use_defaults:
        passwords.extend(["", "admin", "password", "redis", "root"])
    rejected = 0
    for pwd in passwords:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            if pwd == "":
                s.sendall(b"PING\r\n")
                resp = s.recv(1024)
                if b"+PONG" in resp:
                    return {"status": "vulnerable", "message": "No password set (Unauthenticated access)."}
            else:
                s.sendall(_redis_command("AUTH", pwd))
                resp = s.recv(1024)
                if b"+OK" in resp:
                    return {"status": "vulnerable", "message": "A weak Redis password was successfully authenticated."}
            if resp.startswith((b"-NOAUTH", b"-WRONGPASS")) or b"invalid password" in resp.lower():
                rejected += 1
            else:
                return {"status": "skipped", "message": "Redis returned an unexpected authentication response"}
        except (OSError, socket.timeout) as error:
            return {"status": "skipped", "message": f"Redis credential audit could not complete: {error}"}
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    if passwords and rejected == len(passwords):
        return {"status": "safe", "message": "Redis rejected all tested passwords"}
    return {"status": "skipped", "message": "No Redis passwords were available to test"}

def audit_http_basic(ip, port=80, is_ssl=False, custom_credentials=None, use_defaults=True):
    import urllib.request
    import urllib.error
    import base64
    import re
    
    url = f"{'https' if is_ssl else 'http'}://{ip}:{port}/"
    try:
        req = urllib.request.Request(url, method="GET")
        response = urllib.request.urlopen(req, timeout=2)
        response.close()
        return {"status": "safe", "message": "No authentication required"}
    except urllib.error.HTTPError as e:
        try:
            if e.code != 401:
                return {"status": "skipped", "message": f"Returned status {e.code}"}
            authenticate_header = (e.headers or {}).get("WWW-Authenticate", "")
            if not re.search(r"(?:^|,)\s*basic(?:\s|$)", authenticate_header, re.I):
                return {
                    "status": "skipped",
                    "message": "The endpoint does not advertise HTTP Basic authentication.",
                }
        finally:
            e.close()
    except Exception as e:
        return {"status": "skipped", "message": f"Connection failed: {str(e)}"}
        
    credentials = []
    if custom_credentials:
        credentials.extend(custom_credentials)
    if use_defaults:
        credentials.extend([
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "1234"),
            ("admin", "12345"),
            ("admin", ""),
            ("root", "root"),
            ("root", "")
        ])
    
    rejected = 0
    for username, password in credentials:
        try:
            req = urllib.request.Request(url, method="GET")
            auth_str = f"{username}:{password}"
            auth_b64 = base64.b64encode(auth_str.encode()).decode()
            req.add_header("Authorization", f"Basic {auth_b64}")
            
            resp = urllib.request.urlopen(req, timeout=2)
            status_code = resp.code
            resp.close()
            if 200 <= status_code < 300:
                return {"status": "vulnerable", "message": f"Weak credentials confirmed for user '{username}'."}
            return {
                "status": "skipped",
                "message": f"Credential verification returned HTTP status {status_code}.",
            }
        except urllib.error.HTTPError as error:
            try:
                if error.code == 401:
                    rejected += 1
                    continue
                return {
                    "status": "skipped",
                    "message": f"Credential verification returned HTTP status {error.code}.",
                }
            finally:
                error.close()
        except Exception as error:
            return {
                "status": "skipped",
                "message": f"HTTP credential audit could not complete: {error}",
            }
    if credentials and rejected == len(credentials):
        return {"status": "safe", "message": "HTTP Basic rejected all tested credentials"}
    return {"status": "skipped", "message": "No HTTP Basic credentials were available to test"}

def detect_device_type(hostname, mac_vendor, ports_list):
    """
    Auto-detects the device type based on hostname, mac vendor, and open ports.
    """
    hostname_lower = (hostname or "").lower()
    vendor_lower = (mac_vendor or "").lower()
    
    open_ports = set()
    for p in ports_list:
        if isinstance(p, dict):
            if p.get("state") != "open":
                continue
            port_val = p.get("port")
        else:
            port_val = p
        try:
            if port_val:
                open_ports.add(int(port_val))
        except ValueError:
            pass

    if any(k in hostname_lower for k in ["firewall", "fortigate", "pfsense", "opnsense", "checkpoint", "asa", "sonicwall"]):
        return "Firewall"
    if "firewall" in vendor_lower:
        return "Firewall"
        
    is_voip = False
    if any(k in hostname_lower for k in ["phone", "voip", "sip", "yealink", "grandstream", "snom", "fanvil", "polycom", "avaya", "mitel", "poly"]):
        is_voip = True
    elif any(k in vendor_lower for k in ["yealink", "grandstream", "snom", "fanvil", "polycom", "avaya", "mitel", "gigaset", "poly"]):
        is_voip = True
    elif any(p in open_ports for p in [2000, 5060, 5061]):
        is_voip = True
    elif "alcatel" in vendor_lower or "alcatel" in hostname_lower:
        if not any(k in hostname_lower for k in ["switch", "sw-", "sw0", "router", "gateway", "gw-"]):
            is_voip = True
    elif "cisco" in vendor_lower or "cisco" in hostname_lower:
        if any(k in hostname_lower for k in ["phone", "voip", "ata", "spa"]):
            is_voip = True
        elif any(p in open_ports for p in [2000, 5060, 5061]):
            is_voip = True

    if is_voip:
        return "IP Phone"

    is_camera = False
    if any(k in hostname_lower for k in ["camera", "ipc", "cctv", "webcam", "dvr", "nvr"]):
        is_camera = True
    elif any(k in vendor_lower for k in ["hikvision", "dahua", "foscam", "reolink", "amcrest", "hanwha"]):
        is_camera = True
    elif "axis" in vendor_lower and "communications" in vendor_lower:
        is_camera = True
    elif 554 in open_ports:
        is_camera = True

    if is_camera:
        return "IP Camera"

    if any(k in vendor_lower for k in ["vmware", "qemu", "xen", "virtualbox", "proxmox"]):
        return "Virtual Machine"
    if any(k in hostname_lower for k in ["-vm", "vm-", "virtual-"]):
        return "Virtual Machine"
        
    if any(k in hostname_lower for k in ["router", "gateway", "rt-", "gw-", "ubnt", "mikrotik"]):
        return "Router"
    if any(k in vendor_lower for k in ["cisco", "juniper", "ubiquiti", "mikrotik", "linksys", "netgear", "tp-link", "asus", "zyxel"]):
        if 179 in open_ports or 520 in open_ports:
            return "Router"
        if any(k in hostname_lower for k in ["switch", "sw-", "sw0"]):
            return "Switch"
        return "Router"
        
    if any(k in hostname_lower for k in ["switch", "sw-", "catalyst", "procurve", "edge-sw"]):
        return "Switch"
    if "switch" in vendor_lower:
        return "Switch"
        
    if any(k in hostname_lower for k in ["printer", "print", "copier", "epson", "hp-", "canon", "lexmark", "xerox", "brother"]):
        return "Printer"
    if any(p in open_ports for p in [515, 631, 9100]):
        return "Printer"
    if any(k in vendor_lower for k in ["epson", "canon", "lexmark", "brother", "xerox", "konica", "ricoh", "kyocera", "okidata"]):
        return "Printer"
        
    if any(k in hostname_lower for k in ["android", "iphone", "ipad", "phone", "galaxy", "huawei", "xiaomi"]):
        return "Mobile"
    if any(k in vendor_lower for k in ["apple", "samsung", "huawei", "motorola", "htc", "xiaomi", "nokia", "oneplus"]):
        if not any(p in open_ports for p in [80, 443, 22, 3389, 445]):
            return "Mobile"

    if any(k in hostname_lower for k in ["iot", "smart", "camera", "dvr", "nvr", "tv", "chromecast", "raspberry"]):
        return "IoT"
    if any(p in open_ports for p in [1883, 8883]):
        return "IoT"
    if any(k in vendor_lower for k in ["synology", "qnap"]):
        return "IoT"
        
    server_ports = {3306, 5432, 1433, 1521, 389, 636, 110, 995, 143, 993, 25, 465, 587, 8080, 8443, 9000, 27017}
    if any(p in open_ports for p in server_ports):
        return "Server"
    if "server" in hostname_lower:
        return "Server"
        
    if any(k in hostname_lower for k in ["pc", "desktop", "laptop", "workstation", "client", "win10", "win11"]):
        return "Workstation"
    if any(p in open_ports for p in [139, 445, 3389]):
        if "server" in hostname_lower:
            return "Server"
        return "Workstation"
        
    if 22 in open_ports or 23 in open_ports:
        if any(k in vendor_lower for k in ["dell", "hp ", "hewlett", "supermicro", "vmware", "lenovo", "ibm", "fujitsu"]):
            return "Server"
        if "server" in hostname_lower:
            return "Server"
        return "Unknown"
        
    return "Unknown"

def format_local_datetime(dt):
    if not dt:
        return ""
    # Standard format: YYYY-MM-DD HH:MM:SS
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def check_and_send_scan_alert(scan_result):
    setting = SystemSetting.query.filter_by(user_id=scan_result.user_id).first()
    if not setting or not setting.smtp_server or not setting.smtp_sender or not setting.alert_recipient:
        return
        
    try:
        current_data = json.loads(scan_result.result_data) if scan_result.result_data else {}
    except Exception:
        return
        
    current_hosts = current_data.get("hosts", [])
    
    previous_scan = ScanResult.query.filter(
        ScanResult.user_id == scan_result.user_id,
        ScanResult.network_cidr == scan_result.network_cidr,
        ScanResult.status == "completed",
        ScanResult.id < scan_result.id
    ).order_by(ScanResult.id.desc()).first()
    
    new_ports_detected = False
    added_hosts_info = []
    added_ports_info = []
    
    previous_hosts = []
    if previous_scan and previous_scan.result_data:
        try:
            prev_data = json.loads(previous_scan.result_data)
            previous_hosts = prev_data.get("hosts", [])
        except Exception:
            pass
            
    map_prev = {h["address"]: h for h in previous_hosts}
    
    for host in current_hosts:
        ip = host.get("address")
        curr_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
        
        if ip not in map_prev:
            if curr_ports:
                added_hosts_info.append({
                    "address": ip,
                    "hostname": host.get("hostname", ""),
                    "ports": curr_ports
                })
                new_ports_detected = True
        else:
            prev_ports = {
                ((p.get("protocol") or "tcp").lower(), int(p.get("port") or 0)): p
                for p in map_prev[ip].get("ports", [])
                if p.get("state") == "open"
            }
            host_added_ports = []
            for p in curr_ports:
                p_num = int(p["port"])
                p_proto = (p.get("protocol") or "tcp").lower()
                if (p_proto, p_num) not in prev_ports:
                    host_added_ports.append(p)
                    new_ports_detected = True
            if host_added_ports:
                added_ports_info.append({
                    "address": ip,
                    "hostname": host.get("hostname", ""),
                    "ports": host_added_ports
                })

    if new_ports_detected:
        subject = f"[SECURITY ALERT] New Ports/Hosts Detected on {scan_result.network_cidr}"
        local_time_str = format_local_datetime(datetime.now(timezone.utc).replace(tzinfo=None))
        
        hosts_list_html = ""
        for h in added_hosts_info:
            ports_str = ", ".join(f"{p['port']}/{p['protocol']} ({p['service']})" for p in h["ports"])
            hosts_list_html += f"""
            <tr style="border-bottom: 1px solid #edf2f7;">
                <td style="padding: 10px; font-weight: bold; color: #c53030;">{h['address']}</td>
                <td style="padding: 10px;">{h['hostname'] or 'N/A'}</td>
                <td style="padding: 10px; font-weight: bold; color: #2b6cb0;">{ports_str}</td>
            </tr>
            """
            
        ports_list_html = ""
        for p in added_ports_info:
            ports_str = ", ".join(f"{x['port']}/{x['protocol']} ({x['service']})" for x in p["ports"])
            ports_list_html += f"""
            <tr style="border-bottom: 1px solid #edf2f7;">
                <td style="padding: 10px; font-weight: bold; color: #2d3748;">{p['address']}</td>
                <td style="padding: 10px;">{p['hostname'] or 'N/A'}</td>
                <td style="padding: 10px; font-weight: bold; color: #c53030;">{ports_str}</td>
            </tr>
            """
            
        body_html = f"""
        <div style="font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 0 auto; padding: 25px; border: 1px solid #e2e8f0; border-radius: 12px; background-color: #fff; color: #2d3748;">
            <div style="text-align: center; margin-bottom: 25px;">
                <h2 style="color: #2b6cb0; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">🔍 Lynceus Network Change Detected</h2>
                <p style="color: #718096; margin: 5px 0 0 0; font-size: 14px;">A dynamic security scan has detected new access points or services in your subnet!</p>
            </div>
        """
        
        if added_hosts_info:
            body_html += f"""
            <h3 style="color: #c53030; font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #fed7d7; padding-bottom: 5px; margin-bottom: 10px;">🆕 New Hosts Online ({len(added_hosts_info)})</h3>
            <table style="width: 100%; font-size: 13px; color: #4a5568; margin-bottom: 25px; border-collapse: collapse;">
                <thead>
                    <tr style="background: #fff5f5; border-bottom: 1px solid #fed7d7;">
                        <th style="padding: 10px; text-align: left; color: #9b2c2c;">IP Address</th>
                        <th style="padding: 10px; text-align: left; color: #9b2c2c;">Hostname</th>
                        <th style="padding: 10px; text-align: left; color: #9b2c2c;">Open Ports</th>
                    </tr>
                </thead>
                <tbody>
                    {hosts_list_html}
                </tbody>
            </table>
            """
            
        if added_ports_info:
            body_html += f"""
            <h3 style="color: #dd6b20; font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #fefeeb; padding-bottom: 5px; margin-bottom: 10px;">🔌 New Ports on Existing Hosts ({len(added_ports_info)})</h3>
            <table style="width: 100%; font-size: 13px; color: #4a5568; margin-bottom: 25px; border-collapse: collapse;">
                <thead>
                    <tr style="background: #fffaf0; border-bottom: 1px solid #feebc8;">
                        <th style="padding: 10px; text-align: left; color: #c05621;">IP Address</th>
                        <th style="padding: 10px; text-align: left; color: #c05621;">Hostname</th>
                        <th style="padding: 10px; text-align: left; color: #c05621;">New Open Ports</th>
                    </tr>
                </thead>
                <tbody>
                    {ports_list_html}
                </tbody>
            </table>
            """
            
        body_html += f"""
            <div style="background-color: #edf2f7; padding: 12px; border-radius: 6px; font-size: 12px; color: #4a5568; margin-top: 20px;">
                <strong>Scan Network:</strong> {scan_result.network_cidr}<br>
                <strong>Detection Time:</strong> {local_time_str}<br>
                <strong>Action:</strong> Check your asset inventory in the Lynceus portal to trust or block these targets.
            </div>
        </div>
        """
        
        setting_dict = {
            "smtp_server": setting.smtp_server,
            "smtp_port": setting.smtp_port,
            "smtp_username": setting.smtp_username,
            "smtp_password": setting.smtp_password,
            "smtp_sender": setting.smtp_sender,
            "alert_recipient": setting.alert_recipient
        }
        send_notification_email_async(setting_dict, subject, body_html)

def _scheduler_heartbeat_loop(app, scan_id, claim_token, stop_event):
    interval = app.config["SCHEDULER_HEARTBEAT_SECONDS"]
    while not stop_event.wait(interval):
        try:
            with app.app_context():
                updated = ScanResult.query.filter(
                    ScanResult.id == scan_id,
                    ScanResult.status == "running",
                    ScanResult.scheduler_dispatch_state == "started",
                    ScanResult.scheduler_claim_token == claim_token,
                ).update(
                    {ScanResult.scheduler_heartbeat_at: datetime.now(timezone.utc).replace(tzinfo=None)},
                    synchronize_session=False,
                )
                db.session.commit()
                if updated != 1:
                    return
        except Exception:
            # A transient DB lock should not kill the heartbeat permanently.
            try:
                db.session.rollback()
            except Exception:
                pass


def scheduler_claim_is_current(scan_id, claim_token):
    if not claim_token:
        return True
    with db.session.no_autoflush:
        return db.session.query(ScanResult.id).filter(
            ScanResult.id == scan_id,
            ScanResult.status == "running",
            ScanResult.scheduler_dispatch_state == "started",
            ScanResult.scheduler_claim_token == claim_token,
        ).first() is not None


_progress_checkpoint_times = {}
_progress_checkpoint_retry_after = {}
_progress_checkpoint_lock = threading.Lock()


def _independent_scheduler_claim_is_current(scan_id, claim_token):
    ownership_session = sessionmaker(bind=db.engine, expire_on_commit=False)()
    try:
        return ownership_session.query(ScanResult.id).filter(
            ScanResult.id == scan_id,
            ScanResult.status == "running",
            ScanResult.scheduler_dispatch_state == "started",
            ScanResult.scheduler_claim_token == claim_token,
        ).first() is not None
    except Exception:
        return False
    finally:
        ownership_session.close()


def scheduler_progress_checkpoint(scan_id, claim_token, force=False, phase=None):
    """Fence work and throttle progress writes outside the business session."""
    if not claim_token:
        return True
    if phase is not None:
        force = True

    key = (scan_id, claim_token)
    monotonic_now = time.monotonic()
    interval = current_app.config["SCHEDULER_PROGRESS_INTERVAL_SECONDS"]
    with _progress_checkpoint_lock:
        last_update = _progress_checkpoint_times.get(key)
        retry_after = _progress_checkpoint_retry_after.get(key)
    if retry_after is not None and monotonic_now < retry_after:
        return _independent_scheduler_claim_is_current(scan_id, claim_token)
    if not force and last_update is not None and monotonic_now - last_update < interval:
        return _independent_scheduler_claim_is_current(scan_id, claim_token)

    progress_session = sessionmaker(bind=db.engine, expire_on_commit=False)()
    try:
        progress_values = {
            ScanResult.scheduler_progress_at: datetime.now(timezone.utc).replace(
                tzinfo=None
            )
        }
        if phase is not None:
            progress_values[ScanResult.scheduler_execution_phase] = phase
        updated = progress_session.query(ScanResult).filter(
            ScanResult.id == scan_id,
            ScanResult.status == "running",
            ScanResult.scheduler_dispatch_state == "started",
            ScanResult.scheduler_claim_token == claim_token,
        ).update(progress_values, synchronize_session=False)
        progress_session.commit()
    except Exception:
        progress_session.rollback()
        # A transient progress-write lock must not commit or roll back the
        # business session. Back off before another host/port retries it.
        with _progress_checkpoint_lock:
            _progress_checkpoint_retry_after[key] = monotonic_now + min(interval, 5)
        return _independent_scheduler_claim_is_current(scan_id, claim_token)
    finally:
        progress_session.close()

    if updated != 1:
        return False
    with _progress_checkpoint_lock:
        _progress_checkpoint_times[key] = monotonic_now
        _progress_checkpoint_retry_after.pop(key, None)
    return True


def _clear_scheduler_progress_checkpoint(scan_id, claim_token):
    if not claim_token:
        return
    with _progress_checkpoint_lock:
        _progress_checkpoint_times.pop((scan_id, claim_token), None)
        _progress_checkpoint_retry_after.pop((scan_id, claim_token), None)


def _reconcile_scan_worker_exit(
    app, scan_id, claim_token, reconcile_termination_failed=True
):
    if not claim_token:
        return
    with app.app_context():
        owner_filter = (
            ScanResult.id == scan_id,
            ScanResult.scheduler_claim_token == claim_token,
            ScanResult.scheduler_worker_id == app.config["SCAN_WORKER_ID"],
            ScanResult.scheduler_process_id == os.getpid(),
        )
        cancelled = ScanResult.query.filter(
            *owner_filter,
            ScanResult.status == "cancellation_requested",
        ).update(
            {
                ScanResult.status: "cancelled",
                ScanResult.scheduler_dispatch_state: "cancelled",
                ScanResult.scheduler_execution_phase: "cancelled",
            },
            synchronize_session=False,
        )
        terminated = 0
        if reconcile_termination_failed:
            terminated = ScanResult.query.filter(
                *owner_filter,
                ScanResult.status == "termination_failed",
            ).update(
                {
                    ScanResult.status: "failed",
                    ScanResult.scheduler_dispatch_state: "failed",
                    ScanResult.scheduler_execution_phase: "terminated",
                },
                synchronize_session=False,
            )
        if cancelled or terminated:
            db.session.commit()
        else:
            db.session.rollback()


def execute_scan(app, scan_id, audit_credentials=False, scheduler_claim_token=None):
    heartbeat_stop = None
    attempt_registered = False
    transition_started = False
    try:
        if scheduler_claim_token:
            with app.app_context():
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                started = ScanResult.query.filter(
                    ScanResult.id == scan_id,
                    ScanResult.status == "pending",
                    ScanResult.scheduler_dispatch_state == "claimed",
                    ScanResult.scheduler_claim_token == scheduler_claim_token,
                ).update(
                    {
                        ScanResult.status: "running",
                        ScanResult.scheduler_dispatch_state: "started",
                        ScanResult.scheduler_started_at: now,
                        ScanResult.scheduler_heartbeat_at: now,
                        ScanResult.scheduler_progress_at: now,
                        ScanResult.scheduler_execution_phase: "starting",
                    },
                    synchronize_session=False,
                )
                if started != 1:
                    db.session.rollback()
                    return
                db.session.commit()
                transition_started = True

            if not allow_scan_process_start(scan_id, scheduler_claim_token):
                with app.app_context():
                    conflict_payload = json.dumps({
                        "command": "N/A",
                        "output": (
                            "A local process-token conflict prevented this "
                            "attempt from starting. Capacity remains reserved "
                            "until an administrator resolves the orphan."
                        ),
                        "hosts": [],
                    })
                    ScanResult.query.filter(
                        ScanResult.id == scan_id,
                        ScanResult.status == "running",
                        ScanResult.scheduler_claim_token == scheduler_claim_token,
                    ).update(
                        {
                            ScanResult.status: "termination_failed",
                            ScanResult.scheduler_dispatch_state: "orphaned",
                            ScanResult.scheduler_execution_phase: "token_conflict",
                            ScanResult.result_data: conflict_payload,
                        },
                        synchronize_session=False,
                    )
                    db.session.commit()
                    app.logger.critical(
                        "Process token conflict for scan %s; capacity remains reserved.",
                        scan_id,
                    )
                return
            attempt_registered = True

            with app.app_context():
                if not _independent_scheduler_claim_is_current(
                    scan_id, scheduler_claim_token
                ):
                    return

            heartbeat_stop = threading.Event()
            threading.Thread(
                target=_scheduler_heartbeat_loop,
                args=(app, scan_id, scheduler_claim_token, heartbeat_stop),
                daemon=True,
            ).start()

        _execute_scan_body(
            app,
            scan_id,
            audit_credentials,
            scheduler_claim_token=scheduler_claim_token,
            already_started=bool(scheduler_claim_token),
        )
    except ScanOwnershipLost:
        with app.app_context():
            app.logger.info(
                "Scan %s stopped because claim ownership was lost.", scan_id
            )
    except Exception as error:
        with app.app_context():
            if transition_started and scheduler_claim_token:
                failure_payload = json.dumps({
                    "command": "N/A",
                    "output": f"Scan worker failed during setup or execution: {error}",
                    "hosts": [],
                })
                ScanResult.query.filter(
                    ScanResult.id == scan_id,
                    ScanResult.status == "running",
                    ScanResult.scheduler_claim_token == scheduler_claim_token,
                ).update(
                    {
                        ScanResult.status: "failed",
                        ScanResult.scheduler_dispatch_state: "failed",
                        ScanResult.scheduler_execution_phase: "worker_failed",
                        ScanResult.result_data: failure_payload,
                    },
                    synchronize_session=False,
                )
                db.session.commit()
            app.logger.exception("Scan worker %s failed", scan_id)
    finally:
        if heartbeat_stop is not None:
            heartbeat_stop.set()
        if attempt_registered:
            end_scan_process_attempt(scan_id, scheduler_claim_token)
        _clear_scheduler_progress_checkpoint(scan_id, scheduler_claim_token)
        if transition_started:
            _reconcile_scan_worker_exit(
                app,
                scan_id,
                scheduler_claim_token,
                reconcile_termination_failed=attempt_registered,
            )
            try:
                from app import _dispatch_pending_scheduled_scans
                with app.app_context():
                    _dispatch_pending_scheduled_scans(app)
            except Exception:
                pass


def _execute_scan_body(
    app,
    scan_id,
    audit_credentials=False,
    scheduler_claim_token=None,
    already_started=False,
):
    """
    Executes the Nmap scan in a background thread and updates the database,
    evaluating anomalies and rules engine criteria.
    """
    with app.app_context():
        scan_result = ScanResult.query.get(scan_id)
        if not scan_result:
            return

        if scan_result.status == "cancelled":
            return

        if scheduler_claim_token:
            if (
                scan_result.scheduler_claim_token != scheduler_claim_token
                or scan_result.status != "running"
            ):
                return
        elif not already_started:
            scan_result.status = "running"
            if scan_result.scheduler_dispatch_state is not None:
                scan_result.scheduler_dispatch_state = "started"
                scan_result.scheduler_started_at = datetime.now(timezone.utc).replace(tzinfo=None)
            db.session.commit()

        # Determine rule owner: always use admin (global/admin-managed Model A)
        admin_user = User.query.filter_by(is_admin=True).first()
        rule_owner_id = admin_user.id if admin_user else scan_result.user_id
        seed_default_rules(rule_owner_id)

        # Retrieve global exclusions from the admin settings
        admin_setting = SystemSetting.query.filter_by(user_id=admin_user.id).first() if admin_user else None
        
        global_excludes = ""
        if admin_setting and admin_setting.scan_exclusions_active and admin_setting.scan_exclude_targets:
            global_excludes = admin_setting.scan_exclude_targets.strip()
        scan_excludes = scan_result.exclude_targets.strip() if scan_result.exclude_targets else ""
        
        combined_excludes = []
        if global_excludes:
            combined_excludes.append(global_excludes)
        if scan_excludes:
            combined_excludes.append(scan_excludes)
            
        combined_excludes_str = ",".join(combined_excludes) if combined_excludes else None

        def report_nmap_progress(phase):
            return scheduler_progress_checkpoint(
                scan_id,
                scheduler_claim_token,
                force=True,
                phase=phase,
            )

        nmap_result = run_nmap_scan(
            target=scan_result.network_cidr,
            scan_type=scan_result.scan_type,
            ports=scan_result.ports,
            exclude_targets=combined_excludes_str,
            timing_template=scan_result.timing_template,
            scan_id=scan_result.id,
            progress_callback=report_nmap_progress,
            process_token=scheduler_claim_token,
        )

        if not scheduler_progress_checkpoint(
            scan_id,
            scheduler_claim_token,
            force=True,
            phase="post_processing",
        ):
            return

        db.session.refresh(scan_result)
        if (
            scheduler_claim_token
            and scan_result.scheduler_claim_token != scheduler_claim_token
        ):
            return
        if scan_result.status == "cancelled":
            return

        hosts = nmap_result.get("hosts", [])

        # Fetch previous scan completed results for comparison
        previous_scan = ScanResult.query.filter(
            ScanResult.user_id == scan_result.user_id,
            ScanResult.network_cidr == scan_result.network_cidr,
            ScanResult.status == "completed",
            ScanResult.id < scan_result.id
        ).order_by(ScanResult.id.desc()).first()

        prev_hosts_map = {}
        if previous_scan and previous_scan.result_data:
            try:
                prev_data = json.loads(previous_scan.result_data)
                for h in prev_data.get("hosts", []):
                    prev_hosts_map[h["address"]] = {
                        (
                            (p.get("protocol") or "tcp").lower(),
                            int(p.get("port") or 0)
                        )
                        for p in h.get("ports", [])
                        if p.get("state") == "open"
                    }
            except Exception:
                pass

        if nmap_result["success"]:
            if not scheduler_progress_checkpoint(
                scan_id, scheduler_claim_token, phase="asset_processing"
            ):
                return
            # Pass 1: Match/create assets and save pre-scan snapshots on host dicts,
            # then write observations for all scanned hosts.
            # No updates to existing asset details (like IP or MAC) are written to DB yet,
            # preserving the baseline state needed for accurate anomaly detection.
            for host in hosts:
                if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                    return
                ip = host.get("address")
                mac = host.get("mac_address")
                vendor = host.get("mac_vendor")
                hostname = host.get("hostname")

                asset_match = None
                if mac:
                    mac_clean = mac.strip().lower()
                    asset_match = Asset.query.filter(Asset.mac_address.ilike(mac_clean)).first()
                if not asset_match:
                    asset_match = Asset.query.filter_by(ip_address=ip).first()

                if not asset_match:
                    # Create as Untrusted Asset immediately so it has an ID
                    asset_match = Asset(
                        name=hostname or f"Device {ip}",
                        ip_address=ip,
                        mac_address=mac.strip().lower() if mac else None,
                        mac_vendor=vendor,
                        device_type=detect_device_type(hostname, vendor, host.get("ports", [])),
                        operating_system=None,
                        criticality="Medium",
                        ip_assignment_type="DHCP",
                        notes=f"Automatically registered during network scan. Vendor: {vendor or 'Unknown'}",
                        is_trusted=False
                    )
                    db.session.add(asset_match)
                    db.session.commit()
                    host["is_new_rogue"] = True
                else:
                    host["is_new_rogue"] = False

                # Store snapshot values on the host dict for Pass 2 evaluation
                host["_asset_id"] = asset_match.id
                host["_expected_ip"] = asset_match.ip_address
                host["_expected_mac"] = asset_match.mac_address

                # Save current scan snapshot observation
                record_observation(
                    asset_id=asset_match.id,
                    scan_id=scan_result.id,
                    ip_address=ip,
                    mac_address=mac,
                    hostname=hostname,
                    vendor=vendor,
                    operating_system=host.get("operating_system"),
                    open_ports=host.get("ports", [])
                )

            if not scheduler_progress_checkpoint(
                scan_id, scheduler_claim_token, phase="anomaly_evaluation"
            ):
                return
            # Pass 2: Evaluate security anomalies.
            # Evaluates anomalies using pre-scan snapshots, making it sequence-independent
            # and preserving correct IP change detection logic.
            for host in hosts:
                if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                    return
                anomaly_res = evaluate_host_anomalies(host, scan_result.id)
                if anomaly_res:
                    host["mac_anomaly"] = anomaly_res

            if not scheduler_progress_checkpoint(
                scan_id, scheduler_claim_token, phase="asset_update"
            ):
                return
            # Pass 3: Update Asset details in DB with the newly scanned values.
            for host in hosts:
                if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                    return
                asset_id = host.get("_asset_id")
                if asset_id:
                    asset_match = db.session.get(Asset, asset_id)
                    if asset_match:
                        ip = host.get("address")
                        mac = host.get("mac_address")
                        vendor = host.get("mac_vendor")
                        hostname = host.get("hostname")

                        asset_match.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
                        if asset_match.ip_address != ip:
                            asset_match.ip_address = ip
                        if mac and not asset_match.mac_address:
                            asset_match.mac_address = mac.strip().lower()
                        if vendor and not asset_match.mac_vendor:
                            asset_match.mac_vendor = vendor
                        if hostname and (not asset_match.name or asset_match.name.startswith("Device ")):
                            asset_match.name = hostname
                        if asset_match.device_type == "Unknown" or not asset_match.device_type:
                            asset_match.device_type = detect_device_type(hostname, vendor, host.get("ports", []))

            db.session.commit()

            if not scheduler_claim_is_current(scan_id, scheduler_claim_token):
                return
            # Send Email Alert for anomalies if found
            anomalies_found = [h["mac_anomaly"] for h in hosts if "mac_anomaly" in h]
            if anomalies_found:
                admin_user = User.query.filter_by(is_admin=True).first()
                if admin_user:
                    setting = SystemSetting.query.filter_by(user_id=admin_user.id).first()
                    if setting and setting.smtp_server and setting.smtp_sender and setting.alert_recipient:
                        subject = f"[SECURITY ALERT] Network Anomaly Detected on {scan_result.network_cidr}"
                        local_time_str = format_local_datetime(datetime.now(timezone.utc).replace(tzinfo=None))
                        
                        anomalies_list_html = ""
                        for anom in anomalies_found:
                            anom_type_str = {
                                "mac_spoofing": "MAC Spoofing",
                                "ip_hijack": "IP Hijacking / Lease Migration",
                                "rogue_device": "Rogue Device Detected"
                            }.get(anom["type"], anom["type"])
                            
                            anomalies_list_html += f"""
                            <tr style="border-bottom: 1px solid #edf2f7;">
                                <td style="padding: 10px; font-weight: bold; color: #c53030;">{anom_type_str} ({anom.get('confidence_score', 'High')} Confidence)</td>
                                <td style="padding: 10px;">{anom.get('description', '')}</td>
                            </tr>
                            """
                        
                        body_html = f"""
                        <div style="font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 0 auto; padding: 25px; border: 1px solid #fed7d7; border-radius: 12px; background-color: #fff5f5; color: #2d3748;">
                            <div style="text-align: center; margin-bottom: 20px;">
                                <h2 style="color: #c53030; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">⚠️ Network Security Anomaly Alert</h2>
                                <p style="color: #9b2c2c; margin: 5px 0 0 0; font-size: 14px;">Anomalies were detected during the automated network scan!</p>
                            </div>
                            <table style="width: 100%; font-size: 13px; color: #4a5568; margin-bottom: 20px; background: #fff; border-radius: 8px; border: 1px solid #e2e8f0; border-collapse: separate; border-spacing: 0;">
                                <thead>
                                    <tr style="background: #f7fafc;">
                                        <th style="padding: 10px; text-align: left; border-bottom: 1px solid #e2e8f0;">Anomaly Type</th>
                                        <th style="padding: 10px; text-align: left; border-bottom: 1px solid #e2e8f0;">Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {anomalies_list_html}
                                </tbody>
                            </table>
                            <div style="background-color: #fff; border-left: 4px solid #e53e3e; padding: 12px; border-radius: 4px; font-size: 13px; color: #742a2a; margin-top: 15px;">
                                <strong>Time:</strong> {local_time_str}<br>
                                <strong>Status:</strong> Please visit the Lynceus Admin Panel to examine details and resolve findings.
                            </div>
                        </div>
                        """
                        
                        setting_dict = {
                            "smtp_server": setting.smtp_server,
                            "smtp_port": setting.smtp_port,
                            "smtp_username": setting.smtp_username,
                            "smtp_password": setting.smtp_password,
                            "smtp_sender": setting.smtp_sender,
                            "alert_recipient": setting.alert_recipient
                        }
                        send_notification_email_async(setting_dict, subject, body_html)

        if not scheduler_progress_checkpoint(
            scan_id, scheduler_claim_token, phase="credential_audit"
        ):
            return
        # 4. Credential Audits (run BEFORE rule evaluation so rules can read audit results)
        if (audit_credentials or scan_result.credential_ids) and nmap_result["success"]:
            custom_ftp = []
            custom_redis = []
            custom_http = []

            if scan_result.credential_ids:
                try:
                    cred_ids = [int(x.strip()) for x in scan_result.credential_ids.split(",") if x.strip()]
                    if cred_ids:
                        selected_creds = ScanCredential.query.filter(ScanCredential.id.in_(cred_ids)).all()
                        for cred in selected_creds:
                            if cred.protocol == "ftp" or cred.protocol == "any":
                                custom_ftp.append((cred.username or "", cred.password or ""))
                            if cred.protocol == "redis" or cred.protocol == "any":
                                custom_redis.append(cred.password or "")
                            if cred.protocol == "http_basic" or cred.protocol == "any":
                                custom_http.append((cred.username or "", cred.password or ""))
                except Exception:
                    pass

            for host in hosts:
                if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                    return
                ip = host.get("address")
                asset = Asset.query.filter_by(ip_address=ip).first()
                ports_list = host.get("ports", [])
                audited_endpoints = {}
                for port_info in ports_list:
                    if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                        return
                    if port_info.get("state") != "open":
                        continue
                    p_num = int(port_info.get("port") or 0)
                    service = (port_info.get("service") or "").lower()
                    protocol = (port_info.get("protocol") or "tcp").lower()

                    audit_res = None
                    if p_num == 21 or "ftp" in service:
                        if audit_credentials or custom_ftp:
                            audit_res = audit_ftp(ip, p_num, custom_credentials=custom_ftp if custom_ftp else None, use_defaults=audit_credentials)
                    elif p_num == 6379 or "redis" in service:
                        if audit_credentials or custom_redis:
                            audit_res = audit_redis(ip, p_num, custom_passwords=custom_redis if custom_redis else None, use_defaults=audit_credentials)
                    elif protocol == "tcp" and (p_num in [80, 8080, 443, 8443] or "http" in service):
                        if audit_credentials or custom_http:
                            is_ssl = p_num in [443, 8443] or "https" in service
                            audit_res = audit_http_basic(ip, p_num, is_ssl, custom_credentials=custom_http if custom_http else None, use_defaults=audit_credentials)

                    if audit_res:
                        port_info["credential_audit"] = audit_res
                        status = audit_res.get("status")
                        if status in ["safe", "vulnerable"]:
                            audited_endpoints[(protocol, p_num)] = status
                        # Create a finding immediately if vulnerability confirmed
                        if asset and status == "vulnerable":
                            create_credential_audit_finding(asset, ip, port_info, audit_res, scan_id=scan_result.id)
                host["_audited_endpoints"] = audited_endpoints

        if not scheduler_progress_checkpoint(
            scan_id, scheduler_claim_token, phase="rule_evaluation"
        ):
            return
        # 5. Policy rule evaluation (runs AFTER credential audits so Redis rule can read audit results)
        if nmap_result["success"]:
            for host in hosts:
                if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                    return
                ip = host.get("address")
                asset_match = Asset.query.filter_by(ip_address=ip).first()
                if asset_match:
                    prev_ports = prev_hosts_map.get(ip)
                    host["_preserved_rule_fingerprints"] = evaluate_rules_for_host(
                        host,
                        asset_match,
                        rule_owner_id,
                        prev_ports=prev_ports,
                        scan_id=scan_result.id,
                    )

        if not scheduler_progress_checkpoint(
            scan_id, scheduler_claim_token, phase="cve_evaluation"
        ):
            return
        # 6. Dynamic CVE findings check
        if nmap_result["success"]:
            for host in hosts:
                if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                    return
                ip = host.get("address")
                asset = Asset.query.filter_by(ip_address=ip).first()
                if not asset:
                    continue
                cve_failed_ports = set()
                confirmed_unaffected_cves = {}
                for port_info in host.get("ports", []):
                    if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                        return
                    if port_info.get("state") != "open":
                        continue
                    # Use 'product' for VENDOR_PRODUCT_MAP lookup (e.g. 'OpenSSH' not 'ssh')
                    product = port_info.get("product") or ""
                    service = port_info.get("service") or ""
                    raw_version = port_info.get("version") or ""
                    cpe_list = port_info.get("cpe") or []
                    p_num = int(port_info.get("port") or 0)
                    protocol = (port_info.get("protocol") or "tcp").lower()

                    # Build lookup key: prefer product name, fall back to service name
                    lookup_key = product.lower().strip() if product else service.lower().strip()

                    if lookup_key and lookup_key != "-":
                        cves_res = fetch_cves_for_query(lookup_key, version=raw_version, cpe_list=cpe_list)
                        if cves_res.get("success"):
                            if (
                                cves_res.get("lookup_success") is True
                                and cves_res.get("product_confirmed") is True
                                and cves_res.get("version_confirmed") is True
                            ):
                                confirmed_unaffected_cves[(protocol, p_num)] = set(
                                    cves_res.get("confirmed_unaffected_cves", [])
                                )
                            cves = cves_res.get("cves", [])
                            if cves:
                                evaluate_cve_findings(
                                    asset=asset,
                                    ip_address=ip,
                                    port_info=port_info,
                                    cve_list=cves,
                                    scan_id=scan_result.id
                                )
                        else:
                            cve_failed_ports.add((protocol, p_num))
                host["_cve_failed_ports"] = cve_failed_ports
                host["_confirmed_unaffected_cves"] = confirmed_unaffected_cves

        if not scheduler_progress_checkpoint(
            scan_id, scheduler_claim_token, phase="reconciliation"
        ):
            return
        # 7. Finding lifecycle reconciliation — mark unobserved findings 'not_observed'
        if nmap_result["success"]:
            # Collect all fingerprints written in this scan across all pipelines
            from models import SecurityFinding as SF
            scan_fps = set(
                r[0] for r in db.session.query(SF.fingerprint).filter(
                    SF.scan_id == scan_result.id,
                    SF.fingerprint.isnot(None)
                ).all()
            )
            online_ips = {h.get("address") for h in hosts if h.get("status") == "up"}
            scanned_endpoints = nmap_result.get("scanned_endpoints", [])
            for host in hosts:
                if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                    return
                ip = host.get("address")
                asset = Asset.query.filter_by(ip_address=ip).first()
                if asset:
                    host_online = ip in online_ips or host.get("status") == "up"
                    current_open_endpoints = [
                        ((p.get("protocol") or "tcp").lower(), int(p.get("port") or 0))
                        for p in host.get("ports", [])
                        if p.get("state") == "open"
                    ]
                    endpoint_states = {
                        ((p.get("protocol") or "tcp").lower(), int(p.get("port") or 0)): p.get("state")
                        for p in host.get("ports", [])
                    }
                    current_ports_info = {
                        ((p.get("protocol") or "tcp").lower(), int(p.get("port") or 0)): p
                        for p in host.get("ports", [])
                    }
                    cve_failed_ports = host.get("_cve_failed_ports", set())
                    confirmed_unaffected_cves = host.get("_confirmed_unaffected_cves", {})
                    audited_endpoints = host.get("_audited_endpoints", {})
                    reconcile_findings_for_scan(
                        asset=asset,
                        host_online=host_online,
                        observed_fingerprints=(
                            scan_fps | host.get("_preserved_rule_fingerprints", set())
                        ),
                        scan_id=scan_result.id,
                        scan_type=scan_result.scan_type,
                        requested_ports=scan_result.ports,
                        audit_credentials=scan_result.audit_credentials,
                        credential_ids=scan_result.credential_ids,
                        current_open_ports=current_open_endpoints,
                        cve_failed_ports=cve_failed_ports,
                        confirmed_unaffected_cves=confirmed_unaffected_cves,
                        audited_endpoints=audited_endpoints,
                        scanned_endpoints=scanned_endpoints,
                        endpoint_states=endpoint_states,
                        current_ports_info=current_ports_info
                    )

        # Clear internal runtime parameters to prevent JSON serialization errors (tuple keys, sets, etc.)
        for host in hosts:
            if not scheduler_progress_checkpoint(scan_id, scheduler_claim_token):
                return
            host.pop("_asset_id", None)
            host.pop("_expected_ip", None)
            host.pop("_expected_mac", None)
            host.pop("_audited_endpoints", None)
            host.pop("_cve_failed_ports", None)
            host.pop("_confirmed_unaffected_cves", None)
            host.pop("_preserved_rule_fingerprints", None)
            host.pop("is_new_rogue", None)

        result_payload = {
            "command": nmap_result.get("command", "N/A"),
            "output": nmap_result.get("output", ""),
            "hosts": hosts
        }

        serialized_result = json.dumps(result_payload, indent=4)

        if nmap_result["success"]:
            if scheduler_claim_token:
                completed = ScanResult.query.filter(
                    ScanResult.id == scan_id,
                    ScanResult.status == "running",
                    ScanResult.scheduler_dispatch_state == "started",
                    ScanResult.scheduler_claim_token == scheduler_claim_token,
                ).update(
                    {
                        ScanResult.status: "completed",
                        ScanResult.scheduler_dispatch_state: "completed",
                        ScanResult.scheduler_execution_phase: "completed",
                        ScanResult.result_data: serialized_result,
                        ScanResult.scheduler_heartbeat_at: datetime.now(timezone.utc).replace(tzinfo=None),
                    },
                    synchronize_session=False,
                )
                db.session.commit()
                if completed != 1:
                    return
                db.session.refresh(scan_result)
            else:
                scan_result.result_data = serialized_result
                scan_result.status = "completed"
                if scan_result.scheduler_dispatch_state is not None:
                    scan_result.scheduler_dispatch_state = "completed"
                    scan_result.scheduler_execution_phase = "completed"
                db.session.commit()
            
            try:
                check_and_send_scan_alert(scan_result)
            except Exception as e:
                import sys
                print(f"[Email Alert Error]: {str(e)}", file=sys.stderr)
        else:
            if scheduler_claim_token:
                ScanResult.query.filter(
                    ScanResult.id == scan_id,
                    ScanResult.status == "running",
                    ScanResult.scheduler_claim_token == scheduler_claim_token,
                ).update(
                    {
                        ScanResult.status: "failed",
                        ScanResult.scheduler_dispatch_state: "failed",
                        ScanResult.scheduler_execution_phase: "failed",
                        ScanResult.result_data: serialized_result,
                        ScanResult.scheduler_heartbeat_at: datetime.now(timezone.utc).replace(tzinfo=None),
                    },
                    synchronize_session=False,
                )
            else:
                scan_result.result_data = serialized_result
                scan_result.status = "failed"
                if scan_result.scheduler_dispatch_state is not None:
                    scan_result.scheduler_dispatch_state = "failed"
                    scan_result.scheduler_execution_phase = "failed"
            db.session.commit()
