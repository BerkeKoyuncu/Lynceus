import os
import json
import socket
import urllib.request
import urllib.error
import smtplib
import threading
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import current_app

from models import db, User, ScanResult, ScanSchedule, SystemSetting, Asset, ScanCredential, SecurityFinding, SecurityAnomaly
from scanner import run_nmap_scan
from services.anomaly_service import evaluate_host_anomalies
from services.rule_service import evaluate_rules_for_host, evaluate_cve_findings, seed_default_rules
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

def parse_version(v_str):
    import re
    # Extract digit sequences
    nums = re.findall(r'\d+', v_str)
    return tuple(int(x) for x in nums) if nums else ()

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
        return True # Default to True if we cannot parse the version format
  
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

def fetch_cves_for_query(query):
    """
    Queries the CIRCL CVE API for a service query and returns up to 15 CVE details.
    """
    if not query or query == "-":
        return []
    
    cache_key = query.lower()
    if cache_key in CVE_CACHE:
        return CVE_CACHE[cache_key]

    parts = query.split()
    if len(parts) == 0:
        return []
    elif len(parts) == 1:
        product = parts[0]
        version = ""
    else:
        two_word_prod = f"{parts[0]} {parts[1]}".lower()
        if two_word_prod in ["apache httpd", "microsoft iis", "vsftpd project", "werkzeug httpd"]:
            product = two_word_prod
            version = " ".join(parts[2:])
        else:
            product = parts[0]
            version = " ".join(parts[1:])

    product_clean = product.lower().strip()
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
        seen_cves = set()
        filtered_cves = []

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

            # Check if version is affected
            is_affected = True
            is_definite = False
            if version:
                is_affected = False
                cpe_nodes = cve_record.get("containers", {}).get("cna", {}).get("cpeApplicability", [])
                cpe_found = False

                for node in cpe_nodes:
                    for subnode in node.get("nodes", []):
                        for match in subnode.get("cpeMatch", []):
                            cpe_uri = match.get("criteria", "")
                            if api_product in cpe_uri.lower():
                                cpe_found = True
                                if is_version_affected(version, match, api_product):
                                    is_affected = True
                                    break
                        if is_affected:
                            break
                    if is_affected:
                        break

                if cpe_found:
                    if is_affected:
                        is_definite = True
                else:
                    # CPE not found, check description as fallback
                    if api_product in summary.lower():
                        is_affected = True
                        is_definite = False
                    else:
                        is_affected = False
            else:
                is_affected = True
                is_definite = False

            if is_affected:
                seen_cves.add(cve_id)
                filtered_cves.append({
                    "id": cve_id,
                    "summary": summary,
                    "cvss": cvss_score,
                    "is_definite_match": is_definite
                })

        filtered_cves.sort(key=lambda x: x["cvss"] if x["cvss"] is not None else -1, reverse=True)
        filtered_cves = filtered_cves[:15]
        CVE_CACHE[cache_key] = filtered_cves
        return filtered_cves
    except Exception:
        return []

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
    for username, password in credentials:
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=2)
            ftp.login(username, password)
            ftp.quit()
            return {"status": "vulnerable", "message": f"Weak credentials: {username}:{password}"}
        except Exception:
            continue
    return {"status": "safe", "message": "No common default credentials found"}

def audit_redis(ip, port=6379, custom_passwords=None, use_defaults=True):
    passwords = []
    if custom_passwords:
        passwords.extend(custom_passwords)
    if use_defaults:
        passwords.extend(["", "admin", "password", "redis", "root"])
    for pwd in passwords:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            if pwd == "":
                s.sendall(b"PING\r\n")
                resp = s.recv(1024)
                if b"+PONG" in resp:
                    s.close()
                    return {"status": "vulnerable", "message": "No password set (Unauthenticated access)"}
            else:
                s.sendall(f"AUTH {pwd}\r\n".encode())
                resp = s.recv(1024)
                if b"+OK" in resp:
                    s.close()
                    return {"status": "vulnerable", "message": f"Weak password: {pwd}"}
            s.close()
        except Exception:
            continue
    return {"status": "safe", "message": "No common passwords found"}

def audit_http_basic(ip, port=80, is_ssl=False, custom_credentials=None, use_defaults=True):
    import urllib.request
    import urllib.error
    import base64
    
    url = f"{'https' if is_ssl else 'http'}://{ip}:{port}/"
    try:
        req = urllib.request.Request(url, method="GET")
        urllib.request.urlopen(req, timeout=2)
        return {"status": "safe", "message": "No authentication required"}
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return {"status": "skipped", "message": f"Returned status {e.code}"}
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
    
    for username, password in credentials:
        try:
            req = urllib.request.Request(url, method="GET")
            auth_str = f"{username}:{password}"
            auth_b64 = base64.b64encode(auth_str.encode()).decode()
            req.add_header("Authorization", f"Basic {auth_b64}")
            
            resp = urllib.request.urlopen(req, timeout=2)
            if resp.code == 200:
                return {"status": "vulnerable", "message": f"Weak credentials: {username}:{password}"}
        except urllib.error.HTTPError as e:
            if e.code == 401:
                continue
            return {"status": "vulnerable", "message": f"Weak credentials (potential match): {username}:{password}"}
        except Exception:
            continue
    return {"status": "safe", "message": "Authentication required, but common passwords failed"}

def detect_device_type(hostname, mac_vendor, ports_list):
    """
    Auto-detects the device type based on hostname, mac vendor, and open ports.
    """
    hostname_lower = (hostname or "").lower()
    vendor_lower = (mac_vendor or "").lower()
    
    open_ports = set()
    for p in ports_list:
        if isinstance(p, dict):
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
        curr_ports = host.get("ports", [])
        
        if ip not in map_prev:
            if curr_ports:
                added_hosts_info.append({
                    "address": ip,
                    "hostname": host.get("hostname", ""),
                    "ports": curr_ports
                })
                new_ports_detected = True
        else:
            prev_ports = {p["port"]: p for p in map_prev[ip].get("ports", [])}
            host_added_ports = []
            for p in curr_ports:
                p_num = p["port"]
                if p_num not in prev_ports:
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

def execute_scan(app, scan_id, audit_credentials=False):
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

        scan_result.status = "running"
        db.session.commit()

        # Seed default rules for the scanning user if they don't have any rules set up
        seed_default_rules(scan_result.user_id)

        # Retrieve global exclusions from the admin settings
        admin_user = User.query.filter_by(is_admin=True).first()
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

        nmap_result = run_nmap_scan(
            target=scan_result.network_cidr,
            scan_type=scan_result.scan_type,
            ports=scan_result.ports,
            exclude_targets=combined_excludes_str,
            timing_template=scan_result.timing_template,
            scan_id=scan_result.id
        )

        db.session.refresh(scan_result)
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
                    prev_hosts_map[h["address"]] = [int(p.get("port") or 0) for p in h.get("ports", [])]
            except Exception:
                pass

        if nmap_result["success"]:
            for host in hosts:
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

                # Perform Anomaly checks (comparative history evaluation)
                anomaly_res = evaluate_host_anomalies(host, scan_result.id)
                if anomaly_res:
                    host["mac_anomaly"] = anomaly_res

                if asset_match:
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
                    
                    # Evaluate custom rules for this asset
                    prev_ports = prev_hosts_map.get(ip)
                    evaluate_rules_for_host(host, asset_match, scan_result.user_id, prev_ports=prev_ports, scan_id=scan_result.id)
                else:
                    # Create as Untrusted Asset
                    new_asset = Asset(
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
                    db.session.add(new_asset)
                    db.session.commit()

                    # Evaluate custom rules for this new asset
                    evaluate_rules_for_host(host, new_asset, scan_result.user_id, prev_ports=None, scan_id=scan_result.id)

            db.session.commit()

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

        # 4. Weak credentials audits
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
                ip = host.get("address")
                ports_list = host.get("ports", [])
                for port_info in ports_list:
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

        # Dynamic CVE findings check
        if nmap_result["success"]:
            for host in hosts:
                ip = host.get("address")
                asset = Asset.query.filter_by(ip_address=ip).first()
                if not asset:
                    continue
                for port_info in host.get("ports", []):
                    version = port_info.get("version")
                    service = port_info.get("service")
                    if version and version != "-":
                        query = f"{service} {version}"
                        # Fetch CVEs and record findings in the database
                        cves = fetch_cves_for_query(query)
                        if cves:
                            evaluate_cve_findings(
                                asset=asset,
                                ip_address=ip,
                                port_info=port_info,
                                cve_list=cves,
                                scan_id=scan_result.id
                            )

        result_payload = {
            "command": nmap_result.get("command", "N/A"),
            "output": nmap_result.get("output", ""),
            "hosts": hosts
        }

        scan_result.result_data = json.dumps(result_payload, indent=4)

        if nmap_result["success"]:
            scan_result.status = "completed"
            db.session.commit()
            
            try:
                check_and_send_scan_alert(scan_result)
            except Exception as e:
                import sys
                print(f"[Email Alert Error]: {str(e)}", file=sys.stderr)
        else:
            scan_result.status = "failed"
            db.session.commit()
