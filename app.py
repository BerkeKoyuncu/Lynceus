from flask import Flask, render_template, redirect, url_for, request, flash, Response, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta, timezone
import pyotp
try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:
    ZoneInfo = None
    ZoneInfoNotFoundError = Exception
import threading
import time
import click
import json
import csv
import io
import re
import os


from models import db, User, ScanResult, ScanSchedule, SystemSetting, HoneypotLog, HoneypotBlockedIP, SecurityAnomaly, Asset, ScanCredential, get_flask_secret_key
from scanner import calculate_network, validate_scan_target, run_nmap_scan


app = Flask(__name__)

app.config["SECRET_KEY"] = get_flask_secret_key()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

try:
    APP_TIMEZONE = ZoneInfo("Europe/Istanbul") if ZoneInfo else timezone(timedelta(hours=3), "TRT")
except ZoneInfoNotFoundError:
    APP_TIMEZONE = timezone(timedelta(hours=3), "TRT")

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

HONEYPOT_PATHS = [
    "/wp-admin", "/wp-login.php", "/administrator", "/phpmyadmin",
    "/.git", "/.env", "/config.json", "/backup.zip", "/database.sql",
    "/admin/config.php", "/setup.php", "/xmlrpc.php"
]

@app.before_request
def check_honeypot_and_blocking():
    # 1. Skip static assets / CSS / JS / media to ensure the blocked page looks correct
    if request.path.startswith('/static/') or request.path == '/favicon.ico':
        return

    # 2. Check if client IP is blocked
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # Handle multiple IPs in X-Forwarded-For if behind reverse proxy
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()
    
    # We query HoneypotBlockedIP to see if client_ip is present
    is_blocked = HoneypotBlockedIP.query.filter_by(ip_address=client_ip).first()
    if is_blocked:
        # If blocked, redirect to the blocked template unless they are already requesting the blocked route
        # Allow reaching /honeypot/blocked or /logout (so admins/users can log out if they somehow get blocked, or just blocked route)
        if request.endpoint not in ['honeypot_blocked', 'logout', 'static']:
            return redirect(url_for('honeypot_blocked'))
        return

    # 3. Check if they are accessing a honeypot route
    # We check exact match or if path starts with it (case-insensitive and trailing slash stripped)
    request_path = request.path.lower().rstrip('/')
    is_honeypot_hit = False
    for path in HONEYPOT_PATHS:
        if request_path == path or request_path.startswith(path + '/'):
            is_honeypot_hit = True
            break
            
    if is_honeypot_hit:
        # Find admin settings to check if honeypot is active
        admin_user = User.query.filter_by(is_admin=True).first()
        active = True
        auto_block = True
        email_alert = True
        smtp_setting = None
        
        if admin_user:
            smtp_setting = SystemSetting.query.filter_by(user_id=admin_user.id).first()
            if smtp_setting:
                active = smtp_setting.honeypot_active
                auto_block = smtp_setting.honeypot_auto_block
                email_alert = smtp_setting.honeypot_email_alert
                
        if not active:
            # If honeypot is disabled, act as normal (let Flask handle 404)
            return
            
        # Log the hit
        headers_dict = dict(request.headers)
        headers_str = json.dumps(headers_dict, indent=2)
        
        new_log = HoneypotLog(
            ip_address=client_ip,
            user_agent=request.user_agent.string,
            path=request.path,
            headers=headers_str
        )
        db.session.add(new_log)
        
        # Block if auto_block is active (skip loopback addresses to avoid blocking local developer)
        if auto_block and client_ip not in ['127.0.0.1', '::1', 'localhost']:
            existing_block = HoneypotBlockedIP.query.filter_by(ip_address=client_ip).first()
            if not existing_block:
                new_block = HoneypotBlockedIP(
                    ip_address=client_ip,
                    reason=f"Accessed decoy endpoint: {request.path}"
                )
                db.session.add(new_block)
                
        db.session.commit()
        
        # Send Email Alert if enabled
        if email_alert and smtp_setting and smtp_setting.smtp_server and smtp_setting.smtp_sender and smtp_setting.alert_recipient:
            subject = f"[SECURITY ALERT] Honeypot Intrusion Detected: {client_ip}"
            local_time_str = format_local_datetime(datetime.now(timezone.utc).replace(tzinfo=None))
            body_html = f"""
            <div style="font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 0 auto; padding: 25px; border: 1px solid #fed7d7; border-radius: 12px; background-color: #fff5f5; color: #2d3748;">
                <div style="text-align: center; margin-bottom: 20px;">
                    <h2 style="color: #c53030; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">⚠️ Honeypot Security Alert</h2>
                    <p style="color: #9b2c2c; margin: 5px 0 0 0; font-size: 14px;">An intrusion attempt was detected on a decoy honeypot endpoint in your application!</p>
                </div>
                
                <table style="width: 100%; font-size: 13px; color: #4a5568; margin-bottom: 20px; background: #fff; border-radius: 8px; border: 1px solid #e2e8f0; border-collapse: separate; border-spacing: 0;">
                    <tr>
                        <td style="padding: 10px; font-weight: bold; width: 35%; border-bottom: 1px solid #edf2f7;">Attacker IP</td>
                        <td style="padding: 10px; border-bottom: 1px solid #edf2f7; font-weight: bold; color: #c53030;">{client_ip}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; font-weight: bold; border-bottom: 1px solid #edf2f7;">Triggered Path</td>
                        <td style="padding: 10px; border-bottom: 1px solid #edf2f7;"><code>{request.path}</code></td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; font-weight: bold; border-bottom: 1px solid #edf2f7;">Device (User Agent)</td>
                        <td style="padding: 10px; border-bottom: 1px solid #edf2f7; font-size: 11px; color: #718096;">{request.user_agent.string}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; font-weight: bold;">Time</td>
                        <td style="padding: 10px;">{local_time_str}</td>
                    </tr>
                </table>
                
                <div style="background-color: #fff; border-left: 4px solid #e53e3e; padding: 12px; border-radius: 4px; font-size: 13px; color: #742a2a;">
                    <strong>Status:</strong> {"This IP address has been automatically blocked from accessing the PortOjo system." if auto_block else "IP address has not been blocked. Please check your system status and access logs."}
                </div>
            </div>
            """
            
            setting_dict = {
                "smtp_server": smtp_setting.smtp_server,
                "smtp_port": smtp_setting.smtp_port,
                "smtp_username": smtp_setting.smtp_username,
                "smtp_password": smtp_setting.smtp_password,
                "smtp_sender": smtp_setting.smtp_sender,
                "alert_recipient": smtp_setting.alert_recipient
            }
            send_notification_email_async(setting_dict, subject, body_html)
            
        return render_template("decoy_wp.html"), 404

def send_notification_email_async(setting_dict, subject, body_html):
    def send_email_thread():
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = setting_dict.get("smtp_sender")
            msg["To"] = setting_dict.get("alert_recipient")
            
            part = MIMEText(body_html, "html", "utf-8")
            msg.attach(part)
            
            server_name = setting_dict.get("smtp_server")
            port = int(setting_dict.get("smtp_port") or 587)
            username = setting_dict.get("smtp_username")
            password = setting_dict.get("smtp_password")
            
            if port == 465:
                server = smtplib.SMTP_SSL(server_name, port, timeout=10)
            else:
                server = smtplib.SMTP(server_name, port, timeout=10)
                server.ehlo()
                server.starttls()
                server.ehlo()
                
            if username and password:
                server.login(username, password)
                
            server.sendmail(setting_dict.get("smtp_sender"), [setting_dict.get("alert_recipient")], msg.as_string())
            server.quit()
            print(f"[Email Success]: Sent email to {setting_dict.get('alert_recipient')} with subject: {subject}")
        except Exception as e:
            import sys
            print(f"[Email Error]: Failed to send email: {str(e)}", file=sys.stderr)
            
    threading.Thread(target=send_email_thread, daemon=True).start()


def check_and_send_scan_alert(scan_result):
    setting = SystemSetting.query.filter_by(user_id=scan_result.user_id).first()
    if not setting or not setting.smtp_server or not setting.smtp_sender or not setting.alert_recipient:
        return
        
    try:
        current_data = json.loads(scan_result.result_data) if scan_result.result_data else {}
    except Exception:
        return
        
    current_hosts = current_data.get("hosts", [])
    
    # Query the previous completed scan for the same network_cidr and user
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
                port_num = p.get("port")
                if port_num not in prev_ports:
                    host_added_ports.append(p)
                    new_ports_detected = True
            if host_added_ports:
                added_ports_info.append({
                    "address": ip,
                    "hostname": host.get("hostname", ""),
                    "ports": host_added_ports
                })
                
    should_send = False
    subject = ""
    is_alert = False
    
    if new_ports_detected:
        should_send = True
        is_alert = True
        subject = f"[PORT SCAN SECURITY ALERT] New open ports detected on {scan_result.network_cidr}"
    elif not setting.alert_on_new_ports_only:
        should_send = True
        subject = f"[PortOjo] Scan Complete: {scan_result.network_cidr}"
        
    if not should_send:
        return
        
    if is_alert:
        alert_banner = f"""
        <div style="background-color: #fde8e8; border-left: 4px solid #e53e3e; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
            <strong style="color: #c53030; font-size: 16px;">⚠️ SECURITY WARNING: New Open Ports Detected!</strong>
            <p style="color: #742a2a; margin: 5px 0 0 0; font-size: 14px;">
                The latest scan discovered new open ports or new active hosts compared to the previous scan. Please review the details below.
            </p>
        </div>
        """
    else:
        alert_banner = f"""
        <div style="background-color: #f3f4f6; border-left: 4px solid #4a5d4e; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
            <strong style="color: #4a5d4e; font-size: 16px;">Scan Summary</strong>
            <p style="color: #4b5563; margin: 5px 0 0 0; font-size: 14px;">
                The target network scan completed successfully. No new open ports have been detected.
            </p>
        </div>
        """
        
    hosts_html = ""
    if is_alert:
        if added_hosts_info:
            hosts_html += """
            <h3 style="color: #2d3748; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px; margin-top: 25px;">Newly Discovered Devices (New IPs)</h3>
            """
            for h in added_hosts_info:
                hosts_html += f"""
                <div style="background: #fff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                    <strong style="color: #4a5d4e;">IP Address:</strong> {h['address']} 
                    {"(" + h['hostname'] + ")" if h['hostname'] else ""}
                    <table style="width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px;">
                        <thead>
                            <tr style="background: #f7fafc; border-bottom: 2px solid #edf2f7;">
                                <th style="text-align: left; padding: 6px;">Port</th>
                                <th style="text-align: left; padding: 6px;">Protocol</th>
                                <th style="text-align: left; padding: 6px;">Service</th>
                                <th style="text-align: left; padding: 6px;">Version</th>
                            </tr>
                        </thead>
                        <tbody>
                """
                for p in h["ports"]:
                    hosts_html += f"""
                            <tr style="border-bottom: 1px solid #edf2f7;">
                                <td style="padding: 6px; font-weight: bold; color: #e53e3e;">{p.get('port')}</td>
                                <td style="padding: 6px;">{p.get('protocol')}</td>
                                <td style="padding: 6px;">{p.get('service')}</td>
                                <td style="padding: 6px; color: #718096;">{p.get('version') or '-'}</td>
                            </tr>
                    """
                hosts_html += """
                        </tbody>
                    </table>
                </div>
                """
                
        if added_ports_info:
            hosts_html += """
            <h3 style="color: #2d3748; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px; margin-top: 25px;">New Open Ports on Existing Devices</h3>
            """
            for h in added_ports_info:
                hosts_html += f"""
                <div style="background: #fff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                    <strong style="color: #4a5d4e;">IP Address:</strong> {h['address']} 
                    {"(" + h['hostname'] + ")" if h['hostname'] else ""}
                    <table style="width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px;">
                        <thead>
                            <tr style="background: #f7fafc; border-bottom: 2px solid #edf2f7;">
                                <th style="text-align: left; padding: 6px;">Port</th>
                                <th style="text-align: left; padding: 6px;">Protocol</th>
                                <th style="text-align: left; padding: 6px;">Service</th>
                                <th style="text-align: left; padding: 6px;">Version</th>
                            </tr>
                        </thead>
                        <tbody>
                """
                for p in h["ports"]:
                    hosts_html += f"""
                            <tr style="border-bottom: 1px solid #edf2f7;">
                                <td style="padding: 6px; font-weight: bold; color: #e53e3e;">{p.get('port')}</td>
                                <td style="padding: 6px;">{p.get('protocol')}</td>
                                <td style="padding: 6px;">{p.get('service')}</td>
                                <td style="padding: 6px; color: #718096;">{p.get('version') or '-'}</td>
                            </tr>
                    """
                hosts_html += """
                        </tbody>
                    </table>
                </div>
                """
    else:
        total_hosts = len(current_hosts)
        total_open_ports = sum(len(h.get("ports", [])) for h in current_hosts)
        hosts_html = f"""
        <div style="background: #fff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 15px; margin-top: 20px;">
            <p style="margin: 5px 0;"><strong>Total Discovered Devices:</strong> {total_hosts}</p>
            <p style="margin: 5px 0;"><strong>Total Open Ports:</strong> {total_open_ports}</p>
        </div>
        """
        
    body_html = f"""
    <div style="font-family: system-ui, -apple-system, sans-serif; max-width: 650px; margin: 0 auto; padding: 25px; border: 1px solid #e2e8f0; border-radius: 12px; background-color: #fbfbf9; color: #2d3748;">
        <div style="text-align: center; margin-bottom: 25px;">
            <h1 style="color: #4a5d4e; margin: 0; font-size: 24px; font-weight: 700; letter-spacing: -0.5px;">PortOjo Security Alerts</h1>
            <p style="color: #718096; margin: 5px 0 0 0; font-size: 14px;">Network Security & Port Tracking Report</p>
        </div>
        
        {alert_banner}
        
        <table style="width: 100%; font-size: 13px; color: #4a5568; margin-bottom: 20px; background: #fff; border-radius: 6px; border: 1px solid #e2e8f0; border-collapse: separate; border-spacing: 0;">
            <tr style="background: #f7fafc;">
                <td style="padding: 10px; font-weight: bold; border-bottom: 1px solid #e2e8f0;">Scan Parameters</td>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;"></td>
            </tr>
            <tr>
                <td style="padding: 10px; font-weight: bold; width: 35%; border-bottom: 1px solid #edf2f7;">Scan ID</td>
                <td style="padding: 10px; border-bottom: 1px solid #edf2f7;">#{scan_result.id}</td>
            </tr>
            <tr>
                <td style="padding: 10px; font-weight: bold; border-bottom: 1px solid #edf2f7;">Target Network / IP</td>
                <td style="padding: 10px; border-bottom: 1px solid #edf2f7;">{scan_result.network_cidr} ({scan_result.input_ip}/{scan_result.subnet_mask})</td>
            </tr>
            <tr>
                <td style="padding: 10px; font-weight: bold; border-bottom: 1px solid #edf2f7;">Scan Type</td>
                <td style="padding: 10px; border-bottom: 1px solid #edf2f7;">{scan_name_filter(scan_result.scan_type)}</td>
            </tr>
            <tr>
                <td style="padding: 10px; font-weight: bold;">Time</td>
                <td style="padding: 10px;">{format_local_datetime(scan_result.created_at)}</td>
            </tr>
        </table>
        
        {hosts_html}
        
        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0;">
            <p style="font-size: 12px; color: #a0aec0; margin: 0;">
                This email was sent automatically by the PortOjo scanning engine. To change your settings, please visit the settings tab in the application.
            </p>
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
    import socket
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


FAILED_LOGIN_ATTEMPTS = {}

def record_failed_login(ip):
    now = datetime.now()
    if ip not in FAILED_LOGIN_ATTEMPTS:
        FAILED_LOGIN_ATTEMPTS[ip] = []
    FAILED_LOGIN_ATTEMPTS[ip].append(now)
    
    ten_minutes_ago = now - timedelta(minutes=10)
    FAILED_LOGIN_ATTEMPTS[ip] = [t for t in FAILED_LOGIN_ATTEMPTS[ip] if t > ten_minutes_ago]
    
    if len(FAILED_LOGIN_ATTEMPTS[ip]) >= 5:
        if ip not in ['127.0.0.1', '::1', 'localhost']:
            existing_block = HoneypotBlockedIP.query.filter_by(ip_address=ip).first()
            if not existing_block:
                new_block = HoneypotBlockedIP(
                    ip_address=ip,
                    reason="Brute-force login attempts detected (5 failed attempts in 10 minutes)"
                )
                db.session.add(new_block)
                db.session.commit()
                
                admin_user = User.query.filter_by(is_admin=True).first()
                if admin_user:
                    smtp_setting = SystemSetting.query.filter_by(user_id=admin_user.id).first()
                    if smtp_setting and smtp_setting.honeypot_email_alert and smtp_setting.smtp_server and smtp_setting.smtp_sender and smtp_setting.alert_recipient:
                        subject = f"[SECURITY ALERT] Brute-Force Login Attempts Detected: {ip}"
                        local_time_str = format_local_datetime(now)
                        body_html = f"""
                        <div style="font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 0 auto; padding: 25px; border: 1px solid #fed7d7; border-radius: 12px; background-color: #fff5f5; color: #2d3748;">
                            <div style="text-align: center; margin-bottom: 20px;">
                                <h2 style="color: #c53030; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">⚠️ Brute-Force Attack Alert</h2>
                                <p style="color: #9b2c2c; margin: 5px 0 0 0; font-size: 14px;">Multiple failed attempts have been made to the login panel!</p>
                            </div>
                            
                            <table style="width: 100%; font-size: 13px; color: #4a5568; margin-bottom: 20px; background: #fff; border-radius: 8px; border: 1px solid #e2e8f0; border-collapse: separate; border-spacing: 0;">
                                <tr>
                                    <td style="padding: 10px; font-weight: bold; width: 35%; border-bottom: 1px solid #edf2f7;">Attacker IP</td>
                                    <td style="padding: 10px; border-bottom: 1px solid #edf2f7; font-weight: bold; color: #c53030;">{ip}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px; font-weight: bold; border-bottom: 1px solid #edf2f7;">Detail</td>
                                    <td style="padding: 10px; border-bottom: 1px solid #edf2f7;">5 failed login attempts within 10 minutes.</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px; font-weight: bold;">Time</td>
                                    <td style="padding: 10px;">{local_time_str}</td>
                                </tr>
                            </table>
                            
                            <div style="background-color: #fff; border-left: 4px solid #e53e3e; padding: 12px; border-radius: 4px; font-size: 13px; color: #742a2a;">
                                <strong>Status:</strong> This IP address has been automatically blocked.
                            </div>
                        </div>
                        """
                        setting_dict = {
                            "smtp_server": smtp_setting.smtp_server,
                            "smtp_port": smtp_setting.smtp_port,
                            "smtp_username": smtp_setting.smtp_username,
                            "smtp_password": smtp_setting.smtp_password,
                            "smtp_sender": smtp_setting.smtp_sender,
                            "alert_recipient": smtp_setting.alert_recipient
                        }
                        send_notification_email_async(setting_dict, subject, body_html)
            return True
    return False


def execute_scan(scan_id, audit_credentials=False):
    """
    Executes the Nmap scan in a background thread and updates the database.
    """

    with app.app_context():
        scan_result = ScanResult.query.get(scan_id)

        if not scan_result:
            return

        if scan_result.status == "cancelled":
            return

        scan_result.status = "running"
        db.session.commit()

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

        # MAC Auditing, Rogue Device Detection and Asset Sync
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

                if asset_match:
                    # Update last seen
                    asset_match.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
                    
                    # Security checks if MAC is present
                    if mac:
                        mac_clean = mac.strip().lower()
                        # 1. MAC Spoofing Check (IP is same but MAC changed)
                        if asset_match.ip_address == ip and asset_match.mac_address and asset_match.mac_address.lower() != mac_clean:
                            desc = f"IP address {ip} has changed its MAC address from {asset_match.mac_address} to {mac}. Potential MAC Spoofing!"
                            anomaly = SecurityAnomaly(
                                anomaly_type="mac_spoofing",
                                ip_address=ip,
                                mac_address=mac,
                                description=desc
                            )
                            db.session.add(anomaly)
                            host["mac_anomaly"] = {
                                "type": "mac_spoofing",
                                "expected_mac": asset_match.mac_address,
                                "found_mac": mac,
                                "description": desc
                            }
                        
                        # 2. IP Hijack Check (MAC is same but IP changed)
                        elif asset_match.mac_address and asset_match.mac_address.lower() == mac_clean and asset_match.ip_address != ip:
                            desc = f"MAC address {mac} ({vendor or 'Unknown'}) changed its IP address from {asset_match.ip_address} to {ip}."
                            anomaly = SecurityAnomaly(
                                anomaly_type="ip_hijack",
                                ip_address=ip,
                                mac_address=mac,
                                description=desc
                            )
                            db.session.add(anomaly)
                            host["mac_anomaly"] = {
                                "type": "ip_hijack",
                                "expected_ip": asset_match.ip_address,
                                "found_ip": ip,
                                "description": desc
                            }
                    
                    # Sync fields
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
                else:
                    # 3. Rogue Device (Completely new device)
                    desc = f"New unknown device detected on the network: IP {ip}, MAC {mac or 'N/A'} ({vendor or 'Unknown'})."
                    anomaly = SecurityAnomaly(
                        anomaly_type="rogue_device",
                        ip_address=ip,
                        mac_address=mac,
                        description=desc
                    )
                    db.session.add(anomaly)
                    host["mac_anomaly"] = {
                        "type": "rogue_device",
                        "description": desc
                    }
                    
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

            # Send Email Alert for MAC Anomalies if any found
            anomalies_found = [h["mac_anomaly"] for h in hosts if "mac_anomaly" in h]
            if anomalies_found:
                admin_user = User.query.filter_by(is_admin=True).first()
                if admin_user:
                    setting = SystemSetting.query.filter_by(user_id=admin_user.id).first()
                    if setting and setting.smtp_server and setting.smtp_sender and setting.alert_recipient:
                        subject = f"[SECURITY ALERT] Network MAC Anomaly Detected on {scan_result.network_cidr}"
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
                                <td style="padding: 10px; font-weight: bold; color: #c53030;">{anom_type_str}</td>
                                <td style="padding: 10px;">{anom.get('description', '')}</td>
                            </tr>
                            """
                        
                        body_html = f"""
                        <div style="font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 0 auto; padding: 25px; border: 1px solid #fed7d7; border-radius: 12px; background-color: #fff5f5; color: #2d3748;">
                            <div style="text-align: center; margin-bottom: 20px;">
                                <h2 style="color: #c53030; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">⚠️ MAC Address / Network Security Alert</h2>
                                <p style="color: #9b2c2c; margin: 5px 0 0 0; font-size: 14px;">Anomalies threatening network security were detected during the scan!</p>
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
                                <strong>Status:</strong> Please visit the PortOjo Admin Panel to examine details and manage block actions.
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
        
        if (audit_credentials or scan_result.credential_ids) and nmap_result["success"]:
            # Load custom credentials
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
                except Exception as e:
                    print(f"Error parsing custom credentials: {str(e)}")

            for host in hosts:
                ip = host.get("address")
                ports = host.get("ports", [])
                for port_info in ports:
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


def detect_device_type(hostname, mac_vendor, ports_list):
    """
    Auto-detects the device type based on hostname, mac vendor, and open ports.
    Returns one of: 'Server', 'Workstation', 'Router', 'Switch', 'Firewall', 'Printer', 'IoT', 'Mobile', 'Unknown'
    """
    hostname_lower = (hostname or "").lower()
    vendor_lower = (mac_vendor or "").lower()
    
    # Extract port numbers
    open_ports = set()
    for p in ports_list:
        if isinstance(p, dict):
            # Port info dictionary from scanner output
            port_val = p.get("port")
        else:
            port_val = p
        try:
            if port_val:
                open_ports.add(int(port_val))
        except ValueError:
            pass

    # 1. Firewall detection
    if any(k in hostname_lower for k in ["firewall", "fortigate", "pfsense", "opnsense", "checkpoint", "asa", "sonicwall"]):
        return "Firewall"
    if "firewall" in vendor_lower:
        return "Firewall"
        
    # 1.5. VoIP / IP Phone detection
    is_voip = False
    if any(k in hostname_lower for k in ["phone", "voip", "sip", "yealink", "grandstream", "snom", "fanvil", "polycom", "avaya", "mitel", "poly"]):
        is_voip = True
    elif any(k in vendor_lower for k in ["yealink", "grandstream", "snom", "fanvil", "polycom", "avaya", "mitel", "gigaset", "poly"]):
        is_voip = True
    elif any(p in open_ports for p in [2000, 5060, 5061]):  # SCCP, SIP
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

    # 1.6. IP Camera detection
    is_camera = False
    if any(k in hostname_lower for k in ["camera", "ipc", "cctv", "webcam", "dvr", "nvr"]):
        is_camera = True
    elif any(k in vendor_lower for k in ["hikvision", "dahua", "foscam", "reolink", "amcrest", "hanwha"]):
        is_camera = True
    elif "axis" in vendor_lower and "communications" in vendor_lower:
        is_camera = True
    elif 554 in open_ports:  # RTSP
        is_camera = True

    if is_camera:
        return "IP Camera"

    # 1.7. Virtual Machine detection
    if any(k in vendor_lower for k in ["vmware", "qemu", "xen", "virtualbox", "proxmox"]):
        return "Virtual Machine"
    if any(k in hostname_lower for k in ["-vm", "vm-", "virtual-"]):
        return "Virtual Machine"
        
    # 2. Router / Gateway detection
    if any(k in hostname_lower for k in ["router", "gateway", "rt-", "gw-", "ubnt", "mikrotik"]):
        return "Router"
    if any(k in vendor_lower for k in ["cisco", "juniper", "ubiquiti", "mikrotik", "linksys", "netgear", "tp-link", "asus", "zyxel"]):
        if 179 in open_ports or 520 in open_ports:  # BGP, RIP
            return "Router"
        if any(k in hostname_lower for k in ["switch", "sw-", "sw0"]):
            return "Switch"
        return "Router"
        
    # 3. Switch detection
    if any(k in hostname_lower for k in ["switch", "sw-", "catalyst", "procurve", "edge-sw"]):
        return "Switch"
    if "switch" in vendor_lower:
        return "Switch"
        
    # 4. Printer detection
    if any(k in hostname_lower for k in ["printer", "print", "copier", "epson", "hp-", "canon", "lexmark", "xerox", "brother"]):
        return "Printer"
    if any(p in open_ports for p in [515, 631, 9100]):  # LPD, IPP, JetDirect
        return "Printer"
    if any(k in vendor_lower for k in ["epson", "canon", "lexmark", "brother", "xerox", "konica", "ricoh", "kyocera", "okidata"]):
        return "Printer"
        
    # 5. Mobile detection
    if any(k in hostname_lower for k in ["android", "iphone", "ipad", "phone", "galaxy", "huawei", "xiaomi"]):
        return "Mobile"
    if any(k in vendor_lower for k in ["apple", "samsung", "huawei", "motorola", "htc", "xiaomi", "nokia", "oneplus"]):
        if not any(p in open_ports for p in [80, 443, 22, 3389, 445]):
            return "Mobile"

    # 6. IoT detection
    if any(k in hostname_lower for k in ["iot", "smart", "camera", "dvr", "nvr", "tv", "chromecast", "raspberry"]):
        return "IoT"
    if any(p in open_ports for p in [1883, 8883]):  # MQTT
        return "IoT"
    if any(k in vendor_lower for k in ["synology", "qnap"]):  # NAS
        return "IoT"
        
    # 7. Server detection
    server_ports = {3306, 5432, 1433, 1521, 389, 636, 110, 995, 143, 993, 25, 465, 587, 8080, 8443, 9000, 27017}
    if any(p in open_ports for p in server_ports):
        return "Server"
    if "server" in hostname_lower:
        return "Server"
        
    # 8. Workstation detection
    if any(k in hostname_lower for k in ["pc", "desktop", "laptop", "workstation", "client", "win10", "win11"]):
        return "Workstation"
    if any(p in open_ports for p in [139, 445, 3389]):  # NetBIOS, SMB, RDP
        if "server" in hostname_lower:
            return "Server"
        return "Workstation"
        
    if 22 in open_ports or 23 in open_ports:  # SSH, Telnet
        if any(k in vendor_lower for k in ["dell", "hp ", "hewlett", "supermicro", "vmware", "lenovo", "ibm", "fujitsu"]):
            return "Server"
        if "server" in hostname_lower:
            return "Server"
        return "Unknown"
        
    return "Unknown"


def admin_required(function):
    #Allows access only to authenticated admin users.


    @wraps(function)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))

        if not current_user.is_admin:
            flash("You are not authorised to access this page.", "error")
            return redirect(url_for("scan"))

        return function(*args, **kwargs)

    return decorated_function

def migrate_db_schema():
    """
    Safely adds new columns to database tables if they don't exist.
    """
    from sqlalchemy import text
    
    # 1. User table migrations
    try:
        db.session.execute(text("SELECT otp_secret FROM user LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE user ADD COLUMN otp_secret VARCHAR(32)"))
            db.session.commit()
            click.echo("Database schema migrated: added otp_secret to user table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating user table: {str(e)}")

    # 2. SystemSetting table migrations (scan_freeze columns)
    try:
        db.session.execute(text("SELECT scan_freeze_active FROM system_setting LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE system_setting ADD COLUMN scan_freeze_active BOOLEAN DEFAULT 0"))
            db.session.execute(text("ALTER TABLE system_setting ADD COLUMN scan_freeze_start VARCHAR(5) DEFAULT '09:00'"))
            db.session.execute(text("ALTER TABLE system_setting ADD COLUMN scan_freeze_end VARCHAR(5) DEFAULT '17:00'"))
            db.session.commit()
            click.echo("Database schema migrated: added scan_freeze columns to system_setting table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating system_setting table: {str(e)}")

    # 3. SystemSetting table migration for scan_exclude_targets
    try:
        db.session.execute(text("SELECT scan_exclude_targets FROM system_setting LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE system_setting ADD COLUMN scan_exclude_targets TEXT"))
            db.session.commit()
            click.echo("Database schema migrated: added scan_exclude_targets to system_setting table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating scan_exclude_targets in system_setting table: {str(e)}")

    # 4. ScanResult table migration for exclude_targets
    try:
        db.session.execute(text("SELECT exclude_targets FROM scan_result LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE scan_result ADD COLUMN exclude_targets TEXT"))
            db.session.commit()
            click.echo("Database schema migrated: added exclude_targets to scan_result table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating exclude_targets in scan_result table: {str(e)}")

    # 5. ScanSchedule table migration for exclude_targets
    try:
        db.session.execute(text("SELECT exclude_targets FROM scan_schedule LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE scan_schedule ADD COLUMN exclude_targets TEXT"))
            db.session.commit()
            click.echo("Database schema migrated: added exclude_targets to scan_schedule table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating exclude_targets in scan_schedule table: {str(e)}")

    # 6. SystemSetting table migration for scan_exclusions_active
    try:
        db.session.execute(text("SELECT scan_exclusions_active FROM system_setting LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE system_setting ADD COLUMN scan_exclusions_active BOOLEAN DEFAULT 1"))
            db.session.commit()
            click.echo("Database schema migrated: added scan_exclusions_active to system_setting table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating scan_exclusions_active in system_setting table: {str(e)}")

    # 7. ScanCredential table migration
    try:
        db.session.execute(text("SELECT id FROM scan_credential LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS scan_credential (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    username VARCHAR(100),
                    password VARCHAR(100),
                    protocol VARCHAR(20) DEFAULT 'any',
                    created_at DATETIME,
                    FOREIGN KEY(user_id) REFERENCES user(id)
                )
            """))
            db.session.commit()
            click.echo("Database schema migrated: created scan_credential table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating scan_credential table: {str(e)}")

    # 8. ScanResult table migration for credential_ids
    try:
        db.session.execute(text("SELECT credential_ids FROM scan_result LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE scan_result ADD COLUMN credential_ids TEXT"))
            db.session.commit()
            click.echo("Database schema migrated: added credential_ids to scan_result table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating credential_ids in scan_result table: {str(e)}")

    # 9. ScanSchedule table migration for credential_ids
    try:
        db.session.execute(text("SELECT credential_ids FROM scan_schedule LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE scan_schedule ADD COLUMN credential_ids TEXT"))
            db.session.commit()
            click.echo("Database schema migrated: added credential_ids to scan_schedule table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating credential_ids in scan_schedule table: {str(e)}")

    # 10. ScanResult table migration for timing_template
    try:
        db.session.execute(text("SELECT timing_template FROM scan_result LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE scan_result ADD COLUMN timing_template VARCHAR(2) DEFAULT '4'"))
            db.session.commit()
            click.echo("Database schema migrated: added timing_template to scan_result table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating timing_template in scan_result table: {str(e)}")

    # 11. ScanSchedule table migration for timing_template
    try:
        db.session.execute(text("SELECT timing_template FROM scan_schedule LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE scan_schedule ADD COLUMN timing_template VARCHAR(2) DEFAULT '4'"))
            db.session.commit()
            click.echo("Database schema migrated: added timing_template to scan_schedule table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating timing_template in scan_schedule table: {str(e)}")

    # 12. Migrate plaintext user 2FA secrets to encrypted format
    try:
        users = User.query.filter(User._otp_secret.isnot(None)).all()
        migrated_count = 0
        for u in users:
            raw_secret = u._otp_secret
            if raw_secret and not raw_secret.startswith("gAAAA"):
                # It is a plaintext secret, so encrypt it!
                u.otp_secret = raw_secret
                migrated_count += 1
        if migrated_count > 0:
            db.session.commit()
            click.echo(f"Database migration: Encrypted {migrated_count} plaintext user 2FA secrets.")
    except Exception as e:
        db.session.rollback()
        click.echo(f"Error migrating user 2FA secrets: {str(e)}")

    # 13. ScanResult table migration for audit_credentials
    try:
        db.session.execute(text("SELECT audit_credentials FROM scan_result LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE scan_result ADD COLUMN audit_credentials BOOLEAN DEFAULT 0"))
            db.session.commit()
            click.echo("Database schema migrated: added audit_credentials to scan_result table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating audit_credentials in scan_result table: {str(e)}")

    # 14. ScanSchedule table migration for audit_credentials
    try:
        db.session.execute(text("SELECT audit_credentials FROM scan_schedule LIMIT 1"))
    except Exception:
        db.session.rollback()
        try:
            db.session.execute(text("ALTER TABLE scan_schedule ADD COLUMN audit_credentials BOOLEAN DEFAULT 0"))
            db.session.commit()
            click.echo("Database schema migrated: added audit_credentials to scan_schedule table.")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error migrating audit_credentials in scan_schedule table: {str(e)}")



def is_in_freeze_window(start_str, end_str):
    """
    Checks if the current local time falls within the freeze window.
    Handles intervals spanning across midnight (e.g. 22:00 to 06:00).
    """
    try:
        start_time = datetime.strptime(start_str.strip(), "%H:%M").time()
        end_time = datetime.strptime(end_str.strip(), "%H:%M").time()
        
        # Get current local time using APP_TIMEZONE
        now_local = datetime.now(APP_TIMEZONE).time()
        
        if start_time <= end_time:
            # Same day (e.g. 09:00 - 17:00)
            return start_time <= now_local <= end_time
        else:
            # Over midnight (e.g. 22:00 - 06:00)
            return now_local >= start_time or now_local <= end_time
    except Exception:
        return False

def is_scan_frozen():
    """
    Returns True if the system has a scan blackout active and
    the current local time is inside that window.
    """
    try:
        admin_user = User.query.filter_by(is_admin=True).first()
        if not admin_user:
            return False
        admin_setting = SystemSetting.query.filter_by(user_id=admin_user.id).first()
        if not admin_setting or not admin_setting.scan_freeze_active:
            return False
        return is_in_freeze_window(admin_setting.scan_freeze_start, admin_setting.scan_freeze_end)
    except Exception:
        return False

@app.cli.command("init-db")
def init_db():
    """
    Initialises the database tables.
    Run with:
        python -m flask --app app init-db
    """

    db.create_all()
    migrate_db_schema()
    click.echo("Database tables created successfully.")

def print_cli_qr(prov_uri):
    """
    Renders and prints a QR code to the CLI terminal using UTF-8 encoding.
    """
    import sys
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
            
    try:
        import qrcode
        qr = qrcode.QRCode()
        qr.add_data(prov_uri)
        click.echo("\nScan the QR code below with your Authenticator App:")
        qr.print_ascii(out=sys.stdout)
        click.echo("")
    except Exception as e:
        click.echo(f"Could not render terminal QR code: {str(e)}")

@app.cli.command("create-admin")
def create_admin():
    """
    Creates the only admin user for PortOjo or resets their credentials/2FA.
    Run with:
        python -m flask --app app create-admin
    """

    db.create_all()
    migrate_db_schema()

    existing_admin = User.query.filter_by(is_admin=True).first()

    if existing_admin:
        click.echo(f"An admin user already exists: {existing_admin.email}")
        if not click.confirm("Do you want to reset their password and 2FA OTP secret?"):
            return
        
        # Security verification: require current password or app SECRET_KEY
        auth_success = False
        attempts = 3
        while attempts > 0:
            current_pass_or_key = click.prompt(
                "Enter current Admin password OR the App SECRET_KEY to authorise reset",
                hide_input=True
            ).strip()
            
            if check_password_hash(existing_admin.password_hash, current_pass_or_key) or current_pass_or_key == app.config.get("SECRET_KEY"):
                auth_success = True
                break
            else:
                attempts -= 1
                click.echo(f"Authorisation failed. Incorrect password or secret key. {attempts} attempts remaining.")
        
        if not auth_success:
            click.echo("Too many failed attempts. Aborting reset.")
            return

        password = click.prompt(
            "New Admin password",
            hide_input=True,
            confirmation_prompt=True
        )
        
        otp_secret = pyotp.random_base32()
        existing_admin.password_hash = generate_password_hash(password)
        existing_admin.otp_secret = otp_secret
        db.session.commit()
        
        click.echo("==================================================")
        click.echo("ADMIN CREDENTIALS & 2FA OTP SECRET RESET SUCCESSFUL")
        click.echo("==================================================")
        click.echo(f"Admin Email: {existing_admin.email}")
        click.echo(f"Secret Key (Base32): {otp_secret}")
        prov_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=existing_admin.email, issuer_name="PortOjo")
        click.echo(f"Provisioning URI: {prov_uri}")
        print_cli_qr(prov_uri)
        click.echo("Please add this secret key or scan the URI in your Authenticator app (e.g. Google Authenticator).")
        click.echo("==================================================")
        return

    email = click.prompt("Admin email").strip().lower()

    existing_user = User.query.filter_by(email=email).first()

    password = click.prompt(
        "Admin password",
        hide_input=True,
        confirmation_prompt=True
    )

    otp_secret = pyotp.random_base32()

    if existing_user:
        existing_user.is_admin = True
        existing_user.password_hash = generate_password_hash(password)
        existing_user.otp_secret = otp_secret
        db.session.commit()

        click.echo(f"Existing user {email} has been promoted to admin.")
    else:
        admin_user = User(
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=True,
            otp_secret=otp_secret
        )
        db.session.add(admin_user)
        db.session.commit()
        click.echo(f"Admin user {email} created successfully.")

    click.echo("==================================================")
    click.echo("2-FACTOR AUTHENTICATION (2FA) ENABLED FOR ADMIN")
    click.echo("==================================================")
    click.echo(f"Secret Key (Base32): {otp_secret}")
    prov_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=email, issuer_name="PortOjo")
    click.echo(f"Provisioning URI: {prov_uri}")
    print_cli_qr(prov_uri)
    click.echo("Please add this secret key or scan the URI in your Authenticator app (e.g. Google Authenticator).")
    click.echo("==================================================")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def cleanup_stale_scans():
    """
    Marks old pending/running scans as failed.
    This prevents scans from staying in an active state after application restart.
    """

    stale_threshold = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=30)

    stale_scans = ScanResult.query.filter(
        ScanResult.status.in_(["pending", "running"]),
        ScanResult.created_at < stale_threshold
    ).all()

    for scan in stale_scans:
        scan.status = "failed"

        result_payload = {
            "command": "N/A",
            "output": "Scan was interrupted or left unfinished after application restart.",
            "hosts": []
        }

        scan.result_data = json.dumps(result_payload, indent=4)

    if stale_scans:
        db.session.commit()

def run_scheduler_loop():
    """
    Background loop that checks for schedules that need execution.
    It runs as a daemon thread and uses SQLAlchemy query context.
    """
    # Wait for the database and app to initialise
    time.sleep(5)
    
    while True:
        try:
            with app.app_context():
                if is_scan_frozen():
                    # Scan freeze active, defer scheduled scans
                    pass
                else:
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    due_schedules = ScanSchedule.query.filter(
                        ScanSchedule.is_active == True,
                        ScanSchedule.next_run <= now
                    ).all()
                    
                    for schedule in due_schedules:
                        # 1. Create a new ScanResult record
                        scan = ScanResult(
                            user_id=schedule.user_id,
                            input_ip=schedule.input_ip,
                            subnet_mask=schedule.subnet_mask,
                            scan_type=schedule.scan_type,
                            ports=schedule.ports,
                            network_cidr=schedule.network_cidr,
                            exclude_targets=schedule.exclude_targets,
                            credential_ids=schedule.credential_ids,
                            timing_template=schedule.timing_template,
                            audit_credentials=schedule.audit_credentials,
                            status="pending"
                        )
                        db.session.add(scan)
                        db.session.commit()
                        
                        # 2. Trigger the scan execution in a separate thread
                        threading.Thread(
                            target=execute_scan,
                            args=(scan.id, schedule.audit_credentials),
                            daemon=True
                        ).start()
                        
                        # 3. Update the schedule's last_run and next_run times
                        schedule.last_run = now
                        
                        if schedule.frequency == "hourly":
                            schedule.next_run = now + timedelta(hours=1)
                        elif schedule.frequency == "daily":
                            schedule.next_run = now + timedelta(days=1)
                        elif schedule.frequency == "weekly":
                            schedule.next_run = now + timedelta(weeks=1)
                        elif schedule.frequency == "monthly":
                            schedule.next_run = now + timedelta(days=30)
                        else:
                            schedule.next_run = now + timedelta(days=1)
                            
                        db.session.commit()
                    
        except Exception as e:
            import sys
            print(f"[Scheduler Error]: {str(e)}", file=sys.stderr)
            
        time.sleep(30) # Poll every 30 seconds

import os
if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
    threading.Thread(target=run_scheduler_loop, daemon=True).start()


@app.cli.command("cleanup-scans")
def cleanup_scans_command():
    """
    Cleans up stale pending/running scans manually.
    Run with:
        python -m flask --app app cleanup-scans
    """

    db.create_all()
    cleanup_stale_scans()
    click.echo("Stale scans cleaned up successfully.")

def user_can_view_scan(scan_result):
    """
    Checks whether the current user can view the given scan result.
    Normal users can view only their own scans.
    Admin users can view all scans.
    """

    return scan_result.user_id == current_user.id or current_user.is_admin

def format_local_datetime(value):
    """
    Converts stored UTC datetime to Europe/Istanbul local time.
    """

    if not value:
        return ""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    local_value = value.astimezone(APP_TIMEZONE)

    return local_value.strftime("%Y-%m-%d %H:%M:%S")


@app.template_filter("localtime")
def localtime_filter(value):
    return format_local_datetime(value)

SCAN_TYPE_NAMES = {
    "fast": "Fast Port Scan (TCP)",
    "service_version": "Service & Version Scan (TCP)",
    "ping_sweep": "Host Discovery (Ping Sweep)",
    "syn": "TCP SYN Scan (Half-Open)",
    "connect": "TCP Connect Scan (Full Handshake)",
    "udp": "UDP Port Scan",
    "aggressive": "Aggressive Scan",
    "vuln": "Vulnerability Scan (NSE)",
    "quick": "Quick Scan (Legacy)",
    "detailed": "Detailed Scan (Legacy)"
}

@app.template_filter("scan_name")
def scan_name_filter(value):
    return SCAN_TYPE_NAMES.get(value, value.capitalize() if value else "")

@app.route("/dashboard")
@login_required
def dashboard():
    # 1. Fetch user scan stats
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    running_scans = ScanResult.query.filter_by(user_id=current_user.id).filter(ScanResult.status.in_(["pending", "running"])).count()
    completed_scans = ScanResult.query.filter_by(user_id=current_user.id, status="completed").count()
    failed_scans = ScanResult.query.filter_by(user_id=current_user.id, status="failed").count()
    
    # 2. Fetch user schedules stats
    total_schedules = ScanSchedule.query.filter_by(user_id=current_user.id).count()
    active_schedules = ScanSchedule.query.filter_by(user_id=current_user.id, is_active=True).count()
    
    # 3. Check Honeypot & SMTP status
    admin_user = User.query.filter_by(is_admin=True).first()
    
    # Honeypot is a global setting managed by the admin
    honeypot_user_id = admin_user.id if admin_user else current_user.id
    honeypot_setting = SystemSetting.query.filter_by(user_id=honeypot_user_id).first()
    honeypot_active = honeypot_setting.honeypot_active if honeypot_setting else False
    
    # SMTP alerts are user-specific; standard users configure their own SMTP settings
    user_smtp_setting = SystemSetting.query.filter_by(user_id=current_user.id).first()
    smtp_configured = True if (
        user_smtp_setting and 
        user_smtp_setting.smtp_server and 
        user_smtp_setting.smtp_sender and 
        user_smtp_setting.alert_recipient
    ) else False
    
    user_stats = {
        "total_scans": total_scans,
        "running_scans": running_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "total_schedules": total_schedules,
        "active_schedules": active_schedules,
    }
    
    # 4. Fetch admin stats (if admin)
    admin_stats = {}
    if current_user.is_admin:
        admin_stats["active_anomalies"] = SecurityAnomaly.query.filter_by(is_resolved=False).count()
        admin_stats["untrusted_devices"] = Asset.query.filter_by(is_trusted=False).count()
        admin_stats["total_assets"] = Asset.query.count()
        admin_stats["honeypot_logs_count"] = HoneypotLog.query.count()
        admin_stats["blocked_ips_count"] = HoneypotBlockedIP.query.count()
        
    # 5. Fetch recent 5 scans
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.created_at.desc()).limit(5).all()
    
    current_date = format_local_datetime(datetime.now(timezone.utc).replace(tzinfo=None))
    
    return render_template(
        "dashboard.html",
        user_stats=user_stats,
        admin_stats=admin_stats,
        recent_scans=recent_scans,
        honeypot_active=honeypot_active,
        smtp_configured=smtp_configured,
        current_date=current_date,
        honeypot_paths_count=len(HONEYPOT_PATHS)
    )


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not email or not password or not confirm_password:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("A user with that email address is already registered.", "error")
            return redirect(url_for("register"))

        new_user = User(
            email=email,
            password_hash=generate_password_hash(password)
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if client_ip and ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password_hash, password):
            record_failed_login(client_ip)
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

        if user.otp_secret:
            session["pre_2fa_user_id"] = user.id
            if client_ip in FAILED_LOGIN_ATTEMPTS:
                del FAILED_LOGIN_ATTEMPTS[client_ip]
            return redirect(url_for("login_2fa"))
        elif user.is_admin:
            session["setup_2fa_user_id"] = user.id
            session["setup_2fa_secret"] = pyotp.random_base32()
            if client_ip in FAILED_LOGIN_ATTEMPTS:
                del FAILED_LOGIN_ATTEMPTS[client_ip]
            return redirect(url_for("login_2fa_setup"))

        login_user(user)
        if client_ip in FAILED_LOGIN_ATTEMPTS:
            del FAILED_LOGIN_ATTEMPTS[client_ip]
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    pre_2fa_user_id = session.get("pre_2fa_user_id")
    if not pre_2fa_user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, pre_2fa_user_id)
    if not user or not user.otp_secret:
        session.pop("pre_2fa_user_id", None)
        flash("Invalid login session.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp_code):
            login_user(user)
            session.pop("pre_2fa_user_id", None)
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid verification code. Please try again.", "error")

    return render_template("login_2fa.html")


def generate_base64_qr(uri):
    """
    Generates a Base64 encoded SVG image for the given provisioning URI.
    """
    import base64
    import io
    import qrcode
    import qrcode.image.svg
    
    factory = qrcode.image.svg.SvgImage
    img = qrcode.make(uri, image_factory=factory)
    
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/svg+xml;base64,{img_str}"


@app.route("/login/2fa-setup", methods=["GET", "POST"])
def login_2fa_setup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    setup_2fa_user_id = session.get("setup_2fa_user_id")
    setup_2fa_secret = session.get("setup_2fa_secret")

    if not setup_2fa_user_id or not setup_2fa_secret:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, setup_2fa_user_id)
    if not user or not user.is_admin or user.otp_secret:
        session.pop("setup_2fa_user_id", None)
        session.pop("setup_2fa_secret", None)
        flash("Invalid setup session.", "error")
        return redirect(url_for("login"))

    prov_uri = pyotp.totp.TOTP(setup_2fa_secret).provisioning_uri(
        name=user.email, issuer_name="PortOjo"
    )
    
    qr_code_base64 = generate_base64_qr(prov_uri)

    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        totp = pyotp.TOTP(setup_2fa_secret)
        if totp.verify(otp_code):
            user.otp_secret = setup_2fa_secret
            db.session.commit()
            login_user(user)
            session.pop("setup_2fa_user_id", None)
            session.pop("setup_2fa_secret", None)
            flash("2FA configured and login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid verification code. Please try again.", "error")

    return render_template(
        "login_2fa_setup.html",
        secret_key=setup_2fa_secret,
        prov_uri=prov_uri,
        qr_code_base64=qr_code_base64
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout successful.", "success")
    return redirect(url_for("login"))


@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    if request.method == "POST":
        if is_scan_frozen():
            flash("Scan blocked due to Scan Blackout Window", "error")
            return redirect(url_for("scan"))
            
        ip_address = request.form.get("ip_address", "").strip()
        subnet_mask = request.form.get("subnet_mask", "").strip()
        scan_type = request.form.get("scan_type", "").strip()
        ports = request.form.get("ports", "").replace(" ", "").strip()
        timing_template = request.form.get("timing_template", "4").strip()

        if not ip_address or not scan_type:
            flash("Please fill in all required scan fields.", "error")
            return redirect(url_for("scan"))

        valid_scan_types = [
            "quick", "detailed",
            "fast", "service_version", "ping_sweep",
            "syn", "connect", "udp", "aggressive", "vuln"
        ]

        if scan_type not in valid_scan_types:
            flash("Invalid scan type selected.", "error")
            return redirect(url_for("scan"))

        if ports:
            # Validate format (e.g. "80", "80,443", "1-1000", "22,80-100")
            if not re.match(r"^[0-9,-]+$", ports):
                flash("Invalid ports format. Use numbers, commas, and hyphens (e.g., 22,80,443 or 1-1000).", "error")
                return redirect(url_for("scan"))

        network_info = calculate_network(ip_address, subnet_mask if subnet_mask else None)

        if not network_info["success"]:
            flash(f"Invalid scan target: {network_info['error']}", "error")
            return redirect(url_for("scan"))
        
        target_validation = validate_scan_target(network_info, scan_type)

        if not target_validation["success"]:
            flash(target_validation["error"], "error")
            return redirect(url_for("scan"))

        exclude_targets = request.form.get("exclude_targets", "").strip()
        selected_creds = request.form.getlist("credential_ids")
        credential_ids_str = ",".join(selected_creds) if selected_creds else None

        audit_credentials = request.form.get("audit_credentials") == "y"

        scan_result = ScanResult(
            user_id=current_user.id,
            input_ip=ip_address,
            subnet_mask=subnet_mask if subnet_mask else "N/A",
            scan_type=scan_type,
            ports=ports if ports else None,
            network_cidr=network_info["cidr"],
            first_host=network_info["first_host"],
            last_host=network_info["last_host"],
            exclude_targets=exclude_targets if exclude_targets else None,
            credential_ids=credential_ids_str,
            timing_template=timing_template,
            audit_credentials=audit_credentials,
            status="pending"
        )

        db.session.add(scan_result)
        db.session.commit()

        scan_thread = threading.Thread(
            target=execute_scan,
            args=(scan_result.id, audit_credentials)
        )
        scan_thread.daemon = True
        scan_thread.start()

        return redirect(url_for("result", scan_id=scan_result.id))

    # Gather scan freeze details to display warning alert if active
    admin_user = User.query.filter_by(is_admin=True).first()
    admin_setting = SystemSetting.query.filter_by(user_id=admin_user.id).first() if admin_user else None
    is_frozen = False
    freeze_start = "09:00"
    freeze_end = "17:00"
    if admin_setting:
        freeze_start = admin_setting.scan_freeze_start
        freeze_end = admin_setting.scan_freeze_end
        if admin_setting.scan_freeze_active:
            is_frozen = is_in_freeze_window(freeze_start, freeze_end)

    user_credentials = ScanCredential.query.filter_by(user_id=current_user.id).order_by(ScanCredential.name).all()

    return render_template(
        "scan.html",
        is_frozen=is_frozen,
        freeze_start=freeze_start,
        freeze_end=freeze_end,
        user_credentials=user_credentials
    )

@app.route("/scan/<int:scan_id>/stop", methods=["POST"])
@login_required
def stop_scan(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    
    if scan_result.user_id != current_user.id and not current_user.is_admin:
        flash("You are not authorised to stop this scan.", "error")
        return redirect(url_for("result", scan_id=scan_id))
        
    if scan_result.status in ["pending", "running"]:
        scan_result.status = "cancelled"
        db.session.commit()
        
        # Kill the running subprocess
        from scanner import stop_scan_process
        stopped = stop_scan_process(scan_id)
        if stopped:
            flash("Scan has been stopped successfully.", "success")
        else:
            flash("Scan marked as cancelled, but no active process was running.", "warning")
            
    return redirect(url_for("result", scan_id=scan_id))

@app.route("/scan/<int:scan_id>/repeat", methods=["POST"])
@login_required
def repeat_scan(scan_id):
    if is_scan_frozen():
        flash("Scan blocked due to Scan Blackout Window", "error")
        return redirect(url_for("result", scan_id=scan_id))
        
    old_scan = ScanResult.query.get_or_404(scan_id)
    
    if old_scan.user_id != current_user.id and not current_user.is_admin:
        flash("You are not authorised to repeat this scan.", "error")
        return redirect(url_for("scan"))
        
    network_info = calculate_network(old_scan.input_ip, old_scan.subnet_mask if old_scan.subnet_mask != "N/A" else None)
    if not network_info["success"]:
        flash(f"Invalid scan target: {network_info['error']}", "error")
        return redirect(url_for("scan"))
        
    target_validation = validate_scan_target(network_info, old_scan.scan_type)
    if not target_validation["success"]:
        flash(target_validation["error"], "error")
        return redirect(url_for("scan"))
        
    scan_result = ScanResult(
        user_id=current_user.id,
        input_ip=old_scan.input_ip,
        subnet_mask=old_scan.subnet_mask,
        scan_type=old_scan.scan_type,
        ports=old_scan.ports,
        network_cidr=old_scan.network_cidr,
        first_host=old_scan.first_host,
        last_host=old_scan.last_host,
        exclude_targets=old_scan.exclude_targets,
        credential_ids=old_scan.credential_ids,
        timing_template=old_scan.timing_template,
        audit_credentials=old_scan.audit_credentials,
        status="pending"
    )
    
    db.session.add(scan_result)
    db.session.commit()
    
    scan_thread = threading.Thread(
        target=execute_scan,
        args=(scan_result.id, old_scan.audit_credentials)
    )
    scan_thread.daemon = True
    scan_thread.start()
    
    flash("Repeated scan initiated.", "success")
    return redirect(url_for("result", scan_id=scan_result.id))

@app.route("/history")
@login_required
def history():
    scan_results = ScanResult.query.filter_by(
        user_id=current_user.id
    ).order_by(
        ScanResult.created_at.desc()
    ).all()

    has_active_scans = any(
        scan.status in ["pending", "running"] for scan in scan_results
    )

    return render_template(
        "history.html",
        scan_results=scan_results,
        has_active_scans=has_active_scans
    )

@app.route("/schedules")
@login_required
def schedules():
    schedules_list = ScanSchedule.query.filter_by(
        user_id=current_user.id
    ).order_by(
        ScanSchedule.created_at.desc()
    ).all()
    
    return render_template(
        "schedules.html",
        schedules=schedules_list
    )

@app.route("/schedules/new", methods=["GET", "POST"])
@login_required
def new_schedule():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        subnet_mask = request.form.get("subnet_mask", "").strip()
        scan_type = request.form.get("scan_type", "").strip()
        ports = request.form.get("ports", "").replace(" ", "").strip()
        frequency = request.form.get("frequency", "").strip()
        timing_template = request.form.get("timing_template", "4").strip()

        if not name or not ip_address or not scan_type or not frequency:
            flash("Please fill in all required schedule fields.", "error")
            return redirect(url_for("new_schedule"))

        valid_frequencies = ["hourly", "daily", "weekly", "monthly"]
        if frequency not in valid_frequencies:
            flash("Invalid frequency selected.", "error")
            return redirect(url_for("new_schedule"))

        valid_scan_types = [
            "quick", "detailed",
            "fast", "service_version", "ping_sweep",
            "syn", "connect", "udp", "aggressive", "vuln"
        ]
        if scan_type not in valid_scan_types:
            flash("Invalid scan type selected.", "error")
            return redirect(url_for("new_schedule"))

        if ports:
            if not re.match(r"^[0-9,-]+$", ports):
                flash("Invalid ports format. Use numbers, commas, and hyphens.", "error")
                return redirect(url_for("new_schedule"))

        network_info = calculate_network(ip_address, subnet_mask if subnet_mask else None)
        if not network_info["success"]:
            flash(f"Invalid scan target: {network_info['error']}", "error")
            return redirect(url_for("new_schedule"))
        
        target_validation = validate_scan_target(network_info, scan_type)
        if not target_validation["success"]:
            flash(target_validation["error"], "error")
            return redirect(url_for("new_schedule"))

        # Calculate initial next_run based on frequency
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if frequency == "hourly":
            next_run = now + timedelta(hours=1)
        elif frequency == "daily":
            next_run = now + timedelta(days=1)
        elif frequency == "weekly":
            next_run = now + timedelta(weeks=1)
        elif frequency == "monthly":
            next_run = now + timedelta(days=30)
        else:
            next_run = now + timedelta(days=1)

        exclude_targets = request.form.get("exclude_targets", "").strip()
        selected_creds = request.form.getlist("credential_ids")
        credential_ids_str = ",".join(selected_creds) if selected_creds else None
        audit_credentials = request.form.get("audit_credentials") == "y"

        schedule = ScanSchedule(
            user_id=current_user.id,
            name=name,
            input_ip=ip_address,
            subnet_mask=subnet_mask if subnet_mask else "N/A",
            scan_type=scan_type,
            ports=ports if ports else None,
            network_cidr=network_info["cidr"],
            frequency=frequency,
            exclude_targets=exclude_targets if exclude_targets else None,
            credential_ids=credential_ids_str,
            timing_template=timing_template,
            audit_credentials=audit_credentials,
            next_run=next_run
        )

        db.session.add(schedule)
        db.session.commit()

        flash("Scan schedule created successfully.", "success")
        return redirect(url_for("schedules"))

    user_credentials = ScanCredential.query.filter_by(user_id=current_user.id).order_by(ScanCredential.name).all()
    return render_template("schedule_form.html", user_credentials=user_credentials)

@app.route("/schedules/<int:schedule_id>/toggle", methods=["POST"])
@login_required
def toggle_schedule(schedule_id):
    schedule = ScanSchedule.query.get_or_404(schedule_id)
    
    if schedule.user_id != current_user.id and not current_user.is_admin:
        flash("You are not authorised to modify this schedule.", "error")
        return redirect(url_for("schedules"))

    schedule.is_active = not schedule.is_active
    db.session.commit()

    status_str = "activated" if schedule.is_active else "paused"
    flash(f"Schedule '{schedule.name}' has been {status_str}.", "success")
    return redirect(url_for("schedules"))

@app.route("/schedules/<int:schedule_id>/delete", methods=["POST"])
@login_required
def delete_schedule(schedule_id):
    schedule = ScanSchedule.query.get_or_404(schedule_id)
    
    if schedule.user_id != current_user.id and not current_user.is_admin:
        flash("You are not authorised to delete this schedule.", "error")
        return redirect(url_for("schedules"))

    db.session.delete(schedule)
    db.session.commit()

    flash(f"Schedule '{schedule.name}' has been deleted.", "success")
    return redirect(url_for("schedules"))

@app.route("/result/<int:scan_id>/report")
@login_required
def print_report(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)

    if not user_can_view_scan(scan_result):
        flash("You are not authorised to view this scan report.", "error")
        return redirect(url_for("scan"))

    parsed_result = None
    if scan_result.result_data:
        try:
            parsed_result = json.loads(scan_result.result_data)
        except json.JSONDecodeError:
            parsed_result = {
                "command": "Legacy text output",
                "output": scan_result.result_data,
                "hosts": []
            }

    return render_template(
        "report.html",
        scan_result=scan_result,
        parsed_result=parsed_result
    )

@app.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)

    if not user_can_view_scan(scan_result):
        flash("You are not authorised to view this scan result.", "error")
        return redirect(url_for("scan"))

    parsed_result = None

    if scan_result.result_data:
        try:
            parsed_result = json.loads(scan_result.result_data)
        except json.JSONDecodeError:
            parsed_result = {
                "command": "Legacy text output",
                "output": scan_result.result_data,
                "hosts": []
            }

    return render_template(
        "result.html",
        scan_result=scan_result,
        parsed_result=parsed_result
    )

@app.route("/result/<int:scan_id>/export/csv")
@login_required
def export_result_csv(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)

    if not user_can_view_scan(scan_result):
        flash("You are not authorised to export this scan result.", "error")
        return redirect(url_for("scan"))

    if not scan_result.result_data:
        flash("No result data available for export.", "error")
        return redirect(url_for("result", scan_id=scan_result.id))

    try:
        parsed_result = json.loads(scan_result.result_data)
    except json.JSONDecodeError:
        flash("This scan result is not available in structured format.", "error")
        return redirect(url_for("result", scan_id=scan_result.id))

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Scan ID",
        "Created At",
        "Input IP",
        "Subnet Mask",
        "Calculated Network",
        "Scan Type",
        "Scanned Ports",
        "Scan Status",
        "Executed Command",
        "Host",
        "Hostname",
        "Host Status",
        "Port",
        "Protocol",
        "Port State",
        "Service",
        "Version"
    ])

    hosts = parsed_result.get("hosts", [])

    if hosts:
        for host in hosts:
            ports = host.get("ports", [])

            if ports:
                for port in ports:
                    writer.writerow([
                        scan_result.id,
                        format_local_datetime(scan_result.created_at),
                        scan_result.input_ip,
                        scan_result.subnet_mask,
                        scan_result.network_cidr,
                        scan_name_filter(scan_result.scan_type),
                        scan_result.ports if scan_result.ports else "Default",
                        scan_result.status,
                        parsed_result.get("command", ""),
                        host.get("address", ""),
                        host.get("hostname", ""),
                        host.get("status", ""),
                        port.get("port", ""),
                        port.get("protocol", ""),
                        port.get("state", ""),
                        port.get("service", ""),
                        port.get("version", "")
                    ])
            else:
                writer.writerow([
                    scan_result.id,
                    format_local_datetime(scan_result.created_at),
                    scan_result.input_ip,
                    scan_result.subnet_mask,
                    scan_result.network_cidr,
                    scan_name_filter(scan_result.scan_type),
                    scan_result.ports if scan_result.ports else "Default",
                    scan_result.status,
                    parsed_result.get("command", ""),
                    host.get("address", ""),
                    host.get("hostname", ""),
                    host.get("status", ""),
                    "",
                    "",
                    "",
                    "",
                    ""
                ])
    else:
        writer.writerow([
            scan_result.id,
            format_local_datetime(scan_result.created_at),
            scan_result.input_ip,
            scan_result.subnet_mask,
            scan_result.network_cidr,
            scan_name_filter(scan_result.scan_type),
            scan_result.ports if scan_result.ports else "Default",
            scan_result.status,
            parsed_result.get("command", ""),
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            ""
        ])

    filename = f"portojo_scan_{scan_result.id}.csv"

    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@app.route("/result/<int:scan_id>/export/json")
@login_required
def export_result_json(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)

    if not user_can_view_scan(scan_result):
        flash("You are not authorised to export this scan result.", "error")
        return redirect(url_for("scan"))

    if not scan_result.result_data:
        flash("No result data available for export.", "error")
        return redirect(url_for("result", scan_id=scan_result.id))

    try:
        parsed_result = json.loads(scan_result.result_data)
    except json.JSONDecodeError:
        parsed_result = {
            "command": "Legacy text output",
            "output": scan_result.result_data,
            "hosts": []
        }

    export_payload = {
        "scan": {
            "id": scan_result.id,
            "created_at": format_local_datetime(scan_result.created_at),
            "input_ip": scan_result.input_ip,
            "subnet_mask": scan_result.subnet_mask,
            "network_cidr": scan_result.network_cidr,
            "first_host": scan_result.first_host,
            "last_host": scan_result.last_host,
            "scan_type": scan_result.scan_type,
            "ports": scan_result.ports,
            "status": scan_result.status,
            "user_email": scan_result.user.email
        },
        "result": parsed_result
    }

    filename = f"portojo_scan_{scan_result.id}.json"

    return Response(
        json.dumps(export_payload, indent=4),
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@app.route("/result/<int:scan_id>/export/txt")
@login_required
def export_result_txt(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)

    if not user_can_view_scan(scan_result):
        flash("You are not authorised to export this scan result.", "error")
        return redirect(url_for("scan"))

    if not scan_result.result_data:
        flash("No result data available for export.", "error")
        return redirect(url_for("result", scan_id=scan_result.id))

    try:
        parsed_result = json.loads(scan_result.result_data)
    except json.JSONDecodeError:
        parsed_result = {
            "command": "Legacy text output",
            "output": scan_result.result_data,
            "hosts": []
        }

    lines = []

    lines.append("PortOjo Scan Report")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Scan ID: {scan_result.id}")
    lines.append(f"Created At: {format_local_datetime(scan_result.created_at)}")
    lines.append(f"User: {scan_result.user.email}")
    lines.append(f"Input IP Address: {scan_result.input_ip}")
    lines.append(f"Subnet Mask: {scan_result.subnet_mask}")
    lines.append(f"Calculated Network: {scan_result.network_cidr}")
    lines.append(f"First Usable Host: {scan_result.first_host}")
    lines.append(f"Last Usable Host: {scan_result.last_host}")
    lines.append(f"Scan Type: {scan_name_filter(scan_result.scan_type)}")
    if scan_result.scan_type != "ping_sweep":
        lines.append(f"Scanned Ports: {scan_result.ports if scan_result.ports else 'Default'}")
    lines.append(f"Scan Status: {scan_result.status}")
    lines.append("")
    lines.append("Executed Command")
    lines.append("-" * 60)
    lines.append(parsed_result.get("command", "N/A"))
    lines.append("")

    hosts = parsed_result.get("hosts", [])

    if hosts:
        lines.append("Discovered Hosts and Open Ports")
        lines.append("-" * 60)

        for host in hosts:
            lines.append("")
            lines.append(f"Host: {host.get('address', '')}")

            if host.get("hostname"):
                lines.append(f"Hostname: {host.get('hostname')}")

            lines.append(f"Host Status: {host.get('status', '')}")
            lines.append("")

            ports = host.get("ports", [])

            if ports:
                lines.append(f"{'Port':<10}{'Protocol':<12}{'State':<12}{'Service':<20}{'Version'}")
                lines.append("-" * 80)

                for port in ports:
                    lines.append(
                        f"{port.get('port', ''):<10}"
                        f"{port.get('protocol', ''):<12}"
                        f"{port.get('state', ''):<12}"
                        f"{port.get('service', ''):<20}"
                        f"{port.get('version', '')}"
                    )
            else:
                lines.append("No open ports found for this host.")
    else:
        lines.append("No hosts found.")

    additional_output = parsed_result.get("output", "")

    if additional_output:
        lines.append("")
        lines.append("Additional Output")
        lines.append("-" * 60)
        lines.append(additional_output)

    txt_content = "\n".join(lines)

    filename = f"portojo_scan_{scan_result.id}.txt"

    return Response(
        txt_content,
        mimetype="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

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
            return clean_user in clean_cpe or clean_cpe in clean_user

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

VENDOR_PRODUCT_MAP = {
    "openssh": ("openbsd", "openssh"),
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "samba": ("samba", "samba"),
    "microsoft iis": ("microsoft", "iis"),
    "iis": ("microsoft", "iis"),
    "tomcat": ("apache", "tomcat"),
    "redis": ("redis", "redis"),
    "mariadb": ("mariadb", "mariadb"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "squid": ("squid-cache", "squid"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "bind": ("isc", "bind"),
    "werkzeug": ("pallets", "werkzeug"),
    "werkzeug httpd": ("pallets", "werkzeug"),
    "vmware-auth": ("vmware", "workstation")
}

CVE_CACHE = {}

@app.route("/api/cves")
@login_required
def get_cves():
    import urllib.request
    import urllib.error
    import json
    from flask import jsonify

    query = request.args.get("query", "").strip()
    if not query or query == "-":
        return jsonify([])

    cache_key = query.lower()
    if cache_key in CVE_CACHE:
        return jsonify(CVE_CACHE[cache_key])

    # Parse product and version from query
    parts = query.split()
    if len(parts) == 0:
        return jsonify([])
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
            headers={"User-Agent": "PortOjo Vulnerability Scanner"}
        )
        with urllib.request.urlopen(req, timeout=7) as response:
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
            seen_cves.add(cve_id)
            cve_record = item[1]

            # Extract description
            descriptions = cve_record.get("containers", {}).get("cna", {}).get("descriptions", [])
            summary = "No description available."
            for desc in descriptions:
                if desc.get("lang") == "en":
                    summary = desc.get("value")
                    break

            # Extract CVSS
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

            is_affected = True
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

                if not cpe_found or not is_affected:
                    if version.lower() in summary.lower():
                        is_affected = True
                    else:
                        if not cpe_found:
                            is_affected = True

            if is_affected:
                filtered_cves.append({
                    "id": cve_id,
                    "summary": summary,
                    "cvss": cvss_score
                })

        filtered_cves.sort(key=lambda x: x["cvss"] if x["cvss"] is not None else -1, reverse=True)
        filtered_cves = filtered_cves[:15]

        CVE_CACHE[cache_key] = filtered_cves
        return jsonify(filtered_cves)

    except urllib.error.HTTPError as e:
        if e.code == 404:
            CVE_CACHE[cache_key] = []
            return jsonify([])
        return jsonify({"error": f"CVE API error {e.code}"}), 502
    except Exception as e:
        return jsonify({"error": f"Failed to fetch CVEs: {str(e)}"}), 502

@app.route("/scans/compare")
@login_required
def compare_scans():
    scan_a_id = request.args.get("scan_a")
    scan_b_id = request.args.get("scan_b")

    if not scan_a_id or not scan_b_id:
        flash("Please select two valid scans to compare.", "error")
        return redirect(url_for("history"))

    try:
        scan_a = ScanResult.query.get(int(scan_a_id))
        scan_b = ScanResult.query.get(int(scan_b_id))
    except (ValueError, TypeError):
        flash("Invalid scan IDs.", "error")
        return redirect(url_for("history"))

    if not scan_a or not scan_b:
        flash("Selected scans not found in the database.", "error")
        return redirect(url_for("history"))

    if not user_can_view_scan(scan_a) or not user_can_view_scan(scan_b):
        flash("You are not authorised to compare these scans.", "error")
        return redirect(url_for("history"))

    if scan_a.status != "completed" or scan_b.status != "completed":
        flash("You can only compare completed scans.", "error")
        return redirect(url_for("history"))

    # Load result data JSON
    try:
        data_a = json.loads(scan_a.result_data) if scan_a.result_data else {}
        data_b = json.loads(scan_b.result_data) if scan_b.result_data else {}
    except Exception as e:
        flash(f"Failed to read scan data: {str(e)}", "error")
        return redirect(url_for("history"))

    hosts_a = data_a.get("hosts", [])
    hosts_b = data_b.get("hosts", [])

    # Map hosts by IP
    map_a = {h["address"]: h for h in hosts_a}
    map_b = {h["address"]: h for h in hosts_b}

    added_hosts = []
    removed_hosts = []
    modified_hosts = []
    unchanged_hosts = []

    # Calculate Host diffs
    all_ips = set(map_a.keys()).union(set(map_b.keys()))

    total_added_ports = 0
    total_removed_ports = 0
    total_changed_ports = 0

    for ip in all_ips:
        if ip in map_b and ip not in map_a:
            # Added Host
            added_hosts.append(map_b[ip])
        elif ip in map_a and ip not in map_b:
            # Removed Host
            removed_hosts.append(map_a[ip])
        else:
            # Common Host
            host_a = map_a[ip]
            host_b = map_b[ip]

            # Compare ports
            ports_a = {p["port"]: p for p in host_a.get("ports", [])}
            ports_b = {p["port"]: p for p in host_b.get("ports", [])}

            added_ports = []
            removed_ports = []
            changed_ports = []

            all_ports = set(ports_a.keys()).union(set(ports_b.keys()))

            for port in all_ports:
                if port in ports_b and port not in ports_a:
                    added_ports.append(ports_b[port])
                elif port in ports_a and port not in ports_b:
                    removed_ports.append(ports_a[port])
                else:
                    pa = ports_a[port]
                    pb = ports_b[port]

                    # Service/version changes
                    service_changed = pa.get("service") != pb.get("service")
                    version_changed = pa.get("version") != pb.get("version")
                    state_changed = pa.get("state") != pb.get("state")

                    if service_changed or version_changed or state_changed:
                        changed_ports.append({
                            "port": port,
                            "protocol": pb.get("protocol", "tcp"),
                            "state_a": pa.get("state"),
                            "state_b": pb.get("state"),
                            "service_a": pa.get("service"),
                            "service_b": pb.get("service"),
                            "version_a": pa.get("version"),
                            "version_b": pb.get("version")
                        })

            if added_ports or removed_ports or changed_ports:
                modified_hosts.append({
                    "address": ip,
                    "hostname": host_b.get("hostname") or host_a.get("hostname", ""),
                    "added_ports": added_ports,
                    "removed_ports": removed_ports,
                    "changed_ports": changed_ports
                })
                total_added_ports += len(added_ports)
                total_removed_ports += len(removed_ports)
                total_changed_ports += len(changed_ports)
            else:
                unchanged_hosts.append(host_b)

    # Sort results
    added_hosts.sort(key=lambda x: x["address"])
    removed_hosts.sort(key=lambda x: x["address"])
    modified_hosts.sort(key=lambda x: x["address"])
    unchanged_hosts.sort(key=lambda x: x["address"])

    targets_match = scan_a.network_cidr == scan_b.network_cidr

    return render_template(
        "compare.html",
        scan_a=scan_a,
        scan_b=scan_b,
        added_hosts=added_hosts,
        removed_hosts=removed_hosts,
        modified_hosts=modified_hosts,
        unchanged_hosts=unchanged_hosts,
        total_added_ports=total_added_ports,
        total_removed_ports=total_removed_ports,
        total_changed_ports=total_changed_ports,
        targets_match=targets_match
    )

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    tab = request.args.get("tab", "smtp")
    
    # Enforce admin-only access for the freeze, exclusions, and honeypot tabs
    if tab in ["freeze", "exclusions", "honeypot"] and not current_user.is_admin:
        flash("Unauthorised access to settings.", "error")
        return redirect(url_for("settings", tab="smtp"))
        
    setting = SystemSetting.query.filter_by(user_id=current_user.id).first()

    if request.method == "POST":
        form_type = request.form.get("form_type", "smtp")
        
        if form_type in ["freeze", "exclusions", "honeypot"] and not current_user.is_admin:
            flash("Unauthorised access to settings.", "error")
            return redirect(url_for("settings", tab="smtp"))

        if not setting:
            setting = SystemSetting(user_id=current_user.id)
            db.session.add(setting)

        if form_type == "smtp":
            smtp_server = request.form.get("smtp_server", "").strip()
            smtp_port_raw = request.form.get("smtp_port", "").strip()
            smtp_username = request.form.get("smtp_username", "").strip()
            smtp_password = request.form.get("smtp_password", "")
            smtp_sender = request.form.get("smtp_sender", "").strip()
            alert_recipient = request.form.get("alert_recipient", "").strip()
            alert_on_new_ports_only = request.form.get("alert_on_new_ports_only") == "y"

            if not smtp_server:
                flash("SMTP server address cannot be empty.", "error")
                return redirect(url_for("settings", tab="smtp"))

            try:
                smtp_port = int(smtp_port_raw)
            except ValueError:
                flash("SMTP port must be a valid number.", "error")
                return redirect(url_for("settings", tab="smtp"))

            if not smtp_sender or not alert_recipient:
                flash("Sender and Recipient email addresses cannot be empty.", "error")
                return redirect(url_for("settings", tab="smtp"))

            setting.smtp_server = smtp_server
            setting.smtp_port = smtp_port
            setting.smtp_username = smtp_username

            if smtp_password:
                setting.smtp_password = smtp_password

            setting.smtp_sender = smtp_sender
            setting.alert_recipient = alert_recipient
            setting.alert_on_new_ports_only = alert_on_new_ports_only
            
            flash("System and Email settings saved successfully.", "success")
            tab_redirect = "smtp"
        elif form_type == "freeze":
            scan_freeze_active = request.form.get("scan_freeze_active") == "y"
            scan_freeze_start = request.form.get("scan_freeze_start", "09:00").strip()
            scan_freeze_end = request.form.get("scan_freeze_end", "17:00").strip()
            
            # Simple HH:MM validation
            time_pattern = re.compile(r"^\d{2}:\d{2}$")
            if not time_pattern.match(scan_freeze_start) or not time_pattern.match(scan_freeze_end):
                flash("Start Time and End Time must be in HH:MM format (e.g. 09:00, 22:30).", "error")
                return redirect(url_for("settings", tab="freeze"))
                
            setting.scan_freeze_active = scan_freeze_active
            setting.scan_freeze_start = scan_freeze_start
            setting.scan_freeze_end = scan_freeze_end
            
            flash("Scan Blackout settings saved successfully.", "success")
            tab_redirect = "freeze"
        elif form_type == "exclusions":
            scan_exclusions_active = request.form.get("scan_exclusions_active") == "y"
            scan_exclude_targets = request.form.get("scan_exclude_targets", "").strip()
            
            setting.scan_exclusions_active = scan_exclusions_active
            setting.scan_exclude_targets = scan_exclude_targets if scan_exclude_targets else None
            
            flash("Scan Exclusions saved successfully.", "success")
            tab_redirect = "exclusions"
        else:
            honeypot_active = request.form.get("honeypot_active") == "y"
            honeypot_auto_block = request.form.get("honeypot_auto_block") == "y"
            honeypot_email_alert = request.form.get("honeypot_email_alert") == "y"

            setting.honeypot_active = honeypot_active
            setting.honeypot_auto_block = honeypot_auto_block
            setting.honeypot_email_alert = honeypot_email_alert
            
            flash("Honeypot settings saved successfully.", "success")
            tab_redirect = "honeypot"

        db.session.commit()
        return redirect(url_for("settings", tab=tab_redirect))

    credentials = []
    if tab == "credentials":
        credentials = ScanCredential.query.filter_by(user_id=current_user.id).order_by(ScanCredential.created_at.desc()).all()

    return render_template("settings.html", setting=setting, tab=tab, credentials=credentials)

@app.route("/settings/credentials/add", methods=["POST"])
@login_required
def add_credential():
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    protocol = request.form.get("protocol", "any").strip()

    if not name:
        flash("Credential name cannot be empty.", "error")
        return redirect(url_for("settings", tab="credentials"))

    credential = ScanCredential(
        user_id=current_user.id,
        name=name,
        username=username if username else None,
        password=password if password else None,
        protocol=protocol
    )
    db.session.add(credential)
    db.session.commit()
    flash("Credential added successfully.", "success")
    return redirect(url_for("settings", tab="credentials"))

@app.route("/settings/credentials/delete/<int:credential_id>", methods=["POST"])
@login_required
def delete_credential(credential_id):
    credential = ScanCredential.query.filter_by(id=credential_id, user_id=current_user.id).first()
    if not credential:
        flash("Credential not found.", "error")
        return redirect(url_for("settings", tab="credentials"))

    db.session.delete(credential)
    db.session.commit()
    flash("Credential deleted successfully.", "success")
    return redirect(url_for("settings", tab="credentials"))

@app.route("/settings/test-email", methods=["POST"])
@login_required
def test_email():
    setting = SystemSetting.query.filter_by(user_id=current_user.id).first()
    if not setting or not setting.smtp_server or not setting.smtp_sender or not setting.alert_recipient:
        flash("Please fill and save your SMTP settings first.", "error")
        return redirect(url_for("settings"))

    setting_dict = {
        "smtp_server": setting.smtp_server,
        "smtp_port": setting.smtp_port,
        "smtp_username": setting.smtp_username,
        "smtp_password": setting.smtp_password,
        "smtp_sender": setting.smtp_sender,
        "alert_recipient": setting.alert_recipient
    }

    subject = "[PortOjo] Email Notification Test"
    body_html = f"""
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px; background-color: #fcfcf9;">
        <h2 style="color: #4a5d4e; margin-bottom: 10px;">PortOjo Email Test</h2>
        <p>Hello,</p>
        <p>This email is a test notification sent from the PortOjo port scanner application. It confirms that your SMTP settings are working correctly.</p>
        <hr style="border: 0; border-top: 1px solid #ddd; margin: 20px 0;">
        <p style="font-size: 12px; color: #888;">Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    """

    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = setting_dict["smtp_sender"]
        msg["To"] = setting_dict["alert_recipient"]
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        server_name = setting_dict["smtp_server"]
        port = int(setting_dict["smtp_port"] or 587)
        username = setting_dict["smtp_username"]
        password = setting_dict["smtp_password"]

        if port == 465:
            server = smtplib.SMTP_SSL(server_name, port, timeout=7)
        else:
            server = smtplib.SMTP(server_name, port, timeout=7)
            server.ehlo()
            server.starttls()
            server.ehlo()

        if username and password:
            server.login(username, password)

        server.sendmail(setting_dict["smtp_sender"], [setting_dict["alert_recipient"]], msg.as_string())
        server.quit()
        flash("Test email sent successfully! Check the recipient mailbox.", "success")
    except Exception as e:
        flash(f"Failed to send test email: {str(e)}", "error")

    return redirect(url_for("settings"))

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    tab = request.args.get("tab", "scans")

    scan_results = ScanResult.query.order_by(
        ScanResult.created_at.desc()
    ).all()

    users = User.query.order_by(User.created_at.desc()).all()

    has_active_scans = any(
        scan.status in ["pending", "running"] for scan in scan_results
    )

    honeypot_logs = HoneypotLog.query.order_by(HoneypotLog.created_at.desc()).all()
    blocked_ips = HoneypotBlockedIP.query.order_by(HoneypotBlockedIP.created_at.desc()).all()
    
    security_anomalies = SecurityAnomaly.query.order_by(SecurityAnomaly.created_at.desc()).all()

    return render_template(
        "admin.html",
        tab=tab,
        scan_results=scan_results,
        users=users,
        has_active_scans=has_active_scans,
        honeypot_logs=honeypot_logs,
        blocked_ips=blocked_ips,
        security_anomalies=security_anomalies
    )

@app.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
@login_required
@admin_required
def admin_toggle_user_role(user_id):
    if user_id == current_user.id:
        flash("You cannot change your own admin role.", "error")
        return redirect(url_for("admin_panel", tab="users"))

    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    if not user.is_admin:
        user.otp_secret = None
    db.session.commit()

    role_str = "Admin" if user.is_admin else "User"
    flash(f"Role of user {user.email} updated to '{role_str}'.", "success")
    return redirect(url_for("admin_panel", tab="users"))

@app.route("/admin/user/<int:user_id>/reset-2fa", methods=["POST"])
@login_required
@admin_required
def admin_reset_user_2fa(user_id):
    if user_id == current_user.id:
        flash("You cannot reset your own 2FA from here.", "error")
        return redirect(url_for("admin_panel", tab="users"))

    user = User.query.get_or_404(user_id)
    if not user.is_admin:
        flash("Resetting 2FA is only applicable to administrator accounts.", "error")
        return redirect(url_for("admin_panel", tab="users"))

    user.otp_secret = None
    db.session.commit()

    flash(f"Two-Factor Authentication (2FA) has been reset for {user.email}. They will be prompted to set it up again on their next login.", "success")
    return redirect(url_for("admin_panel", tab="users"))

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_panel", tab="users"))

    user = User.query.get_or_404(user_id)

    # Delete related records first to avoid FK constraints
    ScanResult.query.filter_by(user_id=user.id).delete()
    ScanSchedule.query.filter_by(user_id=user.id).delete()
    SystemSetting.query.filter_by(user_id=user.id).delete()
    ScanCredential.query.filter_by(user_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()

    flash(f"User {user.email} and all associated scan data have been deleted.", "success")
    return redirect(url_for("admin_panel", tab="users"))

@app.route("/admin/scan/<int:scan_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    flash("Scan result deleted.", "success")
    return redirect(url_for("admin_panel", tab="scans"))

@app.route("/honeypot/blocked")
def honeypot_blocked():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()
        
    block = HoneypotBlockedIP.query.filter_by(ip_address=client_ip).first()
    if not block:
        return redirect(url_for("index"))
        
    return render_template("blocked.html", ip_address=client_ip, block=block)

@app.route("/admin/honeypot/unblock/<int:block_id>", methods=["POST"])
@login_required
@admin_required
def admin_unblock_ip(block_id):
    block = HoneypotBlockedIP.query.get_or_404(block_id)
    ip = block.ip_address
    db.session.delete(block)
    db.session.commit()
    flash(f"IP {ip} has been unblocked.", "success")
    return redirect(url_for("admin_panel", tab="honeypot"))

@app.route("/admin/honeypot/clear-logs", methods=["POST"])
@login_required
@admin_required
def admin_clear_honeypot_logs():
    HoneypotLog.query.delete()
    db.session.commit()
    flash("Honeypot logs cleared successfully.", "success")
    return redirect(url_for("admin_panel", tab="honeypot"))

@app.route("/admin/assets/<int:asset_id>/toggle-trust", methods=["POST"])
@login_required
@admin_required
def admin_toggle_asset_trust(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    asset.is_trusted = not asset.is_trusted
    
    if asset.is_trusted:
        # Also resolve associated security anomalies
        anomalies = SecurityAnomaly.query.filter(
            SecurityAnomaly.is_resolved == False,
            db.or_(
                SecurityAnomaly.ip_address == asset.ip_address,
                (SecurityAnomaly.mac_address == asset.mac_address) if asset.mac_address else False
            )
        ).all()
        for anomaly in anomalies:
            anomaly.is_resolved = True
            
    db.session.commit()
    status_str = "trusted" if asset.is_trusted else "untrusted"
    flash(f"Asset {asset.name or asset.ip_address} is now marked as {status_str}.", "success")
    return redirect(url_for("admin_assets"))

@app.route("/admin/anomalies/<int:anomaly_id>/resolve", methods=["POST"])
@login_required
@admin_required
def admin_resolve_anomaly(anomaly_id):
    anomaly = SecurityAnomaly.query.get_or_404(anomaly_id)
    anomaly.is_resolved = not anomaly.is_resolved
    db.session.commit()
    status_str = "resolved" if anomaly.is_resolved else "unresolved"
    flash(f"Anomaly #{anomaly.id} ({anomaly.anomaly_type}) marked as {status_str}.", "success")
    return redirect(url_for("admin_panel", tab="anomalies"))

@app.route("/admin/anomalies/<int:anomaly_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_anomaly(anomaly_id):
    anomaly = SecurityAnomaly.query.get_or_404(anomaly_id)
    db.session.delete(anomaly)
    db.session.commit()
    flash(f"Anomaly #{anomaly.id} deleted.", "success")
    return redirect(url_for("admin_panel", tab="anomalies"))


@app.route("/admin/users/bulk-delete", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_users():
    user_ids = request.form.getlist("user_ids")
    if not user_ids:
        flash("No users selected for deletion.", "warning")
        return redirect(url_for("admin_panel", tab="users"))

    try:
        int_ids = [int(uid) for uid in user_ids if int(uid) != current_user.id]
        if not int_ids:
            flash("You cannot delete your own account.", "error")
            return redirect(url_for("admin_panel", tab="users"))

        ScanResult.query.filter(ScanResult.user_id.in_(int_ids)).delete(synchronize_session=False)
        ScanSchedule.query.filter(ScanSchedule.user_id.in_(int_ids)).delete(synchronize_session=False)
        SystemSetting.query.filter(SystemSetting.user_id.in_(int_ids)).delete(synchronize_session=False)
        ScanCredential.query.filter(ScanCredential.user_id.in_(int_ids)).delete(synchronize_session=False)

        deleted_count = User.query.filter(User.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        
        flash(f"Successfully deleted {deleted_count} selected users and their associated scan data.", "success")
        if len(user_ids) > len(int_ids):
            flash("Your own account was excluded from the deletion.", "warning")
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk deletion: {str(e)}", "error")

    return redirect(url_for("admin_panel", tab="users"))


@app.route("/admin/scans/bulk-delete", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_scans():
    scan_ids = request.form.getlist("scan_ids")
    if not scan_ids:
        flash("No scans selected for deletion.", "warning")
        return redirect(url_for("admin_panel", tab="scans"))

    try:
        int_ids = [int(sid) for sid in scan_ids]
        deleted_count = ScanResult.query.filter(ScanResult.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} selected scans.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk deletion: {str(e)}", "error")

    return redirect(url_for("admin_panel", tab="scans"))


@app.route("/admin/honeypot/bulk-unblock", methods=["POST"])
@login_required
@admin_required
def admin_bulk_unblock_ips():
    block_ids = request.form.getlist("block_ids")
    if not block_ids:
        flash("No blocked IPs selected.", "warning")
        return redirect(url_for("admin_panel", tab="honeypot"))

    try:
        int_ids = [int(bid) for bid in block_ids]
        deleted_count = HoneypotBlockedIP.query.filter(HoneypotBlockedIP.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully unblocked {deleted_count} IP addresses.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk unblocking: {str(e)}", "error")

    return redirect(url_for("admin_panel", tab="honeypot"))


@app.route("/admin/honeypot/bulk-delete-logs", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_logs():
    log_ids = request.form.getlist("log_ids")
    if not log_ids:
        flash("No intrusion logs selected.", "warning")
        return redirect(url_for("admin_panel", tab="honeypot"))

    try:
        int_ids = [int(lid) for lid in log_ids]
        deleted_count = HoneypotLog.query.filter(HoneypotLog.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} intrusion logs.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk deletion: {str(e)}", "error")

    return redirect(url_for("admin_panel", tab="honeypot"))


@app.route("/admin/anomalies/bulk-delete", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_anomalies():
    anomaly_ids = request.form.getlist("anomaly_ids")
    if not anomaly_ids:
        flash("No anomalies selected for deletion.", "warning")
        return redirect(url_for("admin_panel", tab="anomalies"))

    try:
        int_ids = [int(aid) for aid in anomaly_ids]
        deleted_count = SecurityAnomaly.query.filter(SecurityAnomaly.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} anomalies.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk deletion: {str(e)}", "error")

    return redirect(url_for("admin_panel", tab="anomalies"))


@app.route("/admin/anomalies/bulk-resolve", methods=["POST"])
@login_required
@admin_required
def admin_bulk_resolve_anomalies():
    anomaly_ids = request.form.getlist("anomaly_ids")
    if not anomaly_ids:
        flash("No anomalies selected to resolve.", "warning")
        return redirect(url_for("admin_panel", tab="anomalies"))

    try:
        int_ids = [int(aid) for aid in anomaly_ids]
        anomalies = SecurityAnomaly.query.filter(SecurityAnomaly.id.in_(int_ids)).all()
        for anomaly in anomalies:
            anomaly.is_resolved = True
        db.session.commit()
        flash(f"Successfully resolved {len(anomalies)} anomalies.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk resolve: {str(e)}", "error")

    return redirect(url_for("admin_panel", tab="anomalies"))


@app.route("/schedules/bulk-delete", methods=["POST"])
@login_required
def bulk_delete_schedules():
    schedule_ids = request.form.getlist("schedule_ids")
    if not schedule_ids:
        flash("No scan schedules selected for deletion.", "warning")
        return redirect(url_for("schedules"))

    try:
        int_ids = [int(sid) for sid in schedule_ids]
        deleted_count = ScanSchedule.query.filter(
            ScanSchedule.id.in_(int_ids),
            ScanSchedule.user_id == current_user.id
        ).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} scan schedules.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk deletion: {str(e)}", "error")

    return redirect(url_for("schedules"))


@app.route("/admin/asset-map")
@login_required
@admin_required
def asset_map():
    assets = Asset.query.all()
    unresolved_anomalies = SecurityAnomaly.query.filter_by(is_resolved=False).all()

    # Build a dictionary to unify hosts by IP address
    unified_hosts = {}

    def get_subnet_prefix(ip_str):
        if not ip_str:
            return "External / Unknown"
        import re
        match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$", ip_str.strip())
        if match:
            return f"{match.group(1)}.0/24"
        return "External / Unknown"

    # 1. Process Assets
    for asset in assets:
        ip = asset.ip_address.strip()
        unified_hosts[ip] = {
            "ip": ip,
            "mac": asset.mac_address,
            "name": asset.name or f"Device {ip}",
            "vendor": asset.mac_vendor or "Unknown",
            "device_type": asset.device_type or "Unknown",
            "operating_system": asset.operating_system or "Unknown",
            "criticality": asset.criticality or "Medium",
            "owner": asset.owner or "",
            "location": asset.location or "",
            "notes": asset.notes or "",
            "is_asset": True,
            "asset_id": asset.id,
            "is_trusted": asset.is_trusted,
            "known_device_id": None,
            "anomalies": [],
            "subnet": get_subnet_prefix(ip),
            "last_seen": format_local_datetime(asset.last_seen) if asset.last_seen else "Never"
        }

    # 2. Add Anomalies
    for anom in unresolved_anomalies:
        ip = anom.ip_address.strip()
        if ip in unified_hosts:
            unified_hosts[ip]["anomalies"].append({
                "id": anom.id,
                "anomaly_type": anom.anomaly_type,
                "description": anom.description,
                "created_at": format_local_datetime(anom.created_at) if anom.created_at else ""
            })
        else:
            # Host not found in assets - do not create a node since it has been deleted or is not tracked
            pass

    hosts_list = list(unified_hosts.values())

    return render_template(
        "admin_asset_map.html",
        hosts=hosts_list
    )

@app.route("/admin/assets")
@login_required
@admin_required
def admin_assets():
    search = request.args.get("search", "").strip()
    criticality = request.args.get("criticality", "").strip()
    device_type = request.args.get("device_type", "").strip()
    ip_assignment_type = request.args.get("ip_assignment_type", "").strip()

    query = Asset.query

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                Asset.name.ilike(search_pattern),
                Asset.ip_address.ilike(search_pattern),
                Asset.mac_address.ilike(search_pattern),
                Asset.mac_vendor.ilike(search_pattern),
                Asset.owner.ilike(search_pattern),
                Asset.serial_number.ilike(search_pattern)
            )
        )

    if criticality:
        query = query.filter(Asset.criticality == criticality)

    if device_type:
        query = query.filter(Asset.device_type == device_type)

    if ip_assignment_type:
        query = query.filter(Asset.ip_assignment_type == ip_assignment_type)

    assets = query.order_by(Asset.last_seen.desc()).all()

    return render_template(
        "admin_assets.html",
        assets=assets,
        search=search,
        criticality=criticality,
        device_type=device_type,
        ip_assignment_type=ip_assignment_type
    )

@app.route("/admin/assets/new", methods=["GET", "POST"])
@login_required
@admin_required
def admin_new_asset():
    if request.method == "POST":
        name = request.form.get("name", "").strip() or None
        ip_address = request.form.get("ip_address", "").strip()
        mac_address = request.form.get("mac_address", "").strip() or None
        mac_vendor = request.form.get("mac_vendor", "").strip() or None
        device_type = request.form.get("device_type", "Unknown").strip()
        operating_system = request.form.get("operating_system", "").strip() or None
        criticality = request.form.get("criticality", "Medium").strip()
        ip_assignment_type = request.form.get("ip_assignment_type", "DHCP").strip()
        owner = request.form.get("owner", "").strip() or None
        location = request.form.get("location", "").strip() or None
        serial_number = request.form.get("serial_number", "").strip() or None
        notes = request.form.get("notes", "").strip() or None

        if not ip_address:
            flash("IP Address is required.", "error")
            return render_template("admin_asset_form.html", asset=None)

        # Create new asset
        asset = Asset(
            name=name,
            ip_address=ip_address,
            mac_address=mac_address,
            mac_vendor=mac_vendor,
            device_type=device_type,
            operating_system=operating_system,
            criticality=criticality,
            ip_assignment_type=ip_assignment_type,
            owner=owner,
            location=location,
            serial_number=serial_number,
            notes=notes
        )
        db.session.add(asset)
        
        # Also resolve associated security anomalies since it's trusted by default
        anomalies = SecurityAnomaly.query.filter(
            SecurityAnomaly.is_resolved == False,
            db.or_(
                SecurityAnomaly.ip_address == asset.ip_address,
                (SecurityAnomaly.mac_address == asset.mac_address) if asset.mac_address else False
            )
        ).all()
        for anomaly in anomalies:
            anomaly.is_resolved = True

        db.session.commit()
        flash(f"Asset {ip_address} has been successfully registered.", "success")
        return redirect(url_for("admin_assets"))

    return render_template("admin_asset_form.html", asset=None)

@app.route("/admin/assets/<int:asset_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def admin_edit_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    if request.method == "POST":
        asset.name = request.form.get("name", "").strip() or None
        asset.ip_address = request.form.get("ip_address", "").strip()
        asset.mac_address = request.form.get("mac_address", "").strip() or None
        asset.mac_vendor = request.form.get("mac_vendor", "").strip() or None
        asset.device_type = request.form.get("device_type", "Unknown").strip()
        asset.operating_system = request.form.get("operating_system", "").strip() or None
        asset.criticality = request.form.get("criticality", "Medium").strip()
        asset.ip_assignment_type = request.form.get("ip_assignment_type", "DHCP").strip()
        asset.owner = request.form.get("owner", "").strip() or None
        asset.location = request.form.get("location", "").strip() or None
        asset.serial_number = request.form.get("serial_number", "").strip() or None
        asset.notes = request.form.get("notes", "").strip() or None

        if not asset.ip_address:
            flash("IP Address is required.", "error")
            return render_template("admin_asset_form.html", asset=asset)

        db.session.commit()
        flash(f"Asset {asset.ip_address} has been updated.", "success")
        return redirect(url_for("admin_assets"))

    return render_template("admin_asset_form.html", asset=asset)

@app.route("/admin/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    ip = asset.ip_address
    mac = asset.mac_address
    
    # Delete anomalies associated with this asset so it disappears from the Asset Map
    SecurityAnomaly.query.filter(
        db.or_(
            SecurityAnomaly.ip_address == ip,
            (SecurityAnomaly.mac_address == mac) if mac else False
        )
    ).delete(synchronize_session=False)

    db.session.delete(asset)
    db.session.commit()
    flash(f"Asset {ip} has been deleted from inventory.", "success")
    return redirect(url_for("admin_assets"))

@app.route("/admin/assets/bulk-delete", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_assets():
    asset_ids = request.form.getlist("asset_ids")
    if not asset_ids:
        flash("No assets selected for deletion.", "warning")
        return redirect(url_for("admin_assets"))

    try:
        int_ids = [int(aid) for aid in asset_ids]
        assets_to_delete = Asset.query.filter(Asset.id.in_(int_ids)).all()
        ips = [a.ip_address for a in assets_to_delete if a.ip_address]
        macs = [a.mac_address for a in assets_to_delete if a.mac_address]
        
        if ips or macs:
            SecurityAnomaly.query.filter(
                db.or_(
                    SecurityAnomaly.ip_address.in_(ips),
                    SecurityAnomaly.mac_address.in_(macs)
                )
            ).delete(synchronize_session=False)

        deleted_count = Asset.query.filter(Asset.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} selected assets from inventory.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk deletion: {str(e)}", "error")

    return redirect(url_for("admin_assets"))

with app.app_context():
    db.create_all()
    migrate_db_schema()
    cleanup_stale_scans()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")