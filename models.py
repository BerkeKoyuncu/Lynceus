from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
import base64
import hashlib
import os
from cryptography.fernet import Fernet

db = SQLAlchemy()

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def get_fernet_key(secret_string: str) -> bytes:
    # Hash the secret string using SHA-256 to get exactly 32 bytes
    key_bytes = hashlib.sha256(secret_string.encode('utf-8')).digest()
    # Base64 urlsafe encode it as required by Fernet
    return base64.urlsafe_b64encode(key_bytes)

def encrypt_val(val: str) -> str:
    if not val:
        return val
    secret = os.environ.get("OTP_ENCRYPTION_KEY") or os.environ.get("SECRET_KEY") or "change-this-secret-key"
    fernet = Fernet(get_fernet_key(secret))
    return fernet.encrypt(val.encode('utf-8')).decode('utf-8')

def decrypt_val(val: str) -> str:
    if not val:
        return val
    # If the value is a Fernet token (typically starts with gAAAA), decrypt it.
    if val.startswith("gAAAA"):
        try:
            secret = os.environ.get("OTP_ENCRYPTION_KEY") or os.environ.get("SECRET_KEY") or "change-this-secret-key"
            fernet = Fernet(get_fernet_key(secret))
            return fernet.decrypt(val.encode('utf-8')).decode('utf-8')
        except Exception:
            return val
    return val

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    is_admin = db.Column(db.Boolean, default=False)
    _otp_secret = db.Column("otp_secret", db.String(255), nullable=True)

    created_at = db.Column(db.DateTime, default=utc_now)

    scan_results = db.relationship("ScanResult", backref="user", lazy=True)

    @property
    def otp_secret(self):
        return decrypt_val(self._otp_secret)

    @otp_secret.setter
    def otp_secret(self, value):
        self._otp_secret = encrypt_val(value)

    def __repr__(self):
        return f"<User {self.email}>"


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    input_ip = db.Column(db.String(45), nullable=False)
    subnet_mask = db.Column(db.String(45), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False)
    ports = db.Column(db.String(100), nullable=True)

    network_cidr = db.Column(db.String(50), nullable=False)
    first_host = db.Column(db.String(45), nullable=True)
    last_host = db.Column(db.String(45), nullable=True)

    status = db.Column(db.String(20), default="pending")

    exclude_targets = db.Column(db.Text, nullable=True)
    credential_ids = db.Column(db.Text, nullable=True)
    timing_template = db.Column(db.String(2), default="4", nullable=True)

    result_data = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=utc_now)

    def __repr__(self):
        return f"<ScanResult {self.network_cidr} - {self.scan_type}>"


class ScanSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    input_ip = db.Column(db.String(45), nullable=False)
    subnet_mask = db.Column(db.String(45), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False)
    ports = db.Column(db.String(100), nullable=True)
    
    network_cidr = db.Column(db.String(50), nullable=False)
    frequency = db.Column(db.String(20), nullable=False)  # 'hourly', 'daily', 'weekly', 'monthly'
    
    last_run = db.Column(db.DateTime, nullable=True)
    next_run = db.Column(db.DateTime, nullable=False)
    
    is_active = db.Column(db.Boolean, default=True)
    exclude_targets = db.Column(db.Text, nullable=True)
    credential_ids = db.Column(db.Text, nullable=True)
    timing_template = db.Column(db.String(2), default="4", nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    def __repr__(self):
        return f"<ScanSchedule {self.name} - {self.frequency}>"


class SystemSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    
    smtp_server = db.Column(db.String(100), default="smtp.gmail.com")
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(100), nullable=True)
    smtp_password = db.Column(db.String(100), nullable=True)
    smtp_sender = db.Column(db.String(100), nullable=True)
    alert_recipient = db.Column(db.String(100), nullable=True)
    
    alert_on_new_ports_only = db.Column(db.Boolean, default=True)
    
    # Honeypot Settings
    honeypot_active = db.Column(db.Boolean, default=True)
    honeypot_auto_block = db.Column(db.Boolean, default=True)
    honeypot_email_alert = db.Column(db.Boolean, default=True)
    # Scan Blackout Settings
    scan_freeze_active = db.Column(db.Boolean, default=False)
    scan_freeze_start = db.Column(db.String(5), default="09:00")
    scan_freeze_end = db.Column(db.String(5), default="17:00")
    
    # Scan Exclusion Settings
    scan_exclusions_active = db.Column(db.Boolean, default=True)
    scan_exclude_targets = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=utc_now)

    def __repr__(self):
        return f"<SystemSetting User {self.user_id}>"


class ScanCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(100), nullable=True)
    protocol = db.Column(db.String(20), default="any")  # 'ftp', 'redis', 'http_basic', 'any'
    created_at = db.Column(db.DateTime, default=utc_now)

    def __repr__(self):
        return f"<ScanCredential {self.name} - {self.protocol}>"


class HoneypotLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text, nullable=True)
    path = db.Column(db.String(255), nullable=False)
    headers = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    def __repr__(self):
        return f"<HoneypotLog {self.ip_address} - {self.path}>"


class HoneypotBlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    def __repr__(self):
        return f"<HoneypotBlockedIP {self.ip_address}>"


class SecurityAnomaly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    anomaly_type = db.Column(db.String(50), nullable=False)  # 'mac_spoofing', 'ip_hijack', 'rogue_device'
    ip_address = db.Column(db.String(45), nullable=False)
    mac_address = db.Column(db.String(45), nullable=True)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now)
    is_resolved = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<SecurityAnomaly {self.anomaly_type} - {self.ip_address}>"


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    mac_address = db.Column(db.String(45), nullable=True)
    mac_vendor = db.Column(db.String(100), nullable=True)
    device_type = db.Column(db.String(50), default="Unknown")  # 'Server', 'Workstation', 'Router', etc.
    operating_system = db.Column(db.String(100), nullable=True)
    criticality = db.Column(db.String(20), default="Medium")  # 'Low', 'Medium', 'High', 'Critical'
    owner = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    serial_number = db.Column(db.String(100), nullable=True)
    ip_assignment_type = db.Column(db.String(20), default="DHCP", nullable=False)  # 'Static', 'DHCP'
    notes = db.Column(db.Text, nullable=True)
    is_trusted = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)
    created_at = db.Column(db.DateTime, default=utc_now)

    def __repr__(self):
        return f"<Asset {self.name or self.ip_address}>"