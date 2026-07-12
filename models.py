from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
import base64
import hashlib
import os
from cryptography.fernet import Fernet

from services.encryption_service import encrypt_val, decrypt_val, get_flask_secret_key, get_encryption_secret_key

db = SQLAlchemy()

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

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

    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    schedule_id = db.Column(
        db.Integer,
        db.ForeignKey("scan_schedule.id", ondelete="SET NULL"),
        nullable=True,
    )
    scheduled_for = db.Column(db.DateTime, nullable=True)
    scheduler_dispatch_state = db.Column(db.String(20), nullable=True)
    scheduler_claimed_at = db.Column(db.DateTime, nullable=True)
    scheduler_claim_token = db.Column(db.String(36), nullable=True)
    scheduler_started_at = db.Column(db.DateTime, nullable=True)
    scheduler_heartbeat_at = db.Column(db.DateTime, nullable=True)
    scheduler_attempt_count = db.Column(db.Integer, nullable=False, default=0)
    scheduler_max_attempts = db.Column(db.Integer, nullable=False, default=3)

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
    audit_credentials = db.Column(db.Boolean, default=False, nullable=True)

    result_data = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=utc_now)

    __table_args__ = (
        db.UniqueConstraint(
            "schedule_id", "scheduled_for", name="uq_scan_result_schedule_occurrence"
        ),
        db.Index(
            "ix_scan_result_scheduler_queue",
            "status",
            "scheduler_dispatch_state",
            "scheduler_claimed_at",
        ),
        db.Index("ix_scan_result_scheduled_for", "scheduled_for"),
    )

    def __repr__(self):
        return f"<ScanResult {self.network_cidr} - {self.scan_type}>"


class ScanSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    
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
    audit_credentials = db.Column(db.Boolean, default=False, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    def __repr__(self):
        return f"<ScanSchedule {self.name} - {self.frequency}>"


class SystemSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), unique=True, nullable=False)
    
    smtp_server = db.Column(db.String(100), default="smtp.gmail.com")
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(100), nullable=True)
    _smtp_password = db.Column("smtp_password", db.String(255), nullable=True)
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

    @property
    def smtp_password(self):
        return decrypt_val(self._smtp_password)

    @smtp_password.setter
    def smtp_password(self, value):
        self._smtp_password = encrypt_val(value)

    def __repr__(self):
        return f"<SystemSetting User {self.user_id}>"


class ScanCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    _username = db.Column("username", db.String(255), nullable=True)
    _password = db.Column("password", db.String(255), nullable=True)
    protocol = db.Column(db.String(20), default="any")  # 'ftp', 'redis', 'http_basic', 'any'
    created_at = db.Column(db.DateTime, default=utc_now)

    @property
    def username(self):
        return decrypt_val(self._username)

    @username.setter
    def username(self, value):
        self._username = encrypt_val(value)

    @property
    def password(self):
        return decrypt_val(self._password)

    @password.setter
    def password(self, value):
        self._password = encrypt_val(value)

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
    confidence_score = db.Column(db.String(20), default="High", nullable=True)  # 'Low', 'Medium', 'High'
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


class SecurityFinding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id", ondelete="CASCADE"), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False, default="tcp")
    service = db.Column(db.String(50), nullable=True)
    version = db.Column(db.String(50), nullable=True)
    cve = db.Column(db.String(50), nullable=True)
    cvss = db.Column(db.Float, nullable=True)
    severity = db.Column(db.String(20), default="Medium")  # 'Low', 'Medium', 'High', 'Critical'
    evidence = db.Column(db.Text, nullable=True)
    first_seen = db.Column(db.DateTime, default=utc_now)
    last_seen = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)
    status = db.Column(db.String(20), default="open")  # 'open', 'resolved', 'accepted_risk', 'false_positive'
    assigned_user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    remediation_note = db.Column(db.Text, nullable=True)
    source_type = db.Column(db.String(50), nullable=True)
    source_rule_id = db.Column(db.Integer, nullable=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_result.id", ondelete="SET NULL"), nullable=True)
    fingerprint = db.Column(db.String(64), nullable=True)
    acceptance_expiry = db.Column(db.DateTime, nullable=True)

    asset = db.relationship("Asset", backref=db.backref("findings", lazy=True, cascade="all, delete-orphan"))
    assigned_user = db.relationship("User", backref="assigned_findings", foreign_keys=[assigned_user_id])

    def __repr__(self):
        return f"<SecurityFinding {self.ip_address}:{self.port} - {self.cve or self.service or 'Issue'}>"


class AssetObservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id", ondelete="CASCADE"), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_result.id", ondelete="CASCADE"), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    mac_address = db.Column(db.String(45), nullable=True)
    hostname = db.Column(db.String(100), nullable=True)
    vendor = db.Column(db.String(100), nullable=True)
    operating_system = db.Column(db.String(100), nullable=True)
    open_ports_hash = db.Column(db.String(64), nullable=True)
    observed_at = db.Column(db.DateTime, default=utc_now)

    asset = db.relationship("Asset", backref=db.backref("observations", lazy=True, cascade="all, delete-orphan"))
    scan = db.relationship("ScanResult", backref=db.backref("observations", lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<AssetObservation {self.ip_address} - Asset {self.asset_id}>"


class SecurityRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), default="Medium")  # 'Low', 'Medium', 'High', 'Critical'
    scope = db.Column(db.String(100), default="*")  # Subnet CIDR or '*'
    port_service_condition = db.Column(db.String(255), nullable=True)  # e.g., 'port:23', 'service:telnet'
    asset_criticality_condition = db.Column(db.String(50), default="*")  # e.g., 'Critical' or '*'
    exception_list = db.Column(db.Text, nullable=True)  # comma-separated IPs or MACs
    remediation_text = db.Column(db.Text, nullable=True)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    user = db.relationship("User", backref=db.backref("security_rules", lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<SecurityRule {self.name} ({self.severity})>"
