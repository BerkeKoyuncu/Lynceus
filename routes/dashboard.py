from flask import Blueprint, render_template, redirect, url_for, current_app
from flask_login import login_required, current_user
from datetime import datetime, timezone

from models import db, User, ScanResult, ScanSchedule, SystemSetting, SecurityAnomaly, Asset, HoneypotLog, HoneypotBlockedIP, SecurityFinding
from services.rule_service import calculate_network_risk_score

dashboard_bp = Blueprint("dashboard", __name__)

def format_local_datetime(dt):
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")

@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    # 1. Fetch user scan stats
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    running_scans = ScanResult.query.filter_by(user_id=current_user.id).filter(
        ScanResult.status.in_([
            "pending",
            "running",
            "cancellation_requested",
            "termination_failed",
        ])
    ).count()
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
    
    # SMTP alerts are user-specific
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

    # 5. Dynamic Risk Score Calculation
    risk_data = calculate_network_risk_score(current_user.id)
    risk_score = risk_data["score"]
    risk_level = risk_data["level"]
    risk_color = risk_data["color"]
    risk_bg = risk_data["bg"]
    risk_factors = risk_data["factors"]

    # 6. Calculate Individual Asset Risk Scores
    assets = Asset.query.all()
    highest_risk_assets = []
    
    unresolved_anomalies = SecurityAnomaly.query.filter_by(is_resolved=False).all()
    anomaly_ips = {a.ip_address: a for a in unresolved_anomalies if a.ip_address}
    anomaly_macs = {a.mac_address.lower(): a for a in unresolved_anomalies if a.mac_address}

    for asset in assets:
        asset_score = 0
        crit = (asset.criticality or "Medium").lower()
        if crit == "critical":
            asset_score += 40
        elif crit == "high":
            asset_score += 30
        elif crit == "low":
            asset_score += 10
        else:  # Medium
            asset_score += 20
            
        if not asset.is_trusted:
            asset_score += 15
            
        has_anomaly = False
        if asset.ip_address in anomaly_ips:
            has_anomaly = True
        if asset.mac_address and asset.mac_address.lower() in anomaly_macs:
            has_anomaly = True
            
        if has_anomaly:
            asset_score += 20
            
        # Add risk score from open findings
        open_findings_count = SecurityFinding.query.filter_by(asset_id=asset.id, status="open").count()
        asset_score += min(open_findings_count * 10, 40)
            
        asset_score = min(asset_score, 100)
        
        if asset_score >= 70:
            asset_level = "Critical" if crit == "critical" else "High"
            asset_color = "var(--error-text)"
            asset_bg = "var(--error-bg)"
        elif asset_score >= 35:
            asset_level = "Medium"
            asset_color = "var(--warning-text)"
            asset_bg = "var(--warning-bg)"
        else:
            asset_level = "Low"
            asset_color = "var(--success-text)"
            asset_bg = "var(--success-bg)"
            
        highest_risk_assets.append({
            "id": asset.id,
            "name": asset.name or asset.ip_address,
            "ip_address": asset.ip_address,
            "mac_address": asset.mac_address or "N/A",
            "criticality": asset.criticality or "Medium",
            "is_trusted": asset.is_trusted,
            "score": asset_score,
            "level": asset_level,
            "color": asset_color,
            "bg": asset_bg
        })
        
    highest_risk_assets.sort(key=lambda x: x["score"], reverse=True)
    top_highest_risk_assets = highest_risk_assets[:5]
    
    current_date = format_local_datetime(datetime.now(timezone.utc).replace(tzinfo=None))
    HONEYPOT_PATHS_COUNT = 12 # Default honeypot paths count
    
    return render_template(
        "dashboard.html",
        user_stats=user_stats,
        admin_stats=admin_stats,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_color=risk_color,
        risk_bg=risk_bg,
        risk_factors=risk_factors,
        highest_risk_assets=top_highest_risk_assets,
        honeypot_active=honeypot_active,
        smtp_configured=smtp_configured,
        current_date=current_date,
        honeypot_paths_count=HONEYPOT_PATHS_COUNT
    )
