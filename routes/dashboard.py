from flask import Blueprint, render_template, redirect, url_for, current_app
from flask_login import login_required, current_user
from datetime import datetime, timezone

from models import User, ScanResult, ScanSchedule, SystemSetting, SecurityAnomaly, Asset, HoneypotLog, HoneypotBlockedIP
from services.risk_service import calculate_network_risk_score

dashboard_bp = Blueprint("dashboard", __name__)

# Handle the format local datetime operation.
def format_local_datetime(dt):
    # Handle the branch where not dt evaluates to true.
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")

# Handle the dashboard operation.
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
    # Handle the branch where current_user.is_admin evaluates to true.
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
    risk_components = risk_data["components"]

    # 6. Asset scores come from the same evidence model as the network score.
    top_highest_risk_assets = risk_data["assets"][:5]
    
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
        risk_components=risk_components,
        highest_risk_assets=top_highest_risk_assets,
        honeypot_active=honeypot_active,
        smtp_configured=smtp_configured,
        current_date=current_date,
        honeypot_paths_count=HONEYPOT_PATHS_COUNT
    )
