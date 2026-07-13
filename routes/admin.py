from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, Response
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime, timezone
import json
import re

from models import ACTIVE_SCAN_STATUSES, db, User, ScanResult, ScanResolutionAudit, SystemSetting, HoneypotLog, HoneypotBlockedIP, SecurityAnomaly, Asset, ScanCredential

admin_bp = Blueprint("admin", __name__)

# Handle the admin required operation.
def admin_required(function):
    # Handle the decorated function operation.
    @wraps(function)
    def decorated_function(*args, **kwargs):
        # Handle the branch where not current_user.is_authenticated evaluates to true.
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        # Handle the branch where not current_user.is_admin evaluates to true.
        if not current_user.is_admin:
            flash("You are not authorised to access this page.", "error")
            return redirect(url_for("scan.scan"))
        return function(*args, **kwargs)
    return decorated_function

# Handle the format local datetime operation.
def format_local_datetime(dt):
    # Handle the branch where not dt evaluates to true.
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")

# Handle the settings operation.
@admin_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    tab = request.args.get("tab", "smtp")
    
    # Enforce admin-only access for the freeze, exclusions, and honeypot tabs
    if tab in ["freeze", "exclusions", "honeypot"] and not current_user.is_admin:
        flash("Unauthorised access to settings.", "error")
        return redirect(url_for("admin.settings", tab="smtp"))
        
    setting = SystemSetting.query.filter_by(user_id=current_user.id).first()

    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        form_type = request.form.get("form_type", "smtp")
        
        # Handle the branch where form_type in ['freeze', 'exclusions', 'honeypot'] and (not current_user.is_admin) evaluates to true.
        if form_type in ["freeze", "exclusions", "honeypot"] and not current_user.is_admin:
            flash("Unauthorised access to settings.", "error")
            return redirect(url_for("admin.settings", tab="smtp"))

        # Handle the branch where not setting evaluates to true.
        if not setting:
            setting = SystemSetting(user_id=current_user.id)
            db.session.add(setting)

        # Handle the branch where form_type == 'smtp' evaluates to true.
        if form_type == "smtp":
            smtp_server = request.form.get("smtp_server", "").strip()
            smtp_port_raw = request.form.get("smtp_port", "").strip()
            smtp_username = request.form.get("smtp_username", "").strip()
            smtp_password = request.form.get("smtp_password", "")
            smtp_sender = request.form.get("smtp_sender", "").strip()
            alert_recipient = request.form.get("alert_recipient", "").strip()
            alert_on_new_ports_only = request.form.get("alert_on_new_ports_only") == "y"

            # Handle the branch where not smtp_server evaluates to true.
            if not smtp_server:
                flash("SMTP server address cannot be empty.", "error")
                return redirect(url_for("admin.settings", tab="smtp"))

            # Run this block with structured exception handling.
            try:
                smtp_port = int(smtp_port_raw)
            # Handle an exception raised by the preceding protected block.
            except ValueError:
                flash("SMTP port must be a valid number.", "error")
                return redirect(url_for("admin.settings", tab="smtp"))

            # Handle the branch where not smtp_sender or not alert_recipient evaluates to true.
            if not smtp_sender or not alert_recipient:
                flash("Sender and Recipient email addresses cannot be empty.", "error")
                return redirect(url_for("admin.settings", tab="smtp"))

            setting.smtp_server = smtp_server
            setting.smtp_port = smtp_port
            setting.smtp_username = smtp_username

            # Handle the branch where smtp_password evaluates to true.
            if smtp_password:
                setting.smtp_password = smtp_password

            setting.smtp_sender = smtp_sender
            setting.alert_recipient = alert_recipient
            setting.alert_on_new_ports_only = alert_on_new_ports_only
            
            flash("System and Email settings saved successfully.", "success")
            tab_redirect = "smtp"
        # Handle the branch where form_type == 'freeze' evaluates to true.
        elif form_type == "freeze":
            scan_freeze_active = request.form.get("scan_freeze_active") == "y"
            scan_freeze_start = request.form.get("scan_freeze_start", "09:00").strip()
            scan_freeze_end = request.form.get("scan_freeze_end", "17:00").strip()
            
            time_pattern = re.compile(r"^\d{2}:\d{2}$")
            # Handle the branch where not time_pattern.match(scan_freeze_start) or not time_pattern.match(scan_freeze_end) evaluates to true.
            if not time_pattern.match(scan_freeze_start) or not time_pattern.match(scan_freeze_end):
                flash("Start Time and End Time must be in HH:MM format (e.g. 09:00, 22:30).", "error")
                return redirect(url_for("admin.settings", tab="freeze"))
                
            setting.scan_freeze_active = scan_freeze_active
            setting.scan_freeze_start = scan_freeze_start
            setting.scan_freeze_end = scan_freeze_end
            
            flash("Scan Blackout settings saved successfully.", "success")
            tab_redirect = "freeze"
        # Handle the branch where form_type == 'exclusions' evaluates to true.
        elif form_type == "exclusions":
            scan_exclusions_active = request.form.get("scan_exclusions_active") == "y"
            scan_exclude_targets = request.form.get("scan_exclude_targets", "").strip()
            
            setting.scan_exclusions_active = scan_exclusions_active
            setting.scan_exclude_targets = scan_exclude_targets if scan_exclude_targets else None
            
            flash("Scan Exclusions saved successfully.", "success")
            tab_redirect = "exclusions"
        # Handle the fallback branch when the preceding condition does not match.
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
        return redirect(url_for("admin.settings", tab=tab_redirect))

    credentials = []
    # Handle the branch where tab == 'credentials' evaluates to true.
    if tab == "credentials":
        credentials = ScanCredential.query.filter_by(user_id=current_user.id).order_by(ScanCredential.created_at.desc()).all()

    return render_template("settings.html", setting=setting, tab=tab, credentials=credentials)

# Add credential.
@admin_bp.route("/settings/credentials/add", methods=["POST"])
@login_required
def add_credential():
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    protocol = request.form.get("protocol", "any").strip()

    # Handle the branch where not name evaluates to true.
    if not name:
        flash("Credential name cannot be empty.", "error")
        return redirect(url_for("admin.settings", tab="credentials"))

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
    return redirect(url_for("admin.settings", tab="credentials"))

# Delete credential.
@admin_bp.route("/settings/credentials/delete/<int:credential_id>", methods=["POST"])
@login_required
def delete_credential(credential_id):
    credential = ScanCredential.query.filter_by(id=credential_id, user_id=current_user.id).first()
    # Handle the branch where not credential evaluates to true.
    if not credential:
        flash("Credential not found.", "error")
        return redirect(url_for("admin.settings", tab="credentials"))

    db.session.delete(credential)
    db.session.commit()
    flash("Credential deleted successfully.", "success")
    return redirect(url_for("admin.settings", tab="credentials"))

# Verify that email behaves as expected.
@admin_bp.route("/settings/test-email", methods=["POST"])
@login_required
def test_email():
    setting = SystemSetting.query.filter_by(user_id=current_user.id).first()
    # Handle the branch where not setting or not setting.smtp_server or (not setting.smtp_sender) or (not setting.alert_recipient) evaluates to true.
    if not setting or not setting.smtp_server or not setting.smtp_sender or not setting.alert_recipient:
        flash("Please fill and save your SMTP settings first.", "error")
        return redirect(url_for("admin.settings"))

    setting_dict = {
        "smtp_server": setting.smtp_server,
        "smtp_port": setting.smtp_port,
        "smtp_username": setting.smtp_username,
        "smtp_password": setting.smtp_password,
        "smtp_sender": setting.smtp_sender,
        "alert_recipient": setting.alert_recipient
    }

    subject = "[Lynceus] Email Notification Test"
    body_html = f"""
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px; background-color: #fcfcf9;">
        <h2 style="color: #4a5d4e; margin-bottom: 10px;">Lynceus Email Test</h2>
        <p>Hello,</p>
        <p>This email is a test notification sent from the Lynceus port scanner application. It confirms that your SMTP settings are working correctly.</p>
        <hr style="border: 0; border-top: 1px solid #ddd; margin: 20px 0;">
        <p style="font-size: 12px; color: #888;">Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    """

    # Run this block with structured exception handling.
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

        # Handle the branch where port == 465 evaluates to true.
        if port == 465:
            server = smtplib.SMTP_SSL(server_name, port, timeout=7)
        # Handle the fallback branch when the preceding condition does not match.
        else:
            server = smtplib.SMTP(server_name, port, timeout=7)
            server.ehlo()
            server.starttls()
            server.ehlo()

        # Handle the branch where username and password evaluates to true.
        if username and password:
            server.login(username, password)

        server.sendmail(setting_dict["smtp_sender"], [setting_dict["alert_recipient"]], msg.as_string())
        server.quit()
        flash("Test email sent successfully! Check the recipient mailbox.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        flash(f"Failed to send test email: {str(e)}", "error")

    return redirect(url_for("admin.settings"))

# Handle the admin panel operation.
@admin_bp.route("/admin")
@login_required
@admin_required
def admin_panel():
    tab = request.args.get("tab", "scans")

    scan_results = ScanResult.query.order_by(ScanResult.created_at.desc()).all()
    users = User.query.order_by(User.created_at.desc()).all()
    has_active_scans = any(
        scan.status in [
            "pending",
            "running",
            "cancellation_requested",
            "termination_failed",
        ]
        for scan in scan_results
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

# Handle the admin toggle user role operation.
@admin_bp.route("/admin/user/<int:user_id>/toggle-admin", methods=["POST"])
@login_required
@admin_required
def admin_toggle_user_role(user_id):
    user = User.query.get_or_404(user_id)
    # Handle the branch where user.id == current_user.id evaluates to true.
    if user.id == current_user.id:
        flash("You cannot demote yourself.", "error")
        return redirect(url_for("admin.admin_panel", tab="users"))

    user.is_admin = not user.is_admin
    db.session.commit()
    role_str = "Administrator" if user.is_admin else "Standard User"
    flash(f"User role updated successfully for {user.email}: {role_str}", "success")
    return redirect(url_for("admin.admin_panel", tab="users"))

# Handle the admin reset user 2fa operation.
@admin_bp.route("/admin/user/<int:user_id>/reset-2fa", methods=["POST"])
@login_required
@admin_required
def admin_reset_user_2fa(user_id):
    user = User.query.get_or_404(user_id)
    user.otp_secret = None
    db.session.commit()
    flash(f"Two-Factor Authentication OTP secret has been reset for administrator: {user.email}", "success")
    return redirect(url_for("admin.admin_panel", tab="users"))

# Handle the admin delete user operation.
@admin_bp.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.filter(User.id == user_id).first_or_404()
    # Handle the branch where user.id == current_user.id evaluates to true.
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin.admin_panel", tab="users"))
    user.is_deleting = True
    db.session.flush()
    # Handle the branch where ScanResult.query.filter(ScanResult.user_id == user.id, ScanResult.status.in_(ACTIVE_SCAN_STATUSES)).first() evaluates to true.
    if ScanResult.query.filter(
        ScanResult.user_id == user.id,
        ScanResult.status.in_(ACTIVE_SCAN_STATUSES),
    ).first():
        user.is_deleting = False
        db.session.commit()
        flash("Stop or resolve the user's active scans before deleting the account.", "error")
        return redirect(url_for("admin.admin_panel", tab="users"))

    # Run this block with structured exception handling.
    try:
        from models import ScanSchedule, SystemSetting, ScanCredential, SecurityRule, AssetObservation, SecurityFinding
        ScanSchedule.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        SystemSetting.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        ScanCredential.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        SecurityRule.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        
        user_scan_ids = [s.id for s in ScanResult.query.filter_by(user_id=user.id).all()]
        # Handle the branch where user_scan_ids evaluates to true.
        if user_scan_ids:
            AssetObservation.query.filter(AssetObservation.scan_id.in_(user_scan_ids)).delete(synchronize_session=False)
            ScanResult.query.filter(ScanResult.id.in_(user_scan_ids)).delete(synchronize_session=False)
            
        SecurityFinding.query.filter_by(assigned_user_id=user.id).update({SecurityFinding.assigned_user_id: None}, synchronize_session=False)

        db.session.delete(user)
        db.session.commit()
        flash(f"User account {user.email} and all their scan data have been permanently deleted.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete user: {str(e)}", "error")

    return redirect(url_for("admin.admin_panel", tab="users"))

# Handle the admin delete scan operation.
@admin_bp.route("/admin/scan/<int:scan_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    # Handle the branch where scan.status in ACTIVE_SCAN_STATUSES evaluates to true.
    if scan.status in ACTIVE_SCAN_STATUSES:
        flash("Stop or resolve the scan before deleting it.", "error")
        return redirect(url_for("admin.admin_panel", tab="scans"))
    from models import AssetObservation
    AssetObservation.query.filter_by(scan_id=scan.id).delete(synchronize_session=False)
    db.session.delete(scan)
    db.session.commit()
    flash("Scan result deleted.", "success")
    return redirect(url_for("admin.admin_panel", tab="scans"))


# Handle the admin resolve orphan scan operation.
@admin_bp.route("/admin/scan/<int:scan_id>/resolve-orphan", methods=["POST"])
@login_required
@admin_required
def admin_resolve_orphan_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    # Handle the branch where scan.status not in {'termination_failed', 'cancellation_requested'} evaluates to true.
    if scan.status not in {"termination_failed", "cancellation_requested"}:
        flash("Only orphaned or stuck-cancellation scans can be resolved.", "warning")
        return redirect(url_for("admin.admin_panel", tab="scans"))
    raw_reason = request.form.get("reason", "")
    reason = re.sub(r"[\r\n\t]+", " ", raw_reason)
    reason = "".join(character for character in reason if character.isprintable())
    reason = re.sub(r"\s+", " ", reason).strip()[:500]
    # Handle the branch where not reason evaluates to true.
    if not reason:
        flash("A resolution reason is required for the audit log.", "error")
        return redirect(url_for("admin.admin_panel", tab="scans"))

    previous_status = scan.status
    previous_worker_id = scan.scheduler_worker_id
    previous_worker_host = scan.scheduler_worker_host
    previous_process_id = scan.scheduler_process_id
    audit = ScanResolutionAudit(
        scan_id=scan.id,
        admin_user_id=current_user.id,
        previous_status=previous_status,
        worker_id=previous_worker_id,
        worker_host=previous_worker_host,
        process_id=previous_process_id,
        reason=reason,
        resolved_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.session.add(audit)
    scan.status = "failed"
    scan.scheduler_dispatch_state = "failed"
    scan.scheduler_execution_phase = "operator_resolved"
    db.session.commit()
    current_app.logger.warning(
        "ADMIN_SCAN_ORPHAN_RESOLVED admin_id=%s scan_id=%s previous_status=%s "
        "worker_id=%s worker_host=%s process_id=%s reason=%r",
        current_user.id,
        scan.id,
        previous_status,
        previous_worker_id,
        previous_worker_host,
        previous_process_id,
        reason,
    )
    flash(
        "Orphan resolved. Concurrency capacity has been released by an administrator.",
        "success",
    )
    return redirect(url_for("admin.admin_panel", tab="scans"))

# Handle the admin unblock ip operation.
@admin_bp.route("/admin/honeypot/unblock/<int:block_id>", methods=["POST"])
@login_required
@admin_required
def admin_unblock_ip(block_id):
    block = HoneypotBlockedIP.query.get_or_404(block_id)
    db.session.delete(block)
    db.session.commit()
    flash(f"IP address {block.ip_address} has been successfully unblocked.", "success")
    return redirect(url_for("admin.admin_panel", tab="honeypot"))

# Handle the admin clear honeypot logs operation.
@admin_bp.route("/admin/honeypot/clear-logs", methods=["POST"])
@login_required
@admin_required
def admin_clear_honeypot_logs():
    # Run this block with structured exception handling.
    try:
        db.session.query(HoneypotLog).delete()
        db.session.commit()
        flash("All decoy honeypot logs cleared successfully.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to clear logs: {str(e)}", "error")
    return redirect(url_for("admin.admin_panel", tab="honeypot"))

# Handle the admin toggle asset trust operation.
@admin_bp.route("/admin/assets/<int:asset_id>/toggle-trust", methods=["POST"])
@login_required
@admin_required
def admin_toggle_asset_trust(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    asset.is_trusted = not asset.is_trusted
    db.session.commit()
    status_str = "trusted" if asset.is_trusted else "untrusted"
    flash(f"Asset {asset.name or asset.ip_address} is now marked as {status_str}.", "success")
    
    # Also resolve anomalies for this IP if marked trusted
    if asset.is_trusted:
        anoms = SecurityAnomaly.query.filter_by(ip_address=asset.ip_address, is_resolved=False).all()
        # Iterate over anoms and bind each item to anom.
        for anom in anoms:
            anom.is_resolved = True
        db.session.commit()
        
    # Return endpoint depending on referrer tab
    ref = request.referrer or ""
    # Handle the branch where 'asset-map' in ref evaluates to true.
    if "asset-map" in ref:
        return redirect(url_for("admin.asset_map"))
    return redirect(url_for("admin.admin_assets"))

# Handle the admin resolve anomaly operation.
@admin_bp.route("/admin/anomalies/<int:anomaly_id>/resolve", methods=["POST"])
@login_required
@admin_required
def admin_resolve_anomaly(anomaly_id):
    anomaly = SecurityAnomaly.query.get_or_404(anomaly_id)
    anomaly.is_resolved = not anomaly.is_resolved
    db.session.commit()
    status_str = "resolved" if anomaly.is_resolved else "unresolved"
    flash(f"Anomaly #{anomaly.id} ({anomaly.anomaly_type}) marked as {status_str}.", "success")
    
    ref = request.referrer or ""
    # Handle the branch where 'asset-map' in ref evaluates to true.
    if "asset-map" in ref:
        return redirect(url_for("admin.asset_map"))
    return redirect(url_for("admin.admin_panel", tab="anomalies"))

# Handle the admin delete anomaly operation.
@admin_bp.route("/admin/anomalies/<int:anomaly_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_anomaly(anomaly_id):
    anomaly = SecurityAnomaly.query.get_or_404(anomaly_id)
    db.session.delete(anomaly)
    db.session.commit()
    flash("Anomaly record deleted successfully.", "success")
    return redirect(url_for("admin.admin_panel", tab="anomalies"))

# Handle the admin bulk delete users operation.
@admin_bp.route("/admin/users/bulk-delete", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_users():
    user_ids = request.form.getlist("user_ids")
    # Handle the branch where not user_ids evaluates to true.
    if not user_ids:
        flash("No users selected for deletion.", "warning")
        return redirect(url_for("admin.admin_panel", tab="users"))
    # Run this block with structured exception handling.
    try:
        int_ids = [int(uid) for uid in user_ids]
        # Handle the branch where current_user.id in int_ids evaluates to true.
        if current_user.id in int_ids:
            flash("You cannot delete your own account in bulk delete.", "error")
            return redirect(url_for("admin.admin_panel", tab="users"))
        users_to_delete = User.query.filter(User.id.in_(int_ids)).all()
        # Iterate over users_to_delete and bind each item to user.
        for user in users_to_delete:
            user.is_deleting = True
        db.session.flush()
        # Handle the branch where ScanResult.query.filter(ScanResult.user_id.in_(int_ids), ScanResult.status.in_(ACTIVE_SCAN_STATUSES)).first() evaluates to true.
        if ScanResult.query.filter(
            ScanResult.user_id.in_(int_ids),
            ScanResult.status.in_(ACTIVE_SCAN_STATUSES),
        ).first():
            db.session.rollback()
            flash("Stop or resolve active scans before deleting these users.", "error")
            return redirect(url_for("admin.admin_panel", tab="users"))

        from models import ScanSchedule, SystemSetting, ScanCredential, SecurityRule, AssetObservation, SecurityFinding
        ScanSchedule.query.filter(ScanSchedule.user_id.in_(int_ids)).delete(synchronize_session=False)
        SystemSetting.query.filter(SystemSetting.user_id.in_(int_ids)).delete(synchronize_session=False)
        ScanCredential.query.filter(ScanCredential.user_id.in_(int_ids)).delete(synchronize_session=False)
        SecurityRule.query.filter(SecurityRule.user_id.in_(int_ids)).delete(synchronize_session=False)
        
        user_scan_ids = [s.id for s in ScanResult.query.filter(ScanResult.user_id.in_(int_ids)).all()]
        # Handle the branch where user_scan_ids evaluates to true.
        if user_scan_ids:
            AssetObservation.query.filter(AssetObservation.scan_id.in_(user_scan_ids)).delete(synchronize_session=False)
            ScanResult.query.filter(ScanResult.id.in_(user_scan_ids)).delete(synchronize_session=False)
            
        SecurityFinding.query.filter(SecurityFinding.assigned_user_id.in_(int_ids)).update({SecurityFinding.assigned_user_id: None}, synchronize_session=False)

        deleted_count = User.query.filter(User.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} user accounts.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete users: {str(e)}", "error")
    return redirect(url_for("admin.admin_panel", tab="users"))

# Handle the admin bulk delete scans operation.
@admin_bp.route("/admin/scans/bulk-delete", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_scans():
    scan_ids = request.form.getlist("scan_ids")
    # Handle the branch where not scan_ids evaluates to true.
    if not scan_ids:
        flash("No scans selected for deletion.", "warning")
        return redirect(url_for("admin.admin_panel", tab="scans"))
    # Run this block with structured exception handling.
    try:
        int_ids = [int(sid) for sid in scan_ids]
        # Handle the branch where ScanResult.query.filter(ScanResult.id.in_(int_ids), ScanResult.status.in_(ACTIVE_SCAN_STATUSES)).first() evaluates to true.
        if ScanResult.query.filter(
            ScanResult.id.in_(int_ids),
            ScanResult.status.in_(ACTIVE_SCAN_STATUSES),
        ).first():
            flash("Stop or resolve active scans before deleting them.", "error")
            return redirect(url_for("admin.admin_panel", tab="scans"))
        from models import AssetObservation
        AssetObservation.query.filter(AssetObservation.scan_id.in_(int_ids)).delete(synchronize_session=False)
        deleted_count = ScanResult.query.filter(ScanResult.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} scan records.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete scans: {str(e)}", "error")
    return redirect(url_for("admin.admin_panel", tab="scans"))

# Handle the admin bulk unblock ips operation.
@admin_bp.route("/admin/honeypot/bulk-unblock", methods=["POST"])
@login_required
@admin_required
def admin_bulk_unblock_ips():
    block_ids = request.form.getlist("block_ids")
    # Handle the branch where not block_ids evaluates to true.
    if not block_ids:
        flash("No blocked IPs selected.", "warning")
        return redirect(url_for("admin.admin_panel", tab="honeypot"))
    # Run this block with structured exception handling.
    try:
        int_ids = [int(bid) for bid in block_ids]
        deleted_count = HoneypotBlockedIP.query.filter(HoneypotBlockedIP.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully unblocked {deleted_count} IP addresses.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to unblock IPs: {str(e)}", "error")
    return redirect(url_for("admin.admin_panel", tab="honeypot"))

# Handle the admin bulk delete logs operation.
@admin_bp.route("/admin/honeypot/bulk-delete-logs", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_logs():
    log_ids = request.form.getlist("log_ids")
    # Handle the branch where not log_ids evaluates to true.
    if not log_ids:
        flash("No logs selected.", "warning")
        return redirect(url_for("admin.admin_panel", tab="honeypot"))
    # Run this block with structured exception handling.
    try:
        int_ids = [int(lid) for lid in log_ids]
        deleted_count = HoneypotLog.query.filter(HoneypotLog.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} log entries.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete logs: {str(e)}", "error")
    return redirect(url_for("admin.admin_panel", tab="honeypot"))

# Handle the admin bulk delete anomalies operation.
@admin_bp.route("/admin/anomalies/bulk-delete", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_anomalies():
    anomaly_ids = request.form.getlist("anomaly_ids")
    # Handle the branch where not anomaly_ids evaluates to true.
    if not anomaly_ids:
        flash("No anomalies selected.", "warning")
        return redirect(url_for("admin.admin_panel", tab="anomalies"))
    # Run this block with structured exception handling.
    try:
        int_ids = [int(aid) for aid in anomaly_ids]
        deleted_count = SecurityAnomaly.query.filter(SecurityAnomaly.id.in_(int_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} anomaly records.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete anomalies: {str(e)}", "error")
    return redirect(url_for("admin.admin_panel", tab="anomalies"))

# Handle the admin bulk resolve anomalies operation.
@admin_bp.route("/admin/anomalies/bulk-resolve", methods=["POST"])
@login_required
@admin_required
def admin_bulk_resolve_anomalies():
    anomaly_ids = request.form.getlist("anomaly_ids")
    # Handle the branch where not anomaly_ids evaluates to true.
    if not anomaly_ids:
        flash("No anomalies selected.", "warning")
        return redirect(url_for("admin.admin_panel", tab="anomalies"))
    # Run this block with structured exception handling.
    try:
        int_ids = [int(aid) for aid in anomaly_ids]
        anoms = SecurityAnomaly.query.filter(SecurityAnomaly.id.in_(int_ids)).all()
        # Iterate over anoms and bind each item to a.
        for a in anoms:
            a.is_resolved = True
        db.session.commit()
        flash(f"Successfully resolved {len(anoms)} selected anomalies.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to resolve anomalies: {str(e)}", "error")
    return redirect(url_for("admin.admin_panel", tab="anomalies"))

# Handle the asset map operation.
@admin_bp.route("/admin/asset-map")
@login_required
def asset_map():
    return redirect(url_for("topology.view_topology"))

# Handle the admin assets operation.
@admin_bp.route("/admin/assets")
@login_required
def admin_assets():
    search = request.args.get("search", "").strip()
    criticality = request.args.get("criticality", "").strip()
    device_type = request.args.get("device_type", "").strip()
    ip_assignment_type = request.args.get("ip_assignment_type", "").strip()

    query = Asset.query
    # Handle the branch where search evaluates to true.
    if search:
        query = query.filter(
            db.or_(
                Asset.name.ilike(f"%{search}%"),
                Asset.ip_address.ilike(f"%{search}%"),
                Asset.mac_address.ilike(f"%{search}%"),
                Asset.mac_vendor.ilike(f"%{search}%"),
                Asset.operating_system.ilike(f"%{search}%"),
                Asset.owner.ilike(f"%{search}%")
            )
        )
    # Handle the branch where criticality evaluates to true.
    if criticality:
        query = query.filter_by(criticality=criticality)
    # Handle the branch where device_type evaluates to true.
    if device_type:
        query = query.filter_by(device_type=device_type)
    # Handle the branch where ip_assignment_type evaluates to true.
    if ip_assignment_type:
        query = query.filter_by(ip_assignment_type=ip_assignment_type)

    assets = query.order_by(Asset.ip_address).all()
    device_types = [r[0] for r in db.session.query(Asset.device_type).distinct().all() if r[0]]

    return render_template(
        "admin_assets.html",
        assets=assets,
        device_types=device_types,
        search=search,
        selected_criticality=criticality,
        selected_device_type=device_type,
        selected_ip_assignment=ip_assignment_type
    )

# Handle the admin new asset operation.
@admin_bp.route("/admin/assets/new", methods=["GET", "POST"])
@login_required
@admin_required
def admin_new_asset():
    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        mac_address = request.form.get("mac_address", "").strip().lower()
        mac_vendor = request.form.get("mac_vendor", "").strip()
        device_type = request.form.get("device_type", "Unknown").strip()
        operating_system = request.form.get("operating_system", "").strip()
        criticality = request.form.get("criticality", "Medium").strip()
        owner = request.form.get("owner", "").strip()
        location = request.form.get("location", "").strip()
        serial_number = request.form.get("serial_number", "").strip()
        ip_assignment_type = request.form.get("ip_assignment_type", "DHCP").strip()
        notes = request.form.get("notes", "").strip()
        is_trusted = request.form.get("is_trusted") == "y"

        # Handle the branch where not ip_address evaluates to true.
        if not ip_address:
            flash("IP Address is required.", "error")
            return redirect(url_for("admin.admin_new_asset"))

        # Simple validation
        try:
            import ipaddress
            ipaddress.ip_address(ip_address)
        # Handle an exception raised by the preceding protected block.
        except ValueError:
            flash("Invalid IP Address format.", "error")
            return redirect(url_for("admin.admin_new_asset"))

        # Handle the branch where mac_address evaluates to true.
        if mac_address:
            # Handle the branch where not re.match('^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$', mac_address) evaluates to true.
            if not re.match(r"^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$", mac_address):
                flash("Invalid MAC Address format. Use e.g. 00:11:22:33:44:55", "error")
                return redirect(url_for("admin.admin_new_asset"))

        # Check duplicate
        dup = None
        # Handle the branch where mac_address evaluates to true.
        if mac_address:
            dup = Asset.query.filter(Asset.mac_address.ilike(mac_address)).first()
        # Handle the branch where not dup evaluates to true.
        if not dup:
            dup = Asset.query.filter_by(ip_address=ip_address).first()

        # Handle the branch where dup evaluates to true.
        if dup:
            flash(f"An asset with target IP/MAC already exists: {dup.name or dup.ip_address}", "error")
            return redirect(url_for("admin.admin_new_asset"))

        asset = Asset(
            name=name if name else f"Device {ip_address}",
            ip_address=ip_address,
            mac_address=mac_address if mac_address else None,
            mac_vendor=mac_vendor if mac_vendor else None,
            device_type=device_type,
            operating_system=operating_system if operating_system else None,
            criticality=criticality,
            owner=owner if owner else None,
            location=location if location else None,
            serial_number=serial_number if serial_number else None,
            ip_assignment_type=ip_assignment_type,
            notes=notes if notes else None,
            is_trusted=is_trusted
        )
        db.session.add(asset)
        db.session.commit()
        flash("Asset added to inventory successfully.", "success")
        return redirect(url_for("admin.admin_assets"))

    return render_template("admin_asset_form.html", asset=None)

# Handle the admin edit asset operation.
@admin_bp.route("/admin/assets/<int:asset_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def admin_edit_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        asset.name = request.form.get("name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        mac_address = request.form.get("mac_address", "").strip().lower()
        asset.mac_vendor = request.form.get("mac_vendor", "").strip()
        asset.device_type = request.form.get("device_type", "Unknown").strip()
        asset.operating_system = request.form.get("operating_system", "").strip()
        asset.criticality = request.form.get("criticality", "Medium").strip()
        asset.owner = request.form.get("owner", "").strip()
        asset.location = request.form.get("location", "").strip()
        asset.serial_number = request.form.get("serial_number", "").strip()
        asset.ip_assignment_type = request.form.get("ip_assignment_type", "DHCP").strip()
        asset.notes = request.form.get("notes", "").strip()
        asset.is_trusted = request.form.get("is_trusted") == "y"

        # Handle the branch where not ip_address evaluates to true.
        if not ip_address:
            flash("IP Address is required.", "error")
            return redirect(url_for("admin.admin_edit_asset", asset_id=asset.id))

        # Run this block with structured exception handling.
        try:
            import ipaddress
            ipaddress.ip_address(ip_address)
        # Handle an exception raised by the preceding protected block.
        except ValueError:
            flash("Invalid IP Address format.", "error")
            return redirect(url_for("admin.admin_edit_asset", asset_id=asset.id))

        # Handle the branch where mac_address evaluates to true.
        if mac_address:
            # Handle the branch where not re.match('^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$', mac_address) evaluates to true.
            if not re.match(r"^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$", mac_address):
                flash("Invalid MAC Address format.", "error")
                return redirect(url_for("admin.admin_edit_asset", asset_id=asset.id))

        # Check duplicate excluding current
        dup = None
        # Handle the branch where mac_address evaluates to true.
        if mac_address:
            dup = Asset.query.filter(Asset.mac_address.ilike(mac_address)).filter(Asset.id != asset.id).first()
        # Handle the branch where not dup evaluates to true.
        if not dup:
            dup = Asset.query.filter_by(ip_address=ip_address).filter(Asset.id != asset.id).first()

        # Handle the branch where dup evaluates to true.
        if dup:
            flash(f"Another asset with target IP/MAC already exists.", "error")
            return redirect(url_for("admin.admin_edit_asset", asset_id=asset.id))

        asset.ip_address = ip_address
        asset.mac_address = mac_address if mac_address else None
        db.session.commit()
        flash("Asset inventory details updated successfully.", "success")
        return redirect(url_for("admin.admin_assets"))

    return render_template("admin_asset_form.html", asset=asset)

# Handle the admin delete asset operation.
@admin_bp.route("/admin/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    
    # Also delete related anomalies to keep db clean
    SecurityAnomaly.query.filter(
        db.or_(
            SecurityAnomaly.ip_address == asset.ip_address,
            SecurityAnomaly.mac_address == asset.mac_address
        )
    ).delete(synchronize_session=False)

    db.session.delete(asset)
    db.session.commit()
    flash("Asset successfully deleted from inventory.", "success")
    return redirect(url_for("admin.admin_assets"))

# Handle the admin bulk delete assets operation.
@admin_bp.route("/admin/assets/bulk-delete", methods=["POST"])
@login_required
@admin_required
def admin_bulk_delete_assets():
    asset_ids = request.form.getlist("asset_ids")
    # Handle the branch where not asset_ids evaluates to true.
    if not asset_ids:
        flash("No assets selected for deletion.", "warning")
        return redirect(url_for("admin.admin_assets"))

    # Run this block with structured exception handling.
    try:
        int_ids = [int(aid) for aid in asset_ids]
        assets_to_delete = Asset.query.filter(Asset.id.in_(int_ids)).all()
        ips = [a.ip_address for a in assets_to_delete if a.ip_address]
        macs = [a.mac_address for a in assets_to_delete if a.mac_address]
        
        # Handle the branch where ips or macs evaluates to true.
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
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk deletion: {str(e)}", "error")

    return redirect(url_for("admin.admin_assets"))
