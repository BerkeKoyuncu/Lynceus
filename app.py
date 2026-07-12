import os
import re
import json
import time
import threading
import uuid
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, session, current_app
from flask_login import LoginManager, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from functools import wraps
import click
from sqlalchemy import and_, func, or_

from models import db, User, ScanResult, ScanDispatchLock, ScanSchedule, SystemSetting, HoneypotLog, HoneypotBlockedIP, SecurityAnomaly, Asset
from services.encryption_service import get_flask_secret_key
from services.scan_service import execute_scan
from services.email_service import send_notification_email_async

login_manager = LoginManager()
login_manager.login_view = "auth.login"
csrf = CSRFProtect()
migrate = Migrate()

try:
    from zoneinfo import ZoneInfo
    APP_TIMEZONE = ZoneInfo("Europe/Istanbul")
except Exception:
    APP_TIMEZONE = timezone(timedelta(hours=3), "TRT")

HONEYPOT_PATHS = [
    "/wp-admin", "/wp-login.php", "/administrator", "/phpmyadmin",
    "/.git", "/.env", "/config.json", "/backup.zip", "/database.sql",
    "/admin/config.php", "/setup.php", "/xmlrpc.php"
]

def format_local_datetime(value):
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(APP_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")

def is_in_freeze_window(start_str, end_str):
    try:
        start_time = datetime.strptime(start_str.strip(), "%H:%M").time()
        end_time = datetime.strptime(end_str.strip(), "%H:%M").time()
        now_local = datetime.now(APP_TIMEZONE).time()
        if start_time <= end_time:
            return start_time <= now_local <= end_time
        else:
            return now_local >= start_time or now_local <= end_time
    except Exception:
        return False

def is_scan_frozen():
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

def get_client_ip():
    if current_app.config.get("TRUST_PROXY"):
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
    return request.remote_addr


def _validate_scheduler_config(app):
    minimums = {
        "MAX_CONCURRENT_SCANS": 1,
        "SCHEDULER_LEASE_SECONDS": 30,
        "SCHEDULER_HEARTBEAT_SECONDS": 5,
        "SCHEDULER_MAX_ATTEMPTS": 1,
    }
    for name, minimum in minimums.items():
        try:
            value = int(app.config[name])
        except (TypeError, ValueError) as error:
            raise RuntimeError(f"{name} must be an integer.") from error
        app.config[name] = max(minimum, value)

    if (
        app.config["SCHEDULER_HEARTBEAT_SECONDS"] * 3
        > app.config["SCHEDULER_LEASE_SECONDS"]
    ):
        raise RuntimeError(
            "SCHEDULER_LEASE_SECONDS must be at least three times "
            "SCHEDULER_HEARTBEAT_SECONDS."
        )

def create_app(config=None):
    app = Flask(__name__)
    
    app.config["SECRET_KEY"] = get_flask_secret_key()
    # Support PostgreSQL dynamically via environment variable, fallback to SQLite
    database_url = os.environ.get("DATABASE_URL") or "sqlite:///database.db"
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["TRUST_PROXY"] = os.environ.get("TRUST_PROXY", "False").lower() in ("true", "1", "yes")
    app.config["SEED_DEMO_DATA"] = os.environ.get("SEED_DEMO_DATA", "False").lower() in ("true", "1", "yes")
    app.config["START_SCHEDULER"] = (
        os.environ.get("START_SCHEDULER", "false").lower() in {"true", "1", "yes"}
    )
    app.config["MAX_CONCURRENT_SCANS"] = os.environ.get("MAX_CONCURRENT_SCANS", "4")
    app.config["SCHEDULER_LEASE_SECONDS"] = os.environ.get("SCHEDULER_LEASE_SECONDS", "120")
    app.config["SCHEDULER_HEARTBEAT_SECONDS"] = os.environ.get("SCHEDULER_HEARTBEAT_SECONDS", "20")
    app.config["SCHEDULER_MAX_ATTEMPTS"] = os.environ.get("SCHEDULER_MAX_ATTEMPTS", "3")

    if config:
        app.config.update(config)
    _validate_scheduler_config(app)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)

    # Register blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.scan import scan_bp
    from routes.admin import admin_bp
    from routes.findings import findings_bp
    from routes.rules import rules_bp
    from routes.topology import topology_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(topology_bp)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.context_processor
    def override_url_for():
        from flask import url_for as flask_url_for
        
        class RequestProxy:
            def __init__(self, original_request):
                self._req = original_request

            @property
            def endpoint(self):
                ep = self._req.endpoint
                if ep and "." in ep:
                    return ep.split(".", 1)[1]
                return ep

            def __getattr__(self, name):
                return getattr(self._req, name)

        def custom_url_for(endpoint, **values):
            # Map legacy names to blueprint names
            legacy_mapping = {
                "index": "auth.index",
                "login": "auth.login",
                "register": "auth.register",
                "logout": "auth.logout",
                "login_2fa": "auth.login_2fa",
                "login_2fa_setup": "auth.login_2fa_setup",
                "dashboard": "dashboard.dashboard",
                "scan": "scan.scan",
                "history": "scan.history",
                "schedules": "scan.schedules",
                "new_schedule": "scan.new_schedule",
                "edit_schedule": "scan.edit_schedule",
                "delete_schedule": "scan.delete_schedule",
                "toggle_schedule": "scan.toggle_schedule",
                "bulk_delete_schedules": "scan.bulk_delete_schedules",
                "compare_scans": "scan.compare_scans",
                "result": "scan.result",
                "result_report": "scan.result_report",
                "print_report": "scan.result_report",
                "repeat_scan": "scan.repeat_scan",
                "stop_scan": "scan.stop_scan",
                "export_result_csv": "scan.export_result_csv",
                "export_result_json": "scan.export_result_json",
                "export_result_txt": "scan.export_result_txt",
                "settings": "admin.settings",
                "add_credential": "admin.add_credential",
                "delete_credential": "admin.delete_credential",
                "test_email": "admin.test_email",
                "admin_panel": "admin.admin_panel",
                "admin_toggle_user_role": "admin.admin_toggle_user_role",
                "admin_reset_user_2fa": "admin.admin_reset_user_2fa",
                "admin_delete_user": "admin.admin_delete_user",
                "admin_delete_scan": "admin.admin_delete_scan",
                "admin_unblock_ip": "admin.admin_unblock_ip",
                "admin_clear_honeypot_logs": "admin.admin_clear_honeypot_logs",
                "admin_toggle_asset_trust": "admin.admin_toggle_asset_trust",
                "admin_resolve_anomaly": "admin.admin_resolve_anomaly",
                "admin_delete_anomaly": "admin.admin_delete_anomaly",
                "admin_bulk_delete_users": "admin.admin_bulk_delete_users",
                "admin_bulk_delete_scans": "admin.admin_bulk_delete_scans",
                "admin_bulk_unblock_ips": "admin.admin_bulk_unblock_ips",
                "admin_bulk_delete_logs": "admin.admin_bulk_delete_logs",
                "admin_bulk_delete_anomalies": "admin.admin_bulk_delete_anomalies",
                "admin_bulk_resolve_anomalies": "admin.admin_bulk_resolve_anomalies",
                "asset_map": "admin.asset_map",
                "admin_assets": "admin.admin_assets",
                "admin_new_asset": "admin.admin_new_asset",
                "admin_edit_asset": "admin.admin_edit_asset",
                "admin_delete_asset": "admin.admin_delete_asset",
                "admin_bulk_delete_assets": "admin.admin_bulk_delete_assets",
            }
            if endpoint in legacy_mapping:
                endpoint = legacy_mapping[endpoint]
            return flask_url_for(endpoint, **values)
        return dict(url_for=custom_url_for, request=RequestProxy(request))

    # Decoystop and blocker
    @app.before_request
    def check_honeypot_and_blocking():
        if request.path.startswith('/static/') or request.path == '/favicon.ico':
            return

        client_ip = get_client_ip()
        is_blocked = HoneypotBlockedIP.query.filter_by(ip_address=client_ip).first()
        if is_blocked:
            if request.endpoint not in ['auth.logout', 'scan.result', 'static', 'honeypot_blocked']:
                # Custom blocked view function
                return redirect(url_for('honeypot_blocked'))
            return

        request_path = request.path.lower().rstrip('/')
        is_honeypot_hit = False
        for path in HONEYPOT_PATHS:
            if request_path == path or request_path.startswith(path + '/'):
                is_honeypot_hit = True
                break
                
        if is_honeypot_hit:
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
                return
                
            headers_dict = dict(request.headers)
            headers_str = json.dumps(headers_dict, indent=2)
            
            new_log = HoneypotLog(
                ip_address=client_ip,
                user_agent=request.user_agent.string,
                path=request.path,
                headers=headers_str
            )
            db.session.add(new_log)
            
            if auto_block and client_ip not in ['127.0.0.1', '::1', 'localhost']:
                existing_block = HoneypotBlockedIP.query.filter_by(ip_address=client_ip).first()
                if not existing_block:
                    new_block = HoneypotBlockedIP(
                        ip_address=client_ip,
                        reason=f"Accessed decoy endpoint: {request.path}"
                    )
                    db.session.add(new_block)
                    
            db.session.commit()
            
            if email_alert and smtp_setting and smtp_setting.smtp_server and smtp_setting.smtp_sender and smtp_setting.alert_recipient:
                subject = f"[SECURITY ALERT] Honeypot Intrusion Detected: {client_ip}"
                local_time_str = format_local_datetime(datetime.now(timezone.utc).replace(tzinfo=None))
                body_html = f"""
                <div style="font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 0 auto; padding: 25px; border: 1px solid #fed7d7; border-radius: 12px; background-color: #fff5f5; color: #2d3748;">
                    <div style="text-align: center; margin-bottom: 20px;">
                        <h2 style="color: #c53030; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">⚠️ Honeypot Security Alert</h2>
                        <p style="color: #9b2c2c; margin: 5px 0 0 0; font-size: 14px;">An intrusion attempt was detected on a decoy honeypot endpoint!</p>
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
                            <td style="padding: 10px; font-weight: bold;">Time</td>
                            <td style="padding: 10px;">{local_time_str}</td>
                        </tr>
                    </table>
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

    @app.route("/honeypot/blocked")
    def honeypot_blocked():
        client_ip = get_client_ip()
        block = HoneypotBlockedIP.query.filter_by(ip_address=client_ip).first()
        if not block:
            return redirect(url_for("auth.index"))
        return render_template("blocked.html", ip_address=client_ip, block=block)

    # CLI actions
    @app.cli.command("init-db")
    def init_db():
        click.echo("Tables are managed by Alembic. Run 'flask db upgrade' to apply all migrations.")
        click.echo("Then run 'flask create-admin' to create the first admin account.")

    def print_cli_qr(prov_uri):
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
        Creates the only admin user for Lynceus or resets their credentials/2FA.
        Run with:
            python -m flask --app app create-admin
        """
        import pyotp
        from werkzeug.security import generate_password_hash, check_password_hash

        existing_admin = User.query.filter_by(is_admin=True).first()

        if existing_admin:
            click.echo(f"An admin user already exists: {existing_admin.email}")
            if not click.confirm("Do you want to reset their password and 2FA OTP secret?"):
                return
            
            auth_success = False
            attempts = 3
            while attempts > 0:
                current_pass_or_key = click.prompt(
                    "Enter current Admin password OR the App SECRET_KEY to authorise reset",
                    hide_input=True
                ).strip()
                
                if check_password_hash(existing_admin.password_hash, current_pass_or_key) or current_pass_or_key == current_app.config.get("SECRET_KEY"):
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
            prov_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=existing_admin.email, issuer_name="Lynceus")
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
        prov_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=email, issuer_name="Lynceus")
        click.echo(f"Provisioning URI: {prov_uri}")
        print_cli_qr(prov_uri)
        click.echo("Please add this secret key or scan the URI in your Authenticator app (e.g. Google Authenticator).")
        click.echo("==================================================")

    @app.cli.command("cleanup-scans")
    def cleanup_scans_command():
        cleanup_stale_scans()
        click.echo("Stale scans cleaned up successfully.")

    @app.cli.command("seed-demo-data")
    def seed_demo_data_command():
        seed_mock_security_data()
        click.echo("Demo security data seeded successfully.")

    # Background threads
    import sys
    is_cli = (
        os.environ.get("FLASK_RUN_FROM_CLI") == "true"
        or (len(sys.argv) > 1 and sys.argv[1] in ["db", "create-admin", "init-db", "cleanup-scans", "seed-demo-data"])
    )
    if (
        app.config.get("START_SCHEDULER", True)
        and not app.config.get("TESTING", False)
        and not is_cli
    ):
        start_scheduler(app)
    if not app.config.get("TESTING", False) and not is_cli:
        start_scan_dispatcher(app)

    with app.app_context():
        if app.config.get("SEED_DEMO_DATA"):
            try:
                seed_mock_security_data()
            except Exception:
                pass
        try:
            cleanup_stale_scans()
        except Exception:
            pass

    return app

def _next_schedule_run(now, frequency):
    intervals = {
        "hourly": timedelta(hours=1),
        "daily": timedelta(days=1),
        "weekly": timedelta(weeks=1),
        "monthly": timedelta(days=30),
    }
    return now + intervals.get(frequency, timedelta(days=1))


def _claim_scheduled_scan(schedule, now):
    """Atomically claim one occurrence and persist a recoverable queued job."""
    due_at = schedule.next_run
    claimed = ScanSchedule.query.filter(
        ScanSchedule.id == schedule.id,
        ScanSchedule.is_active.is_(True),
        ScanSchedule.next_run == due_at,
        ScanSchedule.next_run <= now,
    ).update(
        {
            ScanSchedule.last_run: now,
            ScanSchedule.next_run: _next_schedule_run(now, schedule.frequency),
        },
        synchronize_session=False,
    )
    if claimed != 1:
        db.session.rollback()
        return None

    # Reload under the claim transaction so a configuration edit committed
    # before our UPDATE is reflected in this occurrence.
    db.session.refresh(schedule)
    schedule.next_run = _next_schedule_run(now, schedule.frequency)
    scan_values = {
        "user_id": schedule.user_id,
        "input_ip": schedule.input_ip,
        "subnet_mask": schedule.subnet_mask,
        "scan_type": schedule.scan_type,
        "ports": schedule.ports,
        "network_cidr": schedule.network_cidr,
        "exclude_targets": schedule.exclude_targets,
        "credential_ids": schedule.credential_ids,
        "timing_template": schedule.timing_template,
        "audit_credentials": schedule.audit_credentials,
        "status": "pending",
        "schedule_id": schedule.id,
        "scheduled_for": due_at,
        "scheduler_dispatch_state": "queued",
        "scheduler_attempt_count": 0,
        "scheduler_max_attempts": current_app.config["SCHEDULER_MAX_ATTEMPTS"],
    }
    scan = ScanResult(**scan_values)
    db.session.add(scan)
    db.session.commit()
    return scan.id


def _recover_expired_scan_jobs(now, lease_seconds):
    retry_before = now - timedelta(seconds=lease_seconds)
    eligible = or_(
        ScanResult.scheduler_dispatch_state == "queued",
        and_(
            ScanResult.scheduler_dispatch_state == "claimed",
            or_(
                ScanResult.scheduler_claimed_at.is_(None),
                ScanResult.scheduler_claimed_at <= retry_before,
            ),
        ),
    )
    changed = False
    expired_running = ScanResult.query.filter(
        ScanResult.status == "running",
        ScanResult.scheduler_dispatch_state == "started",
        or_(
            ScanResult.scheduler_heartbeat_at.is_(None),
            ScanResult.scheduler_heartbeat_at <= retry_before,
        ),
    ).all()
    for job in expired_running:
        changed = True
        if job.scheduler_attempt_count >= job.scheduler_max_attempts:
            job.status = "failed"
            job.scheduler_dispatch_state = "failed"
            job.result_data = json.dumps({
                "command": "N/A",
                "output": "Scan exceeded its maximum recovery attempts.",
                "hosts": [],
            })
        else:
            job.status = "pending"
            job.scheduler_dispatch_state = "queued"
            job.scheduler_claim_token = None
            job.scheduler_claimed_at = None
            job.scheduler_started_at = None
            job.scheduler_heartbeat_at = None

    exhausted = ScanResult.query.filter(
        ScanResult.status == "pending",
        eligible,
        ScanResult.scheduler_attempt_count >= ScanResult.scheduler_max_attempts,
    ).all()
    for job in exhausted:
        changed = True
        job.status = "failed"
        job.scheduler_dispatch_state = "failed"
        job.result_data = json.dumps({
            "command": "N/A",
            "output": "Scan exceeded its maximum dispatch attempts.",
            "hosts": [],
        })
    return eligible, retry_before, changed


def _dispatch_pending_scheduled_scans(app, now=None):
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    dispatch_lock = db.session.get(ScanDispatchLock, 1)
    if dispatch_lock is None:
        dispatch_lock = ScanDispatchLock(id=1)
        db.session.add(dispatch_lock)
        db.session.flush()
    ScanDispatchLock.query.filter(ScanDispatchLock.id == 1).update(
        {ScanDispatchLock.touched_at: now}, synchronize_session=False
    )

    lease_seconds = app.config["SCHEDULER_LEASE_SECONDS"]
    eligible, retry_before, _ = _recover_expired_scan_jobs(now, lease_seconds)
    running_count = ScanResult.query.filter(ScanResult.status == "running").count()
    live_claims = ScanResult.query.filter(
        ScanResult.status == "pending",
        ScanResult.scheduler_dispatch_state == "claimed",
        ScanResult.scheduler_claimed_at > retry_before,
    ).count()
    capacity = app.config["MAX_CONCURRENT_SCANS"] - running_count - live_claims
    if capacity <= 0:
        db.session.commit()
        return []

    candidates = ScanResult.query.filter(
        ScanResult.status == "pending",
        eligible,
        ScanResult.scheduler_attempt_count < ScanResult.scheduler_max_attempts,
    ).order_by(
        ScanResult.scheduled_for.asc(),
        ScanResult.created_at.asc(),
        ScanResult.id.asc(),
    ).limit(capacity).all()

    dispatched = []
    for candidate in candidates:
        claim_token = str(uuid.uuid4())
        claimed = ScanResult.query.filter(
            ScanResult.id == candidate.id,
            ScanResult.status == "pending",
            eligible,
            ScanResult.scheduler_attempt_count < ScanResult.scheduler_max_attempts,
        ).update(
            {
                ScanResult.scheduler_dispatch_state: "claimed",
                ScanResult.scheduler_claimed_at: now,
                ScanResult.scheduler_claim_token: claim_token,
                ScanResult.scheduler_attempt_count: (
                    func.coalesce(ScanResult.scheduler_attempt_count, 0) + 1
                ),
            },
            synchronize_session=False,
        )
        if claimed != 1:
            continue
        audit_credentials = bool(candidate.audit_credentials)
        scan_id = candidate.id
        dispatched.append((scan_id, audit_credentials, claim_token))

    db.session.commit()
    dispatched_ids = []
    for scan_id, audit_credentials, claim_token in dispatched:
        threading.Thread(
            target=execute_scan,
            args=(app, scan_id, audit_credentials, claim_token),
            daemon=True,
        ).start()
        dispatched_ids.append(scan_id)
    return dispatched_ids


def start_scheduler(app):
    def run_scheduler_loop():
        time.sleep(5)
        while True:
            try:
                with app.app_context():
                    if is_scan_frozen():
                        pass
                    else:
                        now = datetime.now(timezone.utc).replace(tzinfo=None)
                        due_schedules = ScanSchedule.query.filter(
                            ScanSchedule.is_active == True,
                            ScanSchedule.next_run <= now
                        ).all()
                        
                        for schedule in due_schedules:
                            _claim_scheduled_scan(schedule, now)
            except Exception as e:
                import sys
                print(f"[Scheduler Error]: {str(e)}", file=sys.stderr)
            time.sleep(30)

    threading.Thread(target=run_scheduler_loop, daemon=True).start()


def start_scan_dispatcher(app):
    def run_dispatcher_loop():
        time.sleep(1)
        while True:
            try:
                with app.app_context():
                    _dispatch_pending_scheduled_scans(app)
            except Exception as error:
                import sys
                print(f"[Dispatcher Error]: {error}", file=sys.stderr)
            time.sleep(5)

    threading.Thread(target=run_dispatcher_loop, daemon=True).start()

def seed_mock_security_data():
    try:
        from datetime import datetime, timedelta
        from models import Asset, SecurityFinding, SecurityAnomaly
        
        # 1. Update some assets' properties to make the UI look rich
        asset_70 = Asset.query.filter_by(ip_address="10.3.1.70").first()
        if asset_70:
            asset_70.name = "Win2008-DC"
            asset_70.operating_system = "Windows Server 2008 R2"
            asset_70.criticality = "High"
            
        asset_22 = Asset.query.filter_by(ip_address="10.3.1.22").first()
        if asset_22:
            asset_22.name = "Linux-SSH-Gateway"
            asset_22.operating_system = "Ubuntu Linux 16.04"
            asset_22.criticality = "Medium"
            asset_22.is_trusted = False
            
        asset_23 = Asset.query.filter_by(ip_address="10.3.1.23").first()
        if asset_23:
            asset_23.name = "Unknown-Device"
            asset_23.criticality = "Low"
            asset_23.is_trusted = False
            
        asset_10 = Asset.query.filter_by(ip_address="10.3.1.10").first()
        if asset_10:
            asset_10.name = "Web-Server-Internal"
            asset_10.operating_system = "CentOS Linux 7"
            asset_10.criticality = "High"

        db.session.commit()

        # 2. Seed mock SecurityFindings
        if SecurityFinding.query.count() == 0:
            findings = [
                SecurityFinding(
                    asset_id=asset_70.id if asset_70 else 1,
                    ip_address="10.3.1.70",
                    port=445,
                    service="microsoft-ds",
                    version="Windows Server 2008 R2",
                    cve="CVE-2017-0144",
                    cvss=8.1,
                    severity="High",
                    evidence="Remote code execution vulnerability in Microsoft Server Message Block 1.0 (SMBv1) protocol (MS17-010 / EternalBlue).",
                    status="open",
                    remediation_note="Disable SMBv1 protocol and apply the MS17-010 security update from Microsoft.",
                    first_seen=datetime.now() - timedelta(days=2),
                    last_seen=datetime.now(),
                    due_date=datetime.now() + timedelta(days=7)
                ),
                SecurityFinding(
                    asset_id=asset_22.id if asset_22 else 2,
                    ip_address="10.3.1.22",
                    port=22,
                    service="ssh",
                    version="OpenSSH 7.2p2",
                    cve="CVE-2016-3115",
                    cvss=4.0,
                    severity="Medium",
                    evidence="X11 forwarding session hijacking vulnerability in OpenSSH.",
                    status="open",
                    remediation_note="Upgrade OpenSSH to version 7.3p1 or newer, or disable X11 forwarding if not required.",
                    first_seen=datetime.now() - timedelta(days=5),
                    last_seen=datetime.now(),
                    due_date=datetime.now() + timedelta(days=14)
                ),
                SecurityFinding(
                    asset_id=asset_10.id if asset_10 else 3,
                    ip_address="10.3.1.10",
                    port=80,
                    service="http",
                    version="Apache httpd 2.4.49",
                    cve="CVE-2021-41773",
                    cvss=9.8,
                    severity="Critical",
                    evidence="Path traversal and remote code execution vulnerability in Apache HTTP Server 2.4.49.",
                    status="open",
                    remediation_note="Upgrade Apache HTTP Server to version 2.4.51 or newer immediately.",
                    first_seen=datetime.now() - timedelta(days=1),
                    last_seen=datetime.now(),
                    due_date=datetime.now() + timedelta(days=3)
                )
            ]
            for f in findings:
                db.session.add(f)
            db.session.commit()

        # 3. Seed mock SecurityAnomaly
        if SecurityAnomaly.query.count() == 0:
            anomaly = SecurityAnomaly(
                ip_address="10.3.1.6",
                mac_address="00:11:22:33:44:55",
                anomaly_type="MAC Spoofing",
                description="MAC Spoofing detected: IP 10.3.1.6 changed MAC address from 00:11:22:33:44:55 to 00:aa:bb:cc:dd:ee.",
                is_resolved=False,
                created_at=datetime.now()
            )
            db.session.add(anomaly)
            db.session.commit()
    except Exception as e:
        print(f"Error seeding mock security data: {str(e)}")



def cleanup_stale_scans():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    stale_threshold = now - timedelta(minutes=30)
    _, _, recovered_jobs = _recover_expired_scan_jobs(
        now, current_app.config["SCHEDULER_LEASE_SECONDS"]
    )

    stale_scans = ScanResult.query.filter(
        ScanResult.status.in_(["pending", "running"]),
        ScanResult.created_at < stale_threshold,
        or_(
            ScanResult.status == "running",
            ScanResult.scheduler_dispatch_state.is_(None),
            ScanResult.scheduler_dispatch_state.notin_(["queued", "claimed"]),
        ),
    ).all()
    for scan in stale_scans:
        scan.status = "failed"
        if scan.scheduler_dispatch_state is not None:
            scan.scheduler_dispatch_state = "failed"
        result_payload = {
            "command": "N/A",
            "output": "Scan was interrupted or left unfinished after application restart.",
            "hosts": []
        }
        scan.result_data = json.dumps(result_payload, indent=4)
    if stale_scans or recovered_jobs:
        db.session.commit()

if __name__ == "__main__":
    import os
    app = create_app()
    debug_val = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_val, host="127.0.0.1")
