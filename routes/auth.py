from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp

from models import db, User, HoneypotBlockedIP

auth_bp = Blueprint("auth", __name__)

FAILED_LOGIN_ATTEMPTS = {}

# Retrieve client ip.
def get_client_ip():
    # Handle the branch where current_app.config.get('TRUST_PROXY') evaluates to true.
    if current_app.config.get("TRUST_PROXY"):
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        # Handle the branch where x_forwarded_for evaluates to true.
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
    return request.remote_addr

# Handle the record failed login operation.
def record_failed_login(ip):
    now = datetime.now()
    # Handle the branch where ip not in FAILED_LOGIN_ATTEMPTS evaluates to true.
    if ip not in FAILED_LOGIN_ATTEMPTS:
        FAILED_LOGIN_ATTEMPTS[ip] = []
    FAILED_LOGIN_ATTEMPTS[ip].append(now)
    
    ten_minutes_ago = now - timedelta(minutes=10)
    FAILED_LOGIN_ATTEMPTS[ip] = [t for t in FAILED_LOGIN_ATTEMPTS[ip] if t > ten_minutes_ago]
    
    # Handle the branch where len(FAILED_LOGIN_ATTEMPTS[ip]) >= 5 evaluates to true.
    if len(FAILED_LOGIN_ATTEMPTS[ip]) >= 5:
        # Handle the branch where ip not in ['127.0.0.1', '::1', 'localhost'] evaluates to true.
        if ip not in ['127.0.0.1', '::1', 'localhost']:
            existing_block = HoneypotBlockedIP.query.filter_by(ip_address=ip).first()
            # Handle the branch where not existing_block evaluates to true.
            if not existing_block:
                new_block = HoneypotBlockedIP(
                    ip_address=ip,
                    reason="Brute-force login attempts detected (5 failed attempts in 10 minutes)"
                )
                db.session.add(new_block)
                db.session.commit()
                # Send email logic can be called if needed, but we keep it simple or trigger it
                # We will import and call from app/services if needed

@auth_bp.route("/")
def index():
    # Handle the branch where current_user.is_authenticated evaluates to true.
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    return redirect(url_for("auth.login"))

# Handle the register operation.
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    # Handle the branch where current_user.is_authenticated evaluates to true.
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Handle the branch where not email or not password or (not confirm_password) evaluates to true.
        if not email or not password or not confirm_password:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("auth.register"))

        # Handle the branch where password != confirm_password evaluates to true.
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("auth.register"))

        existing_user = User.query.filter_by(email=email).first()
        # Handle the branch where existing_user evaluates to true.
        if existing_user:
            flash("A user with that email address is already registered.", "error")
            return redirect(url_for("auth.register"))

        new_user = User(
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")

# Handle the login operation.
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    # Handle the branch where current_user.is_authenticated evaluates to true.
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        client_ip = get_client_ip()

        user = User.query.filter_by(email=email).first()
        # Handle the branch where not user or not check_password_hash(user.password_hash, password) evaluates to true.
        if not user or not check_password_hash(user.password_hash, password):
            record_failed_login(client_ip)
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth.login"))

        # Handle the branch where user.otp_secret evaluates to true.
        if user.otp_secret:
            session["pre_2fa_user_id"] = user.id
            # Handle the branch where client_ip in FAILED_LOGIN_ATTEMPTS evaluates to true.
            if client_ip in FAILED_LOGIN_ATTEMPTS:
                del FAILED_LOGIN_ATTEMPTS[client_ip]
            return redirect(url_for("auth.login_2fa"))
        # Handle the branch where user.is_admin evaluates to true.
        elif user.is_admin:
            session["setup_2fa_user_id"] = user.id
            session["setup_2fa_secret"] = pyotp.random_base32()
            # Handle the branch where client_ip in FAILED_LOGIN_ATTEMPTS evaluates to true.
            if client_ip in FAILED_LOGIN_ATTEMPTS:
                del FAILED_LOGIN_ATTEMPTS[client_ip]
            return redirect(url_for("auth.login_2fa_setup"))

        login_user(user)
        # Handle the branch where client_ip in FAILED_LOGIN_ATTEMPTS evaluates to true.
        if client_ip in FAILED_LOGIN_ATTEMPTS:
            del FAILED_LOGIN_ATTEMPTS[client_ip]
        flash("Login successful.", "success")
        return redirect(url_for("dashboard.dashboard"))

    return render_template("login.html")

# Handle the login 2fa operation.
@auth_bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    # Handle the branch where current_user.is_authenticated evaluates to true.
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    pre_2fa_user_id = session.get("pre_2fa_user_id")
    # Handle the branch where not pre_2fa_user_id evaluates to true.
    if not pre_2fa_user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pre_2fa_user_id)
    # Handle the branch where not user or not user.otp_secret evaluates to true.
    if not user or not user.otp_secret:
        session.pop("pre_2fa_user_id", None)
        flash("Invalid login session.", "error")
        return redirect(url_for("auth.login"))

    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        totp = pyotp.TOTP(user.otp_secret)
        # Handle the branch where totp.verify(otp_code) evaluates to true.
        if totp.verify(otp_code):
            login_user(user)
            session.pop("pre_2fa_user_id", None)
            flash("Login successful.", "success")
            return redirect(url_for("dashboard.dashboard"))
        # Handle the fallback branch when the preceding condition does not match.
        else:
            flash("Invalid verification code. Please try again.", "error")

    return render_template("login_2fa.html")

# Handle the generate base64 qr operation.
def generate_base64_qr(uri):
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

# Handle the login 2fa setup operation.
@auth_bp.route("/login/2fa-setup", methods=["GET", "POST"])
def login_2fa_setup():
    # Handle the branch where current_user.is_authenticated evaluates to true.
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    setup_2fa_user_id = session.get("setup_2fa_user_id")
    setup_2fa_secret = session.get("setup_2fa_secret")

    # Handle the branch where not setup_2fa_user_id or not setup_2fa_secret evaluates to true.
    if not setup_2fa_user_id or not setup_2fa_secret:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, setup_2fa_user_id)
    # Handle the branch where not user or not user.is_admin or user.otp_secret evaluates to true.
    if not user or not user.is_admin or user.otp_secret:
        session.pop("setup_2fa_user_id", None)
        session.pop("setup_2fa_secret", None)
        flash("Invalid setup session.", "error")
        return redirect(url_for("auth.login"))

    prov_uri = pyotp.totp.TOTP(setup_2fa_secret).provisioning_uri(
        name=user.email, issuer_name="Lynceus"
    )
    qr_code_base64 = generate_base64_qr(prov_uri)

    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        totp = pyotp.TOTP(setup_2fa_secret)
        # Handle the branch where totp.verify(otp_code) evaluates to true.
        if totp.verify(otp_code):
            user.otp_secret = setup_2fa_secret
            db.session.commit()
            login_user(user)
            session.pop("setup_2fa_user_id", None)
            session.pop("setup_2fa_secret", None)
            flash("2FA configured and login successful.", "success")
            return redirect(url_for("dashboard.dashboard"))
        # Handle the fallback branch when the preceding condition does not match.
        else:
            flash("Invalid verification code. Please try again.", "error")

    return render_template(
        "login_2fa_setup.html",
        secret_key=setup_2fa_secret,
        prov_uri=prov_uri,
        qr_code_base64=qr_code_base64
    )

# Handle the logout operation.
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout successful.", "success")
    return redirect(url_for("auth.login"))
