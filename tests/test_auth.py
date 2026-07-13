from pathlib import Path

from app import create_app
from models import User
from models import db
from werkzeug.security import check_password_hash, generate_password_hash


def test_default_application_port(app):
    assert app.config["APP_PORT"] == 7321


def test_health_endpoint_does_not_require_login(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_runtime_data_directory_override_holds_database_and_secrets(tmp_path, monkeypatch):
    data_dir = tmp_path / "program-data"
    monkeypatch.setenv("LYNCEUS_DATA_DIR", str(data_dir))
    packaged_app = create_app({"TESTING": True, "START_SCHEDULER": False})

    assert Path(packaged_app.instance_path) == data_dir
    assert (data_dir / ".secret_key_flask").is_file()
    with packaged_app.app_context():
        assert Path(db.engine.url.database) == data_dir / "database.db"


def test_admin_password_and_2fa_can_be_reset_independently(app, runner):
    original_otp = "JBSWY3DPEHPK3PXP"
    with app.app_context():
        admin = User.query.filter_by(is_admin=True).first()
        admin.password_hash = generate_password_hash("OldPassword123")
        admin.otp_secret = original_otp
        db.session.commit()

    password_result = runner.invoke(
        args=["reset-admin-password"],
        input="OldPassword123\nNewPassword456\nNewPassword456\n",
    )
    assert password_result.exit_code == 0

    with app.app_context():
        admin = User.query.filter_by(is_admin=True).first()
        assert check_password_hash(admin.password_hash, "NewPassword456")
        assert admin.otp_secret == original_otp

    otp_result = runner.invoke(
        args=["reset-admin-2fa"],
        input="NewPassword456\n",
    )
    assert otp_result.exit_code == 0

    with app.app_context():
        admin = User.query.filter_by(is_admin=True).first()
        assert check_password_hash(admin.password_hash, "NewPassword456")
        assert admin.otp_secret is None

def test_login_logout(client):
    # Register test user
    response = client.post("/register", data={
        "email": "user@test.com",
        "password": "Password123",
        "confirm_password": "Password123"
    }, follow_redirects=True)
    assert b"Registration successful" in response.data
    
    # Login standard user
    response = client.post("/login", data={
        "email": "user@test.com",
        "password": "Password123"
    }, follow_redirects=True)
    assert b"Login successful" in response.data
    assert b"History" in response.data or b"Scan History" in response.data
    
    # Logout
    response = client.get("/logout", follow_redirects=True)
    assert b"Logout successful" in response.data
