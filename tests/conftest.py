import pytest
from app import create_app
from models import db, User, SystemSetting

@pytest.fixture
def app():
    # Set testing configuration
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test_secret_key"
    })
    
    with app.app_context():
        db.create_all()
        # Seed test admin and user
        admin = User(
            email="admin@test.com",
            password_hash="pbkdf2:sha256:600000$test$hash", # dummy
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        
        setting = SystemSetting(
            user_id=admin.id,
            smtp_server="smtp.test.com",
            smtp_port=587,
            smtp_sender="alert@test.com",
            alert_recipient="admin@test.com"
        )
        db.session.add(setting)
        db.session.commit()
        
        yield app
        
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()
