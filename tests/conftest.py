import pytest
from app import create_app
from models import db, ScanDispatchLock, User, SystemSetting

# Handle the app operation.
@pytest.fixture
def app():
    # Set testing configuration
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test_secret_key"
    })
    
    # Manage app.app_context() within this scoped block.
    with app.app_context():
        db.create_all()
        db.session.add(ScanDispatchLock(id=1))
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

# Handle the client operation.
@pytest.fixture
def client(app):
    return app.test_client()

# Handle the runner operation.
@pytest.fixture
def runner(app):
    return app.test_cli_runner()
