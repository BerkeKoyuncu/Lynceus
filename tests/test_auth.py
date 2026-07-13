from models import User


def test_default_application_port(app):
    assert app.config["APP_PORT"] == 7321

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
