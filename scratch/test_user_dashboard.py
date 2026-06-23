import urllib.request
import urllib.parse
from http.cookiejar import CookieJar

cj = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
urllib.request.install_opener(opener)

# Register a new user
reg_url = "http://127.0.0.1:5000/register"
reg_data = urllib.parse.urlencode({
    "email": "testuser@test.com",
    "password": "testuser123",
    "confirm_password": "testuser123"
}).encode("utf-8")

print("Registering new user...")
try:
    req = urllib.request.Request(reg_url, data=reg_data)
    with opener.open(req) as resp:
        print("Register status:", resp.status)
except Exception as e:
    print("Register error (maybe already registered):", e)

# Log in
login_url = "http://127.0.0.1:5000/login"
login_data = urllib.parse.urlencode({
    "email": "testuser@test.com",
    "password": "testuser123"
}).encode("utf-8")

print("Logging in...")
try:
    req = urllib.request.Request(login_url, data=login_data)
    with opener.open(req) as resp:
        content = resp.read().decode("utf-8")
        print("Logged in. Dashboard content length:", len(content))
        with open("scratch/dashboard_rendered_user.html", "w", encoding="utf-8") as f:
            f.write(content)
        print("Wrote dashboard_rendered_user.html")
except Exception as e:
    print("Error:", e)
