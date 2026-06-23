import urllib.request
import urllib.parse
from http.cookiejar import CookieJar

cj = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
urllib.request.install_opener(opener)

# Log in
login_url = "http://127.0.0.1:5000/login"
login_data = urllib.parse.urlencode({
    "email": "admin@admin",
    "password": "admin123"
}).encode("utf-8")

print("Logging in...")
try:
    req = urllib.request.Request(login_url, data=login_data)
    with opener.open(req) as resp:
        content = resp.read().decode("utf-8")
        print("Logged in. Dashboard content length:", len(content))
        # Save dashboard to check
        with open("scratch/dashboard_rendered.html", "w", encoding="utf-8") as f:
            f.write(content)
        print("Wrote dashboard_rendered.html")
except Exception as e:
    print("Error:", e)
