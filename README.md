# Lynceus

Lynceus is a Flask-based network security scanning web application that uses Nmap to discover active hosts, open ports, running services, and potential security issues inside authorised local networks.

The application provides user-based scan management, scan history, scheduled scans, exportable reports, SMTP alerts, honeypot monitoring, brute-force protection, asset inventory, and network anomaly detection.

> **Important:** Lynceus is intended for educational, defensive, and authorised network assessment purposes only. Do not scan networks that you do not own or do not have permission to test.

---

## Features

### Authentication and User Management

- User registration with email address
- Secure password hashing
- Login and logout system
- Two-Factor Authentication (2FA) with Google Authenticator support (automatically enforced for CLI-created admins and web-promoted admins on their first login)
- Generic login error message for better security
- Password visibility toggle on login/register forms
- Admin role with access to global scan and security records

### Network Scanning

- IP address and subnet mask input
- Automatic network/CIDR calculation
- Private, loopback, and link-local scan target validation
- Background scan execution
- Live scan status tracking: `pending`, `running`, `completed`, `failed`, and `cancelled`
- Real-time scan control: Ability to stop/cancel running scans or repeat completed/failed/cancelled scans directly from the result screens
- Custom Scan Timing selectors (T0 to T5) with dynamic CLI command preview updates to customise scan speed and stealth
- Optional custom port range input
- Multiple Nmap scan profiles:

| Scan Type | Nmap Flags | Description |
|---|---|---|
| Fast Port Scan | `-F` | Fast scan of commonly used TCP ports |
| Service & Version Scan | `-sV -T4` | Detects services and version information |
| Host Discovery | `-sn` | Discovers online hosts without port scanning |
| TCP SYN Scan | `-sS` | Half-open TCP scan; falls back to TCP Connect if privileges are missing |
| TCP Connect Scan | `-sT` | Full TCP connection scan |
| UDP Scan | `-sU --top-ports 100` | Scans common UDP ports |
| Aggressive Scan | `-A -T4` | Enables OS detection, version detection, script scanning, and traceroute |
| Vulnerability Scan | `-sV -T4 --script vuln` | Runs Nmap vulnerability detection scripts |

### Result Analysis

- Structured parsing of Nmap XML output
- Host list with IP address, hostname, MAC address, vendor, and status
- Open port table with protocol, state, service, and version
- Search and filtering by IP, port, protocol, state, service, and version
- Dashboard-style scan result statistics
- Network topology map visualization
- CVE lookup for detected service/version information
- Printable executive scan report

### Export Options

Scan results can be exported as:

- CSV
- JSON
- TXT
- Printable report / PDF through browser print

### Scan History and Comparison

- Each user can view their own previous scans
- Admin users can view all scan results
- Completed scans can be compared
- Comparison view highlights:
  - Added hosts
  - Removed hosts
  - Added ports
  - Removed ports
  - Changed services, versions, or states

### Scheduled Scans

- Users can create recurring scan schedules
- Supported frequencies:
  - Hourly
  - Daily
  - Weekly
  - Monthly
- Schedules can be paused, activated, deleted, or bulk-deleted
- Scheduled scans run in the background

### Email Notifications

- SMTP configuration from the settings page
- Test email support
- Optional email notifications when new open ports are detected
- Security alert emails for:
  - New open ports
  - New active hosts
  - MAC anomalies
  - Honeypot hits
  - Brute-force login attempts

### Honeypot and Blocking

- Built-in decoy endpoint monitoring
- Suspicious paths include common administrative and sensitive file paths such as:
  - `/wp-admin`
  - `/wp-login.php`
  - `/phpmyadmin`
  - `/.env`
  - `/.git`
  - `/backup.zip`
- Honeypot event logging
- Optional automatic IP blocking
- Admin interface for viewing logs and unblocking IP addresses

### Brute-Force Protection

- Tracks failed login attempts by IP address
- Automatically blocks an IP address after repeated failed login attempts
- Sends an alert email if SMTP settings are configured

### Asset Inventory

- Admin-managed asset inventory
- Asset fields include:
  - Name
  - IP address
  - MAC address
  - MAC vendor
  - Device type
  - Operating system
  - Criticality
  - Owner
  - Location
  - Serial number
  - IP assignment type
  - Notes
  - Trust status
- Assets can be added, edited, deleted, trusted, untrusted, and bulk-deleted
- Newly discovered devices can be automatically registered as untrusted assets
- Automatic device type classification heuristics supporting Server, Workstation, Router/Switch, Firewall, Printer, IP Phone, IP Camera, and Virtual Machine
- Refined server detection checks to fallback to `Unknown` instead of aggressively guessing `Server` for hosts with open SSH/Telnet ports

### Security Anomaly Detection

Lynceus can detect and record:

- Rogue devices
- MAC spoofing indicators
- IP hijack / lease migration indicators

Admin users can resolve, reopen, delete, and bulk-manage anomaly records.

### Weak Credential Audit

Optional weak credential auditing is available for selected services discovered during scans.

Supported checks include:

- FTP
- Redis
- HTTP Basic Authentication

---

## Technologies Used

- Python
- Flask
- Flask-Login
- Flask-SQLAlchemy
- SQLite
- Nmap
- HTML
- CSS
- JavaScript
- Chart.js
- Vis Network
- Lucide Icons

---

## Project Structure

```text
Lynceus/
├── app.py                  # Main Flask application, routes, scheduler, alerts, admin logic
├── models.py               # SQLAlchemy database models
├── scanner.py              # Network calculation, Nmap execution, XML parsing
├── requirements.txt        # Python dependencies
├── static/
│   └── css/
│       └── style.css       # Application styling
├── templates/
│   ├── base.html           # Main layout and navigation
│   ├── login.html          # Login page
│   ├── login_2fa.html      # Two-Factor Authentication verification page
│   ├── login_2fa_setup.html # Two-Factor Authentication setup/enrollment page
│   ├── register.html       # Registration page
│   ├── dashboard.html      # User/admin dashboard
│   ├── scan.html           # New scan form
│   ├── result.html         # Scan result page
│   ├── history.html        # User scan history
│   ├── compare.html        # Scan comparison page
│   ├── schedules.html      # Scheduled scan list
│   ├── schedule_form.html  # New schedule form
│   ├── settings.html       # SMTP and honeypot settings
│   ├── admin.html          # Admin panel
│   ├── admin_assets.html   # Asset inventory
│   ├── admin_asset_form.html
│   ├── admin_asset_map.html
│   ├── report.html         # Printable report
│   ├── blocked.html        # Blocked IP page
│   └── decoy_wp.html       # Honeypot decoy response
└── README.md
```

---

## Requirements

Before running the application, install:

- Python 3.10 or newer
- Nmap
- Npcap, required on Windows for some Nmap scan types

Nmap must be available from the system `PATH`.

You can verify the installation with:

```bash
nmap --version
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/BerkeKoyuncu/Lynceus.git
cd Lynceus
```

### 2. Create a Virtual Environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure the Database (Required)

**SQLite (default — no configuration needed):**

The application uses SQLite by default and stores its database in `database.db` in the project root.

**PostgreSQL (optional):**

Set the `DATABASE_URL` environment variable before running any commands:

```bash
# Linux/macOS
export DATABASE_URL="postgresql://user:password@localhost/lynceus"

# Windows PowerShell
$env:DATABASE_URL = "postgresql://user:password@localhost/lynceus"
```

`psycopg[binary]` is included in `requirements.txt` and handles the PostgreSQL driver automatically.

### 5. Apply Database Migrations

Database schema is managed by Alembic. **Always run this before `create-admin`:**

```bash
python -m flask --app app db upgrade
```

This creates all required tables from scratch on a fresh database, and is safe to re-run on an existing one.

> **Existing databases managed by a previous `db.create_all()` setup:**
> If you have an existing database that was created by an older version of Lynceus (using `db.create_all()`), stamp it at the baseline revision first so Alembic does not try to re-create tables that already exist:
> ```bash
> python -m flask --app app db stamp 4b1d0851377a
> ```

### 6. Create an Admin User

```bash
python -m flask --app app create-admin
```

The command will prompt for an admin email address, password, and will display a TOTP QR code to scan with your authenticator app (e.g. Google Authenticator). **2FA is mandatory for admin accounts.**

### 7. Clean Up Stale Scans (Optional)

If the application is stopped or crashes while scans are running, those scans might get stuck in a `pending` or `running` state. You can reset them manually with:

```bash
python -m flask --app app cleanup-scans
```

### 8. Run the Application

**Development (localhost only):**

```bash
python -m flask --app app run
```

The development server binds to `127.0.0.1:5000` by default. Debug mode is controlled by the `FLASK_DEBUG` environment variable (default: `false`).

**LAN/Production deployment with Waitress:**

For local network deployment, use [Waitress](https://docs.pylonsproject.org/projects/waitress/) instead of the Flask development server:

```bash
# Bind to all interfaces on port 5000
waitress-serve --call --host 0.0.0.0 --port 5000 app:create_app
```

> **Security note:** Only expose Lynceus on trusted private networks. Do not expose it directly to the internet.

By default the application is reachable at:

```text
http://127.0.0.1:5000   (development)
http://<your-lan-ip>:5000   (waitress, LAN)
```


---

## Basic Usage

1. Register or log in.
2. Go to **New Scan**.
3. Enter an IP address and subnet mask.
4. Select a scan type.
5. Optionally define custom ports.
6. Start the scan.
7. Wait for the scan status to become `completed`.
8. Review discovered hosts, open ports, services, CVE information, and topology.
9. Export the result if needed.
10. Use **Scan History** or **Compare Scans** for later analysis.

---

## Scan Target Restrictions

For safety, Lynceus only allows scans against:

- Private networks
- Loopback addresses
- Link-local networks

Public internet ranges are blocked by target validation.

Scan size is also limited depending on the selected scan type:

| Scan Type | Maximum Address Count |
|---|---:|
| Host Discovery | 2048 |
| Fast Port Scan | 1024 |
| TCP SYN Scan | 512 |
| TCP Connect Scan | 512 |
| Service & Version Scan | 256 |
| UDP Scan | 64 |
| Aggressive Scan | 64 |
| Vulnerability Scan | 64 |

---

## Admin Features

Admin users can access:

- All scan records
- User accounts
- Honeypot logs
- Blocked IP addresses
- Security anomalies
- Asset inventory
- Asset map
- Bulk deletion and bulk resolution tools

---

## Security Notes

- Passwords are stored as hashes.
- Login errors use a generic message to avoid user enumeration.
- 2FA secret keys (OTP secrets) are encrypted at rest in the SQLite database using AES symmetric encryption (via Fernet).
- Decryption keys are derived dynamically from the application's `SECRET_KEY` or `OTP_ENCRYPTION_KEY` environment variable.
- The honeypot system can automatically block suspicious IP addresses.
- Repeated failed login attempts can trigger automatic blocking.
- SMTP credentials are stored in the local SQLite database.
- The default Flask secret key in `app.py` should be changed before any real deployment.
- This project is designed for controlled lab or local network use, not exposed production deployment.

---

## Known Limitations

- Scan execution depends on Nmap being installed correctly.
- TCP SYN scans may require administrator/root privileges.
- UDP, aggressive, and vulnerability scans can take longer than regular TCP scans.
- CVE lookup requires internet access.
- Scheduled scans run through an in-process background thread, so they depend on the Flask application staying active.
- SQLite is suitable for development and small deployments, but not ideal for high-concurrency production use.
- Failed login attempts for brute-force protection are tracked in-memory to prevent write-locking DDoS vulnerabilities in SQLite. Consequently, the temporary counter resets when the application restarts (though permanently blocked IPs remain blocked as they are stored in the database).

---

## License

This project is developed for educational and defensive network security purposes.