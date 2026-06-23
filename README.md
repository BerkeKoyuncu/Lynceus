# Portojo

Portojo is a web-based network scanning application that uses Nmap to detect active hosts, open ports, and running services within a given IP range.

## Features

- User registration and login
- Password visibility toggle
- IP and subnet-based network calculation
- Fast and detailed Nmap scans
- Scan result page with live status
- Scan history for users
- Admin access to all scan results
- Honeypot detection
- MAC spoofing detection

## Technologies

- Python
- Flask
- SQLite
- Nmap
- HTML
- CSS
- JavaScript

## Installation

```bash
git clone https://github.com/kullanici-adin/portojo.git
cd portojo
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py