import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys

# Send notification email async.
def send_notification_email_async(setting_dict, subject, body_html):
    # Send email thread.
    def send_email_thread():
        # Run this block with structured exception handling.
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = setting_dict.get("smtp_sender")
            msg["To"] = setting_dict.get("alert_recipient")
            
            part = MIMEText(body_html, "html", "utf-8")
            msg.attach(part)
            
            server_name = setting_dict.get("smtp_server")
            port = int(setting_dict.get("smtp_port") or 587)
            username = setting_dict.get("smtp_username")
            password = setting_dict.get("smtp_password")
            
            # Handle the branch where port == 465 evaluates to true.
            if port == 465:
                server = smtplib.SMTP_SSL(server_name, port, timeout=10)
            # Handle the fallback branch when the preceding condition does not match.
            else:
                server = smtplib.SMTP(server_name, port, timeout=10)
                server.ehlo()
                server.starttls()
                server.ehlo()
                
            # Handle the branch where username and password evaluates to true.
            if username and password:
                server.login(username, password)
                
            server.sendmail(setting_dict.get("smtp_sender"), [setting_dict.get("alert_recipient")], msg.as_string())
            server.quit()
            print(f"[Email Success]: Sent email to {setting_dict.get('alert_recipient')} with subject: {subject}")
        # Handle an exception raised by the preceding protected block.
        except Exception as e:
            print(f"[Email Error]: Failed to send email: {str(e)}", file=sys.stderr)
            
    threading.Thread(target=send_email_thread, daemon=True).start()
