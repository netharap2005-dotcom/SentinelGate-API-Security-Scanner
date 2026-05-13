import os
import smtplib
from email.message import EmailMessage


def send_email_notification(user_email, subject, body):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_sender = os.getenv("SMTP_SENDER")

    # Safe fallback for demo if SMTP is not configured
    if not all([smtp_host, smtp_port, smtp_user, smtp_password, smtp_sender]):
        print(f"[EMAIL TO: {user_email}]")
        print(f"SUBJECT: {subject}")
        print(body)
        print("-" * 60)
        return True

    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp_sender
        msg["To"] = user_email
        msg.set_content(body)

        with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)

        print(f"[REAL EMAIL SENT TO: {user_email}] SUBJECT: {subject}")
        return True

    except Exception as e:
        print(f"[EMAIL SEND FAILED] {e}")
        return False