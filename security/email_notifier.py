import smtplib
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "guvvalajahnavi16@gmail.com"
EMAIL_PASSWORD = "dgif trrq bdxd frva"   # Gmail app password

def send_emergency_email(to_email, doctor_name, mode="emergency"):
    msg = EmailMessage()

    if mode == "emergency":
        msg["Subject"] = "🚨 Emergency Medical Data Access Alert"
        body = f"""
Emergency access was used on your medical records.

Doctor: {doctor_name}
Reason: Emergency (Break-Glass Access)
Duration: Temporary (Auto-revoked)

If this was not expected, please contact support immediately.
"""
    else:  # prescription mode
        msg["Subject"] = "New Prescription Added in SecureCare"
        body = f"""
Dr. {doctor_name} has added a new prescription for you.

Please login to SecureCare to view it.
"""

    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
