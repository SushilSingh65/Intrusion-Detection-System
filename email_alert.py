import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# === Email Configuration ===
EMAIL_ADDRESS = "sv6815765@gmail.com"
EMAIL_PASSWORD = "czeqbqwdqcnhrhek"
TO_EMAIL = "sm6815765@gmail.com"

def send_email_alert(subject, message):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = TO_EMAIL
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("[EMAIL] Alert sent successfully.")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send alert: {e}")
