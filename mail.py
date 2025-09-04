import smtplib
import random
import ssl
import certifi
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(receiver_email):
    sender_email = "ai.some.speak@gmail.com"
    app_password = "wubqeqovxkwhthpa"  # remove spaces if present

    otp = generate_otp()
    subject = "Your OTP Code"
    body = f"Your One-Time Password (OTP) is: {otp}\nIt is valid for 5 minutes."

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        
        print(f"OTP sent successfully to {receiver_email}")
        return otp
    except Exception as e:
        print("Error sending email:", e)
        return None
