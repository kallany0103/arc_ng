from flask import Flask, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

@app.route("/send", methods=["POST"])
def send():
    data = request.json
    email_address = data.get('email_address')
    email_subject = data.get('email_subject')
    email_message = data.get('email_message')

    sender_email = 'test01031994@gmail.com'
    sender_password = 'vxyxymxfgoocvcme'
    receiver_email = 'shekharctg84@gmail.com'

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = email_subject
    message.attach(MIMEText(email_message, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()

        return jsonify({"message": "Email Sent!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
