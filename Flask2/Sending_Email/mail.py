import os
from flask import Flask
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587  # Port for TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'test01031994@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv('password')

mail = Mail(app)

@app.route('/send_email')
def send_email():
    msg = Message('Hello', sender='test01031994@gmail.com', recipients=['shekharctg84@gmail.com'])
    msg.body = "This is the email content"

    mail.send(msg)
    return 'Email sent!'


if __name__ == '__main__':
    app.run()