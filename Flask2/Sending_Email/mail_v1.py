import os
from flask import Flask
from flask_mail import Mail, Message
from celery import Celery

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Port for TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'test01031994@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv('password')
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

mail = Mail(app)

celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'], backend=app.config['CELERY_RESULT_BACKEND'])
celery.conf.update(app.config)

@celery.task
def send_email():
    with app.app_context():
        msg = Message('Hello', sender='test01031994@gmail.com', recipients=['shekharctg84@gmail.com'])
        msg.body = "This is the email content"

        mail.send(msg)

@app.route('/send_email_task')
def send_email_task():
    send_email.delay()
    return 'Email task sent!'

if __name__ == '__main__':
    app.run()
