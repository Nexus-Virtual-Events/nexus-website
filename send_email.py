import schedule
import time
import smtplib
# from config import *
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import EmailMessage
from jinja2 import Template

account_email = 'nexus.virtualevents@gmail.com'
account_password = 'gatheringsreinvented'
# recipients = ['ahasan20@lawrenceville.org', 'acanberk21@lawrenceville.org']

def send_message(email, name, password):
    now = datetime.datetime.now()

    message_template = Template("")
    message = message_template.render(date=now.strftime("%m/%d/%Y"))

    mail = smtplib.SMTP('smtp.gmail.com', 587)

    mail.ehlo()
    mail.starttls()
    mail.login(account_email, account_password)

    msg = MIMEMultipart()

    msg['From'] = "hi"
    msg["Bcc"] = email
    msg['Subject'] = 'Your Nexus Events Password'
    msg.attach(MIMEText("Hi " + name + ", the password for your Nexus login is:" + password, 'html'))

    mail.send_message(msg)
    del msg

    print('A message is sent\n\n')

    mail.close()
