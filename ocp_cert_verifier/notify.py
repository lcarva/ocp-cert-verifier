import smtplib
from email.mime.text import MIMEText


def send_email(namespace, text, smtp_info):
    if not smtp_info or not smtp_info.get('server'):
        return

    msg = MIMEText(text)
    msg['Subject'] = f'Certificate expiration warning for {namespace}'
    msg['From'] = smtp_info['from']
    msg['To'] = smtp_info['to']

    server = smtplib.SMTP(smtp_info['server'])
    server.send_message(msg)
    server.quit()


def send_email_from_stream(namespace, stream, smtp_info):
    if not stream:
        return
    text = stream.getvalue()
    send_email(namespace, text, smtp_info)
