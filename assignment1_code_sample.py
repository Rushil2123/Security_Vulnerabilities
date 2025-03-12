import os
import pymysql
from urllib.request import urlopen
import re
import smtplib
from email.mime.text import MIMEText

# Use environment variables instead of hardcoded credentials (A02: Cryptographic Failures)
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD')
}

def get_user_input():
    """
    Gets user input and validates it to prevent potential XSS or injection attacks.
    (A05: Security Misconfiguration)
    """
    user_input = input('Enter your name: ')
    if not re.match("^[A-Za-z ]+$", user_input):  # Allow only letters and spaces
        raise ValueError("Invalid input: Only letters and spaces are allowed.")
    return user_input

def send_email(to, subject, body):
    """
    Sends an email securely using smtplib instead of os.system.
    (A03: Injection - Prevents command injection)
    """
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'noreply@example.com'
    msg['To'] = to

    with smtplib.SMTP('localhost') as server:
        server.sendmail(msg['From'], [to], msg.as_string())

def get_data():
    url = 'http://insecure-api.com/get-data'
    data = urlopen(url).read().decode()
    return data

def save_to_db(data):
    query = f"INSERT INTO mytable (column1, column2) VALUES ('{data}', 'Another Value')"
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)
