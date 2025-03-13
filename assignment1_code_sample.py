import os
import pymysql
import smtplib
import re
import ssl
from urllib.request import urlopen
from email.mime.text import MIMEText
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Hardcoded credentials expose sensitive information and can be exploited if the source code is leaked.
# Use environment variables instead of hardcoded credentials to manage them securely.
# This helps prevent unauthorized access if the source code is compromised.
# (OWASP A02: Cryptographic Failures)
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD')
}

def get_user_input():
    """
    Gets user input and validates it to prevent potential XSS or injection attacks.
    Without validation, attackers could inject malicious scripts or SQL commands.
    Regular expressions help ensure only allowed characters are accepted.
    (OWASP A05: Security Misconfiguration)
    """
    user_input = input('Enter your name: ')
    if not re.fullmatch("^[A-Za-z ]+$", user_input):  # Only allow letters and spaces
        raise ValueError("Invalid input: Only letters and spaces are allowed.")
    return user_input

def send_email(to, subject, body):
    """
    Sends an email securely using smtplib instead of os.system.
    Using os.system for email could allow command injection if user input is included in the shell command.
    This method ensures safer handling of email transmission.
    (OWASP A03: Injection - Prevents command injection)
    """
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'noreply@example.com'
        msg['To'] = to

        with smtplib.SMTP_SSL('smtp.example.com', 465) as server:  # Secure SMTP with SSL
            server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASS'))  # Secure authentication
            server.sendmail(msg['From'], [to], msg.as_string())

        logging.info("Email sent successfully to %s", to)
    except Exception as e:
        logging.error("Failed to send email: %s", e)

def get_data():
    """
    Retrieves data from a secure API with HTTPS and SSL verification.
    Using an unencrypted HTTP connection can expose sensitive data to attackers through man-in-the-middle attacks.
    SSL validation helps ensure the connection is secure.
    (OWASP A07: Identification and Authentication Failures)
    """
    url = 'https://secure-api.com/get-data'  # Use HTTPS instead of HTTP
    context = ssl.create_default_context()  # Enforce SSL validation

    try:
        with urlopen(url, context=context, timeout=5) as response:
            data = response.read().decode()
        logging.info("Data successfully fetched from API")
        return data
    except Exception as e:
        logging.error("API request failed: %s", e)
        return None

def save_to_db(data):
    """
    Saves data securely to the database using parameterized queries.
    Using raw SQL queries with string concatenation allows SQL injection attacks.
    Parameterized queries prevent attackers from injecting malicious SQL statements.
    (OWASP A03: Injection - Prevents SQL Injection)
    """
    query = "INSERT INTO mytable (column1, column2) VALUES (%s, %s)"
    
    try:
        connection = pymysql.connect(**db_config)
        with connection.cursor() as cursor:
            cursor.execute(query, (data, "Another Value"))  # Secure parameterized query
            connection.commit()
        logging.info("Data successfully saved to database")
    except pymysql.MySQLError as e:
        logging.error("Database error: %s", e)
    finally:
        if 'connection' in locals() and connection.open:
            connection.close()

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)