# Example vulnerable code for testing LocalVulnAI
# This file intentionally contains common security issues.

import os
import pickle
import subprocess

# Hard-coded secrets
API_KEY = "sk-1234567890abcdefghijklmnop"
password = "admin123"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def login(username, user_input):
    # Potential SQL injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query


def run_command(user_cmd):
    # Command injection
    os.system("echo " + user_cmd)
    subprocess.call(f"ls {user_cmd}", shell=True)


def unsafe_eval(data):
    # Dangerous eval
    return eval(data)


def load_data(payload):
    # Insecure deserialization
    return pickle.loads(payload)


def render_page(user_content):
    # Potential XSS style pattern
    return f"<div>{user_content}</div>"
