# Example vulnerable code for testing LocalVulnAI

import os

# Bad practice - hard-coded secret
API_KEY = "sk-1234567890abcdef"
password = "admin123"

def login(username, user_input):
    # Potential SQL injection pattern
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query

def render_page(user_content):
    # Potential XSS
    return f"<div>{user_content}</div>"
