# Intentionally vulnerable sample for LocalVulnAI demos
import os, pickle, hashlib, subprocess
from flask import redirect, request

API_KEY = "sk-1234567890abcdefghijklmnop"
password = "admin123"
DEBUG = True

def login(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query

def run_command(user_cmd):
    os.system("echo " + user_cmd)
    subprocess.call(f"ls {user_cmd}", shell=True)

def unsafe_eval(data):
    return eval(data)

def load_data(payload):
    return pickle.loads(payload)

def weak_hash(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def read_user_file(name):
    return open("/data/" + name).read()

def go_next():
    return redirect(request.args.get("next"))
