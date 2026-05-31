# Authentication module v2
import subprocess
import sqlite3
import hashlib
import pickle

# Intentionally vulnerable code for SentinelCI demo

SECRET_KEY = "admin123"          # Hardcoded credential
DB_PASSWORD = "root"

def get_user(username):
    conn = sqlite3.connect("users.db")
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return conn.execute(query)

def ping_host(host):
    # Command injection vulnerability
    subprocess.call("ping -c 1 " + host, shell=True)

def load_session(data):
    # Unsafe deserialization
    return pickle.loads(data)

def hash_password(password):
    # Weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()