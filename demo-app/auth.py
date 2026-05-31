# Authentication module v2
import subprocess
import sqlite3
import hashlib
import pickle
import os

# Vulnerability 1: Hardcoded credentials
SECRET_KEY = "admin123"
DB_PASSWORD = "root"
API_KEY = "sk-prod-abc123xyz789"

# Vulnerability 2: SQL Injection
def get_user(username):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return conn.execute(query)

# Vulnerability 3: Command Injection  
def ping_host(host):
    subprocess.call("ping -c 1 " + host, shell=True)

# Vulnerability 4: Unsafe Deserialization
def load_session(data):
    return pickle.loads(data)

# Vulnerability 5: Weak Hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerability 6: Path Traversal
def read_file(filename):
    return open("/var/data/" + filename).read()

# Vulnerability 7: Hardcoded token
def get_admin():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin"
    return token