import subprocess
import sqlite3
import hashlib
import pickle

SECRET_KEY = "admin123"
DB_PASSWORD = "root"

def get_user(username):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return conn.execute(query)

def ping_host(host):
    subprocess.call("ping -c 1 " + host, shell=True)

def load_session(data):
    return pickle.loads(data)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()