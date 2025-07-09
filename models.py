import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

def get_db_connection():
    return sqlite3.connect("scan_results.db", check_same_thread=False)

def create_tables():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            scan_mode TEXT NOT NULL DEFAULT 'manual',
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
   
    c.execute('''
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            scheduled_time TEXT NOT NULL,
            done INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

def register_user(username, password, email):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        hashed = generate_password_hash(password)
        c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, hashed, email))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    if user and check_password_hash(user[1], password):
        return user[0]  # Return user_id
    return None
