import sqlite3
from datetime import datetime

# Step 1: Create the database and table
def init_db():
    conn = sqlite3.connect("scan_results.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Step 2: Save a scan result
def save_scan(target, scan_type, result):
    conn = sqlite3.connect("scan_results.db")
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (target, scan_type, result, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (target, scan_type, result, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

# Step 3: Load all scans
def get_all_scans():
    conn = sqlite3.connect("scan_results.db")
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows
