from flask import Flask, render_template, request, session, redirect, send_file, make_response
from flask_socketio import SocketIO, emit
from models import create_tables, get_db_connection
from auth import auth
from scanners.port_scanner import scan_ports
from scanners.sql_scanner import scan_sql_injection
from scanners.xss_scanner import scan_xss
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import smtplib
import sqlite3
from flask import send_file
from email.mime.text import MIMEText
import textwrap
import json
from fpdf import FPDF
from io import BytesIO
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
socketio = SocketIO(app)
app.register_blueprint(auth)

create_tables()

scheduler = BackgroundScheduler()
scheduler.start()

# =================== DATABASE HELPERS ===================

def save_scan(user_id, target, scan_type, result, scan_mode='manual'):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (user_id, target, scan_type, result, timestamp, scan_mode)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, target, scan_type, result, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_mode))
    conn.commit()
    conn.close()

def save_scheduled_scan(user_id, target, scan_type, run_at):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO scheduled_scans (user_id, target, scan_type, scheduled_time)
        VALUES (?, ?, ?, ?)
    ''', (user_id, target, scan_type, run_at))
    conn.commit()
    conn.close()

# =================== EMAIL UTILITIES ===================

def send_email(to, subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "awakiyang9@gmail.com"
    msg["To"] = to
    try:
        s = smtplib.SMTP('smtp.gmail.com', 587)
        s.starttls()
        s.login("your_email@gmail.com", "your_email_password")  # Use environment vars ideally
        s.sendmail(msg["From"], [msg["To"]], msg.as_string())
        s.quit()
    except Exception as e:
        print("❌ Email error:", e)

def alert_if_critical(result, user_email):
    if "vulnerable" in result.lower() or "critical" in result.lower():
        send_email(user_email, "⚠️ Critical Vulnerability Found", result)

# =================== SCHEDULED SCAN RUNNER ===================

def run_scheduled_scans():
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    c.execute('''
        SELECT id, user_id, target, scan_type FROM scheduled_scans 
        WHERE scheduled_time <= ? AND done = 0
    ''', (now,))
    scans = c.fetchall()

    for scan in scans:
        scan_id, user_id, target, scan_type = scan
        if scan_type == 'Port Scan':
            results = scan_ports(target)
        elif scan_type == 'SQL Injection':
            results = scan_sql_injection(target)
        elif scan_type == 'XSS':
            results = scan_xss(target, stored_test=None)
        else:
            results = [" Unknown scan type"]

        result_text = "\n".join(results)
        save_scan(user_id, target, scan_type, result_text, scan_mode='scheduled')

        # Mark as done
        c.execute('UPDATE scheduled_scans SET done = 1 WHERE id = ?', (scan_id,))
        conn.commit()

        # Email alert
        c.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        if user:
            alert_if_critical(result_text, user[0])

    conn.close()

scheduler.add_job(run_scheduled_scans, 'interval', minutes=1)

# =================== ROUTES ===================

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('index.html', username=session['username'])

@app.route('/history')
def history():
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')

    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()

    # Only manual scans here
    c.execute("SELECT * FROM scans WHERE user_id = ? AND scan_mode = 'manual' ORDER BY timestamp DESC", (user_id,))
    manual_scans = c.fetchall()

    # Scheduled scans info from scheduled_scans table (and link to scans table for completed)
    c.execute("SELECT * FROM scheduled_scans WHERE user_id = ? ORDER BY scheduled_time DESC", (user_id,))
    scheduled_scans_raw = c.fetchall()

    scheduled_scans = []
    for sched in scheduled_scans_raw:
        sched_id = sched[0]
        target = sched[2]
        scan_type = sched[3]
        done = sched[4]
        scheduled_time = sched[5]

        scan_id = None
        if done:
            c.execute('''
                SELECT id FROM scans
                WHERE user_id = ? AND target = ? AND scan_type = ? AND scan_mode = 'scheduled'
                ORDER BY timestamp DESC LIMIT 1
            ''', (user_id, target, scan_type))
            scan_row = c.fetchone()
            if scan_row:
                scan_id = scan_row[0]

        scheduled_scans.append({
            'id': sched_id,
            'target': target,
            'scan_type': scan_type,
            'done': done,
            'scheduled_time': scheduled_time,
            'scan_id': scan_id
        })

    conn.close()

    return render_template('history.html', manual_scans=manual_scans, scheduled_scans=scheduled_scans)


@app.route('/schedule', methods=['GET', 'POST'])
def schedule():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        target = request.form['target']
        scan_type = request.form['scan_type']
        run_at = request.form['run_at']  # format: 'YYYY-MM-DD HH:MM'
        run_datetime = datetime.strptime(run_at, '%Y-%m-%dT%H:%M')
        run_datetime = run_datetime.strftime('%Y-%m-%d %H:%M')
        if run_datetime < datetime.now().strftime('%Y-%m-%d %H:%M'):
            return "❌ Scheduled time must be in the future."

        save_scheduled_scan(session['user_id'], target, scan_type, run_datetime)
        return "✅ Scan scheduled successfully."

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT target, scan_type, scheduled_time, done FROM scheduled_scans WHERE user_id = ?', (session['user_id'],))
    scheduled = c.fetchall()
    conn.close()
    return render_template('schedule.html', scheduled=scheduled)



class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Scan Report', 0, 1, 'C')

def wrap_text(text, width=80):
    """
    Wrap long words to avoid FPDF 'not enough space' error.
    """
    wrapped_lines = []
    for line in text.splitlines():
        if not line.strip():
            wrapped_lines.append('')
            continue
        parts = line.split(' ')
        for part in parts:
            if len(part) > width:
                # break long word into smaller chunks
                wrapped_lines.extend(textwrap.wrap(part, width=width))
            else:
                wrapped_lines.append(part)
        wrapped_lines.append('\n')
    return ' '.join(wrapped_lines)

@app.route('/download/<int:scan_id>')
def download_pdf(scan_id):
    import sqlite3
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    c.execute("SELECT target, scan_type, result, timestamp FROM scans WHERE id=?", (scan_id,))
    row = c.fetchone()
    conn.close()

    if row:
        target, scan_type, result, timestamp = row

        pdf = PDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.add_font('DejaVu', '', 'fonts/DejaVuSans.ttf', uni=True)
        pdf.set_font("Dejavu", size=12)

        # Apply wrapped text safely
        pdf.multi_cell(0, 10, f"Target: {wrap_text(target)}")
        pdf.multi_cell(0, 10, f"Type: {wrap_text(scan_type)}")
        pdf.multi_cell(0, 10, f"Result:\n{wrap_text(result)}")
        pdf.multi_cell(0, 10, f"Time: {wrap_text(timestamp)}")

        # Ensure encoding uses Latin-1 fallback
        pdf_output = pdf.output(dest='S')

        return send_file(BytesIO(pdf_output), download_name=f'report_{scan_id}.pdf', as_attachment=True)
    else:
        return "Scan not found", 404



# =================== SOCKET.IO SCAN ===================

@socketio.on('start_scan')
def handle_scan(data):
    if 'user_id' not in session:
        emit('scan_update', {'msg': '❌ You must be logged in to scan.'})
        return

    target = data.get('target')
    scan_type = data.get('type')

    emit('scan_update', {'msg': f"🔍 Starting {scan_type} scan on {target}"})

    if scan_type == "Port Scan":
        results = scan_ports(target)
    elif scan_type == "SQL Injection":
        results = scan_sql_injection(target)
    elif scan_type == "XSS":
        stored_test_config = {
        'inject_url': f"{target}/comment",
        'reflect_url': f"{target}/view_comments",
        'method': 'POST',
        'param_name': 'comment',
        'post_data': {'user': 'scanner'}
    }
        results = scan_xss(target, stored_test=stored_test_config)

    else:
        results = ["❌ Unknown scan type."]

    for line in results:
        emit('scan_update', {'msg': line})

    result_text = "\n".join(results)
    save_scan(session['user_id'], target, scan_type, result_text, scan_mode='manual')

    # Get user email
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    if user:
        alert_if_critical(result_text, user[0])

    emit('scan_update', {'msg': f"✅ {scan_type} scan complete!"})



# =================== WEEKLY SUMMARY ===================

def send_weekly_summaries():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, email FROM users")
    users = c.fetchall()

    for uid, email in users:
        c.execute("SELECT target, scan_type, timestamp FROM scans WHERE user_id = ? AND timestamp >= datetime('now', '-7 days')", (uid,))
        scans = c.fetchall()
        if scans:
            summary = "\n".join([f"{s[0]} - {s[1]} at {s[2]}" for s in scans])
            send_email(email, "📊 Weekly Scan Summary", summary)

    conn.close()

scheduler.add_job(send_weekly_summaries, 'cron', day_of_week='sun', hour=8)

# =================== MAIN ===================

if __name__ == '__main__':
    socketio.run(app, debug=True)
