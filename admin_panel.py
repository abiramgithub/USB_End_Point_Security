import os
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import sqlite3
import base64
import random
import string
import smtplib
import datetime
from email.message import EmailMessage
import webbrowser

# === ENCODED EMAIL CREDS ===
ENCODED_EMAIL = b'############'
ENCODED_PASS = b'############'
SENDER_EMAIL = base64.b64decode(ENCODED_EMAIL).decode()
APP_PASSWORD = base64.b64decode(ENCODED_PASS).decode()

# === DATABASE PATH ===
DB_FILE = os.path.join(os.getenv('ProgramData'), 'usb_access.db')

# === Database Setup ===
def connect_db():
    return sqlite3.connect(DB_FILE)

def create_tables():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS usb_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        name TEXT,
        email TEXT,
        phone TEXT,
        decision TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        success INTEGER,
        reason TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

# === Email Sender ===
def send_email(to_email, subject, body):
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Email error:", e)
        return False

# === Registration Logic ===
def register_usb_device(device_id):
    if not device_id:
        messagebox.showerror("Error", "Device ID required")
        return
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO usb_devices (device_id) VALUES (?)", (device_id,))
        conn.commit()
        messagebox.showinfo("Success", "Device registered")
    except sqlite3.IntegrityError:
        messagebox.showerror("Exists", "Device ID already registered")
    finally:
        conn.close()

def register_user(name, email, phone):
    if not all([name, email, phone]):
        messagebox.showerror("Error", "All fields required")
        return
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (name, email, phone) VALUES (?, ?, ?)", (name, email, phone))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "User registered")

# === Admin Panel GUI ===
def show_admin_panel():
    create_tables()
    win = tk.Tk()
    win.title("Admin Panel")
    win.geometry("400x470")

    frame1 = ttk.LabelFrame(win, text="Register USB Device")
    frame1.pack(fill="x", padx=10, pady=5)
    usb_entry = tk.Entry(frame1, width=40)
    usb_entry.pack(pady=5)
    tk.Button(frame1, text="Register USB", command=lambda: register_usb_device(usb_entry.get())).pack()

    frame2 = ttk.LabelFrame(win, text="Register User")
    frame2.pack(fill="x", padx=10, pady=10)
    name_entry = tk.Entry(frame2, width=40)
    email_entry = tk.Entry(frame2, width=40)
    phone_entry = tk.Entry(frame2, width=40)
    for lbl, ent in [("Name", name_entry), ("Email", email_entry), ("Phone", phone_entry)]:
        tk.Label(frame2, text=lbl).pack(); ent.pack()
    tk.Button(frame2, text="Register User", command=lambda: register_user(
        name_entry.get(), email_entry.get(), phone_entry.get())).pack(pady=5)

    tk.Button(win, text="View Admin Log", command=view_admin_logs).pack(pady=5)
    tk.Button(win, text="Project Details", command=show_project_details).pack(pady=5)
    tk.Button(win, text="Exit", command=win.quit).pack(pady=5)

    win.mainloop()

# === Project HTML Viewer ===
def show_project_details():
    html_path = os.path.abspath("ProjectDetails.html")
    webbrowser.open(f"file://{html_path}")

# === Admin Access Logging ===
def log_admin_access(email, success, reason):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO admin_logs (email, success, reason) VALUES (?, ?, ?)", (email, success, reason))
    conn.commit()
    conn.close()

def view_admin_logs():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT email, success, reason, timestamp FROM admin_logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    conn.close()

    log_window = tk.Toplevel()
    log_window.title("Admin Access Logs")
    log_window.geometry("500x300")

    tree = ttk.Treeview(log_window, columns=("email", "success", "reason", "timestamp"), show="headings")
    tree.heading("email", text="Email")
    tree.heading("success", text="Success")
    tree.heading("reason", text="Reason")
    tree.heading("timestamp", text="Timestamp")
    tree.pack(fill="both", expand=True)

    for log in logs:
        tree.insert("", "end", values=log)

# === Secure Admin Login with OTP ===
def authenticate_admin_strict():
    create_tables()  # Ensure DB tables are created before any logging
    root = tk.Tk()
    root.withdraw()

    entered_email = simpledialog.askstring("Admin Verification", "Enter Admin Email:", parent=root)

    if not entered_email or entered_email.strip().lower() != SENDER_EMAIL.lower():
        messagebox.showerror("Access Denied", "Email does not match authorized admin.")
        log_admin_access(entered_email or "Unknown", 0, "Email mismatch")
        send_email(SENDER_EMAIL, "Unauthorized Admin Access Attempt", f"An unauthorized attempt was made using email: {entered_email or 'Unknown'} at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        root.destroy()
        return False

    otp = ''.join(random.choices(string.digits, k=6))
    otp_generated_time = datetime.datetime.now()
    max_valid_duration = datetime.timedelta(minutes=5)

    subject = "Admin Panel OTP Verification"
    body = f"Your OTP to access the admin panel is: {otp}\n\nNote: OTP expires in 5 minutes."

    if not send_email(SENDER_EMAIL, subject, body):
        messagebox.showerror("Email Error", "Could not send OTP.")
        log_admin_access(SENDER_EMAIL, 0, "Failed to send OTP")
        root.destroy()
        return False

    attempts = 0
    while attempts < 2:
        entered_otp = simpledialog.askstring("OTP Verification", f"Enter the OTP (Attempt {attempts + 1}/2):", show='*', parent=root)
        now = datetime.datetime.now()

        if not entered_otp:
            messagebox.showwarning("Aborted", "No OTP entered.")
            log_admin_access(SENDER_EMAIL, 0, "No OTP entered")
            break

        if now - otp_generated_time > max_valid_duration:
            messagebox.showerror("Expired", "OTP has expired.")
            log_admin_access(SENDER_EMAIL, 0, "OTP expired")
            break

        if entered_otp == otp:
            log_admin_access(SENDER_EMAIL, 1, "Access granted")
            root.destroy()
            return True
        else:
            attempts += 1
            if attempts == 2:
                messagebox.showerror("Access Denied", "Too many incorrect attempts.")
                log_admin_access(SENDER_EMAIL, 0, "Too many incorrect attempts")
            else:
                messagebox.showwarning("Incorrect", "Wrong OTP. Try again.")

    root.destroy()
    return False


# === Manual Execution Only ===
if __name__ == "__main__":
    if authenticate_admin_strict():
        show_admin_panel()
