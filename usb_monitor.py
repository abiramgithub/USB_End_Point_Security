import os
import time
import wmi
import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog
import base64
import random
import string
import smtplib
import datetime
from email.message import EmailMessage
import traceback

# === DB and Email Config ===
DB_FILE = os.path.join(os.getenv('ProgramData'), 'usb_access.db')
ENCODED_EMAIL = b'############'
ENCODED_PASS = b'############'
SENDER_EMAIL = base64.b64decode(ENCODED_EMAIL).decode()
APP_PASSWORD = base64.b64decode(ENCODED_PASS).decode()

# === USB Control ===
def disable_usb():
    os.system('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f')

def enable_usb():
    os.system('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 3 /f')

# === DB Utils ===
def connect_db():
    return sqlite3.connect(DB_FILE)

def check_device_registered(device_id):
    conn = connect_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM usb_devices WHERE device_id=?", (device_id,))
    res = cur.fetchone(); conn.close()
    return res is not None

def check_user_details(name, email, phone):
    conn = connect_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name=? AND email=? AND phone=?", (name, email, phone))
    res = cur.fetchone(); conn.close()
    return res is not None

def log_access(device_id, name, email, phone, decision):
    conn = connect_db(); cur = conn.cursor()
    cur.execute("INSERT INTO access_logs(device_id,name,email,phone,decision) VALUES(?,?,?,?,?)",
                (device_id, name, email, phone, decision))
    conn.commit(); conn.close()

# === Email OTP ===
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

# === User Auth ===
def prompt_user_auth(device_id, device_name):
    root = tk.Tk(); root.withdraw()

    name = simpledialog.askstring("Verification", f"{device_name} detected.\nEnter Full Name:", parent=root)
    email = simpledialog.askstring("Verification", "Enter Email:", parent=root)
    phone = simpledialog.askstring("Verification", "Enter Phone:", parent=root)

    if not all([name, email, phone]):
        messagebox.showerror("Error", "Incomplete details", parent=root)
        log_access(device_id, name or 'N/A', email or 'N/A', phone or 'N/A', "Incomplete")
        disable_usb(); root.destroy(); return

    if not check_user_details(name, email, phone):
        messagebox.showerror("Access Denied", "User not verified", parent=root)
        log_access(device_id, name, email, phone, "Verification Failed")
        disable_usb(); root.destroy(); return

    pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    if send_email(email, "Your USB Access Password", f"Use this password to access USB:\n\n{pwd}"):
        entered = simpledialog.askstring("OTP", "Enter Password sent to your Email:", parent=root)
        if entered == pwd:
            messagebox.showinfo("Access Granted", "USB access enabled", parent=root)
            enable_usb()
            log_access(device_id, name, email, phone, "Allowed")
        else:
            messagebox.showerror("Error", "Incorrect Password", parent=root)
            disable_usb()
            log_access(device_id, name, email, phone, "Wrong Password")
    else:
        messagebox.showerror("Email Error", "Could not send email", parent=root)
        log_access(device_id, name, email, phone, "Email Failed")
        disable_usb()

    root.destroy()

# === Monitor Loop ===
def monitor_loop():
    c = wmi.WMI()
    seen = set()

    while True:
        try:
            current = {usb.DeviceID for usb in c.Win32_USBHub()}
            new = current - seen
            for device_id in new:
                name = next((usb.Name for usb in c.Win32_USBHub() if usb.DeviceID == device_id), "USB Device")
                if check_device_registered(device_id):
                    prompt_user_auth(device_id, name)
                else:
                    log_access(device_id, "N/A", "N/A", "N/A", "Not Registered")
                    disable_usb()
            seen = current
        except Exception as e:
            print("Monitoring error:", e)
            traceback.print_exc()
        time.sleep(3)


with open("usb_log.txt", "a") as f:
    f.write(f"Monitor started at {datetime.datetime.now()}\n")


if __name__ == "__main__":
    monitor_loop()
