
# 🔐 USB Physical Security System

A robust USB device access control and monitoring tool designed to secure endpoint systems from unauthorized USB usage. Built using Python, this project continuously monitors USB insertions and validates devices against a registered whitelist. It also performs user verification using email-based OTP authentication.

---

## 📌 Features

- 🔄 **Runs at System Startup** (via Task Scheduler)
- 📦 **Real-time USB Monitoring**
- ✅ **Device ID Whitelisting** with SQLite Database
- 👤 **User Identity Verification** (Name, Email, Phone)
- ✉️ **Email-based OTP Authentication**
- 🔐 **Secure Admin Panel Access** via Email Request
- 📁 **Encrypted Log Files & Activity Tracking**
- 🌐 **Project Info Viewer** (HTML integration)
- 🧰 **GUI + Stealth Background Execution**
- 🔒 **USB Port Enabling/Disabling Based on Validation**

---

## 📁 Project Structure

```
USB_Physical_Security/
│
├── usb_security.py                   # Main project logic with GUI
├── usb_register_admin_gui.py        # Admin/User/Device Registration GUI
├── usb_access.db                    # SQLite DB with user and device info
├── ProjectDetails.html              # Embedded HTML for system overview
├── encryption_util.py               # Email/admin credential encryption helper
├── usb_security.exe                 # Bundled executable (via PyInstaller)
├── logs/                            # Encrypted logs of system events
├── README.md                        # Project documentation
```

---

## 🛠 Technologies Used

- **Python 3.10+**
- **Tkinter** for GUI development
- **SQLite** for local storage
- **WMI** for USB detection
- **smtplib** for email OTP delivery
- **PyInstaller** for .exe conversion
- **Base64** for credential obfuscation

---

## 🚀 How It Works

1. System boots → `usb_security.exe` runs silently in background.
2. USB device inserted → system detects and checks device ID.
3. If registered:
   - Prompt user for identity (Name, Email, Phone)
   - Send OTP to registered email
   - If OTP is valid → enable USB port
4. If not registered or OTP fails → disable USB port
5. All events are encrypted and logged.

---

## 🔒 Admin Access Logic

- Users cannot register devices or details directly.
- Admin access must be **requested via email** to the sender email address.
- If approved by admin, user can unlock admin panel with code.

---

## 🧪 Testing Strategy

- ✔️ Registered vs Unregistered USB test
- ✔️ Email OTP verification test
- ✔️ Admin access validation test
- ✔️ Log file encryption & storage check

---

## 💻 How to Run

1. Clone the repo:
```bash
git clone https://github.com/yourusername/usb-physical-security.git
cd usb-physical-security
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the project:
```bash
python usb_security.py
```

> 💡 Convert to `.exe` using:
```bash
pyinstaller --onefile --noconsole --add-data "usb_access.db;." usb_security.py
```

---

## 📧 Contact

Created with 💙 by **Abiram S.**  
Aspiring SOC Analyst & Cybersecurity Developer

---
