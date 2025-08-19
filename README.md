# Palo Alto GlobalProtect VPN After-Hours & Long Session Alerts

🚀 A lightweight Python tool to monitor **Palo Alto GlobalProtect VPN sessions** and send **real-time alerts** to Telegram when:
- Users connect **outside of working hours**
- A VPN session lasts longer than a defined threshold (default: 12h)

---

## ✨ Features
- ✅ Fetches current users via **Palo Alto API**
- ✅ Detects **after-hours connections** (configurable working hours)
- ✅ Detects **long-running sessions**
- ✅ Sends formatted alerts to **Telegram group**
- ✅ **Deduplication**: avoids repeated alerts for the same session
- ✅ Timezone-aware (Asia/Baku default)
- ✅ Safe handling of secrets via `.env`
- ✅ Supports **cron/systemd timers** for scheduling

---

## 📦 Installation

Clone the repo and set up a virtual environment:

```bash
git clone https://github.com/iaghayev/vpn-afterhours-alert.git
cd vpn-afterhours-alert

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---
## ⚙️ Configuration
```bash
cp .env.example .env
nano .env   # change the values according to your setup
```
---

## ▶️ Usage
```bash
python vpn_afterhours.py
```
---

## ⏰ Scheduling
```bash
crontab -e
```
---

```bash
CRON_TZ=Asia/Baku
SHELL=/bin/bash
PATH=/usr/sbin:/usr/bin:/sbin:/bin

# Workdays (Mon-Fri) working hours: 08:01–18:01 → every hour
1 8-18 * * 1-5 /usr/bin/flock -n /tmp/vpn_afterhours.lock -c '/opt/vpn-alert/.venv/bin/python /opt/vpn-alert/vpn_afterhours.py'

# Workdays non-working hours: 00:00–07:59 → every 2 min
*/2 0-7 * * 1-5 /usr/bin/flock -n /tmp/vpn_afterhours.lock -c '/opt/vpn-alert/.venv/bin/python /opt/vpn-alert/vpn_afterhours.py'

# At 08:00 exactly
0 8 * * 1-5 /usr/bin/flock -n /tmp/vpn_afterhours.lock -c '/opt/vpn-alert/.venv/bin/python /opt/vpn-alert/vpn_afterhours.py'

# Workdays evening: 18:02–23:58 → every 2 min
2-59/2 18-23 * * 1-5 /usr/bin/flock -n /tmp/vpn_afterhours.lock -c '/opt/vpn-alert/.venv/bin/python /opt/vpn-alert/vpn_afterhours.py'

# Weekend (Sat=6, Sun=7) → every 2 min
*/2 * * * 6,7 /usr/bin/flock -n /tmp/vpn_afterhours.lock -c '/opt/vpn-alert/.venv/bin/python /opt/vpn-alert/vpn_afterhours.py'
```

---

## 📜 Example Telegram Alert
🔔 İş vaxtından kənar VPN qoşulması

👤 İstifadəçi: john.doe

💻 Kompüter: WIN10PC

🌐 Public IP: xx.xx.xx.xx

🎯 Virtual IP: xx.xx.xx.xx

⏱ Sessiya müddəti: 0 gün 0 saat 0 dəq

🕒 Login (yerli): 2025-08-19 22:05:00 AZT

---

## 🛡️ Security Notes
Do not expose your .env or API keys.

Ensure Palo Alto API uses HTTPS with valid certificate (remove verify=False in production).

Restrict Telegram bot access to only the alert group.
