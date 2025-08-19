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
git clone https://github.com/<your-username>/vpn-afterhours-alert.git
cd vpn-afterhours-alert

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
