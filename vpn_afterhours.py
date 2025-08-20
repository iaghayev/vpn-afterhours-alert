#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, json, urllib.parse, requests, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from dotenv import load_dotenv

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

# =======================
# Load .env
# =======================
load_dotenv()

def env_bool(name, default=False):
    v = os.environ.get(name, str(default)).strip().lower()
    return v in ("1", "true", "yes", "on")

# =======================
# CONFIGURATION
# =======================
FW_IP   = os.environ.get("FW_IP", "")
API_KEY = os.environ.get("API_KEY", "")

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID   = os.environ.get("TG_CHAT_ID", "")

TZ_NAME = os.environ.get("TZ_NAME", "Asia/Baku")
WORK_START_HOUR = int(os.environ.get("WORK_START_HOUR", "8"))
WORK_START_MIN  = int(os.environ.get("WORK_START_MIN",  "1"))
WORK_END_HOUR   = int(os.environ.get("WORK_END_HOUR",   "18"))
WORK_END_MIN    = int(os.environ.get("WORK_END_MIN",    "1"))
ALERT_ON_WEEKENDS = env_bool("ALERT_ON_WEEKENDS", True)

STATE_DIR  = os.environ.get("STATE_DIR", "./state")
STATE_FILE = os.path.join(STATE_DIR, "afterhours_vpn_state.json")

LONG_SESSION_HOURS = int(os.environ.get("LONG_SESSION_HOURS", "12"))

# Weekend ISO: Mon=1 ... Sun=7 → Sat=6, Sun=7
WEEKEND_ISO_DAYS = {6, 7}

# RFC1918 private IP ranges
RFC1918_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]

requests.packages.urllib3.disable_warnings()

def local_tz():
    if ZoneInfo:
        try:
            return ZoneInfo(TZ_NAME)
        except Exception:
            pass
    return timezone.utc

def is_after_hours(dt_local: datetime) -> bool:
    """Check if current time is after-hours."""
    if dt_local.isoweekday() in WEEKEND_ISO_DAYS:
        return bool(ALERT_ON_WEEKENDS)

    start = dt_local.replace(hour=WORK_START_HOUR, minute=WORK_START_MIN, second=0, microsecond=0)
    end   = dt_local.replace(hour=WORK_END_HOUR,   minute=WORK_END_MIN,   second=0, microsecond=0)
    return not (start <= dt_local <= end)

def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"sent": []}

def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    state["sent"] = state.get("sent", [])[-3000:]
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)

def tg_send(text: str):
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    r = requests.post(url, json=data, timeout=15)
    r.raise_for_status()
    return r.json()

def fetch_current_users():
    cmd = "<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>"
    params = {"type": "op", "cmd": cmd, "key": API_KEY}
    url = f"https://{FW_IP}/api/?{urllib.parse.urlencode(params)}"
    r = requests.get(url, timeout=25, verify=False)
    r.raise_for_status()
    root = ET.fromstring(r.text)
    return root.findall(".//result/entry")

def safe_split_domain(primary_val: str) -> str:
    if not primary_val:
        return ""
    if "\\" in primary_val:
        return primary_val.split("\\", 1)[0]
    if "/" in primary_val:
        return primary_val.split("/", 1)[0]
    return ""

def fmt_duration_since(epoch):
    try:
        now = int(datetime.now(timezone.utc).timestamp())
        sec = max(0, now - int(epoch))
    except Exception:
        return "-", 0
    days = sec // 86400
    hours = (sec % 86400) // 3600
    minutes = (sec % 3600) // 60
    total_hours = hours + days * 24
    return f"{days} gün {hours} saat {minutes} dəq", total_hours

def is_external_by_virtual_ip(virt_ip: str) -> bool:
    v = (virt_ip or "").strip()
    return v not in ("", "0.0.0.0", "::")

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ip_address((ip_str or "").strip())
        return any(ip in net for net in RFC1918_NETS)
    except Exception:
        return False

def is_internal_gateway_public_ip(pub_ip: str) -> bool:
    return is_private_ip(pub_ip)

def format_user(entry, tz):
    def gx(tag, default=""):
        v = entry.findtext(tag)
        return v if v is not None else default

    username   = gx("username")
    primary    = gx("primary-username")
    domain     = gx("domain") or safe_split_domain(primary)
    computer   = gx("computer")
    public_ip  = gx("public-ip")
    virt_ip    = gx("virtual-ip")
    appver     = gx("app-version")
    client_os  = gx("client")
    vpn_type   = gx("vpn-type")
    tunnel     = gx("tunnel-type")
    login_utc  = gx("login-time-utc")

    try:
        epoch = int(login_utc)
    except Exception:
        epoch = None

    if epoch:
        dt_local = datetime.fromtimestamp(epoch, timezone.utc).astimezone(tz)
        dt_local_str = dt_local.strftime("%Y-%m-%d %H:%M:%S %Z")
        duration_fmt, total_hours = fmt_duration_since(epoch)
    else:
        dt_local = None
        dt_local_str = gx("login-time") or "unknown"
        duration_fmt, total_hours = "-", 0

    return {
        "username": username,
        "domain": domain,
        "computer": computer,
        "public_ip": public_ip,
        "virtual_ip": virt_ip,
        "appver": appver,
        "client_os": client_os,
        "vpn_type": vpn_type,
        "tunnel": tunnel,
        "login_epoch": epoch,
        "login_local": dt_local,
        "login_local_str": dt_local_str,
        "duration_fmt": duration_fmt,
        "total_hours": total_hours,
        "is_external": is_external_by_virtual_ip(virt_ip),
        "is_internal_gw_pubip": is_internal_gateway_public_ip(public_ip),
    }

def send_vpn_alert(info, trigger_type, sent, state):
    uniq = f'{info["username"]}|{info["login_epoch"]}|{trigger_type}'
    if uniq in sent:
        return False

    if trigger_type in ("afterhours", "afterhours_login"):
        title = "🔔 <b>İş vaxtından kənar VPN qoşulması</b>"
    elif trigger_type == "longsession":
        title = f"⏳ <b>{LONG_SESSION_HOURS} saatdan çox davam edən VPN sessiyası</b>"
    else:
        title = "🔔 <b>VPN xəbərdarlığı</b>"

    msg = (
        f"{title}\n"
        f"👤 İstifadəçi: <code>{info['username'] or '-'}</code>\n"
        f"🏢 Domain: <code>{info['domain'] or '-'}</code>\n"
        f"🧩 VPN növü: <code>{info['vpn_type'] or '-'}</code>\n"
        f"🔒 Tunnel: <code>{info['tunnel'] or '-'}</code>\n"
        f"💻 Kompüter: <code>{info['computer'] or '-'}</code>\n"
        f"🖥️ Client/OS: <code>{info['client_os'] or '-'}</code>\n"
        f"📦 App versiyası: <code>{info['appver'] or '-'}</code>\n"
        f"🌐 Public IP: <code>{info['public_ip'] or '-'}</code>\n"
        f"🎯 Virtual IP: <code>{info['virtual_ip'] or '-'}</code>\n"
        f"⏱ Sessiya müddəti: <code>{info['duration_fmt']}</code>\n"
        f"🕒 Login (yerli): <code>{info['login_local_str']}</code>\n"
    )
    try:
        tg_send(msg)
        sent.add(uniq)
        state["sent"] = list(sent)
        save_state(state)
        return True
    except Exception:
        return False

def main():
    tz = local_tz()
    state = load_state()
    sent = set(state.get("sent", []))

    try:
        entries = fetch_current_users()
    except Exception:
        return

    now_local = datetime.now(tz)
    now_is_after = is_after_hours(now_local)

    for e in entries:
        info = format_user(e, tz)
        if not info["login_epoch"]:
            continue

        # Private/daxili gateway bağlantılarını keç
        if info["is_internal_gw_pubip"]:
            continue

        # Login-in after-hours olub-olmadığını yoxla
        login_is_after = False
        if info["login_local"] is not None:
            login_is_after = is_after_hours(info["login_local"])

        if now_is_after:
            # AFTER-HOURS REJİMİ:
            # 1) Yalnız after-hours-da BAŞLAYAN sessiyalar üçün alert
            if login_is_after:
                send_vpn_alert(info, "afterhours_login", sent, state)

            # 2) 12+ saat davam edən sessiyalar üçün də alert (login vaxtından asılı deyil)
            if info["is_external"] and info["total_hours"] >= LONG_SESSION_HOURS:
                send_vpn_alert(info, "longsession", sent, state)

        else:
            # İŞ SAATLARI REJİMİ:
            # Yalnız 12+ saat davam edən sessiyalar üçün alert
            if info["is_external"] and info["total_hours"] >= LONG_SESSION_HOURS:
                send_vpn_alert(info, "longsession", sent, state)

if __name__ == "__main__":
    main()
