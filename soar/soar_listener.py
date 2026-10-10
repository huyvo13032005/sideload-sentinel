"""
soar_listener.py — SOAR mini playbook: webhook listener -> Telegram notifier.

Đây là bản triển khai THAM KHẢO, viết lại theo đúng hành vi đã quan sát được
trong log/screenshot của lab (endpoint /webhook, response
{"status": "processed", "telegram_sent": true}, format tin nhắn Telegram
"SOAR ALERT - T1129 ..."). Không phải export trực tiếp từ máy Kali vì mã nguồn
gốc không có trong tài liệu đính kèm.

Chạy:
    export TELEGRAM_BOT_TOKEN="..."
    export TELEGRAM_CHAT_ID="..."
    export VT_API_KEY=""   # để trống -> enrichment sẽ bị bỏ qua (VT: skipped)
    python3 soar_listener.py
"""

import os
import logging
from flask import Flask, request, jsonify
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("soar_listener")

app = Flask(__name__)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
VT_API_KEY = os.environ.get("VT_API_KEY", "")


def enrich_with_virustotal(sha256: str) -> str:
    """Tra cứu hash trên VirusTotal. Trả về chuỗi mô tả kết quả enrichment.

    Trong lab, VT_API_KEY chưa được cấu hình nên bước này luôn trả về
    "skipped (no API key)" — đúng như log thực tế quan sát được.
    """
    if not VT_API_KEY:
        return "skipped (no API key)"
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VT_API_KEY},
            timeout=5,
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return f"{stats.get('malicious', 0)} engines flagged malicious"
        return f"lookup failed (HTTP {resp.status_code})"
    except requests.RequestException as e:
        return f"lookup error: {e}"


def send_telegram(text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.warning("Telegram chưa được cấu hình, bỏ qua gửi tin nhắn.")
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        r = requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=5)
        return r.status_code == 200
    except requests.RequestException as e:
        log.error("Gửi Telegram lỗi: %s", e)
        return False


@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_json(force=True, silent=True) or {}
    log.info("Alert received: %s", payload)

    rule_name = payload.get("rule_name", "Unknown rule")
    host = payload.get("host", {}).get("name", "unknown-host")
    dll = payload.get("dll", {})
    dll_path = dll.get("path", "unknown")
    dll_hash = dll.get("hash", {}).get("sha256", "")
    phase = payload.get("phase", "")
    technique = payload.get("technique", "")

    vt_result = enrich_with_virustotal(dll_hash) if dll_hash else "n/a"

    lines = [
        "SOAR ALERT",
        f"Rule: {rule_name}",
        f"Host: {host}",
        f"DLL: {dll_path}",
    ]
    if dll_hash:
        lines.append(f"Hash: {dll_hash}")
    lines.append(f"VT: {vt_result}")
    if phase:
        lines.append(f"Phase: {phase}")
    if technique:
        lines.append(f"Technique: {technique}")
    lines.append("-> De xuat: Co lap endpoint va thu thap forensic.")

    telegram_sent = send_telegram("\n".join(lines))
    log.info("Telegram: %s", "sent" if telegram_sent else "not sent")

    return jsonify({"status": "processed", "telegram_sent": telegram_sent})


if __name__ == "__main__":
    port = int(os.environ.get("SOAR_PORT", 5001))
    log.info("SOAR Listener starting on port %d ...", port)
    app.run(host="0.0.0.0", port=port)
