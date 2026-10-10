"""
simulate_alert.py — Gửi thử 1 alert giả lập tới SOAR listener (dùng khi test,
không cần chờ rule Elastic tự kích hoạt).
"""

import requests

LISTENER_URL = "http://localhost:5001/webhook"

alert = {
    "rule_name": "Suspicious DLL Load From User-Writable Path",
    "host": {"name": "DESKTOP-ULH24T3"},
    "dll": {
        "path": r"C:\Users\Cuonghk\AppData\Local\Temp\T1129-Attack\version.dll",
        "hash": {"sha256": "8e9d5e4f8a0b1c2d3e4f5a6b7c8d9e0f1234567890abcdef1234567890abcdef"},
    },
}

print(f"[*] Sending simulated alert to {LISTENER_URL}")
print(f"[*] Rule: {alert['rule_name']}")
print(f"[*] Host: {alert['host']['name']}")

resp = requests.post(LISTENER_URL, json=alert, timeout=5)
print(f"[+] Response: {resp.status_code}")
print(f"[+] Body: {resp.text}")
