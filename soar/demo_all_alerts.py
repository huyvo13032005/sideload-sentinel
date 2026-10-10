"""
demo_all_alerts.py — Demo toàn bộ luồng SOAR bằng cách gửi lần lượt 7 alert
giả lập, mỗi alert tương ứng một phase trong attack chain (Phase 2 -> Phase 8,
bỏ qua Phase 1 - Reconnaissance vì out of scope — xem Chương 3 báo cáo).
"""

import time
import requests

LISTENER_URL = "http://localhost:5001/webhook"
HOST = {"name": "DESKTOP-ULH24T3"}

ALERTS = [
    ("Phase 2 - Execution - T1129", {
        "rule_name": "Suspicious DLL Load From User-Writable Path",
        "host": HOST,
        "dll": {"path": r"C:\Users\Cuonghk\AppData\Local\Temp\T1129-Attack\version.dll",
                "hash": {"sha256": "a" * 64}},
        "phase": "Phase 2 - Execution", "technique": "T1129",
    }),
    ("Phase 3 - Delivery - T1566.001", {
        "rule_name": "Spearphishing Attachment Detected",
        "host": HOST,
        "dll": {"path": r"C:\Users\Cuonghk\Downloads\Invoice.zip", "hash": {"sha256": "a" * 64}},
        "phase": "Phase 3 - Delivery", "technique": "T1566.001",
    }),
    ("Phase 4 - Execution - T1204.002", {
        "rule_name": "User Executed Malicious LNK File",
        "host": HOST,
        "dll": {"path": r"C:\Users\Cuonghk\Desktop\Invoice_attack.lnk", "hash": {"sha256": "b" * 64}},
        "phase": "Phase 4 - Execution", "technique": "T1204.002",
    }),
    ("Phase 5 - Persistence - T1053.005", {
        "rule_name": "Suspicious Scheduled Task Creation",
        "host": HOST,
        "dll": {"path": r"C:\Windows\System32\Tasks\WindowsUpdate", "hash": {"sha256": "c" * 64}},
        "phase": "Phase 5 - Persistence", "technique": "T1053.005",
    }),
    ("Phase 6 - C2 - T1071.001", {
        "rule_name": "Suspicious HTTP Beacon to External C2",
        "host": HOST,
        "dll": {"path": "powershell.exe -> http://208.100.26.100:8000/beacon", "hash": {"sha256": "d" * 64}},
        "phase": "Phase 6 - C2", "technique": "T1071.001",
    }),
    ("Phase 7 - Discovery - T1033", {
        "rule_name": "System Owner/User Discovery Detected",
        "host": HOST,
        "dll": {"path": "whoami.exe /all", "hash": {"sha256": "e" * 64}},
        "phase": "Phase 7 - Discovery", "technique": "T1033",
    }),
    ("Phase 8 - Exfiltration - T1041", {
        "rule_name": "Exfiltration Over C2 Channel Detected",
        "host": HOST,
        "dll": {"path": "POST http://208.100.26.100:9000/exfil (secret.txt)", "hash": {"sha256": "f" * 64}},
        "phase": "Phase 8 - Exfiltration", "technique": "T1041",
    }),
]

print("DEMO SOAR - Kill Chain Alerts")
print("=" * 50)
for i, (label, payload) in enumerate(ALERTS, start=1):
    print(f"\n[{i}/7] {label}")
    resp = requests.post(LISTENER_URL, json=payload, timeout=5)
    print(f"    -> HTTP {resp.status_code}: {resp.text}")
    time.sleep(2)

print("\n" + "=" * 50)
print("DEMO COMPLETE - Check Telegram for all alerts")
