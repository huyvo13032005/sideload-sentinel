# T1129 Detection Engineering Lab

Phát hiện kỹ thuật **Shared Modules (T1129)** trên Windows Endpoint bằng **Sysmon**,
**Elastic Security** và **Atomic Red Team** — kèm một SOAR mini playbook tự động hoá
cảnh báo qua Telegram.

Đây là repo đi kèm báo cáo Detection Engineering (`docs/report.md`), tổng hợp lại
các artefact dùng được: cấu hình Sysmon, rule Elastic/Sigma, correlation EQL,
MITRE Navigator layer, và script SOAR.

> Phạm vi: Windows Endpoint. Không bao gồm EDR thương mại. Dùng cho mục đích học tập /
> detection engineering — không gồm bất kỳ payload hay công cụ tấn công nào có thể chạy
> trực tiếp; các bước tấn công trong lab chỉ được mô tả lại dưới dạng tài liệu trong báo cáo.

## Cấu trúc repo

```
.
├── docs/
│   └── report.md              # Tóm tắt báo cáo Detection Engineering (8 chương + phụ lục)
├── detection-rules/
│   ├── sysmon-config.xml      # Cấu hình Sysmon dùng trong lab
│   ├── elastic-kql-rule.txt   # Rule "Suspicious DLL Load From User-Writable Path" (KQL)
│   ├── sigma-rule.yml         # Sigma rule tương ứng
│   └── eql-correlation.txt    # Correlation File Creation -> Image Load (EQL)
├── soar/
│   ├── soar_listener.py       # Flask webhook listener -> Telegram (reference implementation)
│   ├── simulate_alert.py      # Gửi thử 1 alert tới listener
│   ├── demo_all_alerts.py     # Gửi 7 alert liên tiếp theo kill chain
│   └── requirements.txt
└── mitre-navigator/
    └── layer.json             # Layer để import vào MITRE ATT&CK Navigator
```

## Kết quả chính

| Kỹ thuật | Tactic | Trạng thái detection |
|---|---|---|
| T1129 — Shared Modules | Execution | **Detected** (rule Elastic hoạt động, risk score 47) |
| T1053.005 — Scheduled Task | Persistence | Partial |
| T1071.001 — App Layer Protocol | C2 | Partial |
| T1218.011 — Rundll32 (pcwutl.dll) | Defense Evasion | False Negative |
| T1566.001, T1204.002 | Initial Access / Execution | Not Detected |
| T1033, T1041 | Discovery / Exfiltration | Not Tested |
| T1595 | Reconnaissance | Out of scope |

Chi tiết đầy đủ: xem `docs/report.md` (hoặc file Word đính kèm trong cùng dự án).

## Rule chính (Elastic KQL)

```
event.code: "7" and
(process.name: "powershell.exe" or process.name: "pwsh.exe" or
process.name: "rundll32.exe" or process.name: "regsvr32.exe") and
(dll.path: *AppData* or dll.path: *Downloads* or
dll.path: *Users\Public* or dll.path: *Windows\Temp*)
```

Xem `detection-rules/` để biết bản Sigma, EQL correlation, và phần tuning đề xuất
(bổ sung `dll.code_signature.trusted`, `process.parent.name`, recency) nêu ở Chương 6
của báo cáo.

## SOAR mini playbook

`soar/soar_listener.py` nhận webhook từ Elastic Rule Action (hoặc từ script giả lập),
trích hash SHA256 của DLL, và gửi cảnh báo qua Telegram Bot. Đây là **bản triển khai
tham khảo**, viết lại theo đúng hành vi đã quan sát được trong log và output của lab
(không phải export trực tiếp từ máy Kali, vì mã nguồn gốc không nằm trong tài liệu đính kèm).

```bash
cd soar
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN="..."
export TELEGRAM_CHAT_ID="..."
python3 soar_listener.py        # chạy trên port 5001
python3 simulate_alert.py       # gửi thử 1 alert
python3 demo_all_alerts.py      # demo 7 alert theo kill chain
```

## Hạn chế đã biết

- Chỉ 1/9 kỹ thuật có alert thật được kiểm chứng trên Elastic.
- Chưa đo false positive định lượng.
- Bước enrich VirusTotal trong SOAR playbook mới ở mức thiết kế (`VT: skipped — no API key`
  trong log thực tế của lab), chưa chạy enrichment thật.
- Chưa có correlation rule bao phủ toàn bộ kill chain.

## Tác giả

huyvo13032005
