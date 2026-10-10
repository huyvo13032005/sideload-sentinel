# T1129 Detection Engineering Lab

Phát hiện kỹ thuật **Shared Modules (T1129)** trên Windows Endpoint bằng **Sysmon**, **Elastic Security** và **Atomic Red Team** — kèm một SOAR mini playbook tự động hoá cảnh báo qua Telegram.

Đây là repo đi kèm báo cáo Detection Engineering (`docs/report.md`), tổng hợp lại các artefact dùng được: cấu hình Sysmon, rule Elastic/Sigma, correlation EQL, MITRE Navigator layer, và script SOAR.

> **Phạm vi:** Windows Endpoint. Dùng cho mục đích học tập / detection engineering — không gồm bất kỳ payload hay công cụ tấn công nào có thể chạy trực tiếp; các bước tấn công trong lab chỉ được mô tả lại dưới dạng tài liệu trong báo cáo.

## Sơ đồ MITRE ATT&CK Layer Mapping

Dưới đây là sơ đồ ánh xạ chiến lược các kỹ thuật được mô phỏng và đánh giá trong lab thông qua MITRE ATT&CK Navigator (Enterprise ATT&CK v19). Sơ đồ này trực quan hoá toàn bộ attack chain từ giai đoạn Reconnaissance đến Exfiltration, phản ánh mức độ bao phủ và hiệu quả của các detection rule đã xây dựng.

https://drive.google.com/drive/folders/1yRJooCb6PJZRhhfrCxD2J61J7deevM6m

**Chú thích màu sắc trên sơ đồ:**
- **Đỏ (Detected):** Kỹ thuật đã được phát hiện thành công bằng rule Elastic (ví dụ: T1129 - Shared Modules).
- **Vàng (Partial/Mapped):** Kỹ thuật đã được mô phỏng, ghi nhận telemetry và xây dựng logic detection (ví dụ: T1053.005, T1071.001).
- **Xám (Simulated):** Kỹ thuật đã được mô phỏng trong attack chain và có dữ liệu log phục vụ phân tích (ví dụ: T1566.001, T1204.002).
- **Trắng (Mapped):** Kỹ thuật đã được ánh xạ trong kịch bản tấn công tổng thể (ví dụ: T1595, T1033, T1041).

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
| T1053.005 — Scheduled Task | Persistence | Mapped (Telemetry & Rule Logic) |
| T1071.001 — App Layer Protocol | C2 | Mapped (Telemetry & Rule Logic) |
| T1218.011 — Rundll32 (pcwutl.dll) | Defense Evasion | Analyzed (Behavioral Mapping) |
| T1566.001, T1204.002 | Initial Access / Execution | Simulated (Attack Chain Validated) |
| T1033, T1041 | Discovery / Exfiltration | Simulated (Attack Chain Validated) |
| T1595 | Reconnaissance | Mapped (Attack Chain Integration) |

Chi tiết đầy đủ: xem `docs/report.md` (hoặc file Word đính kèm trong cùng dự án).

## Rule chính (Elastic KQL)

```
event.code: "7" and
(process.name: "powershell.exe" or process.name: "pwsh.exe" or
process.name: "rundll32.exe" or process.name: "regsvr32.exe") and
(dll.path: *AppData* or dll.path: *Downloads* or
dll.path: *Users\Public* or dll.path: *Windows\Temp*)
```

Xem `detection-rules/` để biết bản Sigma, EQL correlation, và phần tuning đề xuất (bổ sung `dll.code_signature.trusted`, `process.parent.name`, recency) nêu ở Chương 6 của báo cáo.

## SOAR mini playbook

`soar/soar_listener.py` nhận webhook từ Elastic Rule Action (hoặc từ script giả lập), trích hash SHA256 của DLL, và gửi cảnh báo qua Telegram Bot. Đây là **bản triển khai tham khảo**, viết lại theo đúng hành vi đã quan sát được trong log và output của lab.

```bash
cd soar
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN="..."
export TELEGRAM_CHAT_ID="..."
python3 soar_listener.py        # chạy trên port 5001
python3 simulate_alert.py       # gửi thử 1 alert
python3 demo_all_alerts.py      # demo 7 alert theo kill chain
```
