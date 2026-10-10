# Phát hiện kỹ thuật Shared Modules (T1129) trên Windows Endpoint bằng Sysmon, Elastic Security và Atomic Red Team

Báo cáo Detection Engineering. Bản đầy đủ (định dạng Word, dùng để nộp) nằm cùng dự án;
file này là bản markdown tóm tắt, đi kèm toàn bộ hình ảnh thật của lab, dùng cho repo.

## Mục lục

1. [Tổng quan đề tài](#chương-1-tổng-quan-đề-tài)
2. [Cơ sở lý thuyết](#chương-2-cơ-sở-lý-thuyết)
3. [Kịch bản tấn công và Attack Chain](#chương-3-kịch-bản-tấn-công-và-attack-chain)
4. [Telemetry và test case cho T1129](#chương-4-telemetry-và-test-case-sinh-log-cho-t1129)
5. [Detection Engineering trên Elastic/SIEM](#chương-5-detection-engineering-trên-elasticsiem)
6. [False Positive và Tuning](#chương-6-false-positive-và-tuning)
7. [SOAR Playbook](#chương-7-soar-playbook)
8. [Kết luận và hướng phát triển](#chương-8-kết-luận-và-hướng-phát-triển)
- [Phụ lục A — Bảng mapping MITRE ATT&CK](#phụ-lục-a--bảng-mapping-mitre-attck)
- [Phụ lục B — MITRE Navigator Layer JSON](#phụ-lục-b--mitre-navigator-layer-json)

---

## Chương 1. Tổng quan đề tài

DLL sideloading là kỹ thuật phổ biến trong APT: kẻ tấn công lợi dụng cơ chế Windows tự
động nạp DLL khi tiến trình khởi chạy để thực thi mã độc trong một tiến trình hợp lệ.
Trong MITRE ATT&CK, hành vi này là **T1129 — Shared Modules** (tactic Execution).

**Mục tiêu:** (1) xây dựng kịch bản tấn công mô phỏng T1129 trên Windows 10; (2) xây dựng
detection rule trên Elastic Security; (3) đánh giá hiệu quả detection (coverage, FP, MTTD).

**Phạm vi:** Windows Endpoint, Sysmon + Elastic Security + Atomic Red Team. Không mở rộng
Linux/macOS, không cài EDR thương mại.

## Chương 2. Cơ sở lý thuyết

**MITRE ATT&CK vs Cyber Kill Chain:** ATT&CK dùng mô hình TTP (Tactic/Technique/Procedure).
Kill Chain (Lockheed Martin) có 7 phase tuyến tính, trong đó *Weaponization* là một phase
của Kill Chain, **không phải** một tactic của ATT&CK — điểm này cần phân biệt rõ khi mapping
attack chain sang ATT&CK ở Chương 3.

![Hình 2.1 — Trang MITRE ATT&CK T1129](images/hinh-2.1.png)
*Hình 2.1 — ID T1129, Tactic Execution, Platforms Linux/Windows/macOS.*

![Hình 2.2 — Detection Strategy DET0018/AN0052](images/hinh-2.2.png)
*Hình 2.2 — Log sources: Module Load, File Creation, Process Creation, Network Connection,
Process Metadata; Mutable Elements: TimeWindow, SuspiciousPathRegex, UnsignedOnly,
RareSignerThreshold, MinFileSizeKB.*

**Data Component -> Sysmon Event ID:**

| Data Component | Sysmon EID |
|---|---|
| Process Creation | 1 |
| Network Connection | 3 |
| Image Load | 7 |
| File Creation | 11 |
| DNS Query | 22 |

![Hình 2.3 — Detection Strategy DET0081 cho T1218](images/hinh-2.3.png)
![Hình 2.4 — Data Component Module Load (DC0016)](images/hinh-2.4.png)
![Hình 2.5 — Log source Windows của DC0016](images/hinh-2.5.png)

## Chương 3. Kịch bản tấn công và Attack Chain

### 3.1. Hạ tầng

| Máy | Vai trò |
|---|---|
| Kali Linux | Attacker, lưu trang tải tệp và máy chủ nhận dữ liệu |
| Windows 10 Home | Endpoint nạn nhân, chạy Sysmon, gửi log |
| Máy host chính | SIEM (Elastic) |

![Hình 3.1 — Cấu hình mạng Kali](images/hinh-3.1.png)
![Hình 3.2 — Cấu hình mạng Windows 10](images/hinh-3.2.png)

### 3.2. Attack Chain — 8 phase

| Phase | Tactic | Technique | Hành vi |
|---|---|---|---|
| 1. Reconnaissance | Reconnaissance | T1595 | Scan IP block (out of scope) |
| 2. Weaponization | Execution | T1129 | Chuẩn bị .lnk + version.dll |
| 3. Delivery | Initial Access | T1566.001 | Email phishing Invoice.zip |
| 4. Exploitation | Execution | T1204.002 | Double-click .lnk |
| 5. Persistence | Persistence | T1053.005 | schtasks "WindowsUpdate" |
| 6. C2 | Command & Control | T1071.001 | HTTP beacon |
| 7. Discovery | Discovery | T1033 | whoami /all |
| 8. Exfiltration | Exfiltration | T1041 | POST secret.txt |

Ghi chú: T1033 (whoami) thuộc Discovery (TA0007), **không** thuộc "Actions on Objectives"
như một số bảng kill chain tham khảo gộp nhầm. T1595 không triển khai detection vì
Detection Strategy chính thức (DET0817/AN1949) dựa trên Network Traffic — ngoài phạm vi
telemetry (chỉ Sysmon + Windows Event Log) của lab, không phải false negative.

![Hình 3.3 — MITRE T1595.001](images/hinh-3.3.png)
![Hình 3.4 — DET0817/AN1949](images/hinh-3.4.png)

### 3.3. Delivery (T1566.001)

![Hình 3.5 — strings Invoice.pdf.lnk](images/hinh-3.5.png)
![Hình 3.6 — zip + send_phish.py](images/hinh-3.6.png)
![Hình 3.7 — SMB share qua File Explorer](images/hinh-3.7.png)

### 3.4. Persistence (T1053.005)

![Hình 3.8 — msfvenom tạo version_malicious.dll](images/hinh-3.8.png)
![Hình 3.9 — nc listener + SMB server](images/hinh-3.9.png)
![Hình 3.10 — payload.ps1 + pylnk3 create](images/hinh-3.10.png)
![Hình 3.11 — HTTP server log GET payload](images/hinh-3.11.png)
![Hình 3.12 — reverse shell nhận được](images/hinh-3.12.png)
![Hình 3.13 — schtasks create thành công](images/hinh-3.13.png)
![Hình 3.14 — DET0441/AN1221](images/hinh-3.14.png)
![Hình 3.15 — Event 4698](images/hinh-3.15.png)

### 3.5. Command & Control (T1071.001)

![Hình 3.16 — lệnh beacon](images/hinh-3.16.png)
![Hình 3.17 — HTTP log beacon](images/hinh-3.17.png)
![Hình 3.18 — HTTP log 5x heartbeat](images/hinh-3.18.png)

### 3.6. Discovery (T1033)

![Hình 3.19 — whoami /all](images/hinh-3.19.png)

### 3.7. Exfiltration (T1041)

![Hình 3.20 — secret.txt trên Desktop](images/hinh-3.20.png)
![Hình 3.21 — HTTP POST 501](images/hinh-3.21.png)
![Hình 3.22 — netcat port 9000](images/hinh-3.22.png)

### 3.8–3.9. Timeline & IOC

Mốc quan trọng: File Create (09:18:26.832) -> Image Load (09:18:27.357), chênh lệch
~0,5 giây — cơ sở chọn time window correlation ở Chương 5.

| Loại IOC | Giá trị |
|---|---|
| File | version.dll / version_malicious.dll (8704 bytes, msfvenom windows/x64/shell_reverse_tcp) |
| Network | 208.100.26.100:8000 (HTTP C2), :4444 (reverse shell), :9000 (exfil) |
| Behavioral | rundll32/powershell load DLL từ %TEMP%; schtasks "WindowsUpdate" |
| Email | Invoice.zip chứa Invoice.pdf.lnk, gửi tới cuonghk@lab.local |

## Chương 4. Telemetry và test case sinh log cho T1129

Cấu hình Sysmon đầy đủ: xem `detection-rules/sysmon-config.xml`.

### 4.2–4.3. Test case 1 & 2 (baseline + load thủ công)

![Hình 4.1 — notepad.exe](images/hinh-4.1.png)
![Hình 4.2 — Event 4688](images/hinh-4.2.png)
![Hình 4.3 — LoadLibrary thủ công](images/hinh-4.3.png)
![Hình 4.4 — Sysmon EID 7](images/hinh-4.4.png)

### 4.4. Test case 3.1 — Atomic Red Team T1218.011 (rundll32 + pcwutl.dll)

![Hình 4.5 — Atomic Red Team GitHub T1218.011](images/hinh-4.5.png)
![Hình 4.6 — Atomic Test #9](images/hinh-4.6.png)
![Hình 4.7 — Invoke-AtomicTest](images/hinh-4.7.png)
![Hình 4.8 — Sysmon EID 1](images/hinh-4.8.png)
![Hình 4.9 — Event 4688](images/hinh-4.9.png)
![Hình 4.10 — Sysmon EID 7 (pcwutl.dll, Signed Valid)](images/hinh-4.10.png)

### 4.5. Test case 3.2 — Atomic Red Team T1129

![Hình 4.11 — Atomic Red Team GitHub T1129](images/hinh-4.11.png)
![Hình 4.12 — T1129LabLoader](images/hinh-4.12.png)
![Hình 4.13 — tải version.dll từ Kali](images/hinh-4.13.png)
![Hình 4.14 — LoadLibrary](images/hinh-4.14.png)
![Hình 4.15 — Sysmon EID 11 (FileCreate)](images/hinh-4.15.png)
![Hình 4.16 — Sysmon EID 7 (ImageLoad)](images/hinh-4.16.png)
![Hình 4.17 — Elastic Discover](images/hinh-4.17.png)
![Hình 4.18 — Hai sự kiện liền kề trên Elastic](images/hinh-4.18.png)

### 4.6. So sánh 3.1 vs 3.2

| Tiêu chí | 3.1 pcwutl.dll | 3.2 version.dll (Attack) |
|---|---|---|
| Đường dẫn | System32 | %TEMP%\T1129-Attack |
| Chữ ký | Signed, Valid | Signed (nhưng path đáng ngờ) |
| Rule Ch.5 bắt được? | Không (false negative) | Có |

Kết luận: chỉ dùng `dll.path` là chưa đủ, cần bổ sung `code_signature`, `recency`, `signer`.

## Chương 5. Detection Engineering trên Elastic/SIEM

![Hình 5.1 — Rule Suspicious DLL Load From User-Writable Path](images/hinh-5.1.png)

KQL: xem `detection-rules/elastic-kql-rule.txt`.

![Hình 5.2 — Alert thật, risk score 47](images/hinh-5.2.png)
![Hình 5.3 — Rule bổ sung EID 11, risk score 21](images/hinh-5.3.png)
![Hình 5.4 — Dashboard Alerts](images/hinh-5.4.png)
![Hình 5.5 — Sigma rule SigmaHQ pcwutl.dll](images/hinh-5.5.png)

Sigma rule tự viết: `detection-rules/sigma-rule.yml`.
EQL correlation (File Creation -> Image Load): `detection-rules/eql-correlation.txt`.

## Chương 6. False Positive và Tuning

FP tiềm ẩn: trình cài đặt hợp lệ, script admin, dev/test tools, auto-updater — chưa đo
định lượng trong lab.

False negative: pcwutl.dll (Hình 4.10) — DLL hệ thống đã ký số, path hợp lệ nên rule hiện
tại bỏ lọt.

Tuning đề xuất: thêm `dll.code_signature.trusted`, `process.parent.name`, recency (DLL mới
tạo trong vòng dưới 1 giờ trước khi load). Rule sau tuning: xem phần cuối
`detection-rules/elastic-kql-rule.txt`.

## Chương 7. SOAR Playbook

Luồng: Elastic Rule Action (hoặc script giả lập) → webhook POST → Flask listener
(`soar/soar_listener.py`) → trích hash SHA256 → gửi Telegram.

![Hình 7.1 — 2 service chạy song song trên Kali (HTTP server + SOAR Listener)](images/hinh-7.1.png)
![Hình 7.2 — Flask listener khởi động](images/hinh-7.2.png)
![Hình 7.3 — Tạo bot qua BotFather](images/hinh-7.3.png)
![Hình 7.4 — Test gửi tin nhắn Telegram](images/hinh-7.4.png)
![Hình 7.5 — Telegram nhận tin nhắn test](images/hinh-7.5.png)
![Hình 7.6 — curl POST thủ công webhook](images/hinh-7.6.png)
![Hình 7.7 — simulate_alert.py + listener log](images/hinh-7.7.png)
![Hình 7.8 — Telegram nhận alert T1129 đầu tiên (VT: skipped — no API key)](images/hinh-7.8.png)
![Hình 7.9 — demo_all_alerts.py (7 alert)](images/hinh-7.9.png)
![Hình 7.10 — listener log nhận đủ 7 alert](images/hinh-7.10.png)
![Hình 7.11 — Telegram nhận đủ 7 alert](images/hinh-7.11.png)

**Đánh giá:** thời gian từ alert đến Telegram < 5 giây trong lab. Bước enrich VirusTotal
mới ở mức thiết kế, log thực tế ghi `VT: skipped (no API key)`. Chưa có auto-containment.

Script dùng trong demo: `soar/soar_listener.py`, `soar/simulate_alert.py`,
`soar/demo_all_alerts.py` (bản triển khai tham khảo, viết lại theo đúng hành vi quan
sát được trong log/output của lab).

## Chương 8. Kết luận và hướng phát triển

**Đạt được:** đủ 8/8 phase kill chain; detection rule T1129 hoạt động thật trên Elastic;
phát hiện gap pcwutl.dll; SOAR mini playbook hoạt động end-to-end (1 alert và 7 alert).

**Hạn chế:** chỉ 1/9 kỹ thuật có alert thật được kiểm chứng; chưa đo FP định lượng; chưa có
correlation rule bao phủ toàn chain; VirusTotal enrichment chưa chạy thật.

**Hướng phát triển:** hoàn thiện detection cho 8 kỹ thuật còn lại; EQL correlation toàn
chain; mở rộng Linux/macOS; nâng SOAR lên production (API key VT thật, auto-containment,
WSGI server, case management).

## Phụ lục A — Bảng mapping MITRE ATT&CK

| Tactic | Technique | Hành vi | Detection |
|---|---|---|---|
| Reconnaissance | T1595 | Scan IP block | Out of scope |
| Execution | T1129 | DLL sideloading version.dll | **Detected** |
| Initial Access | T1566.001 | Email Invoice.zip | Not Detected |
| Execution | T1204.002 | Double-click .lnk | Not Detected |
| Persistence | T1053.005 | schtasks "WindowsUpdate" | Partial |
| C2 | T1071.001 | HTTP beacon | Partial |
| Discovery | T1033 | whoami /all | Not Tested |
| Exfiltration | T1041 | POST secret.txt | Not Tested |
| Defense Evasion | T1218.011 | pcwutl.dll (benign) | False Negative |

## Phụ lục B — MITRE Navigator Layer JSON

File đầy đủ: `mitre-navigator/layer.json`. Import tại
https://mitre-attack.github.io/attack-navigator/
