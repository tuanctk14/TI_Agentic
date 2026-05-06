# 🎯 Intent Detection Guide

**Version:** 1.0  
**Status:** ✅ Production Ready  
**Date:** 2026-05-06

---

## Tổng quan

**Intent Detection** là hệ thống phân loại tự động các câu hỏi mà user hỏi qua chat:

- **Normal Chat:** Câu hỏi thông thường → Ollama trả lời trực tiếp, **không dùng tool nào**
- **TI Vulnerability:** Câu hỏi về lỗ hổng/CVE/IOC → Gọi tools tìm kiếm, enrich, match device
- **TI Malware:** Câu hỏi về mã độc → Gọi search_malware, correlate threats, analyze device
- **TI Device:** Câu hỏi về thiết bị → Gọi get_device_matches, check_memory, analyze
- **TI General:** Câu hỏi TI khác → Dùng full ReAct loop

**Lợi ích chính:**

✅ User không cần nói "dùng TI mode" hay "tìm CVE" — hệ thống tự hiểu  
✅ Chat thường không lãng phí resource vào tool calling  
✅ TI queries được xử lý với quy trình tối ưu cho loại query  
✅ Cải thiện trải nghiệm người dùng + tốc độ xử lý  

---

## 5 Loại Intent

### 1. `normal` — Câu hỏi thông thường

**Dấu hiệu:**
- Không chứa CVE, IP, hash, malware name, hoặc keyword TI
- Hỏi về khái niệm, giải thích công nghệ, hay câu hỏi chung chung

**Ví dụ:**
- "regex là gì?"
- "giải thích TCP/IP cho tôi"
- "firewall hoạt động như thế nào?"
- "Python khác JavaScript thế nào?"
- "tại sao nên dùng HTTPS?"
- "DNS là gì?"
- "mã hóa RSA hoạt động thế nào?"

**Xử lý:**
1. Não nhận diện intent = "normal"
2. Gọi `_run_normal_chat(query)` — **không dùng TOOLS list**
3. Ollama trả lời trực tiếp với system prompt đơn giản
4. Frontend nhận event type="final" (không có thinking/tool_use)

**Output ví dụ:**
```json
{
  "type": "intent",
  "intent": "normal",
  "entities": {"cves": [], "ips": [], "hashes": [], "malware_names": [], "keywords": []},
  "confidence": 0.95
}
→ [Agent trả lời trực tiếp]
```

---

### 2. `ti_vuln` — Câu hỏi về lỗ hổng/CVE/IOC

**Dấu hiệu:**
- Chứa CVE ID (ví dụ: CVE-2024-38213)
- Hoặc chứa hash (MD5/SHA1/SHA256)
- Hoặc chứa keyword về lỗ hổng: "lỗ hổng", "khai thác", "vá lỗi", "CVSS", "exploit", "POC", v.v.

**Ví dụ:**
- "CVE-2021-44228 nguy hiểm không?" → `cves=["CVE-2021-44228"]`
- "log4shell ảnh hưởng đến thiết bị nào?" → keyword "log4shell" + "ảnh hưởng"
- "lỗ hổng nào đang critical hiện tại?" → keyword "lỗ hổng" + "critical"
- "5f4dcc3b5aa765d61d8327deb882cf99 hash này là gì?" → `hashes=["5f4dcc3b5aa765d61d8327deb882cf99"]`
- "có exploit nào cho lỗ hổng fortinet không?" → keyword "exploit" + "lỗ hổng"

**Quy trình (hardcoded):**
1. `search_vulnerabilities(query)` hoặc `search_iocs(query)`
2. Nếu CVE và CVSS=0 → `enrich_vulnerability(cve_id)` (lấy từ NVD)
3. `get_device_matches(threat_name)` — tìm thiết bị nào bị ảnh hưởng
4. `check_memory(entity_name)` — xem có từng xử lý lần nào
5. Nếu nguy cơ cao → `create_alert(...)`
6. `save_investigation(...)` — lưu vào memory

**System Prompt đặc thù:**
```
Bạn là AI Security Analyst chuyên phân tích lỗ hổng bảo mật.
DATABASE: IOC=12370 | Malware=1194 | CVE=87 | Matches=28
CVE CẦN PHÂN TÍCH: CVE-2024-38213

[Quy trình 6 bước]

OUTPUT FORMAT BẮT BUỘC:
🔍 **THÔNG TIN LỖ HỔNG** — tên, CVSS, mô tả, vector
🖥️ **THIẾT BỊ BỊ ẢNH HƯỞNG** — danh sách hoặc "N/A"
📋 **LỊCH SỬ** — đã xử lý lần nào chưa
⚠️ **ĐÁNH GIÁ** — mức độ, hành động, lý do
```

**Output ví dụ:**
```json
{
  "type": "intent",
  "intent": "ti_vuln",
  "entities": {
    "cves": ["CVE-2024-38213"],
    "ips": [],
    "hashes": [],
    "malware_names": [],
    "keywords": ["ảnh hưởng", "lỗ hổng"]
  },
  "confidence": 0.92
}
[Tool calls: search_vulnerabilities → get_device_matches → create_alert]
{
  "type": "final",
  "content": "CVE-2024-38213... 🖥️ THIẾT BỊ BỊ ẢNH HƯỞNG: SRV-MAIL, PC-Finance..."
}
```

---

### 3. `ti_malware` — Câu hỏi về mã độc

**Dấu hiệu:**
- Chứa tên malware nổi tiếng (LockBit, Emotet, BlackCat, WannaCry, v.v.)
- Hoặc chứa keyword về malware: "mã độc", "virus", "ransomware", "trojan", "botnet", "worm", "RAT", "C2", v.v.

**Ví dụ:**
- "LockBit là gì?" → `malware_names=["LockBit"]`
- "hệ thống có bị nhiễm mã độc gì không?" → keyword "mã độc"
- "Emotet hoạt động thế nào?" → `malware_names=["Emotet"]`
- "có malware ransomware nào trong database không?" → keyword "ransomware"
- "BlackCat có liên quan đến CVE nào?" → `malware_names=["BlackCat"]`
- "diệt virus, hệ thống bị lây cách nào?" → keyword "virus" + "lây"

**Quy trình (hardcoded):**
1. `search_malware(query)`
2. `search_iocs(query)` nếu có hash liên quan
3. `get_device_matches(malware_name)` — thiết bị bị match
4. `check_memory(malware_name)` — lịch sử xử lý
5. `correlate_threats(malware_name)` — CVE/IOC/Actor liên quan
6. `create_alert(...)` nếu nguy cơ cao

**System Prompt đặc thù:**
```
Bạn là AI Security Analyst chuyên phân tích mã độc.
DATABASE: IOC=12370 | Malware=1194 | CVE=87
MALWARE: LockBit

[Quy trình 6 bước]

OUTPUT FORMAT:
🦠 **THÔNG TIN MALWARE** — tên, loại, mức độ, bí danh, mô tả
🎯 **KỸ THUẬT MITRE ATT&CK** — tactic/technique
🖥️ **THIẾT BỊ BỊ ẢNH HƯỞNG** — danh sách
🔗 **IOC LIÊN QUAN** — hash, IP, domain
📋 **LỊCH SỬ PHÁT HIỆN**
💡 **KHUYẾN NGHỊ**
```

**Output ví dụ:**
```json
{
  "type": "intent",
  "intent": "ti_malware",
  "entities": {
    "cves": [],
    "ips": [],
    "hashes": [],
    "malware_names": ["LockBit"],
    "keywords": ["ransomware", "mã độc"]
  },
  "confidence": 0.94
}
[Tool calls: search_malware → get_device_matches → correlate_threats]
{
  "type": "final",
  "content": "🦠 THÔNG TIN MALWARE: LockBit là ransomware... 🖥️ THIẾT BỊ: PC-001..."
}
```

---

### 4. `ti_device` — Câu hỏi về thiết bị/asset

**Dấu hiệu:**
- Chứa IP address (192.168.x.x, 10.x.x.x, v.v.)
- Hoặc chứa hostname/tên thiết bị (server01, win-dc, v.v.)
- Hoặc chứa keyword về thiết bị: "thiết bị", "máy chủ", "máy tính", "lịch sử alert", "nguy cơ", v.v.

**Ví dụ:**
- "server01 đang dính gì?" → `device_hints=["server01"]`
- "192.168.1.10 có vấn đề gì?" → `ips=["192.168.1.10"]`
- "thiết bị nào nguy hiểm nhất?" → keyword "thiết bị" + "nguy hiểm"
- "liệt kê thiết bị đang có nguy cơ cao" → keyword "thiết bị" + "nguy cơ"
- "lịch sử alert của máy chủ web?" → keyword "lịch sử alert" + "máy chủ"
- "win-dc-01 bị ảnh hưởng không?" → `device_hints=["win-dc-01"]`

**Quy trình (hardcoded):**
1. `get_device_matches(device_name)` — lấy tất cả threats match
2. `check_memory(device_name)` — lịch sử alert/nguy cơ
3. Với mỗi threat critical/high: `search_vulnerabilities()` / `search_iocs()`
4. `analyze_device(device_name)` — MITRE ATT&CK analysis
5. `create_alert(...)` nếu phát hiện nguy cơ cao chưa xử lý

**System Prompt đặc thù:**
```
Bạn là AI Security Analyst chuyên phân tích rủi ro thiết bị.
DATABASE: IOC=12370 | Malware=1194 | CVE=87 | Matches=28
THIẾT BỊ: server01

[Quy trình 5 bước]

OUTPUT FORMAT:
🖥️ **THÔNG TIN THIẾT BỊ** — hostname, IP, phòng ban, mức rủi ro tổng thể
🚨 **CÁC MỐI ĐE DỌA HIỆN TẠI** — bảng: Threat | Loại | Mức độ | Trạng thái
📋 **LỊCH SỬ NGUY CƠ** — alert trước, trend
🔒 **CVE/LỖ HỔNG CÓ THỂ BỊ MẮC**
💡 **KHUYẾN NGHỊ ƯU TIÊN**
```

**Output ví dụ:**
```json
{
  "type": "intent",
  "intent": "ti_device",
  "entities": {
    "cves": [],
    "ips": ["192.168.1.10"],
    "hashes": [],
    "malware_names": [],
    "device_hints": [],
    "keywords": ["thiết bị"]
  },
  "confidence": 0.88
}
[Tool calls: get_device_matches → check_memory → analyze_device]
{
  "type": "final",
  "content": "🖥️ THÔNG TIN: 192.168.1.10... 🚨 THREATS: CVE-2024-1234 (high)..."
}
```

---

### 5. `ti_general` — Câu hỏi TI khác

**Dấu hiệu:**
- Chứa keyword TI chung: "opencti", "threat intelligence", "security alert", "tình báo mối đe dọa", v.v.
- Không khớp vào ti_vuln, ti_malware, ti_device

**Ví dụ:**
- "có bao nhiêu threat trong OpenCTI?"
- "phân tích tình báo mối đe dọa hiện tại"
- "cảnh báo bảo mật gần đây là gì?"

**Quy trình:**
- Dùng full ReAct loop như trước đây (không có quy trình đặc thù)

---

## 🛠️ Cơ chế Scoring

Intent được quyết định dựa trên scoring algorithm:

```python
score_vuln    = len(cves) * 3 + len(hashes) * 2 + len(found_vuln_kw)
score_malware = len(malware_names) * 3 + len(found_malware_kw)
score_device  = len(ips) * 2 + len(found_device_kw)
score_ti      = len(found_ti_kw)

# Quyết định intent theo score cao nhất
if total_score == 0:
    intent = "normal"
elif score_device > max(score_vuln, score_malware):
    intent = "ti_device"
elif score_malware > score_vuln:
    intent = "ti_malware"
elif score_vuln > 0:
    intent = "ti_vuln"
else:
    intent = "ti_general"
```

**Hệ số:**
- CVE ID: +3 điểm
- Hash: +2 điểm
- IP: +2 điểm
- Malware name: +3 điểm
- Keyword lỗ hổng: +1 điểm/keyword
- Keyword malware: +1 điểm/keyword
- Keyword thiết bị: +1 điểm/keyword
- Keyword TI chung: +1 điểm/keyword

**Confidence Score:**
- normal: 0.95 (rất tin cậy)
- ti_vuln: 0.5 + score_vuln * 0.1 (max 0.95)
- ti_malware: 0.5 + score_malware * 0.1 (max 0.95)
- ti_device: 0.5 + score_device * 0.1 (max 0.95)
- ti_general: 0.4 + score_ti * 0.15 (max 0.85)

---

## 📊 Intent Events

Mỗi query gửi qua chat sẽ nhận event đầu tiên:

```json
{
  "type": "intent",
  "intent": "ti_vuln" | "ti_malware" | "ti_device" | "ti_general" | "normal",
  "entities": {
    "cves": ["CVE-2024-38213"],
    "ips": ["192.168.1.10"],
    "hashes": ["5f4dcc3b5aa765d61d8327deb882cf99"],
    "malware_names": ["LockBit", "Emotet"],
    "device_hints": ["server01", "win-dc"],
    "keywords": ["lỗ hổng", "khai thác", "thiết bị"]
  },
  "confidence": 0.92
}
```

**Frontend có thể:**
- Hiển thị badge: `[Chat Mode]` vs `[TI Mode]`
- Hiển thị extracted entities cho user xem
- Adjust UI dựa trên intent (ví dụ: ẩn tool list cho "normal", hiển thị cho "ti_*")

---

## 🧪 Testing

**Tất cả test case đã pass:**

```
✓ normal: 'regex là gì?' → no tools
✓ normal: 'firewall hoạt động như thế nào?' → no tools
✓ ti_vuln: 'CVE-2024-38213 nguy hiểm?' → search_vulnerabilities
✓ ti_vuln: 'log4shell ảnh hưởng đến gì?' → search_vulnerabilities
✓ ti_malware: 'LockBit là gì?' → search_malware
✓ ti_malware: 'hệ thống có mã độc không?' → search_malware
✓ ti_device: 'server01 dính gì?' → get_device_matches
✓ ti_device: '192.168.1.10 có gì?' → get_device_matches
```

---

## 📝 Keyword Lists

### Lỗ hổng Keywords (7 từ khóa)
```
lỗ hổng, cve, cvss, khai thác, vá lỗi, ảnh hưởng, bị dính,
leo thang đặc quyền, chèn lệnh, thực thi mã, rce, sqli, xss,
poc, exploit, zero-day, patch, vulnerability, breach,
log4j, log4shell, eternalblue, spring4shell, heartbleed
```

### Malware Keywords
```
mã độc, virus, ransomware, trojan, backdoor, rootkit, botnet,
worm, spyware, keylogger, c2, apt, loader, rat, cryptominer,
emotet, lockbit, blackcat, plugx, remcos, wannacry,
lateral movement, persistence, exfiltration
```

### Device Keywords
```
thiết bị, máy chủ, máy tính, đang dính gì, đang bị gì,
kiểm tra thiết bị, phân tích thiết bị, lịch sử alert,
nguy cơ, rủi ro, device, host, hostname, asset, endpoint
```

### TI General Keywords
```
opencti, nvd, nist, mitre, att&ck, ttps,
indicator of compromise, threat intelligence,
tình báo mối đe dọa, cảnh báo bảo mật,
security alert, matches, so khớp
```

---

## 🚀 Usage Examples

### Via WebSocket Chat

```javascript
// User types: "CVE-2024-38213 có ảnh hưởng không?"

// Server sends:
{
  "type": "intent",
  "intent": "ti_vuln",
  "entities": {"cves": ["CVE-2024-38213"], ...},
  "confidence": 0.91
}

// Then:
{ "type": "reasoning", "step": 0, "content": "Phát hiện câu hỏi về lỗ hổng..." }
{ "type": "thinking", "step": 1, "tool": "search_vulnerabilities", "args": {...} }
{ "type": "tool_result", "step": 1, "tool": "search_vulnerabilities", "count": 1 }
...
{ "type": "message", "content": "CVE-2024-38213... 🖥️ THIẾT BỊ: PC-001..." }
```

### Via REST API

```bash
curl -X POST ws://localhost:8002/ws/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "LockBit là gì?"}'

# Nhận:
# intent event → ti_malware
# tool events → search_malware, get_device_matches, correlate_threats
# final event → kết quả phân tích
```

---

## ⚙️ Configuration

**Tất cả settings hardcoded, không cần config:**

| Setting | Giá trị | Mục đích |
|---------|--------|---------|
| CVE weight | 3 | CVE ID dễ xác định, nên ưu tiên cao |
| Hash weight | 2 | Hash cụ thể nhưng ít phổ biến |
| IP weight | 2 | IP có tính device-specific |
| Malware name weight | 3 | Malware name rõ ràng, ưu tiên cao |
| Normal confidence | 0.95 | Rất tin cậy nếu không có TI signal |
| Confidence max | 0.95 | Cap tối đa confidence ở 95% |

---

## 🔍 Troubleshooting

### Intent sai không như mong đợi

**Nguyên nhân thường:**
1. Keyword không nằm trong list → thêm vào list tương ứng
2. Có CVE cùng với keyword device → CVE được ưu tiên (score * 3)
3. Typo trong CVE format → pattern là `CVE-YYYY-NNNNN`, phải chính xác

**Fix:**
- Tìm `_VULN_KEYWORDS` / `_MALWARE_KEYWORDS` / `_DEVICE_KEYWORDS` trong `agents/ai_agent.py`
- Thêm keyword vào set tương ứng
- Restart server

### Agent không gọi expected tools

**Nguyên nhân thường:**
1. Intent detect sai → kiểm tra intent event trước
2. System prompt không clear → check `_build_intent_system_prompt()`
3. Ollama không "hiểu" tool list → thử rephrase câu hỏi

**Debug:**
```python
from agents.ai_agent import _detect_intent
result = _detect_intent("your query here")
print(result)  # xem intent, entities, confidence
```

---

## 📚 See Also

- [UPGRADE_VERIFICATION.md](UPGRADE_VERIFICATION.md) — Advanced features (confidence scoring, semantic search)
- [QUICK_START_NEW_FEATURES.md](QUICK_START_NEW_FEATURES.md) — API examples
- `agents/ai_agent.py` — Implementation details
- `main.py` — WebSocket event handling

---

✅ Intent Detection ready for production use!
