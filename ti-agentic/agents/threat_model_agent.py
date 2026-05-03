"""
Threat Model Agent
- Phân tích chuỗi tấn công theo MITRE ATT&CK cho từng thiết bị
- Xâu chuỗi IOC + Malware + Vulnerability thành attack path
- Dùng Ollama để sinh narrative phân tích chuyên sâu
"""
import json, re
from datetime import datetime


# ══════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING
# ══════════════════════════════════════════════════════════════

# Tactic ID → Tên + màu
TACTICS = {
    "TA0001": ("Initial Access",        "#e53935"),
    "TA0002": ("Execution",             "#e64a19"),
    "TA0003": ("Persistence",           "#f57f17"),
    "TA0004": ("Privilege Escalation",  "#6a1b9a"),
    "TA0005": ("Defense Evasion",       "#283593"),
    "TA0006": ("Credential Access",     "#00695c"),
    "TA0007": ("Discovery",             "#558b2f"),
    "TA0008": ("Lateral Movement",      "#1565c0"),
    "TA0009": ("Collection",            "#37474f"),
    "TA0010": ("Exfiltration",          "#4e342e"),
    "TA0011": ("Command & Control",     "#ad1457"),
    "TA0040": ("Impact",                "#b71c1c"),
}

# Kỹ thuật theo loại IOC
IOC_TECHNIQUE_MAP = {
    "IP":     [("TA0011","T1071","Application Layer Protocol","Kết nối C2 qua giao thức ứng dụng"),
               ("TA0001","T1190","Exploit Public-Facing Application","Khai thác dịch vụ công khai")],
    "Domain": [("TA0011","T1071","Application Layer Protocol","Kết nối C2 qua domain"),
               ("TA0001","T1566","Phishing","Domain dùng trong phishing")],
    "Hash":   [("TA0002","T1204","User Execution","Người dùng thực thi file độc hại"),
               ("TA0005","T1027","Obfuscated Files","File mã hóa/obfuscated"),
               ("TA0003","T1547","Boot/Logon Autostart","Cài persistence qua autostart")],
    "URL":    [("TA0001","T1566","Phishing","URL phishing"),
               ("TA0002","T1204","User Execution","Drive-by download")],
}

# Kỹ thuật theo loại Malware
MAL_TECHNIQUE_MAP = {
    "ransomware":         [("TA0040","T1486","Data Encrypted for Impact","Mã hóa dữ liệu tống tiền"),
                           ("TA0008","T1570","Lateral Tool Transfer","Phát tán sang thiết bị khác"),
                           ("TA0006","T1003","OS Credential Dumping","Đánh cắp credentials")],
    "trojan":             [("TA0003","T1547","Boot Autostart Execution","Cài persistence"),
                           ("TA0011","T1071","Application Layer Protocol","Kết nối C2"),
                           ("TA0009","T1005","Data from Local System","Thu thập dữ liệu")],
    "remote-access-trojan":[("TA0011","T1105","Ingress Tool Transfer","Download thêm công cụ"),
                            ("TA0007","T1082","System Information Discovery","Thu thập thông tin hệ thống"),
                            ("TA0006","T1056","Input Capture","Keylogging")],
    "botnet":             [("TA0011","T1571","Non-Standard Port","Giao tiếp qua port không chuẩn"),
                           ("TA0008","T1021","Remote Services","Di chuyển ngang qua dịch vụ remote"),
                           ("TA0040","T1498","Network Denial of Service","Tham gia DDoS")],
    "post-exploitation":  [("TA0004","T1068","Exploitation for Privilege Escalation","Leo thang đặc quyền"),
                           ("TA0005","T1055","Process Injection","Inject vào tiến trình hợp lệ"),
                           ("TA0006","T1003","OS Credential Dumping","Dump credentials")],
    "dropper":            [("TA0002","T1059","Command/Scripting Interpreter","Thực thi script"),
                           ("TA0003","T1543","Create/Modify System Process","Tạo service độc hại")],
    "keylogger":          [("TA0006","T1056","Input Capture","Ghi lại phím bấm"),
                           ("TA0009","T1113","Screen Capture","Chụp màn hình")],
}

# Kỹ thuật theo loại CVE / phần mềm bị ảnh hưởng
VULN_TECHNIQUE_MAP = {
    "outlook":   [("TA0001","T1566","Phishing","Email attachment khai thác lỗ hổng Outlook"),
                  ("TA0006","T1187","Forced Authentication","Đánh cắp NTLM hash")],
    "windows":   [("TA0004","T1068","Exploit PE","Khai thác lỗ hổng kernel leo thang quyền"),
                  ("TA0005","T1562","Impair Defenses","Vô hiệu hóa bảo vệ")],
    "fortinet":  [("TA0001","T1190","Exploit Public App","Bypass xác thực Fortinet"),
                  ("TA0004","T1078","Valid Accounts","Dùng tài khoản chiếm quyền")],
    "citrix":    [("TA0001","T1550","Use Alternate Auth","Dùng session token bị rò rỉ"),
                  ("TA0005","T1550","Token Impersonation","Giả mạo phiên hợp lệ")],
    "hikvision": [("TA0001","T1190","Exploit Public App","Command injection camera"),
                  ("TA0008","T1021","Remote Services","Dùng camera làm bàn đạp tấn công mạng nội bộ")],
    "veeam":     [("TA0006","T1078","Valid Accounts","Đánh cắp credentials backup"),
                  ("TA0040","T1490","Inhibit System Recovery","Xóa bản sao lưu")],
    "wordpress": [("TA0001","T1190","Exploit Public App","SQL Injection leo thang thành admin"),
                  ("TA0002","T1059","Command Injection","Thực thi lệnh trên máy chủ web")],
    "kerberos":  [("TA0006","T1558","Steal Kerberos Ticket","Pass-the-ticket"),
                  ("TA0004","T1078","Valid Accounts","Leo thang qua Kerberos")],
    "exchange":  [("TA0001","T1566","Phishing","Khai thác Exchange phát tán email độc hại"),
                  ("TA0004","T1068","Exploit PE","Leo thang qua Exchange")],
    "default":   [("TA0001","T1190","Exploit Public App","Khai thác dịch vụ công khai"),
                  ("TA0004","T1068","Privilege Escalation","Leo thang đặc quyền")],
}

# NIST CSF mapping
NIST_MAP = {
    "TA0001": "ID.RA — Risk Assessment / PR.AC — Access Control",
    "TA0002": "PR.DS — Data Security / DE.CM — Security Monitoring",
    "TA0003": "PR.AC — Access Control / DE.AE — Anomaly Detection",
    "TA0004": "PR.AC — Least Privilege / PR.PT — Protective Technology",
    "TA0005": "DE.CM — Continuous Monitoring / PR.DS — Data Security",
    "TA0006": "PR.AC — Identity Management / PR.AT — Awareness Training",
    "TA0007": "DE.CM — Monitoring / PR.DS — Data Security",
    "TA0008": "PR.AC — Network Segmentation / DE.CM — Monitoring",
    "TA0011": "PR.AC — Access Control / DE.CM — Network Monitoring",
    "TA0040": "RC.RP — Recovery Planning / PR.IP — Backup",
}


# ══════════════════════════════════════════════════════════════
# CORE ANALYSIS FUNCTIONS
# ══════════════════════════════════════════════════════════════

def _get_ioc_techniques(ioc: dict) -> list:
    kind = ioc.get("ioc_type","Unknown")
    return IOC_TECHNIQUE_MAP.get(kind, IOC_TECHNIQUE_MAP["IP"])


def _get_mal_techniques(mal: dict) -> list:
    types = [t.lower() for t in (mal.get("malware_types") or [])]
    techs = []
    for t in types:
        for key, val in MAL_TECHNIQUE_MAP.items():
            if key in t:
                techs.extend(val)
    return techs or MAL_TECHNIQUE_MAP["trojan"]


def _get_vuln_techniques(vuln: dict) -> list:
    sw   = (vuln.get("affected_software") or "").lower()
    desc = (vuln.get("description") or "").lower()
    combined = sw + " " + desc
    for key, techs in VULN_TECHNIQUE_MAP.items():
        if key in combined:
            return techs
    return VULN_TECHNIQUE_MAP["default"]


def _calc_risk_score(threats: list) -> int:
    score = 0
    weights = {"critical": 40, "high": 20, "medium": 10, "low": 5}
    for t in threats:
        score += weights.get(t.get("risk_level","low"), 5)
    return min(score, 100)


def _risk_level_from_score(score: int) -> str:
    if score >= 70: return "critical"
    if score >= 40: return "high"
    if score >= 20: return "medium"
    return "low"


def build_attack_phases(device_threats: list) -> list:
    """
    Xây dựng danh sách attack phases từ danh sách threats của một thiết bị.
    Mỗi phase = một MITRE ATT&CK tactic, chứa các techniques liên quan.
    """
    # Collect all techniques
    tactic_tech = {}  # tactic_id -> {name, techniques: []}

    for threat in device_threats:
        mtype = threat.get("match_type","")
        risk  = threat.get("risk_level","low")

        if mtype == "IOC":
            # Tìm IOC gốc trong store để lấy ioc_type
            ioc_type = threat.get("threat_kind","Unknown")
            techs = IOC_TECHNIQUE_MAP.get(ioc_type, IOC_TECHNIQUE_MAP["IP"])
        elif mtype == "Malware":
            # Tạo mal dict tạm
            types_str = threat.get("threat_kind","trojan")
            fake_mal  = {"malware_types": [t.strip() for t in types_str.split(",")]}
            techs     = _get_mal_techniques(fake_mal)
        elif mtype == "Vulnerability":
            # Lấy thông tin từ threat name (CVE) và match_reasons
            fake_vuln = {
                "affected_software": threat.get("match_reasons",""),
                "description":       threat.get("threat_name",""),
            }
            techs = _get_vuln_techniques(fake_vuln)
        else:
            continue

        for tactic_id, tech_id, tech_name, tech_desc in techs:
            if tactic_id not in tactic_tech:
                tname, _ = TACTICS.get(tactic_id, ("Unknown","#888"))
                tactic_tech[tactic_id] = {"tactic_id": tactic_id, "tactic_name": tname,
                                           "techniques": [], "threat_count": 0}
            # Avoid duplicate techniques
            existing = [t["tech_id"] for t in tactic_tech[tactic_id]["techniques"]]
            if tech_id not in existing:
                tactic_tech[tactic_id]["techniques"].append({
                    "tech_id":   tech_id,
                    "tech_name": tech_name,
                    "desc":      tech_desc,
                    "source":    threat.get("threat_name",""),
                    "risk":      risk,
                })
            tactic_tech[tactic_id]["threat_count"] += 1

    # Sort by standard kill-chain order
    order = list(TACTICS.keys())
    phases = sorted(tactic_tech.values(),
                    key=lambda x: order.index(x["tactic_id"]) if x["tactic_id"] in order else 99)
    return phases


def build_attack_chain_text(phases: list, device: dict) -> str:
    """Tạo mô tả chuỗi tấn công dạng text."""
    if not phases:
        return "Chưa đủ dữ liệu để xây dựng chuỗi tấn công."

    steps = []
    for i, p in enumerate(phases, 1):
        techs = ", ".join(f"{t['tech_id']}:{t['tech_name']}" for t in p["techniques"][:2])
        steps.append(f"{i}. [{p['tactic_name']}] {techs}")

    host = device.get("hostname","Thiết bị")
    return (f"Chuỗi tấn công tiềm năng nhắm vào {host}:\n" +
            " → ".join(f"[{p['tactic_name']}]" for p in phases))


def build_mitigations(phases: list, threats: list) -> list:
    """Tạo danh sách biện pháp giảm thiểu theo mức độ ưu tiên."""
    mits = []
    seen = set()

    # Critical threats first
    for t in sorted(threats, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("risk_level","low"),3)):
        risk    = t.get("risk_level","low")
        tname   = t.get("threat_name","")
        mtype   = t.get("match_type","")
        rec     = t.get("recommendation","")

        if tname in seen: continue
        seen.add(tname)

        if mtype == "IOC":
            action = f"Chặn {t.get('threat_kind','IOC')} '{tname}' trên firewall/DNS"
        elif mtype == "Vulnerability":
            action = f"Vá {tname} ngay — {rec}"
        elif mtype == "Malware":
            action = f"Quét và loại bỏ {tname} — {rec[:80]}"
        else:
            action = rec or f"Xử lý {tname}"

        nist = NIST_MAP.get(phases[0]["tactic_id"] if phases else "", "PR.AC")
        mits.append({
            "priority":  {"critical":"P0 — Ngay lập tức","high":"P1 — Trong 24h",
                          "medium":"P2 — Trong 1 tuần","low":"P3 — Theo lịch"}.get(risk,"P3"),
            "risk":      risk,
            "action":    action,
            "nist":      nist,
            "mitre_ref": phases[0]["tactic_id"] if phases else "TA0001",
        })
        if len(mits) >= 8:
            break

    return mits


# ══════════════════════════════════════════════════════════════
# OLLAMA NARRATIVE ANALYSIS
# ══════════════════════════════════════════════════════════════

def _ollama_narrative(device: dict, phases: list, threats: list) -> str:
    """Dùng Ollama sinh phân tích chuyên sâu dạng narrative."""
    try:
        import ollama

        phase_summary = "; ".join(
            f"{p['tactic_name']}({len(p['techniques'])} kỹ thuật)"
            for p in phases[:6]
        )
        threat_summary = "; ".join(
            f"[{t.get('risk_level','?').upper()}] {t.get('threat_name','?')} ({t.get('match_type','?')})"
            for t in threats[:6]
        )

        prompt = f"""Bạn là chuyên gia Red Team và Threat Intelligence. Hãy phân tích chuỗi tấn công sau.

Thiết bị mục tiêu: {device.get('hostname','?')} | IP: {device.get('ip','?')} | Phòng ban: {device.get('dept','?')}

Mối đe dọa xác định: {threat_summary}

Các giai đoạn tấn công MITRE ATT&CK: {phase_summary}

Hãy viết một đoạn phân tích ngắn (4-6 câu, bằng tiếng Việt) bao gồm:
1. Kịch bản tấn công thực tế nhất có thể xảy ra
2. Giai đoạn nguy hiểm nhất trong chuỗi
3. Tác động tiềm năng lên tổ chức
4. Một khuyến nghị ưu tiên hàng đầu

Chỉ trả lời đoạn phân tích, không thêm tiêu đề hay định dạng."""

        resp = ollama.chat(
            model="llama3.2",
            messages=[{"role":"user","content":prompt}],
            options={"temperature": 0.3}
        )
        return resp["message"]["content"]

    except Exception as e:
        # Fallback nếu Ollama không khả dụng
        if not phases:
            return "Không đủ dữ liệu để phân tích."
        first  = phases[0]["tactic_name"]
        last   = phases[-1]["tactic_name"] if len(phases)>1 else phases[0]["tactic_name"]
        crit_n = len([t for t in threats if t.get("risk_level")=="critical"])
        return (
            f"Thiết bị {device.get('hostname','?')} đang đối mặt với {len(threats)} mối đe dọa "
            f"({crit_n} critical), với chuỗi tấn công tiềm năng bắt đầu từ giai đoạn '{first}' "
            f"và có thể dẫn tới '{last}'. "
            f"Với {len(phases)} giai đoạn ATT&CK được xác định, đây là thiết bị cần ưu tiên xử lý. "
            f"Khuyến nghị: vá các lỗ hổng critical và chặn các IOC đã xác định ngay lập tức. "
            f"(Ollama offline — phân tích tự động, không có AI)"
        )


# ══════════════════════════════════════════════════════════════
# MAIN ANALYSIS FUNCTION
# ══════════════════════════════════════════════════════════════

def analyze_device(device_key: str, threats: list, use_ai: bool = True) -> dict:
    """
    Phân tích đầy đủ threat model cho một thiết bị.

    Params:
        device_key: "hostname|ip"
        threats:    danh sách matches thuộc về thiết bị này
        use_ai:     có dùng Ollama để sinh narrative không

    Returns:
        dict đầy đủ thông tin threat model
    """
    parts    = device_key.split("|",1)
    hostname = parts[0] if len(parts)>0 else "Unknown"
    ip       = parts[1] if len(parts)>1 else "N/A"
    dept     = threats[0].get("asset_dept","N/A") if threats else "N/A"
    device   = {"hostname": hostname, "ip": ip, "dept": dept}

    risk_score = _calc_risk_score(threats)
    risk_level = _risk_level_from_score(risk_score)
    phases     = build_attack_phases(threats)
    chain_text = build_attack_chain_text(phases, device)
    mits       = build_mitigations(phases, threats)

    # Categorize threats
    ioc_threats  = [t for t in threats if t.get("match_type")=="IOC"]
    mal_threats  = [t for t in threats if t.get("match_type")=="Malware"]
    vuln_threats = [t for t in threats if t.get("match_type")=="Vulnerability"]

    # Entry points
    entry_points = []
    for t in vuln_threats[:3]:
        entry_points.append(f"{t['threat_name']} — {t.get('match_reasons','')[:60]}")
    for t in ioc_threats[:2]:
        if t.get("risk_level") in ("critical","high"):
            entry_points.append(f"{t['threat_kind']} {t['threat_name']}")

    # Critical path (highest risk chain)
    critical_path = " → ".join(
        p["tactic_name"] for p in phases
        if any(t["risk"] in ("critical","high") for t in p["techniques"])
    ) or "Không xác định"

    # AI narrative
    narrative = ""
    if use_ai:
        narrative = _ollama_narrative(device, phases, threats)

    return {
        "device":         device,
        "risk_score":     risk_score,
        "risk_level":     risk_level,
        "attack_phases":  phases,
        "attack_chain":   chain_text,
        "critical_path":  critical_path,
        "entry_points":   entry_points,
        "mitigations":    mits,
        "narrative":      narrative,
        "threat_counts":  {
            "total":   len(threats),
            "ioc":     len(ioc_threats),
            "malware": len(mal_threats),
            "vuln":    len(vuln_threats),
            "critical":len([t for t in threats if t.get("risk_level")=="critical"]),
            "high":    len([t for t in threats if t.get("risk_level")=="high"]),
        },
        "analyzed_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    }


def analyze_all_devices(matches: list, use_ai: bool = True) -> list:
    """Phân tích threat model cho tất cả thiết bị có trong matches."""
    # Group by device
    groups = {}
    for m in matches:
        key = f"{m.get('asset_hostname','?')}|{m.get('asset_ip','N/A')}"
        if key not in groups:
            groups[key] = []
        groups[key].append(m)

    results = []
    for key, threats in groups.items():
        try:
            result = analyze_device(key, threats, use_ai=use_ai)
            results.append(result)
        except Exception as e:
            print(f"  Lỗi analyze {key}: {e}")

    # Sort by risk_score desc
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    print(f"✅ Threat model hoàn tất: {len(results)} thiết bị")
    return results


