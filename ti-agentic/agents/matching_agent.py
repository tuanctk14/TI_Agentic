import pandas as pd, re
from pathlib import Path


def load_assets(path: str = "assets/devices.xlsx") -> dict:
    if not Path(path).exists():
        print(f"⚠️  Không tìm thấy {path}")
        return {}
    try:
        xls = pd.read_excel(path, sheet_name=None)
        print(f"✅ Đọc {path}: sheets={list(xls.keys())}")
        return xls
    except Exception as e:
        print(f"❌ Lỗi đọc Excel: {e}")
        return {}


def _norm(val) -> str:
    return str(val).lower().strip() if pd.notna(val) else ""


def match_iocs(iocs: list, sheets: dict) -> list:
    if not sheets or "Devices" not in sheets:
        return []
    devices = sheets["Devices"]
    results = []
    for ioc in iocs:
        if ioc.get("is_false_positive"):
            continue
        ioc_name    = ioc.get("name","").lower()
        ioc_pattern = ioc.get("pattern","").lower()
        for _, row in devices.iterrows():
            reasons = []
            ip   = _norm(row.get("ip",""))
            host = _norm(row.get("hostname",""))
            apps = _norm(row.get("applications",""))
            svcs = _norm(row.get("services",""))
            if ip and (ip == ioc_name or ip in ioc_pattern):
                reasons.append(f"IP trùng: {row.get('ip')}")
            if host and host in ioc_name:
                reasons.append(f"Hostname: {row.get('hostname')}")
            for kw in ["wordpress","exchange","outlook","fortinet","hikvision","veeam","citrix","nginx","apache"]:
                if kw in apps and kw in ioc_name:
                    reasons.append(f"Ứng dụng: {kw}")
            if reasons:
                results.append({
                    "match_type":    "IOC",
                    "threat_id":     ioc["id"],
                    "threat_name":   ioc["name"],
                    "threat_kind":   ioc.get("ioc_type","?"),
                    "risk_level":    ioc.get("risk_level","unknown"),
                    "asset_hostname":str(row.get("hostname","N/A")),
                    "asset_ip":      str(row.get("ip","N/A")),
                    "asset_dept":    str(row.get("department","N/A")),
                    "asset_user":    str(row.get("assigned_user","N/A")),
                    "match_reasons": " | ".join(reasons),
                    "recommendation":_rec_ioc(ioc),
                })
    return results


def match_vulnerabilities(vulns: list, sheets: dict) -> list:
    if not sheets:
        return []
    sw  = sheets.get("InstalledSoftware", pd.DataFrame())
    dev = sheets.get("Devices", pd.DataFrame())
    results = []
    for vuln in vulns:
        cve     = vuln.get("name","")
        aff_sw  = vuln.get("affected_software","").lower()
        if sw.empty:
            continue
        for _, row in sw.iterrows():
            sw_name = _norm(row.get("software_name",""))
            ex_cve  = _norm(row.get("vulnerability_cve",""))
            name_hit = aff_sw and any(kw in sw_name for kw in aff_sw.split())
            cve_hit  = cve.lower() in ex_cve
            if not (name_hit or cve_hit):
                continue
            host = str(row.get("hostname","N/A"))
            ip   = "N/A"
            if not dev.empty:
                mr = dev[dev["hostname"] == host]
                if not mr.empty:
                    ip = str(mr.iloc[0].get("ip","N/A"))
            results.append({
                "match_type":    "Vulnerability",
                "threat_id":     vuln["id"],
                "threat_name":   cve,
                "threat_kind":   "CVE",
                "risk_level":    vuln.get("severity","unknown"),
                "asset_hostname":host,
                "asset_ip":      ip,
                "asset_dept":    "N/A",
                "asset_user":    "N/A",
                "match_reasons": f"{row.get('software_name')} {row.get('version','')} | {cve}",
                "recommendation":_rec_vuln(vuln),
            })
    seen, out = set(), []
    for r in results:
        k = (r["threat_name"], r["asset_hostname"])
        if k not in seen:
            seen.add(k); out.append(r)
    return out


def match_malware(malwares: list, sheets: dict) -> list:
    if not sheets:
        return []
    sw = sheets.get("InstalledSoftware", pd.DataFrame())
    dev = sheets.get("Devices", pd.DataFrame())
    results = []
    kw_map = {
        "lockbit":      ["fortinet","citrix","windows server"],
        "emotet":       ["outlook","exchange","microsoft office"],
        "plugx":        ["outlook","exchange"],
        "cobalt strike":["windows","iis"],
        "blackcat":     ["windows server","vmware"],
        "remcos":       ["microsoft office","excel","word"],
    }
    for mal in malwares:
        mal_lc = mal.get("name","").lower()
        kws = next((v for k,v in kw_map.items() if k in mal_lc), [])
        if not kws or sw.empty:
            continue
        for _, row in sw.iterrows():
            sw_nm = _norm(row.get("software_name",""))
            if not any(k in sw_nm for k in kws):
                continue
            host = str(row.get("hostname","N/A"))
            ip   = "N/A"
            if not dev.empty:
                mr = dev[dev["hostname"] == host]
                if not mr.empty:
                    ip = str(mr.iloc[0].get("ip","N/A"))
            results.append({
                "match_type":    "Malware",
                "threat_id":     mal["id"],
                "threat_name":   mal["name"],
                "threat_kind":   ", ".join(mal.get("malware_types",[])),
                "risk_level":    mal.get("severity","high"),
                "asset_hostname":host,
                "asset_ip":      ip,
                "asset_dept":    "N/A",
                "asset_user":    "N/A",
                "match_reasons": f"Phần mềm dễ bị tấn công: {row.get('software_name')} | Malware: {mal['name']}",
                "recommendation":f"Kiểm tra dấu hiệu lây nhiễm {mal['name']}. {mal.get('description','')[:100]}",
            })
    return results


def run_all_matching(ti_data: dict, excel_path: str = "assets/devices.xlsx") -> list:
    sheets = load_assets(excel_path)
    if not sheets:
        return []
    all_m  = []
    all_m += match_iocs(ti_data.get("iocs",[]), sheets)
    all_m += match_vulnerabilities(ti_data.get("vulnerabilities",[]), sheets)
    all_m += match_malware(ti_data.get("malwares",[]), sheets)
    order  = {"critical":0,"high":1,"medium":2,"low":3,"unknown":4}
    all_m.sort(key=lambda x: order.get(x.get("risk_level","unknown"),4))
    print(f"✅ {len(all_m)} kết quả so khớp thiết bị")
    return all_m


def _rec_ioc(ioc):
    t, r = ioc.get("ioc_type",""), ioc.get("risk_level","")
    if t == "IP" and r in ("critical","high"):
        return "Chặn IP trên firewall ngay, kiểm tra log kết nối"
    if t == "Domain":
        return "Thêm vào DNS blacklist, kiểm tra proxy log"
    if t == "Hash":
        return "Quét toàn hệ thống tìm file có hash này, cách ly nếu thấy"
    return "Điều tra và giám sát thiết bị"


def _rec_vuln(vuln):
    p = "Có" if vuln.get("patch_available") else "Chưa có"
    e = "đang bị khai thác" if vuln.get("exploit_in_wild") else "chưa ghi nhận khai thác"
    return f"Patch: {p}. Exploit: {e}. CVSS: {vuln.get('cvss_score','?')}"
