"""
Normalization Agent - Chuẩn hóa và phân loại dữ liệu mới từ OpenCTI
"""
from datetime import datetime

def normalize_vulnerability(vuln: dict) -> dict:
    """Chuẩn hóa CVE từ OpenCTI"""
    return {
        "id": vuln.get("id", ""),
        "name": vuln.get("name", "").upper(),  # CVE-YYYY-XXXXX
        "description": vuln.get("description", ""),
        "cvss_score": vuln.get("cvss_score") or 0,
        "severity": _determine_severity(vuln.get("cvss_score", 0)),
        "affected_software": vuln.get("affected_software", ""),
        "patch_available": vuln.get("patch_available", False),
        "exploit_in_wild": vuln.get("exploit_in_wild", False),
        "affected_versions": vuln.get("affected_versions", []),
        "labels": vuln.get("labels", []),
        "created_at": vuln.get("created_at", ""),
        "status": "new" if _is_recent(vuln.get("created_at", "")) else "existing"
    }

def normalize_ioc(ioc: dict) -> dict:
    """Chuẩn hóa IOC từ OpenCTI"""
    return {
        "id": ioc.get("id", ""),
        "name": ioc.get("name", ""),
        "pattern": ioc.get("pattern", ""),
        "type": ioc.get("type", []),
        "ioc_type": ioc.get("ioc_type", ""),  # Keep original ioc_type if exists
        "confidence": ioc.get("confidence") or ioc.get("confidence", 50),
        "score": ioc.get("score") or ioc.get("x_opencti_score", 50),
        "description": ioc.get("description", ""),
        "reason": ioc.get("reason", ""),
        "risk_level": ioc.get("risk_level") or _determine_ioc_risk(ioc.get("score") or ioc.get("x_opencti_score", 50), ioc.get("confidence", 50)),
        "is_false_positive": ioc.get("is_false_positive", False),
        "valid_from": ioc.get("valid_from", ""),
        "valid_until": ioc.get("valid_until", ""),
        "created_at": ioc.get("created_at", ""),
        "labels": ioc.get("labels", []),
        "status": "new" if _is_recent(ioc.get("created_at", "")) else "existing"
    }

def normalize_malware(mal: dict) -> dict:
    """Chuẩn hóa Malware từ OpenCTI"""
    return {
        "id": mal.get("id", ""),
        "name": mal.get("name", ""),
        "aliases": mal.get("aliases", []),
        "malware_types": mal.get("malware_types", []),
        "first_seen": mal.get("first_seen", ""),
        "last_seen": mal.get("last_seen", ""),
        "confidence": mal.get("confidence", 50),
        "description": mal.get("description", ""),
        "severity": mal.get("severity") or _determine_malware_severity(mal.get("malware_types", [])),
        "created_at": mal.get("created_at", ""),
        "created": mal.get("created", ""),
        "modified": mal.get("modified", ""),
        "updated_at": mal.get("updated_at", ""),
        "intrusion_sets": mal.get("intrusion_sets", []),
        "target_countries": mal.get("target_countries", []),
        "target_sectors": mal.get("target_sectors", []),
        "labels": mal.get("labels", []),
        "status": "new" if _is_recent(mal.get("created_at", "")) else "existing"
    }

def _determine_severity(cvss_score: float) -> str:
    """Xác định mức độ nguy hiểm dựa trên CVSS"""
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    elif cvss_score > 0:
        return "low"
    return "unknown"

def _determine_ioc_risk(score: float, confidence: float) -> str:
    """Xác định mức risk của IOC"""
    combined = (score + confidence) / 2
    if combined >= 80:
        return "critical"
    elif combined >= 65:
        return "high"
    elif combined >= 50:
        return "medium"
    else:
        return "low"

def _determine_malware_severity(malware_types: list) -> str:
    """Xác định mức độ của Malware dựa trên loại"""
    critical_types = ["Banking Trojan", "Ransomware", "Spyware", "Rootkit"]
    high_types = ["Botnet", "Worm", "Trojan", "Backdoor"]

    for m_type in malware_types:
        if any(ct in m_type for ct in critical_types):
            return "critical"
        elif any(ht in m_type for ht in high_types):
            return "high"

    return "medium"

def _is_recent(created_at: str, days: int = 30) -> bool:
    """Kiểm tra dữ liệu có phải mới không (30 ngày gần đây)"""
    if not created_at:
        return False
    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        now = datetime.now(created.tzinfo) if created.tzinfo else datetime.now()
        return (now - created).days <= days
    except:
        return False

def normalize_batch(data: dict) -> dict:
    """Chuẩn hóa toàn bộ dữ liệu mới từ fetch_all()"""
    return {
        "iocs": [normalize_ioc(i) for i in data.get("iocs", [])],
        "malwares": [normalize_malware(m) for m in data.get("malwares", [])],
        "vulnerabilities": [normalize_vulnerability(v) for v in data.get("vulnerabilities", [])],
        "source": data.get("source", ""),
        "fetched_at": data.get("fetched_at", "")
    }

def get_new_items(normalized_data: dict, old_data: dict = None) -> dict:
    """Lấy các item mới so với dữ liệu cũ"""
    if not old_data:
        return normalized_data

    old_ioc_ids = {i["id"] for i in old_data.get("iocs", [])}
    old_mal_ids = {m["id"] for m in old_data.get("malwares", [])}
    old_vuln_ids = {v["id"] for v in old_data.get("vulnerabilities", [])}

    return {
        "iocs": [i for i in normalized_data.get("iocs", []) if i["id"] not in old_ioc_ids],
        "malwares": [m for m in normalized_data.get("malwares", []) if m["id"] not in old_mal_ids],
        "vulnerabilities": [v for v in normalized_data.get("vulnerabilities", []) if v["id"] not in old_vuln_ids],
        "source": normalized_data.get("source", ""),
        "fetched_at": normalized_data.get("fetched_at", "")
    }
