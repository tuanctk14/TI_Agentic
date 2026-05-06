"""
AI Agent Brain — ReAct pattern với Ollama tool calling
Hỗ trợ Threat Intelligence analysis tự động
Bao gồm Intent Detection để phân biệt câu hỏi thường vs TI queries
"""
import json
import ollama
import os
import re as _re
from typing import Generator, Dict, Any, List
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11555")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
MAX_ITERATIONS = 12  # Tăng từ 5 lên 12 để đủ cho multi-step reasoning + tools

ollama.Client(host=OLLAMA_HOST)

# ══════════════════════════════════════════════════════════════
# INTENT DETECTION — Phân loại câu hỏi trước khi chạy agent
# ══════════════════════════════════════════════════════════════

# Pattern nhận diện CVE
_CVE_PATTERN = _re.compile(r'\bCVE-\d{4}-\d{4,7}\b', _re.IGNORECASE)

# Pattern nhận diện IP
_IP_PATTERN = _re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

# Pattern nhận diện hash (MD5/SHA1/SHA256)
_HASH_PATTERN = _re.compile(r'\b[a-fA-F0-9]{32,64}\b')

# Từ khóa TI liên quan lỗ hổng/CVE/IOC — tiếng Việt ưu tiên
_VULN_KEYWORDS = {
    # ── Tiếng Việt ──
    "lỗ hổng", "lỗ hổng bảo mật", "lỗ hổng này", "lỗ hổng đó",
    "cve", "cvss", "khai thác", "bị khai thác", "vá lỗi", "vá ngay",
    "mức độ nguy hiểm", "nguy hiểm không", "nghiêm trọng không",
    "ảnh hưởng gì", "ảnh hưởng đến", "bị dính", "dính lỗ hổng",
    "ioc", "hash", "phishing", "giả mạo", "địa chỉ ip độc",
    "leo thang đặc quyền", "chiếm quyền", "vượt xác thực",
    "chèn lệnh", "thực thi mã", "rce", "sqli", "xss", "injection",
    "poc", "exploit", "zero-day", "zero day", "patch",
    # ── Tiếng Anh ──
    "vulnerability", "vulnerabilities", "high severity", "critical severity",
    "breach", "compromised", "log4j", "log4shell", "eternalblue",
    "spring4shell", "shellshock", "heartbleed", "bluekeep",
    "privilege escalation", "buffer overflow",
}

# Từ khóa TI liên quan malware — tách riêng để detect chính xác hơn
_MALWARE_KEYWORDS = {
    # ── Tiếng Việt ──
    "mã độc", "phần mềm độc hại", "nhiễm mã độc", "bị nhiễm",
    "virus", "diệt virus", "quét virus", "loại bỏ mã độc",
    "ransomware", "mã hóa dữ liệu", "tống tiền", "bị mã hóa",
    "trojan", "backdoor", "cửa hậu", "rootkit",
    "botnet", "worm", "sâu máy tính", "spyware", "keylogger",
    "theo dõi bàn phím", "dropper", "loader", "payload",
    "malware này", "malware đó", "loại malware", "họ malware",
    "phát tán", "lây lan", "lây nhiễm", "lây qua",
    "dọn sạch", "cách ly", "quarantine",
    "c2", "máy chủ điều khiển", "apt", "nhóm hacker",
    "tấn công có chủ đích", "chiến dịch tấn công",
    # ── Tiếng Anh ──
    "malware", "ransomware family", "malware family", "malware sample",
    "rat", "remote access trojan", "infostealer", "banking trojan",
    "cryptominer", "cryptojacking", "adware", "worm",
    "emotet", "lockbit", "blackcat", "plugx", "remcos", "cobalt strike",
    "lateral movement", "persistence", "exfiltration",
    "wannacry", "notpetya", "lazarus",
}

# Từ khóa TI liên quan thiết bị/asset — tiếng Việt ưu tiên
_DEVICE_KEYWORDS = {
    # ── Tiếng Việt (nhóm chính) ──
    "thiết bị", "thiết bị nào", "thiết bị đó", "thiết bị này",
    "máy chủ", "máy tính", "máy nào", "máy đó",
    "đang dính gì", "đang bị gì", "có vấn đề gì",
    "bị ảnh hưởng không", "có lỗ hổng không", "đang có nguy cơ",
    "kiểm tra thiết bị", "phân tích thiết bị", "xem thiết bị",
    "danh sách thiết bị", "liệt kê thiết bị", "thiết bị nguy hiểm",
    "lịch sử thiết bị", "lịch sử alert", "lịch sử nguy cơ",
    "nguy cơ", "rủi ro", "mức rủi ro",
    "địa chỉ ip", "ip này", "ip đó",
    # ── Tiếng Anh (bổ sung) ──
    "device", "which device", "affected device", "device risk",
    "device history", "device alert", "check device",
    "host", "hostname", "asset", "endpoint", "server",
}

# Keyword tổng hợp TI (nếu khớp ít nhất 1 là TI query)
_TI_GENERAL_KEYWORDS = {
    "opencti", "nvd", "nist", "mitre", "att&ck", "ttps",
    "indicator of compromise", "threat intelligence",
    "tình báo mối đe dọa", "phân tích mối đe dọa",
    "security alert", "cảnh báo bảo mật", "matches",
    "so khớp", "matching",
}

# Pattern nhận diện tên malware phổ biến
_MALWARE_NAME_PATTERN = _re.compile(
    r'\b(LockBit|BlackCat|Emotet|PlugX|Remcos|WannaCry|NotPetya|Lazarus|'
    r'CobaltStrike|Mimikatz|Cobalt Strike|REvil|Conti|BlackMatter|'
    r'AsyncRAT|NjRAT|QuasarRAT|AgentTesla|FormBook|RedLine)\b',
    _re.IGNORECASE
)


def _detect_intent(query: str) -> dict:
    """
    Phân tích câu hỏi và trả về intent + extracted entities.

    Returns:
    {
        "intent": "normal" | "ti_vuln" | "ti_malware" | "ti_device" | "ti_general",
        "entities": {
            "cves": [...],
            "ips": [...],
            "hashes": [...],
            "malware_names": [...],
            "device_hints": [],
            "keywords": [],
        },
        "confidence": float
    }
    """
    q_lower = query.lower().strip()

    # Extract entities
    cves    = _CVE_PATTERN.findall(query)
    ips     = _IP_PATTERN.findall(query)
    hashes  = _HASH_PATTERN.findall(query)

    found_vuln_kw    = [kw for kw in _VULN_KEYWORDS    if kw in q_lower]
    found_malware_kw = [kw for kw in _MALWARE_KEYWORDS if kw in q_lower]
    found_device_kw  = [kw for kw in _DEVICE_KEYWORDS  if kw in q_lower]
    found_ti_kw      = [kw for kw in _TI_GENERAL_KEYWORDS if kw in q_lower]

    malware_names = _MALWARE_NAME_PATTERN.findall(query)

    # ── Scoring ──
    score_vuln    = len(cves) * 3 + len(hashes) * 2 + len(found_vuln_kw)
    score_malware = len(malware_names) * 3 + len(found_malware_kw)
    score_device  = len(ips)  * 2 + len(found_device_kw)
    score_ti      = len(found_ti_kw)

    total_ti = score_vuln + score_malware + score_device + score_ti

    # ── Quyết định intent ──
    if total_ti == 0:
        intent     = "normal"
        confidence = 0.95
    elif score_device > max(score_vuln, score_malware):
        intent     = "ti_device"
        confidence = min(0.95, 0.5 + score_device * 0.1)
    elif score_malware > score_vuln:
        intent     = "ti_malware"
        confidence = min(0.95, 0.5 + score_malware * 0.1)
    elif score_vuln > 0 or cves:
        intent     = "ti_vuln"
        confidence = min(0.95, 0.5 + score_vuln * 0.1)
    else:
        intent     = "ti_general"
        confidence = min(0.85, 0.4 + score_ti * 0.15)

    # Extract device hints (hostname/IP patterns)
    device_hints = []
    if intent in ("ti_device", "ti_general", "ti_malware"):
        # Match patterns like SRV-MAIL-01, server01, PC-Finance, etc.
        hostname_pattern = _re.compile(r'\b([A-Z0-9][A-Z0-9\-]{1,}[0-9]{1,})\b')
        candidates = hostname_pattern.findall(query)
        skip = {"THE", "AND", "FOR", "NOT", "THIS", "THAT", "WITH",
                "CVE", "NVD", "IOC", "TI", "APT", "SERVER", "DEVICE"}
        device_hints = [c for c in candidates if c not in skip][:3]

    return {
        "intent": intent,
        "entities": {
            "cves":          [c.upper() for c in cves],
            "ips":           ips,
            "hashes":        hashes,
            "malware_names": [m for m in malware_names],
            "device_hints":  device_hints,
            "keywords":      found_vuln_kw + found_malware_kw + found_device_kw + found_ti_kw,
        },
        "confidence": confidence,
    }


def _should_retry(tool_result: Dict, tool_name: str) -> bool:
    """Check if should retry with different tool based on result."""
    if not tool_result.get("success") and tool_result.get("count", 0) == 0:
        # No results, can retry
        return True
    return False


def _get_retry_tool(original_tool: str) -> str:
    """Suggest next tool to try if current one returned no results."""
    retry_map = {
        "search_iocs": "search_malware",
        "search_malware": "search_vulnerabilities",
        "search_vulnerabilities": None  # No more retries after this
    }
    return retry_map.get(original_tool)


def _build_system_prompt(store: Dict) -> str:
    """Build dynamic system prompt with current database statistics."""
    ioc_count = len(store.get("iocs", []))
    mal_count = len(store.get("malwares", []))
    vuln_count = len(store.get("vulnerabilities", []))
    matches_count = len(store.get("matches", []))

    return f"""Bạn là AI Security Agent chuyên gia về Threat Intelligence. Phân tích mối đe dọa và trả lời theo format chuẩn.

DATABASE STATS:
- IOC: {ioc_count} items
- Malware: {mal_count} items
- Vulnerabilities: {vuln_count} items
- Device Matches: {matches_count} items

TOOLS AVAILABLE:
- search_iocs(query) — Tìm IOC trong database (hashes, domains, IPs, URLs)
- search_malware(query) — Tìm malware
- search_vulnerabilities(query) — Tìm CVE
- get_device_matches(threat_name) — Tìm thiết bị bị ảnh hưởng
- create_alert(severity, threat_name, affected_assets, reason, recommended_action) — Tạo alert
- check_memory(entity_name) — Kiểm tra lịch sử

QUY TRÌNH (BẮT BUỘC):
1. TRY ALL: Tự động gọi search_iocs(query), search_malware(query), search_vulnerabilities(query)
   - Nếu hash/domain/IP → search_iocs
   - Nếu có từ khóa malware → search_malware
   - Nếu có CVE/vuln keyword → search_vulnerabilities
   - Nếu không chắc → gọi TẤT CẢ để tìm
2. Nếu tìm được ≥1 kết quả: get_device_matches(threat_name) để tìm assets
3. create_alert nếu risk >= HIGH
4. Nếu không tìm được gì: NÓI RÕ "không tìm thấy trong database [OpenCTI]"

MANDATORY: KHÔNG ĐƯỢC YÊU CẦU USER SEARCH - PHẢI TỰ ĐỘNG GỌI TOOLS

RESPONSE FORMAT:
🎯 THREAT: [name or "Not Found"]
📊 STATUS: [Found / Not Found in Database]
💡 Details: [type, score, risk_level if found]
🔗 ASSETS: [count or "N/A"]
"""

# Tool definitions
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_iocs",
            "description": "Tìm kiếm IOC (Indicators of Compromise) trong cơ sở dữ liệu. Có thể tìm theo tên, loại (IP, Domain, URL, Hash, Wallet, Yara) hoặc mức độ rủi ro.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Từ khóa tìm kiếm (tên IOC hoặc IP)"
                    },
                    "ioc_type": {
                        "type": "string",
                        "enum": ["IP", "Domain", "URL", "Hash", "Wallet", "Yara"],
                        "description": "Loại IOC (tùy chọn)"
                    },
                    "risk_level": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Mức độ rủi ro (tùy chọn)"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_malware",
            "description": "Tìm kiếm Malware trong cơ sở dữ liệu. Có thể tìm theo tên hoặc loại malware.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Tên hoặc từ khóa tìm kiếm malware"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_vulnerabilities",
            "description": "Tìm kiếm Vulnerability/CVE. Có thể tìm theo CVE ID, tên phần mềm bị ảnh hưởng, hoặc CVSS score.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "CVE ID hoặc tên phần mềm"
                    },
                    "min_cvss": {
                        "type": "number",
                        "description": "CVSS score tối thiểu (0-10)"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_threat_detail",
            "description": "Lấy chi tiết đầy đủ về một threat cụ thể (IOC, Malware, CVE) từ OpenCTI bao gồm mối liên hệ và các container.",
            "parameters": {
                "type": "object",
                "properties": {
                    "threat_id": {
                        "type": "string",
                        "description": "ID hoặc tên của threat"
                    },
                    "threat_type": {
                        "type": "string",
                        "enum": ["Indicator", "Malware", "Vulnerability"],
                        "description": "Loại threat"
                    }
                },
                "required": ["threat_id", "threat_type"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_device_matches",
            "description": "Lấy danh sách tất cả threats (IOC, Malware, CVE) được phát hiện trên một thiết bị cụ thể.",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_name": {
                        "type": "string",
                        "description": "Tên hoặc hostname của thiết bị"
                    },
                    "threat_type": {
                        "type": "string",
                        "enum": ["IOC", "Malware", "Vulnerability"],
                        "description": "Lọc theo loại threat (tùy chọn)"
                    }
                },
                "required": ["device_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_device",
            "description": "Phân tích chuỗi tấn công MITRE ATT&CK cho một thiết bị, giúp hiểu mục đích và kỹ thuật của attacker.",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_name": {
                        "type": "string",
                        "description": "Tên thiết bị"
                    }
                },
                "required": ["device_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "correlate_threats",
            "description": "Tìm mối liên hệ giữa các threats khác nhau (IOC, Malware, CVE) để xác định attack campaign hoặc adversary.",
            "parameters": {
                "type": "object",
                "properties": {
                    "threat_name": {
                        "type": "string",
                        "description": "Tên threat để tìm liên hệ (ví dụ: APT28, tên malware, CVE)"
                    }
                },
                "required": ["threat_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_vulnerability",
            "description": "Fetch chi tiết CVE từ NVD API: CVSS score, attack vector, CWE, affected CPEs, CISA exploit status. Gọi khi CVSS của CVE là 0 hoặc chưa biết.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE ID dạng CVE-YYYY-NNNNN"
                    }
                },
                "required": ["cve_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_memory",
            "description": "Kiểm tra lịch sử điều tra: CVE/IOC/Malware này đã được xử lý trước đây chưa? Asset có từng bị alert không?",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_name": {
                        "type": "string",
                        "description": "Tên threat hoặc asset name"
                    }
                },
                "required": ["entity_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_alert",
            "description": "Tạo alert khi threat cần hành động ngay lập tức. Gọi sau khi đã phân tích đủ thông tin.",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Mức độ nghiêm trọng"
                    },
                    "threat_name": {
                        "type": "string",
                        "description": "Tên threat (CVE-YYYY-NNNNN, malware, IOC, etc)"
                    },
                    "affected_assets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Danh sách hostname/IP của thiết bị bị ảnh hưởng"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Lý do tại sao cần alert (CVSS cao, có exploit, v.v.)"
                    },
                    "recommended_action": {
                        "type": "string",
                        "description": "Hành động khuyến cáo cho admin (vá, cách ly, v.v.)"
                    }
                },
                "required": ["severity", "threat_name", "affected_assets", "reason", "recommended_action"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_investigation",
            "description": "Lưu kết quả điều tra vào bộ nhớ dài hạn. Gọi ở cuối mỗi phiên phân tích.",
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_name": {
                        "type": "string",
                        "description": "Tên threat được điều tra"
                    },
                    "finding": {
                        "type": "string",
                        "description": "Tóm tắt phát hiện (2-3 câu)"
                    },
                    "action_taken": {
                        "type": "string",
                        "enum": ["alert_created", "no_action_needed", "false_positive", "requires_investigation"],
                        "description": "Hành động đã thực hiện"
                    },
                    "affected_assets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Danh sách asset bị ảnh hưởng (có thể rỗng)"
                    }
                },
                "required": ["entity_name", "finding", "action_taken"]
            }
        }
    }
]


def _parse_tool_calls_from_text(response_text: str) -> list:
    """
    Parse tool calls from response text in format: [TOOL: tool_name|param1:value1|param2:value2]
    Returns list of (tool_name, args_dict) tuples.
    Example: [TOOL: search_vulnerabilities|query:CVE-2024-38213] → ("search_vulnerabilities", {"query": "CVE-2024-38213"})
    """
    tool_calls = []
    import re

    # Find all [TOOL: ...] patterns
    pattern = r'\[TOOL:\s*(\w+)\|([^\]]+)\]'
    matches = re.finditer(pattern, response_text)

    for match in matches:
        tool_name = match.group(1)
        params_str = match.group(2)

        # Parse parameters: param1:value1|param2:value2
        args_dict = {}
        param_pairs = params_str.split('|')
        for pair in param_pairs:
            if ':' in pair:
                key, value = pair.split(':', 1)
                args_dict[key.strip()] = value.strip()

        if tool_name and args_dict:
            tool_calls.append((tool_name, args_dict))

    return tool_calls


def _execute_tool(tool_name: str, arguments: Dict[str, Any], store: Dict) -> Dict[str, Any]:
    """Thực thi một tool và trả về kết quả"""

    if tool_name == "search_iocs":
        query = arguments.get("query", "").lower().strip()
        ioc_type = arguments.get("ioc_type", "")
        risk_level = arguments.get("risk_level", "")

        results = []
        for ioc in store.get("iocs", []):
            ioc_name = ioc.get("name", "").lower().strip()
            ioc_pattern = ioc.get("pattern", "").lower().strip()

            # Match by name (substring or exact), pattern, or hash (case-insensitive, partial OK)
            # For hashes: allow partial match if >= 16 chars match
            is_hash_search = len(query) >= 16 and all(c in '0123456789abcdef' for c in query)
            matches_query = (query in ioc_name or
                           query == ioc_name or
                           query in ioc_pattern or
                           query == ioc_pattern or
                           (is_hash_search and len(query) <= len(ioc_name) and query in ioc_name))

            if not matches_query and is_hash_search and ioc.get("ioc_type") == "Hash":
                # Partial hash match: if first 16+ chars match
                if ioc_name.startswith(query[:16]):
                    matches_query = True

            if matches_query:
                if ioc_type and ioc.get("ioc_type") != ioc_type:
                    continue
                if risk_level and ioc.get("risk_level") != risk_level:
                    continue
                results.append({
                    "name": ioc.get("name"),
                    "type": ioc.get("ioc_type"),
                    "score": ioc.get("score", 0),
                    "confidence": ioc.get("confidence", 0),
                    "risk_level": ioc.get("risk_level", "unknown"),
                    "created_at": ioc.get("created_at", "N/A"),
                    "description": (ioc.get("description") or ioc.get("reason") or "N/A")[:150]
                })

        return {
            "success": len(results) > 0,
            "count": len(results),
            "query": query,
            "results": results[:5]  # Giới hạn 5 kết quả
        }

    elif tool_name == "search_malware":
        query = arguments.get("query", "").lower()

        results = []
        for mal in store.get("malwares", []):
            if query in mal.get("name", "").lower() or query == mal.get("name", "").lower():
                results.append({
                    "name": mal.get("name"),
                    "aliases": mal.get("aliases", [])[:3],
                    "malware_types": mal.get("malware_types", [])[:3],
                    "severity": mal.get("severity", "unknown"),
                    "intrusion_sets": (mal.get("intrusion_sets") or [])[:2],
                    "target_countries": (mal.get("target_countries") or [])[:2],
                    "target_sectors": (mal.get("target_sectors") or [])[:2],
                    "created_at": mal.get("created_at", "N/A"),
                    "description": (mal.get("description") or "N/A")[:150]
                })

        return {
            "success": len(results) > 0,
            "count": len(results),
            "query": query,
            "results": results[:3]
        }

    elif tool_name == "search_vulnerabilities":
        query = arguments.get("query", "").lower()
        min_cvss = arguments.get("min_cvss", 0)

        results = []
        for vuln in store.get("vulnerabilities", []):
            cvss = vuln.get("cvss_v3_score") or vuln.get("cvss_score") or 0
            matches_query = (query in vuln.get("name", "").lower() or
                           query in vuln.get("description_en", "").lower() or
                           query == vuln.get("name", "").lower())

            if matches_query and cvss >= min_cvss:
                results.append({
                    "cve": vuln.get("name"),
                    "cvss_score": cvss,
                    "severity": vuln.get("cvss_v3_severity") or vuln.get("severity") or "unknown",
                    "attack_vector": vuln.get("attack_vector", "N/A"),
                    "cisa_exploit": vuln.get("cisa_exploit_add", "N/A"),
                    "weaknesses": (vuln.get("weaknesses") or [])[:2],
                    "published": vuln.get("published", "N/A")[:10],
                    "description": (vuln.get("description_en") or vuln.get("description") or "N/A")[:150]
                })

        return {
            "success": len(results) > 0,
            "count": len(results),
            "query": query,
            "results": results[:3]
        }

    elif tool_name == "get_threat_detail":
        threat_id = arguments.get("threat_id", "")
        threat_type = arguments.get("threat_type", "")

        # Tìm threat từ store
        threat = None
        if threat_type == "Indicator":
            threat = next((i for i in store.get("iocs", []) if i.get("id") == threat_id or i.get("name") == threat_id), None)
        elif threat_type == "Malware":
            threat = next((m for m in store.get("malwares", []) if m.get("id") == threat_id or m.get("name") == threat_id), None)
        elif threat_type == "Vulnerability":
            threat = next((v for v in store.get("vulnerabilities", []) if v.get("id") == threat_id or v.get("name") == threat_id), None)

        if threat:
            return {
                "success": True,
                "data": threat
            }
        else:
            return {
                "success": False,
                "error": f"Không tìm thấy {threat_type} với ID/tên: {threat_id}"
            }

    elif tool_name == "get_device_matches":
        device_name = arguments.get("device_name", "").lower()
        threat_type = arguments.get("threat_type", "")

        results = []
        for match in store.get("matches", []):
            asset_hostname = match.get("asset_hostname", "").lower()
            asset_ip = match.get("asset_ip", "")

            # Match hostname (exact or substring) or IP (exact)
            hostname_match = (device_name == asset_hostname or
                            device_name in asset_hostname or
                            asset_hostname in device_name)
            ip_match = (device_name == asset_ip)

            if hostname_match or ip_match:
                if threat_type and match.get("match_type") != threat_type:
                    continue
                results.append({
                    "threat_type": match.get("match_type"),
                    "threat_name": match.get("threat_name"),
                    "risk_level": match.get("risk_level"),
                    "reason": match.get("match_reasons", "")[:150],
                    "recommendation": match.get("recommendation", "")[:200]
                })

        return {
            "success": True,
            "device": device_name,
            "count": len(results),
            "matches": results
        }

    elif tool_name == "analyze_device":
        device_name = arguments.get("device_name", "")

        # Gọi threat_model_agent để phân tích
        try:
            from agents.threat_model_agent import analyze_device as threat_analyze

            # Lấy matches cho device
            matches = [m for m in store.get("matches", []) if device_name.lower() in m.get("asset_hostname", "").lower()]

            if matches:
                result = threat_analyze(device_name, matches, use_ai=True)
                return {
                    "success": True,
                    "analysis": result
                }
            else:
                return {
                    "success": False,
                    "error": f"Không tìm thấy threats cho thiết bị: {device_name}"
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Lỗi phân tích: {str(e)}"
            }

    elif tool_name == "correlate_threats":
        threat_name = arguments.get("threat_name", "").lower()

        # Tìm threats có liên hệ
        correlations = []

        # Tìm trong IOC
        matching_iocs = [i for i in store.get("iocs", []) if threat_name in i.get("name", "").lower()]

        # Tìm trong Malware
        matching_malware = [m for m in store.get("malwares", []) if threat_name in m.get("name", "").lower()]

        # Tìm trong CVE
        matching_vulns = [v for v in store.get("vulnerabilities", []) if threat_name in v.get("name", "").lower()]

        correlations = {
            "iocs": len(matching_iocs),
            "malware": len(matching_malware),
            "vulnerabilities": len(matching_vulns),
            "ioc_names": [i.get("name") for i in matching_iocs[:3]],
            "malware_names": [m.get("name") for m in matching_malware[:3]],
            "vuln_names": [v.get("name") for v in matching_vulns[:3]]
        }

        return {
            "success": True,
            "query": threat_name,
            "correlations": correlations
        }

    elif tool_name == "enrich_vulnerability":
        from agents.nvd_client import fetch_nvd
        cve_id = arguments.get("cve_id", "").upper()

        # Check cache first
        nvd_cache = store.get("nvd_cache", {})
        if cve_id in nvd_cache:
            return {
                "success": True,
                "source": "cache",
                "data": nvd_cache[cve_id]
            }

        # Fetch từ NVD
        nvd_data = fetch_nvd(cve_id)
        if nvd_data:
            store["nvd_cache"][cve_id] = nvd_data
            return {
                "success": True,
                "source": "nvd_api",
                "data": nvd_data
            }
        else:
            return {
                "success": False,
                "error": f"Không tìm thấy {cve_id} trong NVD hoặc API timeout"
            }

    elif tool_name == "check_memory":
        from agents.memory_agent import load_memory, check_entity, search_past_investigations

        entity_name = arguments.get("entity_name", "")
        memory = store.get("_memory", {})
        if not memory:
            memory = load_memory()
            store["_memory"] = memory

        # Try exact match first
        result = check_entity(entity_name, memory)

        # If not found, try semantic search
        if not result["found"]:
            similar = search_past_investigations(entity_name, memory, top_k=3)
            if similar:
                return {
                    "success": True,
                    "found": False,  # exact match not found
                    "entity": entity_name,
                    "history": None,
                    "similar_investigations": similar  # fallback results
                }

        return {
            "success": True,
            "found": result["found"],
            "entity": result["entity"],
            "history": result.get("history", {})
        }

    elif tool_name == "create_alert":
        from agents.memory_agent import load_memory, record_alert

        severity = arguments.get("severity", "high")
        threat_name = arguments.get("threat_name", "")
        affected_assets = arguments.get("affected_assets", [])
        reason = arguments.get("reason", "")
        recommended_action = arguments.get("recommended_action", "")

        alert = {
            "id": len(store.get("alerts", [])) + 1,
            "timestamp": str(datetime.now()),
            "severity": severity,
            "threat_name": threat_name,
            "affected_assets": affected_assets,
            "reason": reason,
            "recommended_action": recommended_action,
            "status": "created"
        }

        # Add to store
        store.setdefault("alerts", []).append(alert)

        # Record in memory for each asset
        memory = store.get("_memory", {}) or load_memory()
        for asset in affected_assets:
            record_alert(asset, threat_name, severity, memory)
        store["_memory"] = memory

        return {
            "success": True,
            "alert_id": alert["id"],
            "message": f"Alert created: {severity.upper()} {threat_name} — {len(affected_assets)} assets"
        }

    elif tool_name == "save_investigation":
        from agents.memory_agent import load_memory, record_investigation

        entity_name = arguments.get("entity_name", "")
        finding = arguments.get("finding", "")
        action_taken = arguments.get("action_taken", "no_action_needed")
        affected_assets = arguments.get("affected_assets", [])

        memory = store.get("_memory", {}) or load_memory()
        record_investigation(entity_name, finding, action_taken, affected_assets, memory=memory)
        store["_memory"] = memory

        return {
            "success": True,
            "message": f"Investigation saved: {entity_name} — {action_taken}"
        }

    else:
        return {
            "success": False,
            "error": f"Tool không được hỗ trợ: {tool_name}"
        }


def _run_normal_chat(query: str) -> Generator:
    """Flow cho câu hỏi thường — Ollama trả lời trực tiếp, không gọi tool."""
    try:
        response = ollama.chat(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Bạn là AI assistant thông minh, am hiểu về bảo mật thông tin và công nghệ. "
                        "Trả lời bằng tiếng Việt, ngắn gọn và dễ hiểu. "
                        "Nếu user hỏi bằng tiếng Anh thì trả lời tiếng Anh. "
                        "Không đề cập đến database threat intelligence hay tools nội bộ."
                    )
                },
                {"role": "user", "content": query}
            ],
            stream=False
        )
        yield {
            "type": "final",
            "step": 1,
            "content": response.message.content or "Xin lỗi, tôi không thể trả lời câu hỏi này."
        }
    except Exception as e:
        yield {"type": "error", "step": 1, "error": f"Lỗi Ollama: {str(e)}"}


def _build_vuln_query(entities: dict, original_query: str) -> str:
    """Sinh câu hỏi tối ưu cho TI vuln flow dựa trên entities đã extract."""
    if entities["cves"]:
        return f"Phân tích {' và '.join(entities['cves'])}: tìm thông tin, thiết bị bị ảnh hưởng, khuyến nghị xử lý"
    elif entities["hashes"]:
        return f"Tìm IOC hash {entities['hashes'][0]} trong database, xác định mức độ nguy hiểm và thiết bị liên quan"
    elif entities["ips"]:
        return f"Tìm IOC IP {entities['ips'][0]}, kiểm tra có phải C2 hay malicious IP không"
    else:
        return original_query


def _build_malware_query(entities: dict, original_query: str) -> str:
    """Sinh câu hỏi tối ưu cho TI malware flow."""
    if entities.get("malware_names"):
        names = " và ".join(entities["malware_names"][:2])
        return (
            f"Phân tích malware {names}: "
            f"tìm thông tin chi tiết, loại malware, mức độ nguy hiểm, "
            f"thiết bị nào đang bị match/lây nhiễm, lịch sử phát hiện, "
            f"khuyến nghị xử lý và các IOC liên quan"
        )
    elif entities.get("hashes"):
        return f"Tìm và phân tích IOC hash {entities['hashes'][0]}: xác định malware liên quan, thiết bị bị ảnh hưởng"
    else:
        return (
            f"Phân tích yêu cầu về malware: {original_query}. "
            f"Tìm malware liên quan trong database, thiết bị bị match, lịch sử phát hiện"
        )


def _build_device_query(entities: dict, original_query: str) -> str:
    """Sinh câu hỏi tối ưu cho TI device flow."""
    if entities["ips"]:
        return f"Phân tích thiết bị có IP {entities['ips'][0]}: liệt kê tất cả threats đang match, lịch sử alert, mức độ rủi ro"
    elif entities["device_hints"]:
        hint = entities["device_hints"][0]
        return f"Phân tích thiết bị '{hint}': tìm tất cả IOC, CVE, malware đang match, lịch sử nguy cơ, khuyến nghị"
    else:
        return (
            "Liệt kê top thiết bị nguy hiểm nhất hiện tại: "
            "thiết bị có nhiều matches nhất, mức risk cao nhất, "
            "và các lỗ hổng chưa được xử lý"
        )


def _build_intent_system_prompt(intent: str, entities: dict, store: dict) -> str:
    """Sinh system prompt chuyên biệt theo intent."""
    ioc_count   = len(store.get("iocs", []))
    mal_count   = len(store.get("malwares", []))
    vuln_count  = len(store.get("vulnerabilities", []))
    match_count = len(store.get("matches", []))
    last_update = store.get("last_update", "chưa cập nhật")

    db_context = (
        f"DATABASE (cập nhật: {last_update}): "
        f"IOC={ioc_count} | Malware={mal_count} | CVE={vuln_count} | Matches={match_count}"
    )

    if intent == "ti_vuln":
        cve_hint = ""
        if entities.get("cves"):
            cve_hint = f"\nCVE CẦN PHÂN TÍCH: {', '.join(entities['cves'])}"
        if entities.get("hashes"):
            cve_hint += f"\nHASH CẦN KIỂM TRA: {', '.join(entities['hashes'])}"
        if entities.get("ips"):
            cve_hint += f"\nIP CẦN KIỂM TRA: {', '.join(entities['ips'])}"

        return f"""You are a Security Analyst analyzing vulnerability information.
{db_context}{cve_hint}

==== TOOL EXECUTION FORMAT ====
When you need to use a tool, output EXACTLY this format on a new line:
[TOOL: search_vulnerabilities|query:CVE-2024-38213]
[TOOL: enrich_vulnerability|cve_id:CVE-2024-38213]
[TOOL: get_device_matches|threat_name:CVE-2024-38213]
[TOOL: create_alert|severity:HIGH|threat_name:CVE|affected_assets:HOST1,HOST2|reason:...|action:...]

DO NOT start with text analysis. START WITH A TOOL CALL in the format above.

YOUR SEQUENCE:
1. [TOOL: search_vulnerabilities|query:...] to find the CVE
2. [TOOL: enrich_vulnerability|cve_id:...] to get CVSS/severity
3. [TOOL: get_device_matches|threat_name:...] to find affected devices
4. [TOOL: create_alert|...] if severity >= HIGH and devices affected
5. [TOOL: save_investigation|...] to save findings
6. Then output summary in plain text with emoji

RULES:
- FIRST LINE MUST be a [TOOL: ...] call
- NEVER ask user to run tools
- Output format: [TOOL_NAME|param1:value1|param2:value2]
- No markdown, no HTML, plain text only"""

    elif intent == "ti_malware":
        malware_hint = ""
        if entities.get("malware_names"):
            malware_hint = f"\nMALWARE: {', '.join(entities['malware_names'])}"
        if entities.get("hashes"):
            malware_hint += f"\nHASH: {', '.join(entities['hashes'])}"

        return f"""You are a Security Analyst analyzing malware information.
{db_context}{malware_hint}

==== TOOL EXECUTION FORMAT ====
When you need to use a tool, output EXACTLY this format on a new line:
[TOOL: search_malware|query:Emotet]
[TOOL: get_device_matches|threat_name:Emotet]
[TOOL: create_alert|severity:CRITICAL|threat_name:Emotet|affected_assets:HOST1,HOST2|reason:...|action:...]

DO NOT start with text analysis. START WITH A TOOL CALL in the format above.

YOUR SEQUENCE:
1. [TOOL: search_malware|query:...] to find the malware
2. [TOOL: get_device_matches|threat_name:...] to find affected devices
3. [TOOL: create_alert|...] if high-risk and devices affected
4. [TOOL: save_investigation|...] to save findings
5. Then output summary in plain text with emoji

RULES:
- FIRST LINE MUST be a [TOOL: ...] call
- NEVER ask user to run tools
- Output format: [TOOL_NAME|param1:value1|param2:value2]
- No markdown, no HTML, plain text only"""

    elif intent == "ti_device":
        device_hint = ""
        if entities.get("ips"):
            device_hint = f"\nTHIẾT BỊ: IP {', '.join(entities['ips'])}"
        elif entities.get("device_hints"):
            device_hint = f"\nTHIẾT BỊ: {', '.join(entities['device_hints'])}"

        return f"""You are a Security Analyst analyzing device risk and threats.
{db_context}{device_hint}

==== TOOL EXECUTION FORMAT ====
When you need to use a tool, output EXACTLY this format on a new line:
[TOOL: get_device_matches|threat_name:device_name]
[TOOL: search_vulnerabilities|query:CVE-XXXX]
[TOOL: create_alert|severity:HIGH|threat_name:CVE|affected_assets:device_name|reason:...|action:...]

DO NOT start with text analysis. START WITH A TOOL CALL in the format above.

YOUR SEQUENCE:
1. [TOOL: get_device_matches|threat_name:...] to find threats on device
2. [TOOL: check_memory|entity_name:...] to check prior alerts
3. [TOOL: create_alert|...] for each high-risk threat found
4. [TOOL: save_investigation|...] to save findings
5. Then output summary in plain text with emoji

RULES:
- FIRST LINE MUST be a [TOOL: ...] call
- NEVER ask user to run tools
- Output format: [TOOL_NAME|param1:value1|param2:value2]
- No markdown, no HTML, plain text only"""

    else:  # ti_general
        return _build_system_prompt(store)


def run_agent(user_query: str, store: Dict) -> Generator:
    """
    Entry point chính — tự phát hiện intent và chạy flow phù hợp.

    Flow:
      normal   → _run_normal_chat()  (không gọi tool)
      ti_vuln  → ReAct loop với focus vào vuln/IOC analysis
      ti_device → ReAct loop với focus vào device analysis
      ti_general → ReAct loop đầy đủ (behavior hiện tại)
    """
    # Load memory đầu session
    from agents.memory_agent import load_memory
    store["_memory"] = load_memory()

    # ── BƯỚC 1: Detect intent ──
    intent_result = _detect_intent(user_query)
    intent   = intent_result["intent"]
    entities = intent_result["entities"]
    confidence = intent_result["confidence"]

    # Thông báo intent cho frontend
    yield {
        "type": "intent",
        "intent": intent,
        "entities": entities,
        "confidence": confidence
    }

    # ── BƯỚC 2: Normal chat — thoát ngay, không gọi tool ──
    if intent == "normal":
        yield from _run_normal_chat(user_query)
        return

    # ── BƯỚC 3: TI flow — chuẩn bị query và system prompt ──
    if intent == "ti_vuln":
        effective_query = _build_vuln_query(entities, user_query)
        yield {
            "type": "reasoning",
            "step": 0,
            "content": "Phát hiện câu hỏi về lỗ hổng bảo mật. Đang tìm kiếm thông tin..."
        }

    elif intent == "ti_malware":
        effective_query = _build_malware_query(entities, user_query)
        yield {
            "type": "reasoning",
            "step": 0,
            "content": "Phát hiện câu hỏi về mã độc. Đang phân tích malware..."
        }

    elif intent == "ti_device":
        effective_query = _build_device_query(entities, user_query)
        yield {
            "type": "reasoning",
            "step": 0,
            "content": "Phát hiện câu hỏi về thiết bị. Đang phân tích..."
        }

    else:  # ti_general
        effective_query = user_query
        yield {
            "type": "reasoning",
            "step": 0,
            "content": "Đang phân tích yêu cầu..."
        }

    # ── BƯỚC 4: Xây dựng system prompt theo intent ──
    system_prompt = _build_intent_system_prompt(intent, entities, store)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": effective_query}
    ]

    last_tool_name = None
    last_tool_result = None

    iteration = 0
    while iteration < MAX_ITERATIONS:
        iteration += 1

        try:
            # Gọi Ollama với tool calling
            response = ollama.chat(
                model=MODEL,
                messages=messages,
                tools=TOOLS,
                stream=False
            )

            # Extract reasoning từ response content nếu có (optional)
            response_text = response.message.content or ""
            if response_text and ("REASONING:" in response_text.upper() or "Reasoning:" in response_text):
                # Parse reasoning statements (case-insensitive)
                lines = response_text.split("\n")
                for line in lines:
                    if "REASONING:" in line.upper():
                        reasoning = line.split(":", 1)[1].strip() if ":" in line else ""
                        if reasoning and len(reasoning) > 5:
                            yield {
                                "type": "reasoning",
                                "step": iteration,
                                "content": reasoning[:200]  # limit length
                            }

            # Check for tool calls (either structured or in text)
            has_tool_calls = hasattr(response.message, 'tool_calls') and response.message.tool_calls

            # If no structured tool_calls, try to parse from response text
            parsed_tool_calls = []
            if not has_tool_calls and response_text:
                parsed_tool_calls = _parse_tool_calls_from_text(response_text)
                if parsed_tool_calls:
                    print(f"[DEBUG] Parsed {len(parsed_tool_calls)} tool calls from response text")
                    has_tool_calls = True  # Treat parsed calls as tool calls

            if not has_tool_calls and response_text:
                # Agent generated text without tool calls — log it for debugging
                print(f"[DEBUG] Iteration {iteration}, Intent: {intent}, NO tool_calls. Text: {response_text[:150]}")

            # Kiểm tra nếu agent muốn gọi tool (structured or parsed)
            if has_tool_calls:
                # Agent muốn gọi tool
                # Use either structured tool_calls or parsed tool_calls
                tool_calls_to_process = response.message.tool_calls if not parsed_tool_calls else []

                # If we have parsed tool calls, convert them to a format compatible with processing
                if parsed_tool_calls:
                    for tool_name, tool_args in parsed_tool_calls:
                        yield {
                            "type": "tool_use",
                            "step": iteration,
                            "tool": tool_name,
                            "args": tool_args
                        }

                        # Thực thi tool
                        try:
                            result = _execute_tool(tool_name, tool_args, store)

                            # Track for self-correction
                            last_tool_name = tool_name
                            last_tool_result = result

                            # Self-correction: if search tool returned no results, suggest next tool
                            if tool_name in ["search_iocs", "search_malware", "search_vulnerabilities"]:
                                if _should_retry(result, tool_name):
                                    retry_tool = _get_retry_tool(tool_name)
                                    if retry_tool:
                                        result["_self_correction"] = f"No results, try {retry_tool} instead"
                                        yield {
                                            "type": "self_correction",
                                            "step": iteration,
                                            "original_tool": tool_name,
                                            "suggestion": f"No results with {tool_name}, suggesting {retry_tool}"
                                        }

                            messages.append({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": []
                            })
                            messages.append({
                                "role": "tool",
                                "content": json.dumps(result, ensure_ascii=False)
                            })

                            yield {
                                "type": "tool_result",
                                "step": iteration,
                                "tool": tool_name,
                                "result": result
                            }
                        except Exception as e:
                            yield {
                                "type": "tool_error",
                                "step": iteration,
                                "tool": tool_name,
                                "error": str(e)
                            }
                    # After processing parsed calls, continue to next iteration
                    continue

                # Process structured tool calls
                for tool_call in tool_calls_to_process:
                    tool_name = tool_call.function.name
                    tool_args = tool_call.function.arguments

                    # Báo client đang gọi tool
                    yield {
                        "type": "tool_use",
                        "step": iteration,
                        "tool": tool_name,
                        "args": tool_args
                    }

                    # Validate tool arguments trước khi execute
                    if tool_name == "search_iocs" and "risk_level" in tool_args:
                        if tool_args["risk_level"] not in ["critical", "high", "medium", "low", ""]:
                            tool_args.pop("risk_level")  # Remove invalid risk_level
                    if tool_name == "search_iocs" and "ioc_type" in tool_args:
                        if tool_args["ioc_type"] not in ["IP", "Domain", "URL", "Hash", "Wallet", "Yara", ""]:
                            tool_args.pop("ioc_type")  # Remove invalid ioc_type

                    # Thực thi tool
                    try:
                        result = _execute_tool(tool_name, tool_args, store)

                        # Track for self-correction
                        last_tool_name = tool_name
                        last_tool_result = result

                        # Thêm kết quả vào messages
                        messages.append({
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [tool_call]
                        })

                        # Self-correction: if search tool returned no results, suggest next tool
                        if tool_name in ["search_iocs", "search_malware", "search_vulnerabilities"]:
                            if _should_retry(result, tool_name):
                                retry_tool = _get_retry_tool(tool_name)
                                if retry_tool:
                                    result["_self_correction"] = f"No results, try {retry_tool} instead"
                                    yield {
                                        "type": "self_correction",
                                        "step": iteration,
                                        "original_tool": tool_name,
                                        "suggestion": f"No results with {tool_name}, suggesting {retry_tool}"
                                    }

                        messages.append({
                            "role": "tool",
                            "content": json.dumps(result, ensure_ascii=False)
                        })

                        # Báo client kết quả — với special handling cho alert và memory
                        if tool_name == "create_alert" and result.get("success"):
                            yield {
                                "type": "alert",
                                "severity": tool_args.get("severity", "high"),
                                "threat": tool_args.get("threat_name", ""),
                                "assets": tool_args.get("affected_assets", []),
                                "message": result.get("message", "")
                            }
                        elif tool_name == "check_memory" and result.get("found"):
                            yield {
                                "type": "memory_recall",
                                "entity": tool_args.get("entity_name", ""),
                                "history": result.get("history", {})
                            }
                        else:
                            yield {
                                "type": "tool_result",
                                "step": iteration,
                                "tool": tool_name,
                                "result": result
                            }
                    except Exception as e:
                        yield {
                            "type": "tool_error",
                            "step": iteration,
                            "tool": tool_name,
                            "error": str(e)
                        }
            else:
                # Agent không gọi tool, chỉ generate text
                # AUTO-TRIGGER: Nếu là TI query và iteration <= 2 → BUỘC gọi search tools thay vì trả response
                should_auto_trigger = (iteration <= 2 and intent != "normal" and
                                     intent in ["ti_vuln", "ti_malware", "ti_device", "ti_general"])

                if should_auto_trigger:
                    # Auto-trigger search based on intent — DON'T show agent's text response
                    auto_tool = None
                    auto_query = effective_query

                    # Detect IOC/hash/IP/CVE in query
                    has_hash = len(entities.get("hashes", [])) > 0 or _HASH_PATTERN.search(user_query)
                    has_ip = len(entities.get("ips", [])) > 0
                    has_cve = len(entities.get("cves", [])) > 0
                    has_malware = len(entities.get("malware_names", [])) > 0

                    # Choose tool based on what was found
                    if has_cve:
                        auto_tool = "search_vulnerabilities"
                    elif has_malware:
                        auto_tool = "search_malware"
                    elif has_hash or has_ip:
                        auto_tool = "search_iocs"
                    elif intent == "ti_vuln":
                        auto_tool = "search_vulnerabilities"
                    elif intent == "ti_malware":
                        auto_tool = "search_malware"
                    elif intent in ["ti_device", "ti_general"]:
                        # Default for general: try search_iocs (covers hash/IP/domain)
                        auto_tool = "search_iocs"

                    if auto_tool:
                        # Force tool call without showing agent's text response
                        result = _execute_tool(auto_tool, {"query": auto_query}, store)

                        # Add to message history so agent can process
                        messages.append({
                            "role": "assistant",
                            "content": "",  # Empty content, tool call only
                            "tool_calls": []
                        })
                        messages.append({
                            "role": "tool",
                            "content": json.dumps(result, ensure_ascii=False)
                        })

                        yield {
                            "type": "tool_result",
                            "step": iteration,
                            "tool": auto_tool,
                            "result": result
                        }
                        # Continue loop to let agent process result
                        continue

                # If agent still doesn't call tools after 2 iterations, return final response
                # Only return text responses on iteration > 1 or for non-TI queries
                final_response = response.message.content
                yield {
                    "type": "final",
                    "step": iteration,
                    "content": final_response
                }
                break

        except Exception as e:
            yield {
                "type": "error",
                "step": iteration,
                "error": f"Lỗi gọi Ollama: {str(e)}"
            }
            break
