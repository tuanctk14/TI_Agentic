"""
AI Agent Brain — ReAct pattern với Ollama tool calling
Hỗ trợ Threat Intelligence analysis tự động
"""
import json
import ollama
import os
from typing import Generator, Dict, Any, List
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
MAX_ITERATIONS = 12  # Tăng từ 5 lên 12 để đủ cho multi-step reasoning + tools

ollama.Client(host=OLLAMA_HOST)

# System prompt cho Agent với enforced reasoning và quy trình 7 bước
SYSTEM_PROMPT = """Bạn là AI Security Agent chuyên gia về Threat Intelligence. Phân tích mối đe dọa và trả lời theo format chuẩn.

TOOLS AVAILABLE:
- search_iocs(query) — Tìm IOC trong database (hashes, domains, IPs, URLs)
- search_malware(query) — Tìm malware
- search_vulnerabilities(query) — Tìm CVE
- get_device_matches(threat_name) — Tìm thiết bị bị ảnh hưởng
- create_alert(severity, threat_name, affected_assets, reason, recommended_action) — Tạo alert
- check_memory(entity_name) — Kiểm tra lịch sử

QUY TRÌNH (BẮT BUỘC):
1. search_iocs(query) HOẶC search_malware(query) HOẶC search_vulnerabilities(query)
2. Nếu tìm được: get_device_matches(threat_name) để tìm assets
3. Quyết định: alert nếu (found AND risk_high) OR (exploit in wild)
4. Nếu alert: create_alert(...)

OUTPUT FORMAT (BẮT BUỘC SAU MỗI TRẢ LỜI):

🎯 THREAT NAME: [tên mối đe dọa từ search result]
📊 DECISION: [Alert / No Alert]
💡 REASON: [giải thích ngắn 1-2 câu]
🔗 AFFECTED ASSETS: [số lượng hoặc "N/A"]

RULES:
- Luôn gọi search_* trước
- Nếu tìm được kết quả: hiển thị chi tiết từ result (type, score, description)
- Nếu NOT found: nói rõ "IOC/CVE không tìm thấy trong database"
- KHÔNG bao giờ bỏ qua search result - phải hiển thị dữ liệu tìm được
- Response tối đa 200 ký tự (ngoài format trên)
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


def _execute_tool(tool_name: str, arguments: Dict[str, Any], store: Dict) -> Dict[str, Any]:
    """Thực thi một tool và trả về kết quả"""

    if tool_name == "search_iocs":
        query = arguments.get("query", "").lower()
        ioc_type = arguments.get("ioc_type", "")
        risk_level = arguments.get("risk_level", "")

        results = []
        for ioc in store.get("iocs", []):
            # Match by name, pattern, or exact hash
            matches_query = (query in ioc.get("name", "").lower() or
                           query in ioc.get("pattern", "").lower() or
                           query == ioc.get("name", "").lower())

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
            if device_name in match.get("asset_hostname", "").lower() or device_name in match.get("asset_ip", ""):
                if threat_type and match.get("match_type") != threat_type:
                    continue
                results.append({
                    "threat_type": match.get("match_type"),
                    "threat_name": match.get("threat_name"),
                    "risk_level": match.get("risk_level"),
                    "reason": match.get("match_reasons", "")[:100],
                    "recommendation": match.get("recommendation", "")[:100]
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
        from agents.memory_agent import load_memory, check_entity

        entity_name = arguments.get("entity_name", "")
        memory = store.get("_memory", {})
        if not memory:
            memory = load_memory()
            store["_memory"] = memory

        result = check_entity(entity_name, memory)
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


def run_agent(user_query: str, store: Dict) -> Generator:
    """
    ReAct loop: Reasoning → Acting → Observing
    Gửi từng bước về WebSocket
    Load memory đầu session để agent có context lâu dài
    """
    # Load memory ngay đầu session
    from agents.memory_agent import load_memory
    store["_memory"] = load_memory()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_query}
    ]

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

            # Kiểm tra nếu agent muốn gọi tool
            if hasattr(response.message, 'tool_calls') and response.message.tool_calls:
                # Agent muốn gọi tool
                for tool_call in response.message.tool_calls:
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

                        # Thêm kết quả vào messages
                        messages.append({
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [tool_call]
                        })
                        messages.append({
                            "role": "tool",
                            "content": json.dumps(result, ensure_ascii=False)
                        })

                        # Báo client kết quả
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
                # Agent có câu trả lời cuối
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
