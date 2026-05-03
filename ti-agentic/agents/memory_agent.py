"""
Memory Agent — Long-term memory storage cho agent
Lưu lịch sử điều tra, alert, threats đã biết vào file JSON
"""
import json
from pathlib import Path
from datetime import datetime

MEMORY_FILE = Path("data/agent_memory.json")

def load_memory() -> dict:
    """Load memory từ file. Trả về dict rỗng nếu chưa có."""
    if MEMORY_FILE.exists():
        try:
            return json.loads(MEMORY_FILE.read_text(encoding='utf-8'))
        except Exception as e:
            print(f"  Memory load error: {e}")
            return _default_memory()
    return _default_memory()

def _default_memory() -> dict:
    """Default empty memory structure"""
    return {
        "investigations": {},      # CVE/IOC/Malware → {first_seen, last_seen, action_taken, ...}
        "alerted_assets": {},      # Asset hostname → {last_alert, alert_count, threats}
        "known_threats": {},       # Threat name → {first_seen, severity, handled}
        "metadata": {
            "version": "1.0",
            "created": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat()
        }
    }

def save_memory(memory: dict) -> None:
    """Save memory to file."""
    try:
        memory["metadata"]["last_updated"] = datetime.now().isoformat()
        MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        MEMORY_FILE.write_text(json.dumps(memory, ensure_ascii=False, indent=2), encoding='utf-8')
    except Exception as e:
        print(f"  Memory save error: {e}")

def check_entity(entity_name: str, memory: dict) -> dict:
    """
    Check if entity (CVE, IOC, Malware, or Asset) exists in memory.

    Returns:
        {
            "found": bool,
            "type": "investigation|asset|threat",
            "history": {...}  # the actual memory record if found
        }
    """
    entity_name_lower = entity_name.lower()

    # Check investigations (CVE, IOC, Malware)
    for name, record in memory.get("investigations", {}).items():
        if name.lower() == entity_name_lower:
            return {
                "found": True,
                "type": "investigation",
                "entity": name,
                "history": record
            }

    # Check alerted assets
    for name, record in memory.get("alerted_assets", {}).items():
        if name.lower() == entity_name_lower:
            return {
                "found": True,
                "type": "asset",
                "entity": name,
                "history": record
            }

    # Check known threats
    for name, record in memory.get("known_threats", {}).items():
        if name.lower() == entity_name_lower:
            return {
                "found": True,
                "type": "threat",
                "entity": name,
                "history": record
            }

    return {
        "found": False,
        "type": None,
        "entity": entity_name,
        "history": None
    }

def record_investigation(entity_name: str, finding: str, action_taken: str,
                        affected_assets: list = None, cvss: float = None,
                        memory: dict = None) -> None:
    """
    Record an investigation result in memory.

    Args:
        entity_name: CVE-YYYY-NNNNN, IOC name, or Malware name
        finding: short description of what was found
        action_taken: "alert_created", "no_action_needed", "false_positive", etc.
        affected_assets: list of asset names affected by this threat
        cvss: CVSS score if available
        memory: the memory dict (will load if None)
    """
    if memory is None:
        memory = load_memory()

    if entity_name not in memory["investigations"]:
        memory["investigations"][entity_name] = {
            "first_seen": datetime.now().isoformat(),
            "times_investigated": 0,
            "actions": []
        }

    record = memory["investigations"][entity_name]
    record["last_seen"] = datetime.now().isoformat()
    record["times_investigated"] = record.get("times_investigated", 0) + 1
    record["action_taken"] = action_taken
    record["affected_assets"] = affected_assets or []
    if cvss is not None:
        record["cvss"] = cvss

    # Add to actions history
    if "actions" not in record:
        record["actions"] = []
    record["actions"].append({
        "timestamp": datetime.now().isoformat(),
        "finding": finding,
        "action": action_taken
    })

    save_memory(memory)

def record_alert(asset_hostname: str, threat_name: str, severity: str,
                memory: dict = None) -> None:
    """
    Record an alert for an asset.

    Args:
        asset_hostname: hostname or IP of the affected asset
        threat_name: CVE-YYYY-NNNNN, Malware name, IOC name, etc.
        severity: "critical", "high", "medium", "low"
        memory: the memory dict (will load if None)
    """
    if memory is None:
        memory = load_memory()

    if asset_hostname not in memory["alerted_assets"]:
        memory["alerted_assets"][asset_hostname] = {
            "threats": [],
            "alert_count": 0
        }

    asset_record = memory["alerted_assets"][asset_hostname]
    asset_record["last_alert"] = datetime.now().isoformat()
    asset_record["alert_count"] = asset_record.get("alert_count", 0) + 1
    asset_record["severity"] = severity

    if threat_name not in asset_record.get("threats", []):
        if "threats" not in asset_record:
            asset_record["threats"] = []
        asset_record["threats"].append(threat_name)

    save_memory(memory)

def record_threat(threat_name: str, severity: str, threat_type: str,
                 memory: dict = None) -> None:
    """
    Record a known threat in memory.

    Args:
        threat_name: CVE, Malware name, IOC name, etc.
        severity: "critical", "high", "medium", "low"
        threat_type: "CVE", "Malware", "IOC", "Actor"
        memory: the memory dict (will load if None)
    """
    if memory is None:
        memory = load_memory()

    if threat_name not in memory["known_threats"]:
        memory["known_threats"][threat_name] = {
            "first_seen": datetime.now().isoformat(),
            "handled": False
        }

    record = memory["known_threats"][threat_name]
    record["last_seen"] = datetime.now().isoformat()
    record["severity"] = severity
    record["type"] = threat_type

    save_memory(memory)
