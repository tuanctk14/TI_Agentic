"""
Memory Agent — Long-term memory storage cho agent
Lưu lịch sử điều tra, alert, threats đã biết vào file JSON
Includes TF-IDF semantic search for finding similar past investigations
"""
import json
from pathlib import Path
from datetime import datetime
from collections import Counter
import math

MEMORY_FILE = Path("data/agent_memory.json")


class _TFIDFIndex:
    """Pure Python TF-IDF implementation for semantic search of past investigations."""

    def __init__(self):
        self.documents = {}  # doc_id → text
        self.vocab = set()   # all unique terms
        self.term_freqs = {} # doc_id → {term: count}
        self.doc_freqs = {}  # term → count of docs containing it
        self.num_docs = 0

    def tokenize(self, text: str) -> list:
        """Simple tokenization: lowercase, split on whitespace, remove short terms."""
        if not text:
            return []
        tokens = text.lower().split()
        # Keep terms >= 3 chars, filter common stopwords
        stopwords = {"the", "and", "or", "is", "a", "an", "to", "of", "for", "in", "on", "with"}
        return [t for t in tokens if len(t) >= 3 and t not in stopwords]

    def build(self, documents: dict) -> None:
        """Build index from documents dict (doc_id → text)."""
        self.documents = documents.copy()
        self.term_freqs = {}
        self.doc_freqs = {}
        self.vocab = set()
        self.num_docs = len(documents)

        for doc_id, text in documents.items():
            tokens = self.tokenize(text)
            self.term_freqs[doc_id] = dict(Counter(tokens))

            for token in set(tokens):
                self.vocab.add(token)
                self.doc_freqs[token] = self.doc_freqs.get(token, 0) + 1

    def search(self, query: str, top_k: int = 5) -> list:
        """
        Search for similar documents using cosine similarity.
        Returns list of (doc_id, similarity_score) tuples, sorted by score descending.
        """
        if not self.num_docs or not self.vocab:
            return []

        query_tokens = self.tokenize(query)
        if not query_tokens:
            return []

        # Compute TF-IDF vector for query
        query_vector = {}
        for token in query_tokens:
            if token in self.doc_freqs:
                tf = query_tokens.count(token) / len(query_tokens)
                idf = math.log(self.num_docs / self.doc_freqs[token])
                query_vector[token] = tf * idf

        # Cosine similarity with each document
        results = []
        for doc_id, text in self.documents.items():
            if doc_id not in self.term_freqs:
                continue

            doc_vector = {}
            for token, count in self.term_freqs[doc_id].items():
                if token in self.doc_freqs:
                    tf = count / len(self.tokenize(text))
                    idf = math.log(self.num_docs / self.doc_freqs[token])
                    doc_vector[token] = tf * idf

            # Cosine similarity
            dot_product = sum(query_vector.get(t, 0) * doc_vector.get(t, 0)
                             for t in set(query_vector.keys()) | set(doc_vector.keys()))
            query_norm = math.sqrt(sum(v ** 2 for v in query_vector.values())) or 1
            doc_norm = math.sqrt(sum(v ** 2 for v in doc_vector.values())) or 1
            similarity = dot_product / (query_norm * doc_norm) if query_norm * doc_norm > 0 else 0

            if similarity > 0:
                results.append((doc_id, similarity))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]


# Global TF-IDF index (rebuilt after memory save)
_tfidf_index = _TFIDFIndex()


def _rebuild_index(memory: dict) -> None:
    """Rebuild TF-IDF index from investigations in memory."""
    documents = {}
    for entity_name, record in memory.get("investigations", {}).items():
        # Combine entity name + finding + action for search
        finding = record.get("actions", [{}])[-1].get("finding", "") if record.get("actions") else ""
        action = record.get("action_taken", "")
        text = f"{entity_name} {finding} {action}"
        documents[entity_name] = text

    _tfidf_index.build(documents)


def search_past_investigations(query: str, memory: dict = None, top_k: int = 5) -> list:
    """
    Semantic search for similar past investigations using TF-IDF.

    Args:
        query: search query (e.g., "CVE network exploit", "malware C2")
        memory: memory dict (will load if None)
        top_k: number of results to return

    Returns:
        list of (entity_name, similarity_score, record_summary) tuples
    """
    if memory is None:
        memory = load_memory()

    if not memory.get("investigations"):
        return []

    # Ensure index is built
    if not _tfidf_index.num_docs:
        _rebuild_index(memory)

    results = _tfidf_index.search(query, top_k=top_k)

    # Augment with record summaries
    detailed_results = []
    for entity_name, score in results:
        record = memory["investigations"].get(entity_name, {})
        summary = {
            "entity": entity_name,
            "similarity": round(score, 3),
            "first_seen": record.get("first_seen"),
            "last_seen": record.get("last_seen"),
            "action_taken": record.get("action_taken"),
            "times_investigated": record.get("times_investigated", 0)
        }
        detailed_results.append(summary)

    return detailed_results


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
    """Save memory to file and rebuild TF-IDF index."""
    try:
        memory["metadata"]["last_updated"] = datetime.now().isoformat()
        MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        MEMORY_FILE.write_text(json.dumps(memory, ensure_ascii=False, indent=2), encoding='utf-8')
        # Rebuild index after save
        _rebuild_index(memory)
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
