"""
Decision Agent — Quyết định "có cần alert không?" dựa trên rule-based scoring
Được gọi bởi ai_agent.py khi đã collected đủ dữ liệu về threat
"""
import ollama
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11555")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

def assess_risk(entity_name: str, entity_type: str, cvss_score: float,
                affected_assets: list, memory_context: dict,
                enrichment_data: dict = None) -> dict:
    """
    Assess risk và quyết định có cần alert không.

    Args:
        entity_name: CVE-YYYY-NNNNN, Malware name, IOC name, etc.
        entity_type: "CVE", "IOC", "Malware", "Actor"
        cvss_score: CVSS score (0-10) hoặc 0 nếu không có
        affected_assets: list of asset hostnames bị ảnh hưởng
        memory_context: result từ memory_agent.check_entity()
        enrichment_data: dict từ NVD hoặc các source khác, optional

    Returns:
        {
            "should_alert": bool,
            "severity": "critical" | "high" | "medium" | "low",
            "score": int (0-100),
            "reasons": [list of reasons],
            "recommended_action": short string (1-2 sentences)
        }
    """
    if enrichment_data is None:
        enrichment_data = {}

    score = 0
    reasons = []

    # === SCORING LOGIC ===

    # 1. CVSS Score
    if cvss_score >= 9.0:
        score += 40
        reasons.append(f"CVSS {cvss_score} — Critical level")
    elif cvss_score >= 7.0:
        score += 25
        reasons.append(f"CVSS {cvss_score} — High severity")
    elif cvss_score >= 4.0:
        score += 10
        reasons.append(f"CVSS {cvss_score} — Medium severity")
    elif cvss_score > 0:
        score += 3
        reasons.append(f"CVSS {cvss_score} — Low severity")

    # 2. Number of affected assets
    num_assets = len(affected_assets) if affected_assets else 0
    if num_assets >= 5:
        score += 25
        reasons.append(f"{num_assets} thiết bị bị ảnh hưởng (rất nhiều)")
    elif num_assets >= 3:
        score += 20
        reasons.append(f"{num_assets} thiết bị bị ảnh hưởng (nhiều)")
    elif num_assets >= 1:
        score += 10
        reasons.append(f"{num_assets} thiết bị bị ảnh hưởng")

    # 3. CISA Exploit Add date (có trong NVD)
    cisa_exploit = enrichment_data.get("cisa_exploit_add", "")
    if cisa_exploit:
        score += 15
        reasons.append("Exploit đang được khai thác thực tế (CISA)")

    # 4. Memory context — has this been seen before?
    if memory_context and memory_context.get("found"):
        history = memory_context.get("history", {})
        last_seen = history.get("last_seen", "")
        alert_sent = history.get("alert_sent", False)

        # Already alerted recently?
        if alert_sent and last_seen:
            try:
                last_date = datetime.fromisoformat(last_seen)
                days_ago = (datetime.now() - last_date).days
                if days_ago < 7:
                    # Already alerted < 1 week ago
                    score += 5  # Lower priority
                    reasons.append(f"Đã alert từ {days_ago} ngày trước (follow-up)")
                else:
                    score += 10
                    reasons.append("Chưa được xử lý từ lần trước")
            except:
                score += 10
                reasons.append("Chưa được xử lý từ lần trước")
        else:
            score += 10
            reasons.append("Lần đầu tiên phát hiện threat này")
    else:
        score += 10
        reasons.append("Lần đầu tiên phát hiện threat này")

    # 5. Entity type
    if entity_type == "CVE":
        if cvss_score == 0:
            # CVE chưa có CVSS → suspicious, tăng điểm
            score += 5
            reasons.append("CVE chưa được định giá (tiềm ẩn nguy hiểm)")

    # === DETERMINE SEVERITY ===
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    else:
        severity = "low"

    # === ALERT DECISION ===
    # Default: alert nếu score >= 60 (high-risk)
    # Luôn alert nếu: CVSS >= 7.0 AND có ít nhất 1 asset
    should_alert = (score >= 60) or (cvss_score >= 7.0 and num_assets >= 1)

    # === RECOMMENDED ACTION ===
    recommended_action = _generate_action(entity_name, entity_type, severity,
                                          affected_assets, cvss_score, enrichment_data)

    # === CONFIDENCE SCORE ===
    # Based on evidence count (number of scoring factors that triggered)
    evidence_count = len(reasons)
    if evidence_count >= 4:
        confidence = 0.9
    elif evidence_count == 3:
        confidence = 0.75
    elif evidence_count == 2:
        confidence = 0.6
    else:
        confidence = 0.4

    # Needs human review if we're alerting but confidence is low
    needs_human_review = should_alert and confidence < 0.6

    return {
        "should_alert": should_alert,
        "severity": severity,
        "score": min(100, score),  # cap at 100
        "reasons": reasons,
        "recommended_action": recommended_action,
        "confidence": confidence,
        "needs_human_review": needs_human_review,
        "evidence_count": evidence_count,
        "timestamp": datetime.now().isoformat()
    }


def _generate_action(entity_name: str, entity_type: str, severity: str,
                     affected_assets: list, cvss_score: float,
                     enrichment_data: dict) -> str:
    """Generate a recommended action based on threat characteristics."""

    if severity == "critical":
        if cvss_score >= 9.0:
            return f"Vá ngay lập tức, cách ly {affected_assets[0] if affected_assets else 'affected systems'} khỏi mạng nếu cần thiết."
        else:
            return f"Vá trong vòng 24 giờ, giám sát {len(affected_assets)} thiết bị bị ảnh hưởng."

    elif severity == "high":
        return f"Lập kế hoạch vá trong tuần này, ưu tiên {affected_assets[0] if affected_assets else 'critical systems'}."

    elif severity == "medium":
        return f"Vá trong vòng 30 ngày, không yêu cầu cách ly."

    else:  # low
        return f"Theo dõi và vá trong chu kỳ bảo trì thường xuyên."


def assess_with_reasoning(entity_name: str, entity_type: str, cvss_score: float,
                          affected_assets: list, memory_context: dict,
                          enrichment_data: dict = None) -> dict:
    """
    assess_risk + LLM-generated justification (fallback nếu offline).
    """
    result = assess_risk(entity_name, entity_type, cvss_score,
                        affected_assets, memory_context, enrichment_data)

    # Optional: gọi Ollama để sinh lý do chi tiết hơn
    try:
        prompt = f"""Bạn là security expert. Tóm tắt lý do vì sao threat này cần/không cần alert:

Threat: {entity_name} ({entity_type})
CVSS: {cvss_score}
Affected Assets: {len(affected_assets)} — {', '.join(affected_assets[:3])}{'...' if len(affected_assets) > 3 else ''}
Decision: {'⚠️ ALERT' if result['should_alert'] else '✅ NO ALERT'} ({result['severity']})

Reasons (brief, 1 sentence):"""

        response = ollama.generate(
            model=MODEL,
            host=OLLAMA_HOST,
            prompt=prompt,
            stream=False,
            context=[],
        )

        reasoning = response.get("response", "").strip()[:150]
        if reasoning:
            result["llm_reasoning"] = reasoning
    except:
        pass  # Ollama offline, skip LLM reasoning

    return result


def batch_assess(threats: list) -> dict:
    """
    Batch assess multiple threats and return prioritized list.

    Args:
        threats: list of threat dicts, each must have:
            {
                "entity_name": str,
                "entity_type": str,
                "cvss_score": float,
                "affected_assets": list,
                "memory_context": dict,
                "enrichment_data": dict (optional)
            }

    Returns:
        {
            "total": int,
            "alerts": int,
            "human_review_needed": int,
            "results": [sorted by priority: critical alerts, then high, then medium],
            "summary": "X alerts | Y need human review"
        }
    """
    results = []

    for threat in threats:
        assessment = assess_risk(
            entity_name=threat.get("entity_name", "Unknown"),
            entity_type=threat.get("entity_type", "Unknown"),
            cvss_score=threat.get("cvss_score", 0),
            affected_assets=threat.get("affected_assets", []),
            memory_context=threat.get("memory_context", {}),
            enrichment_data=threat.get("enrichment_data", {})
        )
        assessment["entity_name"] = threat.get("entity_name")
        assessment["entity_type"] = threat.get("entity_type")
        results.append(assessment)

    # Sort by priority: critical alerts first, then high, then medium, then low
    # Within same severity: high score first
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda x: (
        not x["should_alert"],  # alerts first
        severity_order.get(x["severity"], 999),
        -x["score"]  # higher score first
    ))

    alert_count = sum(1 for r in results if r["should_alert"])
    human_review_count = sum(1 for r in results if r.get("needs_human_review", False))

    return {
        "total": len(threats),
        "alerts": alert_count,
        "human_review_needed": human_review_count,
        "results": results,
        "summary": f"{alert_count} alerts | {human_review_count} need human review"
    }
