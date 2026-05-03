"""
NVD Client — Fetch detailed CVE data from National Vulnerability Database
Được gọi bởi ai_agent.py để làm giàu CVSS và metadata CVE
"""
import requests
import time

def fetch_nvd(cve_id: str, cache: dict = None) -> dict:
    """
    Fetch detailed CVE data from NVD API.

    Args:
        cve_id: CVE ID dạng CVE-YYYY-NNNNN
        cache: optional dict to check/update cache (để ai_agent tự quản lý cache)

    Returns:
        dict với keys: nvd_id, published, cvss_v3_score, cvss_v3_severity,
                      attack_vector, weaknesses, affected_cpes, cisa_exploit_add, etc.
                      Hoặc {} nếu không tìm thấy
    """
    try:
        cve_id = cve_id.upper() if isinstance(cve_id, str) else cve_id
        if not cve_id.startswith("CVE-"):
            return {}

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        # Add delay to respect NVD API rate limiting (6 requests/minute = 10 sec/request)
        time.sleep(0.1)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = requests.get(url, timeout=15)
                if resp.status_code == 200:
                    break
                elif resp.status_code == 429:
                    # Rate limited, wait exponentially longer
                    wait_time = 10 * (2 ** attempt)
                    print(f"  NVD rate limited, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"  NVD API error {resp.status_code} for {cve_id}")
                    return {}
            except Exception as e:
                print(f"  NVD request error: {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
                return {}

        if resp.status_code != 200:
            return {}

        data = resp.json()
        if not data.get("vulnerabilities"):
            return {}

        cve = data["vulnerabilities"][0].get("cve", {})

        # Extract key fields
        nvd_data = {
            "nvd_id": cve.get("id", ""),
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "vul_status": cve.get("vulnStatus", ""),
            "description_en": "",
            "cvss_v3_score": None,
            "cvss_v3_severity": "",
            "cvss_v3_vector": "",
            "cvss_v2_score": None,
            "cvss_v2_severity": "",
            "attack_vector": "N/A",
            "attack_complexity": "N/A",
            "weaknesses": [],
            "affected_cpes": [],
            "references": [],
            "cisa_exploit_add": cve.get("cisaExploitAdd", ""),
            "cisa_action_due": cve.get("cisaActionDue", ""),
            "cisa_required_action": cve.get("cisaRequiredAction", ""),
        }

        # Get description
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                nvd_data["description_en"] = desc.get("value", "")
                break

        # Get CVSS scores
        metrics = cve.get("metrics", {})

        # CVSS v3.1
        for metric in metrics.get("cvssMetricV31", []):
            if metric.get("type") == "Primary":
                cvss_data = metric.get("cvssData", {})
                nvd_data["cvss_v3_score"] = cvss_data.get("baseScore")
                nvd_data["cvss_v3_severity"] = cvss_data.get("baseSeverity", "")
                nvd_data["cvss_v3_vector"] = cvss_data.get("vectorString", "")
                nvd_data["attack_vector"] = cvss_data.get("attackVector", "N/A")
                nvd_data["attack_complexity"] = cvss_data.get("attackComplexity", "N/A")
                break

        # CVSS v2.0 if no v3
        if not nvd_data["cvss_v3_score"]:
            for metric in metrics.get("cvssMetricV2", []):
                if metric.get("type") == "Primary":
                    cvss_data = metric.get("cvssData", {})
                    nvd_data["cvss_v2_score"] = cvss_data.get("baseScore")
                    nvd_data["cvss_v2_severity"] = cvss_data.get("baseSeverity", "")
                    break

        # Get weaknesses
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    nvd_data["weaknesses"].append(desc.get("value", ""))

        # Get affected CPEs (up to 5 for display)
        configs = cve.get("configurations", [])
        if configs:
            for config in configs:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            cpe = cpe_match.get("criteria", "")
                            versions = []
                            if cpe_match.get("versionStartIncluding"):
                                versions.append(f"from {cpe_match['versionStartIncluding']}")
                            if cpe_match.get("versionEndExcluding"):
                                versions.append(f"before {cpe_match['versionEndExcluding']}")
                            version_str = " ".join(versions) if versions else ""
                            nvd_data["affected_cpes"].append(f"{cpe} {version_str}".strip())
                            if len(nvd_data["affected_cpes"]) >= 5:
                                break

        # Get references (up to 5)
        for ref in cve.get("references", [])[:5]:
            nvd_data["references"].append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            })

        return nvd_data
    except Exception as e:
        print(f"  NVD fetch error for {cve_id}: {str(e)[:100]}")
        return {}
