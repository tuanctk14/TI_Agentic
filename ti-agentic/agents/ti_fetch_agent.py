"""
TI Fetch Agent - lay TOAN BO du lieu tu OpenCTI bang phan trang.
Ho tro: Indicators, Malware, Vulnerabilities, Threat Actors.
Co ham search_opencti() de tim kiem truc tiep theo tu khoa.
"""
import os, re, traceback, time, json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
OPENCTI_URL   = os.getenv("OPENCTI_URL", "").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")

CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)
IOCS_CACHE = CACHE_DIR / "iocs.json"
MALS_CACHE = CACHE_DIR / "malwares.json"
VULS_CACHE = CACHE_DIR / "vulnerabilities.json"
ACTS_CACHE = CACHE_DIR / "threat_actors.json"
METADATA_FILE = CACHE_DIR / "metadata.json"



def _gql(query, variables, timeout=240):
    import requests, urllib3
    urllib3.disable_warnings()
    r = requests.post(
        f"{OPENCTI_URL}/graphql",
        headers={"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"},
        json={"query": query, "variables": variables},
        timeout=timeout, verify=False,
    )
    r.raise_for_status()
    d = r.json()
    if "errors" in d:
        raise RuntimeError(str(d["errors"]))
    return d


def _load_cache(cache_file):
    if cache_file.exists():
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"  Loi load cache {cache_file}: {e}")
    return []

def _save_cache(data, cache_file):
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  Luu cache {cache_file.name}: {len(data)} items")
    except Exception as e:
        print(f"  Loi save cache {cache_file}: {e}")

def _get_metadata():
    if METADATA_FILE.exists():
        try:
            with open(METADATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    return {"last_sync": None, "synced_ids": []}

def _save_metadata(meta):
    try:
        with open(METADATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"  Loi save metadata: {e}")

def _paginate(query, data_key, transform_fn, page_size=100, max_total=0, extra_vars=None):
    results, cursor, page = [], None, 0
    base = {"first": page_size, **(extra_vars or {})}
    # Timeout lâu hơn cho từng loại dữ liệu
    timeout = 300 if data_key == "vulnerabilities" else 180
    max_retries = 2
    retry_count = 0

    while True:
        try:
            raw   = _gql(query, {**base, "after": cursor}, timeout=timeout)
            block = raw["data"][data_key]
            edges = block.get("edges", [])
            retry_count = 0  # Reset retry khi thành công
        except Exception as e:
            # Nếu lỗi, retry 1 lần rồi break
            if retry_count < max_retries:
                print(f"  Trang {page} loi [{data_key}]: {e}. Retry...")
                retry_count += 1
                time.sleep(1)
                continue
            else:
                print(f"  Trang {page} loi [{data_key}]: {e}. Dung lai, dung cache.")
                break

        for edge in edges:
            try: results.append(transform_fn(edge["node"]))
            except Exception as ex:
                print(f"    Transform loi: {ex}")
                pass
        page += 1
        print(f"  [{data_key}] trang {page}: +{len(edges)}, tong {len(results)}")
        pi = block.get("pageInfo", {})
        if not pi.get("hasNextPage"): break
        if max_total and len(results) >= max_total: break
        cursor = pi.get("endCursor")
        time.sleep(0.1)
    return results


# --- Indicators ---
_IOC_Q = """query($first:Int $after:ID){
  indicators(first:$first after:$after orderBy:created_at orderMode:desc){
    pageInfo{hasNextPage endCursor}
    edges{node{id name pattern indicator_types confidence x_opencti_score description
               valid_from valid_until created_at objectLabel{value}}}}}"""

def _ioc_t(n):
    return {"id":n["id"],"name":n.get("name",""),"pattern":n.get("pattern",""),
            "type":n.get("indicator_types") or [],"confidence":n.get("confidence") or 50,
            "score":n.get("x_opencti_score") or 50,"description":n.get("description") or "",
            "valid_from":str(n.get("valid_from",""))[:10],
            "valid_until":str(n.get("valid_until",""))[:10],
            "created_at":str(n.get("created_at",""))[:10],
            "labels":[lb["value"] for lb in (n.get("objectLabel") or [])]}

# --- Malware ---
_MAL_Q = """query($first:Int $after:ID){malwares(first:$first after:$after orderBy:created_at orderMode:desc){pageInfo{hasNextPage endCursor} edges{node{id name aliases malware_types first_seen last_seen confidence description created created_at modified updated_at objectLabel{value} stixCoreRelationships(first:100){edges{node{relationship_type fromType toType from{... on IntrusionSet{id name}} to{... on Country{id name} ... on Sector{id name}}}}}}}}}"""

def _mal_t(n):
    c = n.get("confidence") or 50
    intrusion_sets = []
    target_countries = []
    target_sectors = []

    # Process all relationships
    rels = n.get("stixCoreRelationships", {}).get("edges", [])
    for rel_edge in rels:
        rel = rel_edge.get("node", {})
        from_type = rel.get("fromType", "")
        to_type = rel.get("toType", "")

        if from_type == "Intrusion-Set":
            from_data = rel.get("from", {})
            from_name = from_data.get("name", "")
            if from_name and from_name not in intrusion_sets:
                intrusion_sets.append(from_name)

        if to_type == "Country":
            to_data = rel.get("to", {})
            to_name = to_data.get("name", "")
            if to_name and to_name not in target_countries:
                target_countries.append(to_name)

        if to_type == "Sector":
            to_data = rel.get("to", {})
            to_name = to_data.get("name", "")
            if to_name and to_name not in target_sectors:
                target_sectors.append(to_name)

    d = {
        "id":n["id"],"name":n.get("name",""),"aliases":n.get("aliases") or [],
        "malware_types":n.get("malware_types") or [],
        "first_seen":str(n.get("first_seen",""))[:10],
        "last_seen":str(n.get("last_seen",""))[:10],
        "confidence":c,"description":n.get("description") or "",
        "labels":[lb["value"] for lb in (n.get("objectLabel") or [])],
        "severity":"critical" if c>=90 else "high" if c>=70 else "medium",
        "intrusion_sets":intrusion_sets,
        "target_countries":target_countries,
        "target_sectors":target_sectors,
        "original_creation_date":str(n.get("created") or "")[:10],
        "modification_date":str(n.get("modified") or "")[:10],
        "created_at":str(n.get("created_at") or "")[:10]
    }
    return d

# --- Vulnerabilities ---
_VUL_Q = """query($first:Int $after:ID){
  vulnerabilities(first:$first after:$after orderBy:created_at orderMode:desc){
    pageInfo{hasNextPage endCursor}
    edges{node{id name description x_opencti_cvss_base_score
               x_opencti_cvss_base_severity created created_at modified updated_at objectLabel{value}}}}}"""

def _vul_t(n):
    score = n.get("x_opencti_cvss_base_score") or 0
    sev   = (n.get("x_opencti_cvss_base_severity") or "").lower().strip()
    if not sev or sev=="none":
        sev = "critical" if score>=9 else "high" if score>=7 else "medium" if score>=4 else "low" if score>0 else "unknown"
    d = {
        "id":n["id"],"name":n.get("name",""),"description":n.get("description") or "",
        "cvss_score":score,"severity":sev,"affected_software":"Xem description",
        "patch_available":False,"exploit_in_wild":False,"affected_versions":[],
        "labels":[lb["value"] for lb in (n.get("objectLabel") or [])]
    }
    d["original_creation_date"] = str(n.get("created") or "")[:10]
    d["modification_date"] = str(n.get("modified") or "")[:10]
    d["created_at"] = str(n.get("created_at") or "")[:10]
    return d

# --- Threat Actors ---
_ACT_Q = """query($first:Int $after:ID){
  threatActors(first:$first after:$after orderBy:created_at orderMode:desc){
    pageInfo{hasNextPage endCursor}
    edges{node{id name aliases threat_actor_types first_seen last_seen confidence description sophistication}}}}"""

def _act_t(n):
    return {"id":n["id"],"name":n.get("name",""),"aliases":n.get("aliases") or [],
            "types":n.get("threat_actor_types") or [],"first_seen":str(n.get("first_seen",""))[:10],
            "last_seen":str(n.get("last_seen",""))[:10],"confidence":n.get("confidence") or 50,
            "description":n.get("description") or "","sophistication":n.get("sophistication","")}


# ══════════════════════════════════════════════════════════════
# REALTIME SEARCH - tim kiem truc tiep OpenCTI theo tu khoa
# ══════════════════════════════════════════════════════════════
def search_opencti(keyword: str, limit: int = 20) -> dict:
    """Tim kiem truc tiep OpenCTI. Dung cho chat AI."""
    if not _use_real():
        print(f"[ERROR] OpenCTI chua cau hinh, khong the search. Hay cau hinh OPENCTI_URL va OPENCTI_TOKEN")
        return {"iocs":[], "malwares":[], "vulnerabilities":[], "actors":[], "source":"Error"}

    print(f"[SEARCH] Tim kiem OpenCTI: '{keyword}'")
    result = {"iocs":[], "malwares":[], "vulnerabilities":[], "actors":[], "source":"OpenCTI"}

    sq_ioc = """query($s:String $n:Int){indicators(first:$n search:$s orderBy:confidence orderMode:desc){
        edges{node{id name pattern indicator_types confidence description created_at}}}}"""
    sq_mal = """query($s:String $n:Int){malwares(first:$n search:$s orderBy:confidence orderMode:desc){
        edges{node{id name aliases malware_types confidence description first_seen last_seen}}}}"""
    sq_vul = """query($s:String $n:Int){vulnerabilities(first:$n search:$s orderBy:x_opencti_cvss_base_score orderMode:desc){
        edges{node{id name description x_opencti_cvss_base_score x_opencti_cvss_base_severity}}}}"""
    sq_act = """query($s:String $n:Int){threatActors(first:$n search:$s){
        edges{node{id name aliases threat_actor_types confidence description first_seen last_seen}}}}"""

    for q, key, tfn in [
        (sq_ioc,"indicators",  lambda n: _classify(_ioc_t(n))),
        (sq_mal,"malwares",    _mal_t),
        (sq_vul,"vulnerabilities", _vul_t),
        (sq_act,"threatActors",_act_t),
    ]:
        rkey = {"indicators":"iocs","malwares":"malwares",
                "vulnerabilities":"vulnerabilities","threatActors":"actors"}[key]
        try:
            d = _gql(q, {"s": keyword, "n": limit})
            for e in d["data"][key]["edges"]:
                result[rkey].append(tfn(e["node"]))
        except Exception as ex:
            print(f"  {key} search error: {ex}")

    total = sum(len(v) for v in result.values() if isinstance(v,list))
    print(f"  -> {total} ket qua cho '{keyword}'")
    return result


# ══════════════════════════════════════════════════════════════
# CLASSIFICATION
# ══════════════════════════════════════════════════════════════
_FP = {"8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9",
       "192.168.1.1","127.0.0.1","10.0.0.1","0.0.0.0","255.255.255.255"}

def _classify(ioc):
    name, pattern, conf = ioc.get("name","").strip(), ioc.get("pattern",""), int(ioc.get("confidence") or 50)
    is_fp = name in _FP or conf < 15

    if   pattern.startswith(('rule ', 'import "', '/*')):            kind="Yara"
    elif pattern.startswith('[cryptocurrency-wallet'):               kind="Wallet"
    elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', name):                kind="IP"
    elif re.fullmatch(r'[a-fA-F0-9]{32,64}', name):                  kind="Hash"
    elif name.startswith(("http://","https://")):                     kind="URL"
    elif re.search(r'\.[a-z]{2,}$|xn--',name, re.IGNORECASE):        kind="Domain"
    else:                                                             kind="Unknown"

    if is_fp:     risk,reason="low",     "False positive"
    elif conf>=90:risk,reason="critical","Da xac nhan doc hai"
    elif conf>=75:risk,reason="high",    "Kha nang cao la moi de doa"
    elif conf>=50:risk,reason="medium",  "Can dieu tra them"
    else:         risk,reason="low",     "Confidence thap"
    return {**ioc,"ioc_type":kind,"is_false_positive":is_fp,"risk_level":risk,"reason":reason}


def _use_real():
    return bool(OPENCTI_URL and OPENCTI_TOKEN and len(OPENCTI_TOKEN)>5)


# ══════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════
def fetch_all(limit: int = 0, force_refresh: bool = False, incremental: bool = True) -> dict:
    """
    limit=0 -> lay TAT CA khong gioi han.
    force_refresh=True -> lay lai toan bo.
    incremental=True -> chi lay du lieu moi (default)
    """
    t0 = time.time()

    # Neu incremental=True, load cache cu de so sanh
    old_ioc_ids = set()
    old_mal_ids = set()
    old_vuln_ids = set()

    if incremental and not force_refresh:
        try:
            old_iocs = _load_cache(IOCS_CACHE) or []
            old_mals = _load_cache(MALS_CACHE) or []
            old_vulns = _load_cache(VULS_CACHE) or []
            old_ioc_ids = {i["id"] for i in old_iocs}
            old_mal_ids = {m["id"] for m in old_mals}
            old_vuln_ids = {v["id"] for v in old_vulns}
            print(f"[INCREMENTAL] Old cache: IOC:{len(old_ioc_ids)} Mal:{len(old_mal_ids)} Vuln:{len(old_vuln_ids)}")
        except:
            pass

    if not _use_real():
        print("[ERROR] OpenCTI chua cau hinh. Hay set OPENCTI_URL va OPENCTI_TOKEN")
        cached_iocs = _load_cache(IOCS_CACHE)
        if cached_iocs:
            return {"iocs":cached_iocs,"malwares":_load_cache(MALS_CACHE),"vulnerabilities":_load_cache(VULS_CACHE),
                    "actors":_load_cache(ACTS_CACHE),"source":"Cache (no OpenCTI)",
                    "fetched_at":datetime.now().strftime("%d/%m/%Y %H:%M:%S")}
        return {"iocs":[],"malwares":[],"vulnerabilities":[],"actors":[],
                "source":"Error: Unconfigured OpenCTI","fetched_at":datetime.now().strftime("%d/%m/%Y %H:%M:%S")}

    print(f"\n[CONNECT] OpenCTI: {OPENCTI_URL}")
    print(f"[MODE] Che do: {'TOAN BO' if not limit else f'toi da {limit}'}")

    try:
        print("[FETCH] Dang tai IOCs...")
        iocs_raw = _paginate(_IOC_Q,"indicators",_ioc_t,100,limit)
        iocs = [_classify(i) for i in iocs_raw]
        # Filter only new IOCs if incremental
        if incremental and old_ioc_ids:
            iocs_new = [i for i in iocs if i.get("id") not in old_ioc_ids]
            print(f"  -> Lay duoc {len(iocs)} IOCs, new: {len(iocs_new)}")
            iocs = iocs_new if iocs_new else iocs  # If no new, keep all
        else:
            print(f"  -> Lay duoc {len(iocs)} IOCs")

        print("[FETCH] Dang tai Malwares...")
        mals = _paginate(_MAL_Q,"malwares",_mal_t,100,limit)
        # Filter only new Malwares if incremental
        if incremental and old_mal_ids:
            mals_new = [m for m in mals if m.get("id") not in old_mal_ids]
            print(f"  -> Lay duoc {len(mals)} Malwares, new: {len(mals_new)}")
            mals = mals_new if mals_new else mals  # If no new, keep all
        else:
            print(f"  -> Lay duoc {len(mals)} Malwares")

        print("[FETCH] Dang tai Vulnerabilities...")
        # Parallel fetch cho Vulnerabilities với timeout bảo vệ
        import threading
        vulns_result = [None]
        def fetch_vulns():
            try:
                vulns_result[0] = _paginate(_VUL_Q,"vulnerabilities",_vul_t,100,limit)
            except Exception as e:
                print(f"  Vulnerability fetch error: {e}")
                vulns_result[0] = None

        vuln_thread = threading.Thread(target=fetch_vulns, daemon=True)
        vuln_thread.start()
        vuln_thread.join(timeout=60)  # Tăng timeout lên 60s

        if vuln_thread.is_alive() or vulns_result[0] is None:
            print(f"  [Vulnerabilities fetch timeout/failed] -> Dung cache cu")
            vulns = _load_cache(VULS_CACHE)
            if not vulns:
                vulns = []
                print(f"  Khong co cache, dung danh sach rong")
        else:
            vulns = vulns_result[0] or []
            # Filter only new Vulnerabilities if incremental
            if incremental and old_vuln_ids:
                vulns_new = [v for v in vulns if v.get("id") not in old_vuln_ids]
                print(f"  -> Lay duoc {len(vulns)} Vulnerabilities, new: {len(vulns_new)}")
                vulns = vulns_new if vulns_new else vulns  # If no new, keep all
            else:
                print(f"  -> Lay duoc {len(vulns)} Vulnerabilities")

        print("[FETCH] Dang tai Threat Actors...")
        actors = []
        try:
            actors = _paginate(_ACT_Q,"threatActors",_act_t,50,limit)
            print(f"  -> Lay duoc {len(actors)} Threat Actors")
        except Exception as e:
            print(f"  Threat Actors loi: {e}")
            actors = _load_cache(ACTS_CACHE) or []

        # Luu cache neu co du lieu moi
        if iocs: _save_cache(iocs, IOCS_CACHE)
        if mals: _save_cache(mals, MALS_CACHE)
        if vulns: _save_cache(vulns, VULS_CACHE)
        if actors: _save_cache(actors, ACTS_CACHE)

        meta = {"last_sync": datetime.now().isoformat(), "ioc_count": len(iocs), "mal_count": len(mals), "vuln_count": len(vulns), "actor_count": len(actors)}
        _save_metadata(meta)

        src = f"OpenCTI ({OPENCTI_URL})"
    except Exception as e:
        print(f"[ERROR] Loi OpenCTI: {e}"); traceback.print_exc()
        print("[FALLBACK] Dang load cache...")
        iocs = _load_cache(IOCS_CACHE)
        mals = _load_cache(MALS_CACHE)
        vulns = _load_cache(VULS_CACHE)
        actors = _load_cache(ACTS_CACHE)
        if not iocs:
            return {"iocs":[],"malwares":[],"vulnerabilities":[],"actors":[],
                    "source":"Error: OpenCTI connection failed","fetched_at":datetime.now().strftime("%d/%m/%Y %H:%M:%S")}
        src = "Cache (OpenCTI connection failed)"

    print(f"\nHoan tat {time.time()-t0:.1f}s | IOC:{len(iocs)} Mal:{len(mals)} Vuln:{len(vulns)} Actor:{len(actors)}")
    return {"iocs":iocs,"malwares":mals,"vulnerabilities":vulns,"actors":actors,
            "source":src,"fetched_at":datetime.now().strftime("%d/%m/%Y %H:%M:%S")}


def fetch_indicators(limit=100):
    return fetch_all(limit)["iocs"]


if __name__ == "__main__":
    d = fetch_all(0)
    print(f"Nguon: {d['source']} | IOC:{len(d['iocs'])} Mal:{len(d['malwares'])} Vuln:{len(d['vulnerabilities'])}")
