"""TI Agentic Demo Backend"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import ollama, json, os, shutil, traceback, re, requests
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pandas as pd
from dotenv import load_dotenv

load_dotenv()
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
ollama.Client(host=OLLAMA_HOST)

# Import NVD client (extracted to separate module)
from agents.nvd_client import fetch_nvd

VN_TZ = timezone(timedelta(hours=7))
UPLOAD_IOC_FILE  = Path("data/uploaded_iocs.json")
UPLOAD_VULN_FILE = Path("data/uploaded_vulns.json")
UPLOAD_LOG_FILE  = Path("data/upload_log.json")

for _d in ["reports","data","uploads","assets"]:
    Path(_d).mkdir(exist_ok=True)

store = {
    "iocs":[], "malwares":[], "vulnerabilities":[], "actors":[],
    "matches":[], "last_update":None, "source":"",
    "upload_log":[], "uploaded_iocs":[], "uploaded_vulns":[],
    "nvd_cache":{},  # Cache for NVD API responses
    "alerts":[], "alerts_history":[],  # Alerts created by agent
    "_memory":{},  # Agent's long-term memory (loaded per-session in ai_agent.py)
}
scheduler = AsyncIOScheduler()

def _save_upload_data():
    try:
        UPLOAD_IOC_FILE.write_text(json.dumps(store["uploaded_iocs"],  ensure_ascii=False))
        UPLOAD_VULN_FILE.write_text(json.dumps(store["uploaded_vulns"], ensure_ascii=False))
        UPLOAD_LOG_FILE.write_text(json.dumps(store["upload_log"],      ensure_ascii=False))
    except Exception as e:
        print(f"Save loi: {e}")

def _load_upload_data():
    try:
        if UPLOAD_IOC_FILE.exists():  store["uploaded_iocs"]  = json.loads(UPLOAD_IOC_FILE.read_text())
        if UPLOAD_VULN_FILE.exists(): store["uploaded_vulns"] = json.loads(UPLOAD_VULN_FILE.read_text())
        if UPLOAD_LOG_FILE.exists():  store["upload_log"]     = json.loads(UPLOAD_LOG_FILE.read_text())
        print(f"Loaded: {len(store['uploaded_iocs'])} uploaded IOC, {len(store['upload_log'])} logs")
    except Exception as e:
        print(f"Load loi: {e}")

def _load_from_cache():
    """Load all data from cache files to populate store immediately"""
    try:
        from pathlib import Path
        cache_dir = Path("cache")
        iocs_file = cache_dir / "iocs.json"
        mals_file = cache_dir / "malwares.json"
        vulns_file = cache_dir / "vulnerabilities.json"
        meta_file = cache_dir / "metadata.json"

        if iocs_file.exists():
            with open(iocs_file, encoding='utf-8') as f:
                store["iocs"] = json.load(f)
        if mals_file.exists():
            with open(mals_file, encoding='utf-8') as f:
                store["malwares"] = json.load(f)
        if vulns_file.exists():
            with open(vulns_file, encoding='utf-8') as f:
                store["vulnerabilities"] = json.load(f)

        if meta_file.exists():
            meta = json.loads(meta_file.read_text(encoding='utf-8'))
            store["last_update"] = meta.get("last_sync", "")

        print(f"📦 Loaded from cache | IOC:{len(store['iocs'])} Mal:{len(store['malwares'])} Vuln:{len(store['vulnerabilities'])}")
    except Exception as e:
        print(f"⚠️ Cache load error: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_upload_data()
    # Load from cache immediately to make data available
    _load_from_cache()
    scheduler.add_job(_refresh, "interval", minutes=15, id="auto_refresh")
    scheduler.start()
    print("\n http://localhost:8002\n")
    import threading
    threading.Thread(target=_refresh, daemon=True).start()
    yield
    scheduler.shutdown()

app = FastAPI(title="TI Agentic Demo", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def _refresh():
    print(f"\n[{datetime.now(VN_TZ):%H:%M:%S}] 🔄 Auto-refresh...")
    try:
        from agents.ti_fetch_agent import fetch_all
        from agents.matching_agent import run_all_matching
        from agents.nvd_client import fetch_nvd

        # Bước 1: Lấy dữ liệu từ OpenCTI (với cache fallback)
        print("  [1/5] Lay du lieu tu OpenCTI...")
        data = fetch_all(limit=0)
        if not data.get("iocs"):
            print(f"  ⚠️ Khong co du lieu, dung cache cu")
            return

        # Bước 2: Lưu trực tiếp dữ liệu (đã normalize từ ti_fetch_agent)
        print("  [2/5] Chuan hoa va phan loai du lieu...")
        # Data từ fetch_all đã qua _classify, _ioc_t, _mal_t, _vul_t - không cần normalize lại
        normalized = {
            "iocs": data.get("iocs", []),
            "malwares": data.get("malwares", []),
            "vulnerabilities": data.get("vulnerabilities", []),
            "source": data.get("source", ""),
            "fetched_at": data.get("fetched_at", "")
        }

        # Bước 3: Enrichment - Lấy thêm thông tin từ NVD cho CVE
        print("  [3/5] Enrichment du lieu tu NVD...")
        # Skipping NVD enrichment due to API rate limiting
        # Real data from OpenCTI already has CVSS for most CVEs
        # Only re-enable if you have NVD API key or private mirror

        # Bước 4: Matching - So khớp với thiết bị nội bộ
        print("  [4/5] Matching voi thiet bi noi bo...")
        fresh_ioc_names  = {i["name"] for i in normalized["iocs"]}
        fresh_vuln_names = {v["name"] for v in normalized["vulnerabilities"]}
        extra_iocs  = [i for i in store["uploaded_iocs"]  if i["name"] not in fresh_ioc_names]
        extra_vulns = [v for v in store["uploaded_vulns"] if v["name"] not in fresh_vuln_names]

        all_iocs = normalized["iocs"] + extra_iocs
        all_vulns = normalized["vulnerabilities"] + extra_vulns

        store["iocs"] = all_iocs
        store["malwares"] = normalized["malwares"]
        store["vulnerabilities"] = all_vulns
        store["actors"] = normalized.get("actors", [])
        store["source"] = normalized.get("source", "")

        matches = run_all_matching(
            {"iocs": all_iocs, "malwares": store["malwares"], "vulnerabilities": all_vulns},
            "assets/devices.xlsx")
        store["matches"] = matches

        # Bước 5: Phân tích và cập nhật
        print("  [5/5] Phan tich va cap nhat...")
        store["last_update"] = datetime.now(VN_TZ).strftime("%d/%m/%Y %H:%M:%S")

        print(f"\n✅ Refresh OK")
        print(f"   IOC: {len(all_iocs)} | Malware: {len(store['malwares'])} | Vuln: {len(all_vulns)} | Matches: {len(matches)}")
        print(f"   Nguon: {store['source']}")

    except Exception as e:
        print(f"\n❌ Refresh error: {e}")
        traceback.print_exc()

def _ollama_ok():
    try: ollama.list(); return True
    except: return False

def _build_context(query, live_search=False):
    ql=query.lower(); words=[w for w in ql.split() if len(w)>2]; parts=[]
    def hit(t): return any(w in (t or "").lower() for w in words)
    iocs=[i for i in store["iocs"] if hit(i.get("name","")) or hit(i.get("description",""))]
    mals=[m for m in store["malwares"] if hit(m.get("name","")) or hit(m.get("description",""))]
    vuls=[v for v in store["vulnerabilities"] if hit(v.get("name","")) or hit(v.get("description",""))]
    devs=[m for m in store["matches"] if hit(m.get("threat_name","")) or hit(m.get("asset_hostname",""))]
    if live_search:
        try:
            from agents.ti_fetch_agent import search_opencti
            lv=search_opencti(query,limit=10)
            ex={i["id"] for i in iocs}
            for i in lv.get("iocs",[]):
                if i["id"] not in ex: iocs.append(i); ex.add(i["id"])
            if lv.get("source")=="OpenCTI": parts.append("(Tim kiem truc tiep OpenCTI)")
        except: pass
    if iocs:
        parts.append(f"=== IOC ({len(iocs)}) ===")
        for i in iocs[:8]: parts.append(f"- [{i.get('risk_level','?').upper()}] {i['name']} ({i.get('ioc_type','?')}): {i.get('description','')[:100]}")
    if mals:
        parts.append("=== Malware ===")
        for m in mals[:5]: parts.append(f"- {m['name']} ({','.join(m.get('malware_types',[]))}): {m.get('description','')[:100]}")
    if vuls:
        parts.append("=== CVE ===")
        for v in vuls[:5]: parts.append(f"- {v['name']} CVSS:{v.get('cvss_score','?')}: {v.get('description','')[:100]}")
    if devs:
        parts.append("=== Thiet bi ===")
        for d in devs[:6]: parts.append(f"- {d['asset_hostname']} ({d['asset_ip']}) -- {d['threat_name']}")
    return "\n".join(parts)

@app.get("/api/health")
async def health():
    return {"status":"ok","backend":"running","ollama":"connected" if _ollama_ok() else "offline",
            "source":store["source"],"ioc_count":len(store["iocs"]),"malware_count":len(store["malwares"]),
            "vuln_count":len(store["vulnerabilities"]),"match_count":len(store["matches"]),"last_update":store["last_update"]}

@app.post("/api/refresh")
async def manual_refresh():
    import asyncio, threading
    # Run _refresh in a background thread since it's not async
    threading.Thread(target=_refresh, daemon=True).start()
    return {"status":"ok","message":"Dang cap nhat..."}

@app.get("/api/stats")
async def stats():
    iocs,matches=store["iocs"],store["matches"]
    return {"ioc_total":len(iocs),"ioc_critical":sum(1 for i in iocs if i.get("risk_level")=="critical"),
            "ioc_high":sum(1 for i in iocs if i.get("risk_level")=="high"),"ioc_medium":sum(1 for i in iocs if i.get("risk_level")=="medium"),
            "ioc_fp":sum(1 for i in iocs if i.get("is_false_positive")),"malware_count":len(store["malwares"]),
            "vuln_count":len(store["vulnerabilities"]),"vuln_critical":sum(1 for v in store["vulnerabilities"] if v.get("severity")=="critical"),
            "match_count":len(matches),"affected_assets":len(set(m["asset_hostname"] for m in matches)),
            "last_update":store["last_update"],"source":store["source"]}

@app.get("/api/iocs")
async def get_iocs(limit:int=0,risk:str=""):
    d=store["iocs"]
    if risk: d=[i for i in d if i.get("risk_level")==risk]
    data = [dict(i) for i in d] if limit<=0 else [dict(i) for i in d[:limit]]
    return JSONResponse({"status":"ok","count":len(data),"data":data,"last_update":store["last_update"]})

@app.get("/api/malwares")
async def get_malwares():
    # Convert to list of pure dicts to avoid serialization issues
    data = [dict(m) for m in store["malwares"]]
    return JSONResponse({"status":"ok","count":len(data),"data":data})

@app.get("/api/vulnerabilities")
async def get_vulns():
    data = []
    for v in store["vulnerabilities"]:
        vuln = dict(v)
        # Try to get NVD data for this CVE (from cache or fetch)
        cve_name = vuln.get("name", "")
        if cve_name and cve_name.upper().startswith("CVE-"):
            # Check cache first
            if cve_name not in store["nvd_cache"]:
                nvd_data = fetch_nvd(cve_name)
                if nvd_data:
                    store["nvd_cache"][cve_name] = nvd_data

            nvd_data = store["nvd_cache"].get(cve_name, {})
            if nvd_data:
                # Merge NVD data, preferring NVD over OpenCTI
                vuln["cvss_score"] = nvd_data.get("cvss_v3_score") or vuln.get("cvss_score", 0)
                vuln["cvss_v3_score"] = nvd_data.get("cvss_v3_score")
                vuln["severity"] = nvd_data.get("cvss_v3_severity") or vuln.get("severity", "unknown")
                vuln["cvss_v3_severity"] = nvd_data.get("cvss_v3_severity")
                vuln["attack_vector"] = nvd_data.get("attack_vector", "N/A")
                vuln["attack_complexity"] = nvd_data.get("attack_complexity", "N/A")
                vuln["weaknesses"] = nvd_data.get("weaknesses", [])
                vuln["affected_cpes"] = nvd_data.get("affected_cpes", [])
                vuln["cisa_exploit_add"] = nvd_data.get("cisa_exploit_add", "")
                vuln["published"] = nvd_data.get("published", "")
                vuln["vul_status"] = nvd_data.get("vul_status", "")
                vuln["description_en"] = nvd_data.get("description_en", "")
        data.append(vuln)
    return JSONResponse({"status":"ok","count":len(data),"data":data})

@app.get("/api/matches")
async def get_matches(type:str=""):
    d=store["matches"]
    if type: d=[m for m in d if m.get("match_type","").lower()==type.lower()]
    data = [dict(m) for m in d]
    return JSONResponse({"status":"ok","count":len(data),"data":data})

@app.get("/api/search")
async def search(q:str=""):
    if not q:
        return JSONResponse({"iocs":[dict(i) for i in store["iocs"][:200]],"malwares":[dict(m) for m in store["malwares"]],"vulnerabilities":[dict(v) for v in store["vulnerabilities"]],"matches":[dict(m) for m in store["matches"]]})
    ql=q.lower()
    def hit(obj,*keys): return any(ql in str(obj.get(k,"")).lower() for k in keys)
    return JSONResponse({"iocs":[dict(i) for i in store["iocs"] if hit(i,"name","description","ioc_type","risk_level")],
            "malwares":[dict(m) for m in store["malwares"] if hit(m,"name","description")],
            "vulnerabilities":[dict(v) for v in store["vulnerabilities"] if hit(v,"name","description","affected_software")],
            "matches":[dict(m) for m in store["matches"] if hit(m,"threat_name","asset_hostname","match_reasons")]})

@app.get("/api/alerts")
async def get_alerts():
    """Lấy danh sách alerts được tạo bởi agent"""
    return {"status":"ok","count":len(store["alerts"]),"data":store["alerts"]}

# THREAT DETAIL
@app.get("/api/ti/detail")
async def get_ti_detail(id:str="",name:str="",type:str=""):
    from agents.ti_fetch_agent import _use_real
    if not _use_real():
        return JSONResponse(503,{"error":"OpenCTI chua cau hinh"})
    try:
        return _fetch_detail_opencti(id,name,type)
    except Exception as e:
        traceback.print_exc()
        return JSONResponse(500,{"error":str(e)})

def _fetch_detail_opencti(obj_id, name, obj_type):
    from agents.ti_fetch_agent import _gql

    # --- Fragment dung chung cho entity types ---
    ENTITY_FRAG = """
        ... on Malware { __typename name }
        ... on Indicator { __typename name }
        ... on AttackPattern { __typename name x_mitre_id }
        ... on ThreatActor { __typename name }
        ... on IntrusionSet { __typename name }
        ... on Campaign { __typename name }
        ... on Tool { __typename name }
        ... on Vulnerability { __typename name }
        ... on Country { __typename name }
        ... on Sector { __typename name }
        ... on Organization { __typename name }
        ... on Individual { __typename name }
        ... on Report { __typename name }
        ... on Note { __typename attribute_abstract }
        ... on Case { __typename name }
        ... on Grouping { __typename name }
    """

    rels, conts = [], []
    observables = []

    # --- Find object data from store ---
    obj_data = {}
    if obj_type in ["Indicator", "IOC", "Hash", "Domain", "URL", "Wallet", "Yara"]:
        obj_data = next((i for i in store["iocs"] if i.get("id") == obj_id or i.get("name") == name), {})
    elif obj_type == "Malware":
        obj_data = next((m for m in store["malwares"] if m.get("id") == obj_id or m.get("name") == name), {})
    elif obj_type in ["Vulnerability", "CVE"]:
        obj_data = next((v for v in store["vulnerabilities"] if v.get("id") == obj_id or v.get("name") == name), {})

    # ── Fetch NVD data for CVE/Vulnerability ──
    nvd_data = {}
    if obj_type in ["Vulnerability", "CVE"] and obj_data:
        cve_name = obj_data.get("name", name)
        if cve_name:
            nvd_data = fetch_nvd(cve_name)
            if nvd_data:
                # Merge NVD data with obj_data for display
                obj_data = {**obj_data, **nvd_data}

    # ── Latest Created Relationships từ OpenCTI ──
    rel_q = f"""
    query($id:String! $first:Int){{
      stixCoreRelationships(
        fromOrToId:[$id] first:$first
        orderBy:created_at orderMode:desc
      ){{
        edges{{ node{{
          id relationship_type created_at updated_at start_time stop_time confidence
          from{{ {ENTITY_FRAG} }}
          to{{ {ENTITY_FRAG} }}
        }}}}
      }}
    }}"""
    try:
        d = _gql(rel_q, {"id": obj_id, "first": 100})
        for e in d["data"]["stixCoreRelationships"]["edges"]:
            n = e["node"]
            frm = n.get("from") or {}
            to  = n.get("to")  or {}
            def lbl(o):
                return o.get("name") or o.get("attribute_abstract") or o.get("x_mitre_id", "?")
            rels.append({
                "relationship_type": n.get("relationship_type", ""),
                "from_type": frm.get("__typename", ""),
                "from_name": lbl(frm),
                "to_type":   to.get("__typename", ""),
                "to_name":   lbl(to),
                "created_at": str(n.get("created_at", ""))[:16],
                "updated_at": str(n.get("updated_at", ""))[:16],
                "start_time": str(n.get("start_time", ""))[:10],
                "stop_time": str(n.get("stop_time", ""))[:10],
                "confidence": n.get("confidence", 0),
            })
        print(f"  Relationships: {len(rels)} latest relationships retrieved")
    except Exception as e:
        print(f"  Rel query err: {e}")

    # ── Observables liên kết (cho IOC/Indicator/Hash/Domain/URL) ──
    if obj_type in ["Indicator", "IOC", "Hash", "Domain", "URL", "Wallet"]:
        obs_q = f"""
        query($id:String! $first:Int){{
          stixCoreRelationships(
            fromOrToId:[$id] first:$first
            relationship_type:"based-on"
            orderBy:created_at orderMode:desc
          ){{
            edges{{ node{{
              id relationship_type
              from{{
                ... on Indicator {{ id name pattern }}
                ... on ObservedData {{ id }}
              }}
              to{{
                ... on Indicator {{ id name pattern }}
                ... on ObservedData {{ id }}
              }}
            }}}}
          }}
        }}"""
        try:
            d = _gql(obs_q, {"id": obj_id, "first": 100})
            observed_data_ids = set()

            for e in d["data"]["stixCoreRelationships"]["edges"]:
                n = e["node"]
                frm = n.get("from") or {}
                to = n.get("to") or {}

                # Detect ObservedData (has ID but no pattern) vs Indicator (has pattern)
                if frm.get("id"):
                    if frm.get("pattern"):
                        # It's an Indicator, parse pattern
                        pass
                    else:
                        # It's ObservedData, collect for later
                        observed_data_ids.add(frm.get("id"))

                if to.get("id"):
                    if to.get("pattern"):
                        # It's an Indicator, parse pattern
                        pass
                    else:
                        # It's ObservedData, collect for later
                        observed_data_ids.add(to.get("id"))

                # Parse pattern từ Indicator nếu có
                pattern = frm.get("pattern") or to.get("pattern")
                if pattern:
                    import re
                    # Parse STIX pattern: [file:hashes.'SHA-256' = 'value']
                    # Or: [file:hashes.MD5 = 'value']
                    pattern_matches = re.findall(r"\[([^:]+):([^\]]+)\]", pattern)
                    for obj_t, attributes in pattern_matches:
                        # Split multiple conditions in attributes
                        conditions = re.findall(r"([^\s]+)\s*=\s*'([^']+)'", attributes)
                        for attr_name, attr_value in conditions:
                            if 'hashes.' in attr_name.lower():
                                # Extract hash type from hashes.'TYPE' or hashes.TYPE
                                hash_match = re.search(r"hashes\.(?:')?([^']+)(?:')?", attr_name, re.IGNORECASE)
                                if hash_match:
                                    hash_type = hash_match.group(1)
                                    observables.append({
                                        "type": obj_t,
                                        "field": f"Hash ({hash_type})",
                                        "value": attr_value
                                    })
                            else:
                                # Other file properties
                                observables.append({
                                    "type": obj_t,
                                    "field": attr_name,
                                    "value": attr_value
                                })

            # Query ObservedData objects individually
            for obs_id in observed_data_ids:
                obs_detail_q = f"""
                query($id:String!){{
                  stixCyberObservable(id:$id){{
                    id
                    x_opencti_data
                    ... on File {{
                      name
                      size
                      hashes
                    }}
                  }}
                }}"""
                try:
                    obs_data = _gql(obs_detail_q, {"id": obs_id})
                    obs_obj = obs_data.get("data", {}).get("stixCyberObservable", {})
                    if obs_obj:
                        # Try to get from x_opencti_data (raw JSON)
                        if obs_obj.get("x_opencti_data"):
                            try:
                                import json as json_lib
                                raw_data = obs_obj.get("x_opencti_data")
                                if isinstance(raw_data, str):
                                    raw_data = json_lib.loads(raw_data)
                                if isinstance(raw_data, dict):
                                    if raw_data.get("name"):
                                        observables.append({
                                            "type": "File",
                                            "field": "Name",
                                            "value": raw_data.get("name")
                                        })
                                    if raw_data.get("size"):
                                        observables.append({
                                            "type": "File",
                                            "field": "Size",
                                            "value": str(raw_data.get("size"))
                                        })
                            except:
                                pass

                        # Get from standard fields
                        if obs_obj.get("name"):
                            if not any(o.get("field") == "Name" for o in observables):
                                observables.append({
                                    "type": "File",
                                    "field": "Name",
                                    "value": obs_obj.get("name")
                                })
                        if obs_obj.get("size"):
                            if not any(o.get("field") == "Size" for o in observables):
                                observables.append({
                                    "type": "File",
                                    "field": "Size",
                                    "value": str(obs_obj.get("size"))
                                })
                        if obs_obj.get("hashes"):
                            hashes = obs_obj.get("hashes")
                            if isinstance(hashes, dict):
                                for hash_type, hash_val in hashes.items():
                                    observables.append({
                                        "type": "File",
                                        "field": f"Hash ({hash_type})",
                                        "value": hash_val
                                    })
                except Exception as e:
                    print(f"    ObservedData detail err for {obs_id}: {str(e)[:80]}")

            if observables:
                print(f"  Observables: {len(observables)} observables retrieved")
        except Exception as e:
            print(f"  Obs query err: {e}")

    # ── Latest Containers about the object từ OpenCTI ──
    # Try alternative: Get reports containing the object (stixCoreObjectContainers doesn't exist)
    try:
        rep_q = f"""
        query($id:Any! $first:Int){{
          reports(
            first:$first
            orderBy:published orderMode:desc
            filters:{{
              mode:and
              filters:[{{key:"objects" values:[$id]}}]
              filterGroups:[]
            }}
          ){{
            edges{{ node{{
              id name published created modified updated_at confidence
              createdBy{{ name }}
              objectMarking{{ definition }}
            }}}}
          }}
        }}"""
        d2 = _gql(rep_q, {"id": obj_id, "first": 100})
        for e in d2["data"]["reports"]["edges"]:
            n = e["node"]
            conts.append({
                "entity_type": "Report",
                "name":        n.get("name", ""),
                "created_at":  str(n.get("created", ""))[:10],
                "updated_at":  str(n.get("modified") or n.get("updated_at", ""))[:10],
                "published":   str(n.get("published", ""))[:10],
                "author":      (n.get("createdBy") or {}).get("name", ""),
                "marking":     ", ".join(m.get("definition", "") for m in (n.get("objectMarking") or [])),
                "confidence":  n.get("confidence", 0),
            })
        print(f"  Containers (reports): {len(conts)} reports retrieved")
    except Exception as e:
        print(f"  Containers retrieval error: {e}")

    return {
        "id": obj_id, "name": name, "type": obj_type,
        "object_type": obj_type, "object": obj_data,
        "relationships": rels, "containers": conts, "observables": observables, "source": "OpenCTI"
    }

# THREAT MODEL
@app.post("/api/threat-model/device")
async def analyze_one_device(payload:dict):
    hostname=payload.get("hostname",""); ip=payload.get("ip",""); use_ai=payload.get("use_ai",True)
    if not hostname: return JSONResponse(400,{"error":"Thieu hostname"})
    threats=[m for m in store["matches"] if m.get("asset_hostname")==hostname and (not ip or m.get("asset_ip")==ip)]
    if not threats: return JSONResponse(404,{"error":f"Khong tim thay {hostname}"})
    try:
        from agents.threat_model_agent import analyze_device
        result=analyze_device(f"{hostname}|{ip or threats[0].get('asset_ip','N/A')}",threats,use_ai=use_ai)
        return {"status":"ok","data":result}
    except Exception as e:
        traceback.print_exc(); return JSONResponse(500,{"error":str(e)})

# UPLOAD
@app.post("/api/upload")
async def upload(file:UploadFile=File(...)):
    suffix=Path(file.filename).suffix.lower()
    if suffix not in {".json",".csv",".xlsx",".xls",".txt",".pdf"}:
        return JSONResponse(400,{"error":f"Khong ho tro: {suffix}"})
    save_path=Path("uploads")/file.filename
    with open(save_path,"wb") as f: shutil.copyfileobj(file.file,f)
    added=_parse_upload(save_path,suffix)
    store["upload_log"].append({"filename":file.filename,"time":datetime.now(VN_TZ).strftime("%d/%m/%Y %H:%M"),"added":added,"type":suffix.lstrip(".")})
    _save_upload_data()
    return {"status":"ok","filename":file.filename,"added":added,"message":f"Them thanh cong: {added['iocs']} IOC, {added['vulnerabilities']} CVE"}

def _parse_upload(path,suffix):
    from agents.ti_fetch_agent import _classify
    added={"iocs":0,"malwares":0,"vulnerabilities":0}
    ex_ioc={i["name"] for i in store["iocs"]}; ex_vuln={v["name"] for v in store["vulnerabilities"]}
    new_iocs=[]; new_vulns=[]
    def _add_ioc(name,confidence=70,desc="Uploaded"):
        name=str(name).strip()
        if not name or name in ex_ioc or len(name)<4: return
        now=datetime.now(VN_TZ).strftime("%Y-%m-%d")
        ioc=_classify({"id":f"up-{len(new_iocs)}","name":name,"pattern":f"[value='{name}']","type":["malicious-activity"],"confidence":int(confidence),"description":desc,"valid_from":now,"valid_until":"","created_at":now})
        new_iocs.append(ioc); ex_ioc.add(name); added["iocs"]+=1
    def _add_vuln(cve,src=""):
        if not cve or cve in ex_vuln: return
        now=datetime.now(VN_TZ).strftime("%Y-%m-%d")
        new_vulns.append({"id":f"pdf-{cve}","name":cve,"description":f"Trich xuat tu {src}","cvss_score":0,"severity":"unknown","affected_software":"Xem source","patch_available":False,"exploit_in_wild":False,"affected_versions":[],"original_creation_date":now,"modification_date":now,"created_at":now})
        ex_vuln.add(cve); added["vulnerabilities"]+=1
    try:
        if suffix==".pdf": _parse_iocs_from_text(_extract_pdf_text(path),path.name,_add_ioc,_add_vuln)
        elif suffix==".json":
            raw=json.loads(path.read_text(encoding="utf-8"))
            items=raw if isinstance(raw,list) else raw.get("iocs",raw.get("indicators",[raw]))
            for idx,item in enumerate(items):
                _add_ioc(str(item.get("name") or item.get("value") or "").strip(),item.get("confidence",70),str(item.get("description","JSON")))
        elif suffix==".csv":
            df=pd.read_csv(path); cols=[c.lower() for c in df.columns]
            for _,row in df.iterrows():
                name=""
                for col in ["ioc","indicator","value","name","ip","domain","hash"]:
                    if col in cols:
                        v=str(row.iloc[cols.index(col)]).strip()
                        if v and v!="nan": name=v; break
                _add_ioc(name,int(row.get("confidence",70)) if "confidence" in cols else 70,"CSV")
        elif suffix in (".xlsx",".xls"):
            xls=pd.read_excel(path,sheet_name=None)
            for sn,df in xls.items():
                cols=[c.lower() for c in df.columns]
                for _,row in df.iterrows():
                    name=""
                    for col in ["ioc","indicator","value","name","ip","domain","hash"]:
                        if col in cols:
                            v=str(row.iloc[cols.index(col)]).strip()
                            if v and v!="nan": name=v; break
                    _add_ioc(name,70,f"Excel:{path.name}/{sn}")
        elif suffix==".txt":
            _parse_iocs_from_text(path.read_text(encoding="utf-8",errors="ignore"),path.name,_add_ioc,_add_vuln)
    except Exception as e: print(f"Parse loi: {e}")
    store["iocs"].extend(new_iocs); store["vulnerabilities"].extend(new_vulns)
    store["uploaded_iocs"].extend(new_iocs); store["uploaded_vulns"].extend(new_vulns)
    try:
        from agents.matching_agent import run_all_matching
        store["matches"]=run_all_matching({"iocs":store["iocs"],"malwares":store["malwares"],"vulnerabilities":store["vulnerabilities"]},"assets/devices.xlsx")
    except: pass
    return added

def _extract_pdf_text(path):
    parts=[]
    try:
        import pdfplumber
        with pdfplumber.open(str(path)) as pdf:
            for page in pdf.pages:
                t=page.extract_text()
                if t: parts.append(t)
    except Exception as e: print(f"PDF err: {e}")
    return "\n".join(parts)

def _parse_iocs_from_text(text,src,add_ioc,add_vuln):
    for m in re.findall(r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b',text): add_ioc(m,65,f"PDF:{src}")
    for m in re.findall(r'\b[a-fA-F0-9]{32,64}\b',text): add_ioc(m,65,f"PDF:{src}")
    for m in re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',text):
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$',m) and '.' in m and len(m)>6: add_ioc(m,65,f"PDF:{src}")
    for m in re.findall(r'https?://[^\s<>"\']+',text): add_ioc(m[:200],65,f"PDF:{src}")
    for m in re.findall(r'CVE-\d{4}-\d{4,7}',text,re.IGNORECASE): add_vuln(m.upper(),src)

@app.get("/api/upload-log")
async def upload_log(): return {"log":store["upload_log"]}

# PDF REPORT
@app.get("/api/reports/list")
async def list_reports():
    """Liet ke tat ca file PDF trong thu muc reports."""
    reports_dir = Path("reports")
    files = sorted(reports_dir.glob("*.pdf"), key=lambda f: f.stat().st_mtime, reverse=True)
    return {"files": [
        {"name": f.name,
         "size_kb": round(f.stat().st_size / 1024, 1),
         "date": datetime.fromtimestamp(f.stat().st_mtime, VN_TZ).strftime("%d/%m/%Y %H:%M"),
         "path": str(f).replace("\\","/")}
        for f in files
    ]}

@app.post("/api/report")
async def create_report(type: str = "daily"):
    now_vn    = datetime.now(VN_TZ)
    date_str  = now_vn.strftime("%Y-%m-%d_%H%M")
    pdf_path  = f"reports/{type}_report_{date_str}.pdf"
    count_info = _gen_pdf(pdf_path, type, now_vn)
    return {"status":"ok","message":f"Bao cao PDF da tao: {pdf_path}","file":pdf_path,"count_info":count_info}

@app.get("/api/report/download")
async def download_report(file: str = Query(...)):
    p = Path(file)
    if not p.exists():
        p2 = Path("reports") / p.name
        if p2.exists():
            p = p2
        else:
            return JSONResponse(404, {"error": "File khong ton tai"})
    # inline -> browser mo truc tiep thay vi download
    from fastapi.responses import Response
    with open(str(p), "rb") as f:
        content = f.read()
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename=\"{p.name}\""}
    )

def _gen_pdf(out_path,report_type,now_vn=None):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER
    if now_vn is None: now_vn=datetime.now(VN_TZ)

    # --- Loc du lieu theo ky bao cao ---
    today_str = now_vn.strftime("%Y-%m-%d")
    week_start = (now_vn - timedelta(days=now_vn.weekday())).strftime("%Y-%m-%d")
    month_str  = now_vn.strftime("%Y-%m")

    def in_period(item):
        """Kiem tra item co thuoc ky bao cao khong (dua tren created_at hoac modified)."""
        ca = str(item.get("created_at","") or "")[:10]
        mo = str(item.get("modified","") or item.get("valid_from","") or "")[:10]
        date = ca if ca > mo else mo   # lay ngay muon nhat
        if not date or len(date) < 7:
            return True  # khong co ngay -> luon hien
        if report_type == "daily":
            return date == today_str
        elif report_type == "weekly":
            return date >= week_start
        elif report_type == "monthly":
            return date[:7] == month_str
        return True

    all_iocs    = store["iocs"]
    all_mals    = store["malwares"]
    all_vulns   = store["vulnerabilities"]
    all_matches = store["matches"]

    iocs    = [i for i in all_iocs    if in_period(i)]
    mals    = [m for m in all_mals    if in_period(m)]
    vulns   = [v for v in all_vulns   if in_period(v)]
    matches = [m for m in all_matches if in_period(m)]

    # Neu loc qua khat thi lay het nhung danh dau
    filtered = len(iocs) < len(all_iocs) or len(vulns) < len(all_vulns)
    period_label = {
        "daily":   f"ngày {now_vn.strftime('%d/%m/%Y')}",
        "weekly":  f"tuần từ {week_start}",
        "monthly": f"tháng {now_vn.strftime('%m/%Y')}",
    }.get(report_type, "")

    doc=SimpleDocTemplate(out_path,pagesize=A4,leftMargin=1.8*cm,rightMargin=1.8*cm,topMargin=2*cm,bottomMargin=2*cm)
    styles=getSampleStyleSheet()
    C_HEAD=colors.HexColor("#1a237e"); C_ALT=colors.HexColor("#e8eaf6"); C_WHITE=colors.white
    RCOL={"critical":colors.HexColor("#b71c1c"),"high":colors.HexColor("#e65100"),"medium":colors.HexColor("#f57f17"),"low":colors.HexColor("#2e7d32")}
    title_s=ParagraphStyle("t",parent=styles["Title"],fontSize=16,textColor=C_HEAD,alignment=TA_CENTER,spaceAfter=4)
    sub_s=ParagraphStyle("s",parent=styles["Normal"],fontSize=9,textColor=colors.HexColor("#546e7a"),alignment=TA_CENTER,spaceAfter=2)
    h2_s=ParagraphStyle("h",parent=styles["Heading2"],fontSize=12,textColor=C_HEAD,spaceBefore=12,spaceAfter=6)
    sm_s=ParagraphStyle("sm",parent=styles["Normal"],fontSize=8,leading=11)
    def rc(level): return RCOL.get((level or "").lower(),colors.grey)
    def tbl(headers,rows,widths):
        data=[headers]+(rows or [["—"]*len(headers)])
        t=Table(data,colWidths=widths,repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_HEAD),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),8),("ALIGN",(0,0),(-1,0),"CENTER"),
            ("FONTNAME",(0,1),(-1,-1),"Helvetica"),("FONTSIZE",(0,1),(-1,-1),7.5),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#b0bec5")),("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_ALT]),
            ("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
        return t

    type_label={"daily":"HÀNG NGÀY","weekly":"HÀNG TUẦN","monthly":"HÀNG THÁNG"}.get(report_type,"ĐỊNH KỲ")
    story=[Spacer(1,0.3*cm)]
    story.append(Paragraph(f"BÁO CÁO THREAT INTELLIGENCE {type_label}",title_s))
    story.append(Paragraph(
        f"Kỳ: {period_label}  |  Tạo lúc: {now_vn.strftime('%d/%m/%Y %H:%M:%S')} (UTC+7)  |  "
        f"Nguồn: {store.get('source','?')}",sub_s))
    if filtered:
        story.append(Paragraph(
            f"* Chỉ hiển thị dữ liệu trong {period_label}. "
            f"Tổng kho: {len(all_iocs)} IOC | {len(all_vulns)} CVE | {len(all_mals)} Malware",
            ParagraphStyle("note",parent=styles["Normal"],fontSize=8,textColor=colors.HexColor("#e65100"),alignment=TA_CENTER,spaceAfter=4)))
    story.append(HRFlowable(width="100%",thickness=1.5,color=C_HEAD,spaceAfter=10))

    story.append(Paragraph("1. TỔNG QUAN",h2_s))
    story.append(tbl(["Chỉ số","Giá trị","Chỉ số","Giá trị"],[
        ["Tổng IOC",str(len(iocs)),"Critical",str(sum(1 for i in iocs if i.get("risk_level")=="critical"))],
        ["False Positive",str(sum(1 for i in iocs if i.get("is_false_positive"))),"High",str(sum(1 for i in iocs if i.get("risk_level")=="high"))],
        ["Malware",str(len(mals)),"CVE Critical",str(sum(1 for v in vulns if v.get("severity")=="critical"))],
        ["Thiết bị ảnh hưởng",str(len(set(m["asset_hostname"] for m in matches))),"Tổng matches",str(len(matches))]
    ],[5.5*cm,3*cm,5.5*cm,3*cm]))
    story.append(Spacer(1,0.3*cm))

    danger=[i for i in iocs if i.get("risk_level") in ("critical","high")]
    story.append(Paragraph(f"2. IOC NGUY HIỂM — {len(danger)} mục ({period_label})",h2_s))
    if danger:
        story.append(tbl(["IOC","Loại","Mức độ","Conf.","Ngày tạo","Lý do"],
            [[Paragraph(i["name"],sm_s),i.get("ioc_type","?"),
              Paragraph(f'<font color="{rc(i["risk_level"]).hexval()}">{i["risk_level"].upper()}</font>',sm_s),
              f'{i.get("confidence",0)}%',str(i.get("created_at",""))[:10],
              Paragraph(i.get("reason","")[:60],sm_s)] for i in danger[:35]],
            [5.5*cm,1.8*cm,2.2*cm,1.3*cm,2.2*cm,4.5*cm]))
    elif filtered:
        story.append(Paragraph(f"Không có IOC nguy hiểm mới trong {period_label}.",sm_s))
    story.append(Spacer(1,0.3*cm))

    story.append(Paragraph(f"3. LỖ HỔNG — {len(vulns)} mục ({period_label})",h2_s))
    if vulns:
        story.append(tbl(["CVE","CVSS","Mức độ","Phần mềm","Patch","Ngày tạo","Mô tả"],
            [[Paragraph(f'<b>{v["name"]}</b>',sm_s),
              Paragraph(f'<font color="{rc(v["severity"]).hexval()}">{str(v.get("cvss_score","?"))}</font>',sm_s),
              Paragraph(f'<font color="{rc(v["severity"]).hexval()}">{v.get("severity","?").upper()}</font>',sm_s),
              v.get("affected_software","?"),"Có" if v.get("patch_available") else "Chưa",
              str(v.get("created_at",""))[:10],Paragraph(v.get("description","")[:70],sm_s)] for v in vulns[:25]],
            [2.8*cm,1.3*cm,2*cm,2.5*cm,1.3*cm,2*cm,5.6*cm]))
    elif filtered:
        story.append(Paragraph(f"Không có CVE mới trong {period_label}.",sm_s))
    story.append(Spacer(1,0.3*cm))

    story.append(Paragraph(f"4. MALWARE — {len(mals)} mục ({period_label})",h2_s))
    if mals:
        story.append(tbl(["Tên","Loại","Mức độ","Ngày tạo","Ngày chỉnh sửa","Mô tả"],
            [[Paragraph(f'<b>{m["name"]}</b>',sm_s),", ".join(m.get("malware_types",[]))[:25],
              Paragraph(f'<font color="{rc(m["severity"]).hexval()}">{m.get("severity","?").upper()}</font>',sm_s),
              str(m.get("created_at",""))[:10],str(m.get("modified",""))[:10],
              Paragraph(m.get("description","")[:90],sm_s)] for m in mals[:20]],
            [3.5*cm,2.8*cm,2*cm,2.2*cm,2.2*cm,4.8*cm]))
    elif filtered:
        story.append(Paragraph(f"Không có Malware mới trong {period_label}.",sm_s))
    story.append(Spacer(1,0.3*cm))

    crit_m=[m for m in matches if m.get("risk_level") in ("critical","high")]
    story.append(Paragraph(f"5. THIẾT BỊ BỊ ẢNH HƯỞNG — {len(crit_m)} mục",h2_s))
    if crit_m:
        story.append(tbl(["Thiết bị","IP","Mối đe dọa","Loại","Mức độ","Hành động"],
            [[Paragraph(f'<b>{m.get("asset_hostname","?")}</b>',sm_s),m.get("asset_ip","?"),
              Paragraph(m.get("threat_name","?"),sm_s),m.get("match_type","?"),
              Paragraph(f'<font color="{rc(m["risk_level"]).hexval()}">{m["risk_level"].upper()}</font>',sm_s),
              Paragraph(m.get("recommendation","")[:70],sm_s)] for m in crit_m[:25]],
            [3*cm,2.5*cm,3*cm,2*cm,2*cm,5*cm]))

    story.extend([Spacer(1,0.6*cm),HRFlowable(width="100%",thickness=0.5,color=colors.HexColor("#b0bec5")),Spacer(1,0.15*cm)])
    story.append(Paragraph(
        f"Báo cáo tự động bởi TI Agentic Demo  |  {now_vn.strftime('%d/%m/%Y %H:%M:%S')} (UTC+7)  |  Kỳ: {period_label}",
        ParagraphStyle("ft",parent=styles["Normal"],fontSize=7,textColor=colors.HexColor("#90a4ae"),alignment=TA_CENTER)))
    doc.build(story)
    print(f"PDF: {out_path}")
    return f"IOC: {len(iocs)} | CVE: {len(vulns)} | Malware: {len(mals)} | Kỳ: {period_label}"


# OPEN REPORTS FOLDER
@app.post("/api/reports/open-folder")
async def open_reports_folder():
    import subprocess, platform
    reports_path = Path("reports").resolve()
    try:
        sys_name = platform.system()
        if sys_name == "Windows":
            subprocess.Popen(["explorer", str(reports_path)])
        elif sys_name == "Darwin":
            subprocess.Popen(["open", str(reports_path)])
        else:
            subprocess.Popen(["xdg-open", str(reports_path)])
        return {"status":"ok","path":str(reports_path)}
    except Exception as e:
        return JSONResponse(500,{"error":str(e),"path":str(reports_path)})


# AI AGENT — Run agentic analysis
class AgentQuery(BaseModel):
    query: str

@app.post("/api/agent/run")
async def run_agent_endpoint(req: AgentQuery):
    if not req.query or not req.query.strip():
        return {"success":False,"error":"query required"}

    if not _ollama_ok():
        return {"success":False,"error":"Ollama offline"}

    try:
        from agents.ai_agent import run_agent

        steps = []
        for event in run_agent(req.query.strip(), store):
            steps.append(event)

        return {"success":True,"steps":steps,"count":len(steps)}
    except Exception as e:
        return {"success":False,"error":str(e)[:200]}


# WEBSOCKET CHAT
@app.websocket("/ws/chat")
async def chat_ws(websocket: WebSocket):
    await websocket.accept()
    from agents.ai_agent import run_agent

    # Send welcome message as JSON
    welcome_msg = {
        "type": "welcome",
        "content": f"🤖 TI-Bot san sang (Agentic AI)!\n📊 IOC:{len(store['iocs'])} | Mal:{len(store['malwares'])} | CVE:{len(store['vulnerabilities'])}\n🔗 Nguon: {store['source']}\n\n💡 Toi co the giup ban tim kiem, phan tich threat, va dua ra kien nghi bao ve."
    }

    if not _ollama_ok():
        await websocket.send_json({"type": "error", "content": "Ollama offline"})
        return

    await websocket.send_json(welcome_msg)

    try:
        while True:
            msg=await websocket.receive_text()
            if not msg.strip(): continue

            if not _ollama_ok():
                await websocket.send_json({"type":"error","content":"Ollama offline."})
                continue

            try:
                # Chay AI Agent
                for event in run_agent(msg, store):
                    if event["type"] == "reasoning":
                        await websocket.send_json({
                            "type": "reasoning",
                            "step": event.get("step", 1),
                            "content": event.get("content")
                        })
                    elif event["type"] == "tool_use":
                        await websocket.send_json({
                            "type": "thinking",
                            "step": event.get("step", 1),
                            "tool": event.get("tool"),
                            "args": event.get("args")
                        })
                    elif event["type"] == "tool_result":
                        count = event.get("result", {}).get("count", 0)
                        await websocket.send_json({
                            "type": "tool_result",
                            "step": event.get("step", 1),
                            "tool": event.get("tool"),
                            "count": count
                        })
                    elif event["type"] == "alert":
                        await websocket.send_json({
                            "type": "alert",
                            "severity": event.get("severity"),
                            "threat": event.get("threat_name"),
                            "assets": event.get("affected_assets", []),
                            "message": event.get("alert_message", "")
                        })
                    elif event["type"] == "memory_recall":
                        await websocket.send_json({
                            "type": "memory_recall",
                            "entity": event.get("entity"),
                            "history": event.get("history", {})
                        })
                    elif event["type"] == "final":
                        await websocket.send_json({
                            "type": "message",
                            "content": event.get("content")
                        })
                    elif event["type"] == "error":
                        await websocket.send_json({
                            "type": "error",
                            "content": event.get("error")
                        })
            except Exception as e:
                await websocket.send_json({"type":"error","content":f"Loi AI: {str(e)[:200]}"})
    except WebSocketDisconnect: pass
    except Exception as e: print(f"WS loi: {e}")

if os.path.exists("frontend"):
    app.mount("/",StaticFiles(directory="frontend",html=True),name="static")

if __name__=="__main__":
    import uvicorn
    uvicorn.run(app,host="0.0.0.0",port=8002,reload=False)
