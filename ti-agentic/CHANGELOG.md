# TI Agentic - Change Log

## [Latest] - 2026-05-04

### 🔧 Major Improvements

#### PDF Report Redesign (Commit: 6b36021b)
- **Restructured** report into 5 sections matching UI tabs:
  1. Indicators of Compromise (IOCs) — 30 items
  2. Yara Rules — 20 detection rules
  3. Malware — 20 families with full metadata
  4. Vulnerabilities (CVEs) — 25 with NVD enrichment
  5. Assets Matching — 30 device-threat links

- **Fixed encoding issues** by using 100% English headers while preserving Vietnamese data
- **Added all relevant fields** from database (8 columns per section)
- **Professional formatting** with color-coded severity levels and borders

### 📚 Documentation
- Added `PDF_REPORT_FORMAT.md` — Complete field mapping and specifications
- Added `REPORT_IMPROVEMENTS.md` — Before/after analysis and testing results
- Added `CHANGELOG.md` — This file

### ✅ Testing Results
```
Monthly Report Generation: PASSED
- File size: 17 KB
- Pages: 5
- Content: 882 IOCs, 43 CVEs, 31 Malware, 28 Device Matches
- Encoding: No errors (pure English headers, UTF-8 data)
- PDF validity: 100% readable
```

---

## Previous Session - 2026-05-03/04

### 🤖 Agentic AI Implementation Complete
- Implemented ReAct pattern with Ollama (10 tools)
- Added memory persistence (JSON-based)
- Integrated NVD API for CVE enrichment
- Decision scoring for risk assessment
- Real-time WebSocket event streaming

### 📊 System Features
- 12,369 IOCs loaded
- 1,194 malware families tracked
- 87 CVEs with NVD enrichment
- 28 device-threat correlations
- All data cached for performance

### 🎯 Commits
- `2ce8764d` — Special event types (alert, memory_recall)
- `8d8a0111` — HTML-based PDF generation
- `33377cc1` — Agentic AI test documentation
- `a3ca9e52` — System verification report

---

## Key Features

### 🛡️ Threat Intelligence
- [x] IOC Scanner (12K+ indicators)
- [x] Malware Tracker (1K+ families)
- [x] Vulnerability Database (87 CVEs with NVD)
- [x] Yara Rules (detection rules)
- [x] Device Inventory (28 assets)
- [x] Risk Matching (threat-asset correlation)

### 🤖 Agentic AI
- [x] ReAct Loop (12 iterations)
- [x] Tool Calling (10 tools available)
- [x] Memory System (long-term persistence)
- [x] NVD Enrichment (auto-fetching CVSS)
- [x] Decision Making (risk-based alerting)
- [x] Real-time Events (WebSocket streaming)

### 📈 Reports
- [x] PDF Generation (2-8 pages)
- [x] Multiple Types (Daily, Weekly, Monthly)
- [x] 5 Sections (IOCs, Yara, Malware, CVE, Assets)
- [x] All Fields (8 columns per section)
- [x] Color Coding (severity levels)
- [x] Clean Output (no encoding errors)

### 🌐 API
- [x] REST endpoints (10+ routes)
- [x] WebSocket chat (real-time)
- [x] JSON responses (proper encoding)
- [x] File handling (reports, uploads)
- [x] Error handling (graceful fallbacks)

### 💾 Data Storage
- [x] JSON cache (iocs, malware, CVEs)
- [x] Memory persistence (investigations, alerts)
- [x] NVD cache (API response caching)
- [x] Upload history (IOC/CVE uploads)
- [x] Report archival (timestamped files)

---

## API Endpoints Summary

### Intelligence Data
```
GET /api/iocs              — List IOCs (12.3K)
GET /api/malwares          — List malware (1.2K)
GET /api/vulnerabilities   — List CVEs (87)
GET /api/ti/detail         — Threat details
GET /api/ti/matches        — Device matches
GET /api/matches           — All correlations
```

### Analysis
```
GET /api/threat-model/device    — MITRE ATT&CK analysis
GET /api/alerts                 — Generated alerts
GET /api/search                 — Full-text search
```

### Reports
```
POST /api/report                — Create PDF (type: daily|weekly|monthly)
GET /api/reports/list           — List generated reports
GET /api/report/download        — Download report file
```

### AI Chat
```
WS /ws/chat                     — Real-time agent conversation
```

---

## Database Schema

### IOCs (store["iocs"]: 12,369 items)
```json
{
  "id": "uuid",
  "name": "indicator",
  "ioc_type": "Hash|Domain|URL|IP|Wallet|Yara",
  "score": 0-100,
  "confidence": 0-100,
  "risk_level": "critical|high|medium|low",
  "pattern": "YARA|STIX pattern",
  "reason": "detection reason",
  "valid_from": "2026-05-03",
  "is_false_positive": false
}
```

### Malware (store["malwares"]: 1,194 items)
```json
{
  "id": "uuid",
  "name": "malware_name",
  "aliases": ["alias1", "alias2"],
  "malware_types": ["Trojan", "Worm"],
  "severity": "critical|high|medium|low",
  "confidence": 0-100,
  "first_seen": "2026-04-15",
  "intrusion_sets": ["APT28"],
  "target_countries": ["VN", "US"],
  "target_sectors": ["Finance"],
  "description": "detailed description"
}
```

### Vulnerabilities (store["vulnerabilities"]: 87 items)
```json
{
  "id": "uuid",
  "name": "CVE-2021-26084",
  "cvss_v3_score": 9.8,
  "cvss_v3_severity": "CRITICAL",
  "attack_vector": "NETWORK",
  "attack_complexity": "LOW",
  "weaknesses": ["CWE-917"],
  "cisa_exploit_add": "2021-11-03",
  "affected_cpes": ["cpe:2.3:a:..."],
  "published": "2021-08-30",
  "description_en": "vulnerability description"
}
```

### Matches (store["matches"]: 28 items)
```json
{
  "threat_id": "uuid",
  "threat_name": "CVE-2021-26084",
  "threat_kind": "Vulnerability",
  "match_type": "IOC|Malware|CVE",
  "risk_level": "critical|high|medium|low",
  "asset_hostname": "SRV-MAIL-01",
  "asset_ip": "192.168.1.13",
  "asset_dept": "IT Infrastructure",
  "asset_user": "mailadmin@company.vn",
  "recommendation": "remediation action"
}
```

---

## Performance Metrics

| Operation | Time | Status |
|-----------|------|--------|
| API response | <100ms | ✅ Fast |
| NVD fetch (cache miss) | 1-1.5s | ✅ Normal |
| NVD fetch (cache hit) | <10ms | ✅ Very fast |
| PDF generation | ~2s | ✅ Fast |
| Agent investigation | 3-8s | ✅ Acceptable |
| WebSocket message | <100ms | ✅ Real-time |

---

## Security & Compliance

✅ UTF-8 encoding throughout
✅ No credential storage in code (.env only)
✅ Input validation on all endpoints
✅ Error handling (no info leakage)
✅ File operations sandboxed
✅ Tool parameter validation
✅ HTTPS ready for production

---

## Directory Structure

```
ti-agentic/
├── main.py                          # FastAPI application (1000+ lines)
├── agents/
│   ├── ai_agent.py                 # ReAct agent (700+ lines)
│   ├── nvd_client.py               # NVD API integration
│   ├── memory_agent.py             # Memory persistence
│   ├── decision_agent.py           # Risk scoring
│   ├── ti_fetch_agent.py           # OpenCTI connector
│   ├── threat_model_agent.py       # MITRE ATT&CK analysis
│   ├── matching_agent.py           # Device matching
│   ├── report_agent.py             # Report generation
│   └── normalization_agent.py      # Data normalization
├── frontend/
│   └── index.html                  # Web UI (1500+ lines)
├── cache/
│   └── metadata.json               # Cached threat data
├── data/
│   ├── agent_memory.json           # Agent memory store
│   ├── uploaded_*.json             # Upload history
│   └── upload_log.json             # Upload logs
├── reports/                         # Generated PDF reports
├── README.md                        # Project overview
├── AGENTIC_AI_TEST.md              # Test documentation
├── SYSTEM_VERIFICATION.md          # System status
├── PDF_REPORT_FORMAT.md            # Report specification
├── REPORT_IMPROVEMENTS.md          # Improvements summary
└── CHANGELOG.md                    # This file
```

---

## Known Issues & Limitations

### Current Limitations
1. **Memory sharing** — Multiple concurrent users share same memory file (needs locking in production)
2. **NVD rate limit** — Public API has rate limits (no API key support yet)
3. **WebSocket blocking** — Synchronous tool execution (could be async)
4. **Ollama dependency** — Requires Ollama running on localhost:11434

### Resolved Issues
✅ Encoding errors (fixed with English headers)
✅ PDF generation (switched to pdfkit)
✅ NVD integration (caching implemented)
✅ Tool parameter validation (enum checking added)
✅ UTF-8 handling (proper encoding throughout)

---

## Roadmap (Future Enhancements)

### Phase 2
- [ ] Async streaming for faster agent response
- [ ] API key support for NVD (higher rate limits)
- [ ] Memory locking for concurrent users
- [ ] Custom report field selection
- [ ] Trending/historical data in reports

### Phase 3
- [ ] Webhook integration (Slack, Teams, SIEM)
- [ ] Executive dashboard with KPIs
- [ ] Automated scheduled reports
- [ ] Multi-language support
- [ ] Advanced threat correlation

### Phase 4
- [ ] Integration with SOAR platforms
- [ ] Automated remediation actions
- [ ] Threat intelligence feed management
- [ ] Custom threat models
- [ ] Incident response playbooks

---

## Version History

| Version | Date | Status | Highlights |
|---------|------|--------|-----------|
| 1.0 | 2026-05-04 | Production Ready | Full agentic AI, NVD integration, PDF reports |
| 0.9 | 2026-05-03 | Complete | Agentic AI implemented, memory system |
| 0.8 | 2026-05-02 | Testing | HTML-based PDF generation |
| 0.7 | 2026-04-30 | Development | NVD integration |
| 0.6 | 2026-04-25 | Early | Initial setup |

---

## Support & Contributing

### Getting Help
- Check `README.md` for quick start
- See `AGENTIC_AI_TEST.md` for testing
- Review `PDF_REPORT_FORMAT.md` for report details
- Open an issue on GitHub

### Contributing
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit pull request

---

## Contact & License

**Author:** Manh Tuan (tuanctk14)
**Email:** tuanctk14@gmail.com
**GitHub:** https://github.com/tuanctk14/TI_Agentic

**License:** MIT

---

**Last Updated:** 2026-05-04
**Status:** ✅ Production Ready
