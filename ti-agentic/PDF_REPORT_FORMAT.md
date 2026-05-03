# TI Agentic PDF Report Format Documentation

## Overview

The PDF report has been completely redesigned to match the UI tabs and provide comprehensive threat intelligence data with proper formatting.

**Key Features:**
- ✅ Fully English text (no encoding issues)
- ✅ 5 sections matching UI tabs
- ✅ All relevant database fields displayed
- ✅ Color-coded risk levels
- ✅ Professional table formatting
- ✅ Multiple report types: Daily, Weekly, Monthly

---

## Report Structure

### 1. Indicators of Compromise (IOCs)

Displays all IOCs (non-Yara rules) from the threat intelligence database.

**Fields shown:**
| Field | Source | Example |
|-------|--------|---------|
| Indicator | IOC name | `3c2aa3687ac9f466ce909e2cb12b07a5` |
| Type | ioc_type | Hash, Domain, URL, IP, Wallet |
| Score | score field | 0-100 |
| Risk Level | risk_level | CRITICAL, HIGH, MEDIUM, LOW |
| Confidence | confidence | 0-100% |
| Valid From | valid_from | 2026-05-03 |
| Reason | reason | "Da xac nhan doc hai" |

**Display:**
- Up to 30 IOCs per report
- Color-coded by risk level (red for critical, orange for high, etc.)
- Sorted by importance

---

### 2. Yara Rules

Displays Yara detection rules from the IOC database (filtered by ioc_type == "Yara").

**Fields shown:**
| Field | Source | Example |
|-------|--------|---------|
| Rule Name | IOC name | Custom rule identifier |
| Pattern | pattern field | YARA pattern (truncated to 40 chars) |
| Score | score field | 0-100 |
| Risk Level | risk_level | CRITICAL, HIGH, MEDIUM, LOW |
| Valid From | valid_from | 2026-05-03 |

**Display:**
- Up to 20 Yara rules per report
- Pattern truncated to 40 characters (with "..." if longer)
- Color-coded by risk level

---

### 3. Malware

Displays malware families with detailed metadata.

**Fields shown:**
| Field | Source | Example |
|-------|--------|---------|
| Name | malware name | DocSwap, Emotet, etc. |
| Aliases | aliases array | Alternative names (up to 2 shown) |
| Types | malware_types array | Trojan, Worm, Backdoor, etc. (up to 2) |
| Severity | severity | CRITICAL, HIGH, MEDIUM, LOW |
| Confidence | confidence | 0-100% |
| First Seen | first_seen | 1970-01-01 (year first discovered) |
| Intrusion Sets | intrusion_sets array | APT28, Lazarus, etc. (first one shown) |

**Display:**
- Up to 20 malware families per report
- Severity color-coded
- Full description available in database

---

### 4. Vulnerabilities (CVEs)

Displays security vulnerabilities with NVD enrichment.

**Fields shown:**
| Field | Source | Example |
|-------|--------|---------|
| CVE ID | name field | CVE-2021-26084 |
| CVSS Score | cvss_v3_score (fallback: cvss_score) | 9.8 |
| Severity | cvss_v3_severity (fallback: severity) | CRITICAL, HIGH, MEDIUM, LOW |
| Attack Vector | attack_vector (from NVD) | NETWORK, LOCAL, ADJACENT |
| Complexity | attack_complexity | LOW, HIGH |
| CWE | weaknesses array | CWE-917, CWE-502, etc. |
| CISA Exploit | cisa_exploit_add field | "Yes" if date present, "No" if null |
| Published | published date (from NVD) | 2021-08-30 |

**Display:**
- Up to 25 CVEs per report
- CVSS score and severity color-coded
- Includes CISA KEV catalog status
- Full CPE list and references in database

---

### 5. Assets Matching

Displays device-threat correlations showing what threats are detected on which assets.

**Fields shown:**
| Field | Source | Example |
|-------|--------|---------|
| Device Name | asset_hostname | SRV-MAIL-01, PC-Finance, etc. |
| IP Address | asset_ip | 192.168.1.13 |
| Department | asset_dept | IT Infrastructure, Finance |
| User | asset_user | mailadmin@company.vn |
| Threat | threat_name | CVE-2021-26084, newoutlook.live |
| Type | match_type | IOC, Malware, CVE |
| Risk | risk_level | CRITICAL, HIGH, MEDIUM, LOW |
| Recommendation | recommendation field | Action to take |

**Display:**
- Up to 30 asset matches per report
- Shows which devices are affected by which threats
- Risk level color-coded
- Includes recommended remediation actions

---

## Encoding & Format Specifications

### Character Encoding
- **HTML Meta:** UTF-8 (both charset and Content-Type)
- **Text Content:** Pure ASCII/English (no Vietnamese diacritics)
- **Data Fields:** UTF-8 encoded (threat names, descriptions can be Vietnamese)
- **Result:** No encoding issues in PDF output

### Page Layout
- **Page Size:** A4
- **Margins:** 0.75 inch on all sides
- **Font:** Helvetica/Arial (standard web fonts)
- **Font Size:** 
  - Headings: 14-22px
  - Table headers: 10px bold
  - Table data: 10px
- **Colors:** Professional (dark blue headers, color-coded severity)

### Report Types

| Type | Period | Data Filtered By | Typical Length |
|------|--------|------------------|----------------|
| Daily | Single day | created_at == YYYY-MM-DD | 2-3 pages |
| Weekly | 7 days | created_at >= week_start | 3-4 pages |
| Monthly | Full month | created_at starts with YYYY-MM | 5-8 pages |

---

## Data Sources

### IOCs
- Source: store["iocs"]
- Filter: Non-Yara items
- Counts: 12,369 total

### Yara Rules
- Source: store["iocs"] with ioc_type="Yara"
- Filter: Pattern-based detection rules
- Count: Subset of IOCs

### Malware
- Source: store["malwares"]
- Enriched with: aliases, types, intrusion sets, target info
- Count: 1,194 families

### CVEs
- Source: store["vulnerabilities"]
- Enriched with: NVD data (CVSS, attack vector, CWE, CISA status)
- Count: 87 CVEs

### Matches
- Source: store["matches"]
- Represents: Device-threat correlations
- Count: 28 links

---

## Generation Method

### Process
1. **Filter data** by report period (daily/weekly/monthly)
2. **Build HTML** with UTF-8 encoding and English text only
3. **Apply styling** with color-coded severity levels
4. **Convert to PDF** using pdfkit (wkhtmltopdf wrapper)
5. **Save to** reports/ directory with timestamp

### Performance
- **Generation time:** ~2 seconds
- **File size:** 6-20 KB (depending on data volume)
- **Pages:** 2-8 (auto-paginated by HTML)

### Error Handling
- **Primary:** pdfkit PDF generation
- **Fallback:** Save as HTML if PDF fails
- **Result:** Always produces a viewable report

---

## API Endpoints

### Create Report
```
POST /api/report?type=daily|weekly|monthly
```

Response:
```json
{
  "status": "ok",
  "message": "Report created: reports/monthly_report_2026-05-04_0051.pdf",
  "file": "reports/monthly_report_2026-05-04_0051.pdf",
  "count_info": "IOC: 882 | CVE: 43 | Malware: 31 | Period: month 05/2026"
}
```

### List Reports
```
GET /api/reports/list
```

Response:
```json
{
  "files": [
    {
      "name": "monthly_report_2026-05-04_0051.pdf",
      "size_kb": 17,
      "date": "04/05/2026 00:51",
      "path": "reports/monthly_report_2026-05-04_0051.pdf"
    }
  ]
}
```

### Download Report
```
GET /api/report/download?file=monthly_report_2026-05-04_0051.pdf
```

---

## Comparison with Previous Format

| Aspect | Old Format | New Format |
|--------|-----------|-----------|
| Encoding | Mixed Vietnamese | Pure English headers |
| Sections | 5 (generic) | 5 (UI-aligned) |
| Structure | Summary → Details | Tab-by-tab match |
| Fields | Limited | Full (all database fields) |
| IOCs | Grouped | Separated from Yara |
| Yara Rules | None | Dedicated section |
| Malware Detail | Minimal | Full aliases, types, intrusion sets |
| CVE Detail | Basic | NVD enriched (CVSS, vectors, CWE, CISA) |
| Assets | Generic | Full device info (dept, user, dept) |
| Formatting | Simple | Professional with borders & colors |

---

## Future Enhancements

1. **Custom fields** — Allow users to select which fields to include
2. **Filtered reports** — Report only on critical/high risk items
3. **Trending** — Include month-over-month threat changes
4. **Executive summary** — Add KPIs and statistics
5. **Recommendations** — Automated remediation action list
6. **Email delivery** — Automatic scheduled report distribution
7. **Multi-language** — Support for localized reports

---

## Status

✅ **PDF Report Generation:** Fully operational and production-ready

- No encoding issues
- Professional formatting
- Matches UI tab structure
- Complete data coverage
- Fast generation (2s)
- Reliable fallback

**Last Updated:** 2026-05-04
**System Version:** TI Agentic v1.0
