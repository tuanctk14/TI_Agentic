# 🛡️ TI Agentic — Threat Intelligence Platform

A comprehensive Threat Intelligence (TI) platform powered by agentic AI with real-time threat analysis, IOC scanning, malware tracking, and vulnerability assessment.

## 🌟 Features

### Core Intelligence Gathering
- **IOC Scanner** — Search and analyze Indicators of Compromise (hashes, domains, URLs, IPs)
- **Malware Tracker** — Track malware families, intrusion sets, target countries/sectors
- **Vulnerability Database** — Monitor CVEs with CVSS scores and CISA exploit data
- **Yara Rules** — Create and manage YARA detection rules

### Agentic AI
- **ReAct Pattern** — Tool-using agent with Ollama integration
- **Real-time Visualization** — Watch agent reasoning and tool execution
- **Multi-step Analysis** — Autonomous threat investigation with memory
- **Threat Modeling** — ATT&CK framework mapping with NIST mitigations

### Attack Surface Monitoring
- **Device Inventory** — Track network assets and vulnerabilities
- **Risk Scoring** — Automatic severity assessment (Critical/High/Medium/Low)
- **Threat Matching** — Link observed threats to monitored devices

### Data Integration
- **OpenCTI API** — Synchronized intelligence from OpenCTI platform
- **NVD Integration** — National Vulnerability Database enrichment
- **WebSocket Real-time** — Live updates for AI analysis

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Ollama (for AI agent analysis)
- OpenCTI (threat intelligence data)

### Installation

```bash
# Clone repository
git clone https://github.com/tuanctk14/TI_Agentic.git
cd TI_Agentic

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your OpenCTI and Ollama settings
```

### Running the Application

```bash
# Start FastAPI server
python main.py

# Open browser
# Frontend: http://localhost:8002
# API Docs: http://localhost:8002/docs
```

## 📁 Project Structure

```
ti-agentic/
├── main.py                 # FastAPI application
├── agents/
│   ├── ai_agent.py        # ReAct agent with tool calling
│   ├── nvd_client.py      # NVD API integration
│   ├── ti_fetch_agent.py  # OpenCTI data fetching
│   └── memory_agent.py    # Long-term memory management
├── frontend/
│   └── index.html         # Interactive web UI
├── data/
│   └── agent_memory.json  # Persistent agent memory
├── cache/
│   └── metadata.json      # Cached threat intelligence
└── requirements.txt       # Python dependencies
```

## 🔧 Configuration

### Environment Variables (.env)

```env
# OpenCTI
OPENCTI_URL=http://your-opencti-url
OPENCTI_TOKEN=your-api-token
OPENCTI_ORGANIZATION=your-organization-id

# Ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=mistral

# Application
PORT=8002
LOG_LEVEL=INFO
```

## 📊 Usage

### Dashboard
Monitor overview of all threats, devices, and AI analysis results.

### IOC Scanner
- Search hashes, domains, URLs, IPs
- View detailed information and relationships
- Track detection scores and metadata

### Malware Tracker
- Browse malware families and variants
- See associated intrusion sets
- Identify target countries and sectors

### Vulnerabilities
- Filter by severity and status
- View CVSS scores and attack vectors
- Check CISA exploit dates

### Chat AI
- Ask questions about threats
- Run automatic investigations
- Get recommendations for remediation

### Attack Surface
- View network device inventory
- See active threats per device
- Analyze attack paths with ATT&CK mapping

## 🤖 Agentic AI Features

### ReAct Pattern
The AI agent uses the ReAct (Reasoning + Acting) pattern:
1. **Reasoning** — Analyze threat characteristics
2. **Acting** — Use tools (search, enrich, correlate)
3. **Memory** — Remember past investigations
4. **Decision** — Recommend actions

### Available Tools
- `search_vulnerabilities` — Query threat database
- `enrich_vulnerability` — Fetch NVD details
- `get_device_matches` — Find affected assets
- `create_alert` — Generate security alerts
- `check_memory` — Recall past findings

## 📈 API Endpoints

### Threat Intelligence
- `GET /api/iocs` — List indicators of compromise
- `GET /api/malwares` — List malware families
- `GET /api/vulnerabilities` — List vulnerabilities
- `GET /api/ti/detail` — Get detailed entity information
- `GET /api/ti/matches` — Get device matches for threats

### Analysis
- `POST /api/threat-model/device` — Analyze device threats
- `GET /api/alerts` — Get generated alerts
- `GET /api/search` — Search across all threat types

### WebSocket
- `WS /ws/chat` — Real-time chat with AI agent

## 🔐 Security

- API key authentication for OpenCTI
- HTTPS support for production
- No credentials stored in code (use .env)
- Regular data cache validation

## 📝 License

MIT License - see LICENSE file for details

## 👤 Author

**Hoang Tuan** (tuanctk14)
- GitHub: [@tuanctk14](https://github.com/tuanctk14)
- Email: hoanglv.des@gmail.com

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📞 Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Built with ❤️ for the cybersecurity community**
