# Threat Intelligence Dashboard – IOC Aggregator & Enrichment Platform

> A Python threat intelligence platform that aggregates IOCs from 5 open-source
> feeds, enriches them via **VirusTotal** and **AbuseIPDB**, scores their risk,
> and visualises everything on an interactive **Streamlit** dashboard.

**Category:** Threat Intelligence / OSINT / Security Operations
**Author:** Kuldeep J. Jotaniya — MSc Cyber Security, Ravensbourne University (2025)

---

## 🎯 Objective

Mirror a real SOC analyst threat-intel workflow end to end: collect IOCs from
open feeds, enrich them with context, score and prioritise them, and present
actionable intelligence on a dashboard.

## ✨ Features

- **Feed aggregator** — pulls IPs, domains, URLs and file hashes from
  **AlienVault OTX, URLhaus, Feodo Tracker, ThreatFox and AbuseIPDB**, with
  cross-feed de-duplication.
- **Automated enrichment** — queries VirusTotal v3 (detection ratio, reputation)
  and AbuseIPDB (abuse confidence, ISP, country).
- **Risk-scoring engine** — weighted 1-10 score:
  `0.5·VT_ratio + 0.3·AbuseIPDB/100 + 0.2·recency`.
- **Interactive dashboard** — Streamlit app with IOC-type pie, risk histogram,
  feed-source breakdown, live filtering, search and CSV export.
- **On-demand lookup** — `--lookup <indicator>` enriches and scores any IOC.
- **Reporting** — generates a 1-page Markdown threat summary and a
  **Splunk-compatible lookup CSV** for SIEM integration.
- **Runs offline** — `--demo` mode and the dashboard work with a bundled,
  pre-enriched dataset, so it renders with **no API keys required**.

## 🗂 Repository Structure

```
03-threat-intel-dashboard/
├── main.py                    # Pipeline: collect → dedupe → enrich → score → store
├── feeds/                     # One collector per source (+ _common helpers)
│   ├── otx_feed.py  urlhaus_feed.py  feodo_feed.py
│   ├── threatfox_feed.py  abuseipdb_feed.py
├── enrichment/                # virustotal.py, abuseipdb.py
├── scoring/                   # scorer.py (pure-Python, unit-testable)
├── dashboard/app.py           # Streamlit dashboard
├── reports/
│   ├── generate_report.py     # Markdown report + Splunk lookup CSV generator
│   ├── sample_threat_report.md
│   └── sample_splunk_lookup.csv
├── data/
│   ├── demo_iocs.json         # Bundled enriched demo dataset
│   └── iocs.json              # Pipeline output (generated)
└── requirements.txt
```

## 🚀 Usage

```bash
pip install -r requirements.txt

# 1. Offline demo (no API keys needed):
python main.py --demo

# 2. Live collection (uses any keys that are set):
export VT_API_KEY=...           # https://www.virustotal.com (free)
export ABUSEIPDB_API_KEY=...    # https://www.abuseipdb.com (free)
export OTX_API_KEY=...          # https://otx.alienvault.com (free)
python main.py --collect --limit 50

# 3. Look up a single indicator:
python main.py --lookup 45.155.205.233

# 4. Generate a report + Splunk lookup table:
python reports/generate_report.py --demo --splunk-csv reports/lookup.csv

# 5. Launch the dashboard:
streamlit run dashboard/app.py
```

URLhaus, Feodo Tracker and ThreatFox work **without any API key**, so a live
`--collect` returns real data out of the box; VirusTotal/AbuseIPDB/OTX simply add
enrichment when their keys are present.

## 🌐 Threat Feeds Integrated

| Feed | IOC types | API key |
|------|-----------|---------|
| AlienVault OTX | IP, domain, URL, hash | Free key |
| URLhaus (abuse.ch) | Malicious URLs | None |
| Feodo Tracker (abuse.ch) | C2 IPs (Emotet/TrickBot/…) | None |
| ThreatFox (abuse.ch) | Malware IOCs (+MITRE) | Optional |
| AbuseIPDB | IP reputation | Free key |

## 🧮 Risk Scoring

The scorer (`scoring/scorer.py`) is dependency-free and easy to reason about:

```
weighted = (vt_detection_ratio * 0.5)
         + (abuseipdb_score/100 * 0.3)
         + (recency_weight      * 0.2)     # 1.0 today → 0.0 at 30 days
score    = round(weighted * 9) + 1          # 1..10
```

`classify()` maps scores to Critical (8-10) / High (6-7) / Medium (4-5) /
Low (1-3).

## 📊 Dashboard & Deployment

`streamlit run dashboard/app.py` launches the interactive UI. To share a public
portfolio link, deploy free on **Streamlit Community Cloud** pointing at
`dashboard/app.py` — it auto-loads the demo dataset so it works without secrets.

## 🧠 Learning Outcomes

- Threat-intelligence lifecycle (collection → processing → analysis → dissemination)
- IOC types and enrichment workflows
- API integration & automation with Python
- OSINT methodology and open-source tooling
- Dashboard design for security operations
- MITRE ATT&CK / malware-family mapping (carried as IOC tags)

## 🎓 Aligned Certifications

CompTIA CySA+ · Recorded Future Threat Intelligence · TryHackMe Threat
Intelligence paths

## ⚠️ Disclaimer

IOCs are real-world indicators — never connect to or execute them. The bundled
demo dataset uses documentation/RFC-reserved ranges and example domains. Respect
each feed's and API's terms of service and rate limits.
