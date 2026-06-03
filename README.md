# Cybersecurity Projects — Kuldeep J. Jotaniya

> **SOC Analyst (Entry Level)** portfolio · MSc Cyber Security, Ravensbourne
> University (2025)

A hands-on portfolio of three blue-team / security-engineering projects built to
demonstrate practical SOC analyst skills: SIEM detection engineering, cloud
security auditing, and threat intelligence. Each project is self-contained with
runnable code, documentation, and sample data.

---

## 📁 Projects

### 1. [SOC Home Lab – Real-Time Threat Detection](./01-soc-home-lab) · `SOC / SIEM`
A fully operational SOC home lab using **Splunk SIEM**, **Sysmon** and **Atomic
Red Team**. Simulates real attacks, detects **12 MITRE ATT&CK techniques** with
documented SPL use cases, includes Python triage helpers, a Dashboard Studio
definition, an ATT&CK Navigator layer, and a full NIST 800-61 incident report.

`Splunk` · `Sysmon` · `Atomic Red Team` · `MITRE ATT&CK` · `Python` · `Kali`

### 2. [AWS Security Misconfiguration Audit](./02-aws-security-audit) · `Cloud Security`
A **Python + Boto3** CSPM tool running **15 read-only audit checks** across IAM,
S3, EC2 and CloudTrail, mapping every finding to **CIS AWS Benchmark** and
**NIST** controls, and producing JSON output plus an executive HTML report. Runs
against a live account or in `--demo` mode with no AWS account.

`Python` · `Boto3` · `AWS` · `CIS Benchmark` · `NIST CSF` · `CSPM`

### 3. [Threat Intelligence Dashboard](./03-threat-intel-dashboard) · `Threat Intel`
A **Python** threat-intel platform aggregating IOCs from **5 OSINT feeds**
(OTX, URLhaus, Feodo Tracker, ThreatFox, AbuseIPDB), enriching via **VirusTotal**
and **AbuseIPDB**, scoring risk 1-10, and visualising on an interactive
**Streamlit** dashboard. Includes Splunk lookup export and an offline demo mode.

`Python` · `Streamlit` · `VirusTotal` · `AbuseIPDB` · `OSINT` · `Plotly`

---

## 🚀 Quick Start

Each project runs in an **offline demo mode** so you can try it without any
accounts or API keys:

```bash
# Project 1 — parse simulated attack telemetry into a triage ticket
cd 01-soc-home-lab/scripts
python3 log_parser.py sample_events.json

# Project 2 — audit a misconfigured AWS lab (no AWS account required)
cd 02-aws-security-audit && pip install -r requirements.txt
python audit.py --demo

# Project 3 — aggregate + score IOCs, then launch the dashboard
cd 03-threat-intel-dashboard && pip install -r requirements.txt
python main.py --demo
streamlit run dashboard/app.py
```

## 🛠 Skills Demonstrated

| Domain | Skills |
|--------|--------|
| SIEM / Detection | Splunk SPL, detection use cases, dashboards, alert tuning |
| Incident Response | NIST 800-61 workflow, IOC documentation, triage playbooks |
| Cloud Security | AWS IAM/S3/EC2/CloudTrail hardening, CIS/NIST mapping, CSPM |
| Threat Intelligence | OSINT feeds, IOC enrichment, risk scoring, ATT&CK mapping |
| Automation | Python tooling, API integration, report generation |

## 🎓 Certifications Targeted

CompTIA Security+ · CompTIA CySA+ · Splunk Core Certified User · AWS Cloud
Practitioner · Google Cybersecurity Professional · ISC2 CC · TryHackMe SOC Level 1

## 📫 Contact

**Kuldeep J. Jotaniya** — MSc Cyber Security, Ravensbourne University (2025)
Targeting entry-level SOC Analyst roles.

> ⚠️ All offensive techniques and audit tooling here are for **authorised,
> isolated lab use only**. Never run them against systems you do not own or are
> not explicitly permitted to test.
