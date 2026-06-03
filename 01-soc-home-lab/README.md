# SOC Home Lab – Real-Time Threat Detection with Splunk & Atomic Red Team

> A fully operational SOC home lab that simulates real enterprise attacks with
> Atomic Red Team, ingests Windows + Sysmon telemetry into **Splunk SIEM**,
> detects 12 MITRE ATT&CK techniques, and produces professional incident
> response documentation.

**Category:** SOC / SIEM / Threat Detection
**Author:** Kuldeep J. Jotaniya — MSc Cyber Security, Ravensbourne University (2025)

---

## 🎯 Objective

Demonstrate hands-on SOC analyst skills by building a detection lab that
simulates enterprise attacks, ingests logs into Splunk, writes detection rules,
and produces professional incident reports and triage playbooks.

## 🏗 Architecture

```
                 ┌────────────────────────┐
                 │  Attacker VM (Kali)     │  Atomic Red Team / manual TTPs
                 │  10.10.10.10            │
                 └───────────┬────────────┘
                             │  attacks
                             ▼
   ┌────────────────────────┐        forwards logs        ┌────────────────────┐
   │  Victim VM (Windows 10) │  ───────────────────────▶   │  SIEM VM (Ubuntu)  │
   │  10.10.10.20            │   Splunk Universal           │  Splunk Free       │
   │  Sysmon + WinEventLog   │   Forwarder (9997/TCP)       │  index=windows     │
   └────────────────────────┘                              └────────────────────┘

   Network: Host-only / NAT, isolated from the internet.
   Virtualization: VirtualBox or VMware on a Windows/Ubuntu host.
```

| VM | OS | Role |
|----|----|------|
| Attacker | Kali Linux | Simulate attacker TTPs (Atomic Red Team + manual) |
| Victim | Windows 10 | Target generating Security/System logs + Sysmon |
| SIEM | Ubuntu Server | Splunk Free; receives forwarded logs via Universal Forwarder |

## 🧰 Tools & Technologies

Splunk (Free/Trial) · Sysmon · Splunk Universal Forwarder · Atomic Red Team ·
Kali Linux · Windows Event Logs (Security/System/Application) · VirusTotal API
(optional IOC enrichment) · Python (helper scripts).

## 🗂 Repository Structure

```
01-soc-home-lab/
├── README.md                         # This file (architecture + setup)
├── docs/
│   ├── detection_use_cases.md        # 12 documented use cases
│   └── incident_response_report.md   # Full NIST 800-61 IR report
├── splunk/
│   ├── detection_use_cases.spl       # 12 detection queries (SPL)
│   └── soc_detection_dashboard.json  # Dashboard Studio definition
├── scripts/
│   ├── log_parser.py                 # Triage Windows/Sysmon JSON exports
│   ├── alert_formatter.py            # Render detections into a triage ticket
│   └── sample_events.json            # Sample attack telemetry
├── mitre/
│   └── attack_navigator_layer.json   # ATT&CK Navigator coverage layer
└── screenshots/                      # Dashboard & alert captures
```

## ⚙️ Setup Guide (summary)

1. **Provision VMs** in VirtualBox/VMware on a host-only network (10.10.10.0/24).
2. **SIEM VM** — install Splunk Free on Ubuntu, enable a receiving input on
   `9997/TCP` (`Settings → Forwarding and receiving`), create `index=windows`.
3. **Victim VM** — install [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
   with a config such as [SwiftOnSecurity's](https://github.com/SwiftOnSecurity/sysmon-config),
   then install the **Splunk Universal Forwarder** and configure `inputs.conf`:
   ```ini
   [WinEventLog://Security]
   index = windows
   [WinEventLog://System]
   index = windows
   [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   index = windows
   renderXml = false
   ```
   Point the forwarder at the SIEM: `splunk add forward-server 10.10.10.20:9997`.
4. **Attacker VM** — install Atomic Red Team and run techniques, e.g.:
   ```powershell
   Invoke-AtomicTest T1059.001   # PowerShell
   Invoke-AtomicTest T1003.001   # LSASS dumping
   Invoke-AtomicTest T1547.001   # Run key persistence
   ```
5. **Import detections** — paste queries from `splunk/detection_use_cases.spl`,
   save as alerts, and import `splunk/soc_detection_dashboard.json` via
   Dashboard Studio. Load `mitre/attack_navigator_layer.json` into the
   [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## 🔎 Detection Use Cases

12 use cases covering PowerShell abuse, brute force, credential dumping,
persistence, ingress tool transfer, C2 beaconing, web-shell activity, account
manipulation, defense evasion and log clearing. Full catalogue in
[`docs/detection_use_cases.md`](docs/detection_use_cases.md); queries in
[`splunk/detection_use_cases.spl`](splunk/detection_use_cases.spl).

## 🐍 Helper Scripts (offline triage demo)

Even without a running Splunk instance you can demo the analysis workflow:

```bash
cd scripts
# Parse exported Windows/Sysmon events into prioritised detections:
python3 log_parser.py sample_events.json

# Pipe detections into a ready-to-paste triage ticket:
python3 log_parser.py sample_events.json --json | python3 alert_formatter.py - --out triage_ticket.md
```

`scripts/sample_events.json` contains a full simulated attack chain;
`scripts/sample_triage_ticket.md` is example output.

## 📄 Incident Response Report

[`docs/incident_response_report.md`](docs/incident_response_report.md) is a full
NIST SP 800-61 incident report for one simulated intrusion — timeline, IOCs,
containment/eradication/recovery, root cause and lessons learned.

## 🧠 Learning Outcomes

- Splunk SPL query writing and dashboard creation
- MITRE ATT&CK framework mapping
- Windows Event Log & Sysmon analysis
- Incident documentation and escalation workflows
- Attack simulation and blue-team detection tuning

## 🎓 Aligned Certifications

CompTIA Security+ · Splunk Core Certified User · Google Cybersecurity
Professional Certificate · TryHackMe SOC Level 1

## ⚠️ Disclaimer

Run all attack simulations only inside the isolated lab network. Atomic Red Team
executes real offensive techniques — never run it against systems you do not own
or are not authorised to test.
