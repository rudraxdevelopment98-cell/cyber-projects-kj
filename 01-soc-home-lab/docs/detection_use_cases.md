# Detection Use Case Catalogue

This catalogue documents the detection logic deployed in the SOC Home Lab. Each
use case follows a consistent format an analyst would expect in an enterprise
detection library: ID, MITRE mapping, data source, logic summary, severity and a
triage action. The corresponding SPL lives in
[`../splunk/detection_use_cases.spl`](../splunk/detection_use_cases.spl).

| ID | Name | MITRE | Data Source | Severity |
|----|------|-------|-------------|----------|
| UC-001 | Suspicious PowerShell Execution | T1059.001 | Security 4688 / Sysmon 1 | High |
| UC-002 | Multiple Failed Logins (Brute Force) | T1110 / T1078 | Security 4625/4624 | Medium |
| UC-003 | New / Suspicious Service Installed | T1543.003 | System 7045 | High |
| UC-004 | Credential Dumping (LSASS Access) | T1003.001 | Sysmon 10 | Critical |
| UC-005 | Registry Run Key Persistence | T1547.001 | Sysmon 13 | High |
| UC-006 | Ingress Tool Transfer | T1105 | Security 4688 / Sysmon 1 | High |
| UC-007 | Suspicious Outbound C2 Beacon | T1071 | Sysmon 3 | High |
| UC-008 | Exploit Public-Facing App (web shell) | T1190 | Sysmon 1 | Critical |
| UC-009 | Account Created / Privilege Escalation | T1136 / T1098 | Security 4720/4728/4732 | High |
| UC-010 | Security Tooling Tampering | T1562.001 | Security 4688 / Sysmon 1 | High |
| UC-011 | Scheduled Task Persistence | T1053.005 | Security 4698/4688 | Medium |
| UC-012 | Security Event Log Cleared | T1070.001 | Security 1102 / System 104 | High |

---

## UC-001 — Suspicious PowerShell Execution
- **MITRE:** T1059.001 (Command and Scripting Interpreter: PowerShell)
- **Logic:** Process-creation events for `powershell.exe`/`pwsh.exe` containing
  encoding, download or in-memory execution indicators (`-enc`,
  `FromBase64String`, `DownloadString`, `IEX`, `-w hidden`).
- **Severity:** High
- **Triage:** Decode any base64/`-enc` payload, identify the parent process,
  hash-check any dropped binary in VirusTotal, escalate if confirmed malicious.

## UC-002 — Multiple Failed Logins (Brute Force)
- **MITRE:** T1110 (Brute Force) → T1078 (Valid Accounts)
- **Logic:** More than 5 `EventCode=4625` failures per source IP/account; a
  companion transaction search flags failure bursts immediately followed by a
  `4624` success (likely compromise).
- **Severity:** Medium (raise to High on a following success)
- **Triage:** Block the source IP, confirm whether a success followed, notify the
  account owner, enforce MFA.

## UC-003 — New / Suspicious Service Installed
- **MITRE:** T1543.003 (Create or Modify System Process: Windows Service)
- **Logic:** `EventCode=7045` service installs, flagging binaries that run from
  temp/appdata or invoke script interpreters.
- **Severity:** High
- **Triage:** Verify the service against change records, hash-check
  `ServiceFileName` in VirusTotal, isolate the host if the service is unknown.

## UC-004 — Credential Dumping (LSASS Access)
- **MITRE:** T1003.001 (OS Credential Dumping: LSASS Memory)
- **Logic:** Sysmon `EventCode=10` process-access events targeting `lsass.exe`
  with high-risk `GrantedAccess` masks used by Mimikatz.
- **Severity:** Critical
- **Triage:** Isolate the host, capture a memory image, reset exposed
  credentials, hunt for lateral movement.

## UC-005 — Registry Run Key Persistence
- **MITRE:** T1547.001 (Registry Run Keys / Startup Folder)
- **Logic:** Sysmon `EventCode=13` registry writes to `...\CurrentVersion\Run`.
- **Severity:** High
- **Triage:** Validate the autostart entry, remove if unauthorised, scan for
  additional persistence.

## UC-006 — Ingress Tool Transfer
- **MITRE:** T1105 (Ingress Tool Transfer)
- **Logic:** LOLBin download patterns — `certutil -urlcache`,
  `bitsadmin /transfer`, `Invoke-WebRequest`, `curl`/`wget`, `DownloadFile`.
- **Severity:** High
- **Triage:** Inspect and sandbox the downloaded artefact, block the source URL.

## UC-007 — Suspicious Outbound C2 Beacon
- **MITRE:** T1071 (Application Layer Protocol)
- **Logic:** Sysmon `EventCode=3` outbound connections to non-RFC1918
  destinations, high count to very few unique IPs (beaconing).
- **Severity:** High
- **Triage:** Correlate the destination with threat intel, review beacon
  interval/jitter, block at the egress proxy.

## UC-008 — Exploit Public-Facing Application
- **MITRE:** T1190 (Exploit Public-Facing Application)
- **Logic:** Web server processes (`w3wp.exe`, `httpd`, `nginx`, `tomcat`)
  spawning shells/recon tools — a hallmark of web shell activity.
- **Severity:** Critical
- **Triage:** Locate the dropped web shell, review web access logs, contain.

## UC-009 — Account Created / Privilege Escalation
- **MITRE:** T1136 (Create Account), T1098 (Account Manipulation)
- **Logic:** `4720` user creation and `4728/4732/4756` privileged-group adds.
- **Severity:** High
- **Triage:** Confirm a change ticket exists, otherwise disable the account.

## UC-010 — Security Tooling Tampering
- **MITRE:** T1562.001 (Impair Defenses: Disable or Modify Tools)
- **Logic:** Commands disabling Defender real-time monitoring, adding exclusions,
  stopping `WinDefend`, or disabling the firewall.
- **Severity:** High
- **Triage:** Re-enable protection, investigate the responsible user/process.

## UC-011 — Scheduled Task Persistence
- **MITRE:** T1053.005 (Scheduled Task)
- **Logic:** `4698` task creation or `schtasks /create` command lines.
- **Severity:** Medium
- **Triage:** Inspect the task action/trigger, remove if unauthorised.

## UC-012 — Security Event Log Cleared
- **MITRE:** T1070.001 (Indicator Removal: Clear Windows Event Logs)
- **Logic:** `EventCode=1102` (Security) or `104` (System) log-clear events.
- **Severity:** High
- **Triage:** Treat as a high-confidence IoC; pivot to forwarded logs/EDR that
  survive local clears and begin formal IR.
