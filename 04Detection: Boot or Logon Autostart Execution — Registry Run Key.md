## Detection: Boot or Logon Autostart Execution — Registry Run Keys

**MITRE ATT&CK:** T1547.001 - Registry Run Keys / Startup Folder
**Severity:** Medium-High
**Author:** Shachin P R
**Date:** 2026-07-18

---

### What it detects
Creation of a value under `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
(or the equivalent `HKLM` hive), one of the oldest and most common
Windows persistence mechanisms — any executable path placed here
runs automatically at every user logon.

---

### Why registry Run keys remain relevant
Despite being a well-known technique, Run key persistence is still
widely used because:
- It survives reboots without needing a scheduled task or service
- It requires no special privileges when written to `HKCU`
- It blends in with legitimate software that also uses this
  mechanism (many installers register update-checkers this way)
- It's fast to deploy — a single `reg add` or `Set-ItemProperty`
  command, no dropped files required beyond the payload itself

---

### Simulated attack (Atomic Red Team)
**Test:** `T1547.001-1` — Reg Key Run
```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
```

---

### Sysmon config verification
Checked the running Sysmon configuration (`Sysmon64.exe -c`) before
testing. The config contains only two rule groups: `ProcessCreate`
and `ProcessAccess`. **There is no `RegistryEvent` rule group at all**
— meaning Sysmon in this lab is not configured to log actual registry
key/value creation events (EID 12/13/14) at any point. This is the
key fact that shapes everything below.

---

### Wazuh Detection Result — Caught Indirectly, Not Directly
Three rules fired on this simulated attack, but all three triggered
from **process creation** (EID 1) — inspecting the command line of
`reg.exe` itself — not from an actual registry-modification event,
because no such event exists in this lab's telemetry.

| Rule | Level | Description | Signal source |
|---|---|---|---|
| 92041 | 10 | Value added to registry key has Base64-like pattern | Command-line text pattern match on `reg.exe`'s arguments |
| 92052 | 4 | Windows command prompt started by an abnormal process | Process lineage (cmd.exe spawned by PowerShell) |
| 92032 | 3 | Suspicious Windows cmd shell execution | Process lineage |

```json
{
  "rule": { "level": 10, "id": "92041",
    "description": "Value added to registry key has Base64-like pattern",
    "mitre": { "id": ["T1027", "T1112"] } },
  "data": { "win": { "eventdata": {
    "image": "C:\\Windows\\System32\\reg.exe",
    "commandLine": "REG  ADD \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /V \"Atomic Red Team\" ..."
  }}}
}
```

### Root cause / Finding
The detection worked in this instance, but through a **compensating
control** — pattern-matching `reg.exe`'s command-line text — rather
than the direct telemetry source (an actual registry write event).
This is a materially weaker detection than it appears:

- It depends entirely on the attacker using `reg.exe` or `cmd.exe`
  with the key path spelled out in plaintext on the command line
- An attacker using PowerShell's `Set-ItemProperty` /
  `New-ItemProperty` cmdlets, direct Win32 Registry API calls, or a
  compiled tool that writes to the registry programmatically would
  produce **no matching command-line text at all** and would likely
  evade all three of these rules simultaneously
- Rule 92041 specifically appears designed to catch obfuscated
  (Base64-like) payloads in registry values — it is not a general
  "something was added to a Run key" rule; it happened to fire here
  because the flagged pattern-matching logic was broad enough to
  catch this particular command line, not because it directly
  recognized Run-key persistence as a concept

This is the clearest capability gap identified across the whole
project: **Sysmon's `RegistryEvent` monitoring was never enabled**,
so Wazuh has no direct visibility into registry modifications at all
— every registry-related detection in this lab is, by necessity, an
indirect inference from process/command-line data.

---

### False Positives identified
- Legitimate installers and update utilities commonly write to
  `HKCU\...\Run` using `reg.exe` or PowerShell during normal
  install/update flows — rule 92052/92032 (abnormal shell parentage)
  would need allow-listing by parent process (e.g., known installer
  frameworks) to avoid noise in a real environment
- Rule 92041's Base64-pattern match could false-positive on any
  legitimately long or alphanumeric-heavy registry value unrelated
  to obfuscation

---

### Blind Spots / What this misses
- **No direct registry telemetry**: Sysmon's `RegistryEvent` rule
  group (EID 12/13/14) is not enabled in this lab — the single
  biggest gap found in this project. Enabling it would allow Wazuh
  to detect Run key creation directly, regardless of which tool
  wrote it
- **API-based or scripted registry writes** (PowerShell cmdlets,
  compiled malware calling `RegSetValueEx` directly) would bypass
  every rule that fired in this test, since none of them inspect
  registry content — only command-line text of specific tools
  (`reg.exe`, `cmd.exe`)
- **HKLM Run keys, Winlogon keys, and other autostart locations**
  covered by other T1547.001 sub-tests were not evaluated in this
  round

---

### Recommended response
1. Treat any of these three rules firing as a **possible** persistence
   attempt, not confirmed — verify by directly querying the referenced
   registry key/value on the endpoint before escalating
2. Given the confirmed telemetry gap, **do not treat the absence of
   these alerts as evidence of no persistence** — a scripted or
   API-based Run key write would produce zero alerts in this lab's
   current configuration
3. Priority remediation for this lab: enable Sysmon's `RegistryEvent`
   rule group to close this gap before relying on this detection
   coverage for anything beyond a portfolio demonstration
4. If confirmed malicious, remove the registry value, identify and
   quarantine the referenced executable, and check for related
   persistence in other common locations (Scheduled Tasks, Services,
   Startup folder) since an attacker rarely relies on a single
   mechanism

---
