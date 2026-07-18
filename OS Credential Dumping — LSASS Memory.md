## Detection: OS Credential Dumping — LSASS Memory

**MITRE ATT&CK:** T1003.001 - LSASS Memory
**Severity:** Critical (when true positive)
**Author:** Shachin P R
**Date:** 2026-07-12

---

### What it detects
Direct memory access to `lsass.exe` (Local Security Authority Subsystem
Service), the Windows process that holds credential material in
memory for all logged-on users — password hashes, Kerberos tickets,
and sometimes plaintext secrets, kept there to support single sign-on.
Dumping LSASS memory is one of the highest-value credential theft
techniques available to an attacker with local access.

---

### Why LSASS is the highest-value target on a host
Unlike Credential Manager, IIS config, or NTLM relay (plain T1003's
other sub-techniques), which expose credentials scoped to a single
service or saved logon, LSASS holds material for **every account
that has authenticated on the machine at once**. A single successful
dump can yield the credentials of every user who has logged on,
not just one.

---

### Sysmon Event IDs used
| Event ID | Name | What it captures |
|---|---|---|
| EID 10 | ProcessAccess | Source process opening a handle to `lsass.exe`, including the specific `GrantedAccess` rights requested |

---

### Sysmon config verification
Before testing, I checked the actual Sysmon configuration running on
the endpoint (`Sysmon64.exe -c`) rather than assuming coverage:
```
ProcessAccess    onmatch: include   combine rules using 'Or'
    TargetImage   filter: is   value: 'C:\Windows\system32\lsass.exe'
```
This confirms Sysmon is configured to log **any** process accessing
`lsass.exe`, with no `GrantedAccess` filter and no source-process
exclusions. Whatever happens downstream, Sysmon itself is not the
bottleneck — this matters for correctly attributing the finding below.

---

### Simulated attack (Atomic Red Team)
**Test:** `T1003.001-1` — Dump LSASS.exe Memory using ProcDump
```
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp
```

**Attempt 1 — Windows Defender active:** Blocked before execution.
`Get-MpThreatDetection` confirmed the exact ProcDump command line was
flagged and remediated (`ActionSuccess: True`) before the process
could touch LSASS at all.

**Attempt 2 — Defender's real-time protection temporarily disabled:**
Attack succeeded. Confirmed via a 77MB `lsass_dump.dmp` file created
on disk, and via Sysmon EID 1 showing the real `procdump.exe` process
(PID 4972, signed Sysinternals binary, correct hash) actually launch.
Defender was re-enabled immediately after.

---

### Wazuh Detection Result — Rule Fired for a Different Source, Not for ProcDump
Wazuh's built-in rule **92900** ("Lsass process was accessed...possible
credential dump", Level 12, mapped to T1003.001) fired correctly and
repeatedly — but only for **`MsMpEng.exe`** (Windows Defender's own
scanning engine performing routine LSASS reads), never for
**`procdump.exe`**, despite Sysmon confirming both processes generated
EID 10 events (Defender's access is expected background telemetry;
ProcDump's request was the actual simulated attack).

```json
{
  "rule": { "level": 12, "id": "92900",
    "description": "Lsass process was accessed by ...MsMpEng.exe with read permissions, possible credential dump" },
  "data": { "win": { "eventdata": {
    "sourceImage": "...MsMpEng.exe",
    "targetImage": "C:\\WINDOWS\\system32\\lsass.exe",
    "grantedAccess": "0x101000"
  }}}
}
```

### Root cause
Comparing the two `GrantedAccess` values Sysmon logged:
- Defender's scan (**detected**): `0x101000` / `0x1010`
- ProcDump's full memory dump request: a broader access mask
  (consistent with `PROCESS_VM_READ` + `PROCESS_QUERY_INFORMATION`
  combined for a full `-ma` minidump) that evidently doesn't match
  rule 92900's matching logic

This mirrors the exact design of my own Splunk T1003 rule from
Project 1, which matched on a **specific fixed value**
(`GrantedAccess=0x1f3fff`) rather than "any access to lsass.exe."
Wazuh's default rule appears to use the same specific-value-matching
approach rather than a broad "any access" trigger — meaning it has
the same structural limitation a hand-built SIEM rule would have:
**it catches known access patterns, not all possible ones.**

---

### Known limitation / Finding
Wazuh's out-of-the-box LSASS detection rule did **not** generalize to
ProcDump's specific access request, despite Sysmon correctly logging
the raw event with no filtering in place. Sysmon-level visibility was
never the gap — Wazuh's rule specificity was. A more robust detection
would need to either broaden rule 92900's matching (any `GrantedAccess`
against `lsass.exe` from a non-allowlisted source) or add a
complementary rule targeting known dumping-tool access masks
specifically, closer to what I built by hand for Splunk.

---

### False Positives identified
- `MsMpEng.exe` (Windows Defender) routinely accesses LSASS as part
  of legitimate real-time credential-theft protection scanning —
  this is expected, benign, high-frequency activity and is the
  primary source of noise for this rule in practice
- Any other installed AV/EDR agent performing similar scans would
  produce the same pattern and needs allow-listing by source path,
  not by suppressing the rule entirely

---

### Blind Spots / What this misses
- Rule specificity to certain `GrantedAccess` values means novel or
  less common dumping tools using different access masks may not
  trigger this rule at all (as demonstrated here with ProcDump)
- Comsvcs.dll-based dumping, direct syscalls/API unhooking, and
  NanoDump-style techniques were not tested in this lab and may
  request different access masks entirely
- This detection is memory-access based only — it says nothing about
  what happens to the dump file afterward (exfiltration, offline
  cracking), which would need separate file-transfer or process
  monitoring to catch

---

### Recommended response
1. Any alert on rule 92900 — first check `SourceImage`; known AV/EDR
   paths are near-certainly benign, anything else warrants immediate
   escalation
2. If source is unrecognized or a known dumping tool (ProcDump,
   Mimikatz, comsvcs.dll via rundll32) — treat as confirmed credential
   theft, P1 incident regardless of whether the specific rule fired
   automatically
3. Given the confirmed detection gap above, **do not rely on this
   single rule alone** — cross-reference any `lsass.exe`-adjacent
   process creation events (EID 1) for known dumping tool names/hashes
   as a compensating control
4. Isolate the host and preserve the dump file location as evidence
   if a real dump file is found on disk (as this test demonstrated
   is possible even when Wazuh's rule doesn't fire)

---
