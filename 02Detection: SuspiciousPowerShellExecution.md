## Detection: Suspicious PowerShell Execution (Encoded Command)

**MITRE ATT&CK:** T1059.001 - PowerShell
**Severity:** High
**Author:** Shachin P R
**Date:** 2026-07-12

---

### What it detects
Execution of `powershell.exe` with a base64-encoded `-EncodedCommand`
argument (`-E`/`-EncodedCommand`), including cases where the
PowerShell process is spawned by WMI (`WmiPrvSE.exe`) rather than
directly by a user. Encoded commands are a standard technique to
obfuscate PowerShell payloads from casual log review and simple
string-matching defenses.

---

### Why encoded PowerShell is dangerous
Attackers and post-exploitation frameworks encode PowerShell payloads
to:
- Evade naive keyword-based detection (no plaintext `Invoke-Mimikatz`
  or similar strings visible in the command line)
- Bypass basic AV signature matching
- Chain multiple obfuscation layers (base64 → gzip → base64 is common)
- Blend in with legitimate admin tooling, which also occasionally
  uses `-EncodedCommand` for parameter escaping

When the parent process is `WmiPrvSE.exe` rather than a normal shell
or Explorer, it signals **remote or programmatic execution** — WMI is
a common lateral movement and remote-execution vector (T1047), making
this pairing (WMI + encoded PowerShell) notably higher-signal than
either indicator alone.

---

### Sysmon Event IDs used
| Event ID | Name | What it captures |
|---|---|---|
| EID 1 | ProcessCreate | Full command line, parent process, user, integrity level, hash |

Unlike the process injection detection (which needed EID 8/10), this
detection runs entirely on EID 1 process-creation telemetry — the
same event ID Wazuh's default ruleset already parses out of the box.

---

### Wazuh Detection (built-in ruleset — no custom rule authored)
Where the Splunk lab required a hand-built `case()` rule to flag
EncodedCommand/Bypass/Hidden/WebDownload patterns, Wazuh's default
Sysmon rule set (decoder: `windows_eventchannel`, group:
`sysmon_eid1_detections`) already covers this technique natively.
Two rules fired independently from the same simulated attack:

**Rule 92071** (fired on the WMI-spawned variant):
```json
{
  "rule": {
    "level": 12,
    "description": "A powershell process created by WMI executed a base64 encoded command",
    "id": "92071",
    "mitre": { "id": ["T1047", "T1059.001"], "technique": ["Windows Management Instrumentation", "PowerShell"] }
  }
}
```

**Rule 92027** (fired on a related, lower-severity PowerShell-parent pattern):
```json
{
  "rule": {
    "level": 4,
    "description": "Powershell process spawned powershell instance",
    "id": "92027",
    "mitre": { "id": ["T1059.001"], "technique": ["PowerShell"] }
  }
}
```

No rule authoring was required to get this detection — only ensuring
the `Microsoft-Windows-Sysmon/Operational` event channel was actually
being forwarded to the manager (see deployment notes; this channel is
**not** enabled by default on a fresh agent install).

---

### Severity classification logic
| Rule | Level | Reason |
|---|---|---|
| 92071 | 12 (High) | WMI-spawned + base64-encoded command — indicates remote/programmatic execution combined with obfuscation, a strong dual-signal pairing |
| 92027 | 4 (Low) | PowerShell spawning PowerShell alone — common in legitimate scripting (module reloads, nested scopes), weak signal on its own |

---

### Simulated attack (Atomic Red Team)
**Test:** `T1059.001-15` — `ATHPowerShellCommandLineParameter -EncodedCommand parameter variations`
```
powershell.exe -NoProfile -E VwByAGkAdABlAC0ASABvAHMAdAAgADMAZQA0OTY5ZTYtNzUwYi00MGUzLTkyYjItNTg5NmM4OThjODU0
```
Decodes to a benign `Write-Host <GUID>` marker — payload content is
harmless by design; the detection is on the execution pattern, not
payload analysis.

---

### True Positive Example
**Test — WMI-spawned encoded PowerShell**
Time: 2026-07-12 04:06:32 UTC
Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
ParentImage: `C:\Windows\System32\wbem\WmiPrvSE.exe`
ParentUser: `NT AUTHORITY\NETWORK SERVICE`
Rule fired: 92071 (Level 12)
Note: Parent process context (WMI provider host, NETWORK SERVICE
account) is what elevates this above a simple encoded-command match —
a user double-clicking a script wouldn't produce this parent chain.

---

### False Positives identified
- Legitimate admin/deployment scripts occasionally use
  `-EncodedCommand` purely to escape special characters in complex
  parameters, not to obfuscate intent
- Software deployment tools (SCCM, Intune, some RMM agents) routinely
  spawn PowerShell via WMI for remote script execution — this is
  expected in managed enterprise environments and would need
  allow-listing by parent process path or signed-tool exclusion
- Not observed in this lab (single-endpoint, no legitimate WMI-based
  management tooling running), but a required tuning step before
  deploying this logic in a real fleet

---

### Blind Spots / What this misses
- **Non-base64 obfuscation:** XOR, custom string-splitting, or
  `-Command` (non-encoded) obfuscation with string concatenation
  won't match the `-EncodedCommand` pattern this relies on
- **Process-less execution:** PowerShell run via `.NET` reflection
  (e.g., loading `System.Management.Automation` directly into another
  process) never spawns `powershell.exe` at all — no EID 1 for
  Sysmon to capture
- **Payload content is invisible here:** detection is purely on
  execution pattern; the actual decoded command (what it *does*) isn't
  evaluated by this rule at all
- **Constrained Language Mode bypass techniques** and AMSI-evasion
  payloads aren't distinguished from benign encoded commands by this
  rule alone

---

### Recommended response
1. Decode the base64 payload immediately — confirm intent before
   escalating (many false positives decode to benign content)
2. Check ParentImage — WMI/NETWORK SERVICE parent context (as seen
   here) warrants faster escalation than a normal user-shell parent
3. Correlate with any EID 3 (network connection) within 2 minutes of
   execution — encoded PowerShell reaching out externally is a strong
   C2 indicator
4. Cross-reference with process injection (T1055) or credential
   access (T1003) alerts on the same host and timeframe — encoded
   PowerShell is frequently a delivery stage, not the end goal
5. If WMI-spawned and unauthorized — treat as possible lateral
   movement from another host, not just local execution

---
