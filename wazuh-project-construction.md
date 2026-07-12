# Wazuh EDR Home Lab — Part 1: Deployment on Constrained Hardware

**Shachin P R | SOC Portfolio Project 2**

## Overview

Following the Splunk SIEM detection lab (`siem-home-lab`), this project deploys Wazuh — a free, open-source EDR platform — across a two-VM home lab to investigate simulated endpoint threats. Where Project 1 focused on log correlation and SIEM analytics, this project adds real-time endpoint detection, file integrity monitoring, and active response — capabilities a pure log-aggregation SIEM can't provide.

**Stack:** Windows 11 VM (Sysmon + Wazuh agent) ↔ Ubuntu 24 VM (Wazuh manager), VirtualBox host-only network.

## Architecture Decision: Manager-Only Deployment

Wazuh's standard "all-in-one" deployment bundles three components: the manager, the indexer (OpenSearch/JVM-based), and the dashboard. Official sizing guidance recommends roughly 8GB RAM and 50GB disk for this combination even at small agent counts — the indexer's JVM heap alone defaults to ~4GB.

The lab hardware (HP Victus, 16GB RAM shared across host + 2 VMs) couldn't support that. Rather than force it, the lab runs **manager-only**: no indexer, no dashboard. Alerts are read directly from `/var/ossec/logs/alerts/alerts.json`, validated via `wazuh-logtest`, and queried through the manager's REST API. This trades dashboard visuals for a leaner, more transparent pipeline — and forces direct engagement with raw detection data rather than a pre-built UI.

## Deployment Log: What Actually Went Wrong

Home-lab writeups often skip the friction. This section doesn't.

**1. Disk exhaustion from the vulnerability-detection feed.**
The first Ubuntu VM (18GB disk) filled to 100% within hours of the manager's first start. Root cause: Wazuh's vulnerability-detection module (enabled by default) downloads a CVE feed into `/var/ossec/queue/vd/feed` and stages data in `/var/ossec/tmp` — together these consumed over 12GB on first run. Fix: disable the module *before* the first service start, not after:
```bash
sudo sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s/<enabled>yes<\/enabled>/<enabled>no<\/enabled>/' /var/ossec/etc/ossec.conf
```
This isn't needed for this lab's detection scenarios (endpoint behavior, not CVE matching), so disabling it is a legitimate scoping decision, not just a workaround.

**2. LVM disk sizing on VM rebuild.**
Rebuilding with a larger virtual disk revealed the new VM's LVM logical volume wasn't sized correctly on creation — required checking `vgs`/`lvs` for available free extents before the filesystem would actually reflect the larger disk.

**3. Clock/NTP misconfiguration.**
The Windows 11 VM's time service was stopped with no NTP source configured (`w32tm /resync` failed with "no time data was available"). Left uncorrected, this contributes to agent status reporting oddly at the manager.

**4. Duplicate agent registration.**
An interrupted first enrollment attempt left a stale agent name (`win11-endpoint`) registered against a manager that no longer existed post-rebuild. The new manager rejected re-enrollment under the same name until the stale entry was removed via `manage_agents`.

**5. Sysmon telemetry wasn't flowing by default.**
Sysmon was already running (carried over from Project 1), but a fresh Wazuh agent install only forwards the `Application`, `Security`, and `System` Windows event channels — **not** `Microsoft-Windows-Sysmon/Operational`. Sysmon's process-creation telemetry (the data source this whole project depends on) required manually adding a `<localfile>` block for that channel:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Lesson:** a working agent connection doesn't mean the right data is being collected. "Active" status and "receiving the telemetry I actually need" are two different checks.

## First Detection Scenario: T1059.001 — Suspicious PowerShell

**Simulation tool:** Atomic Red Team, test `T1059.001-15` (`ATHPowerShellCommandLineParameter -EncodedCommand parameter variations`) — executes `powershell.exe` with a base64-encoded `-E` argument.

**Result:** Wazuh's default Sysmon-based ruleset detected it without any custom rule required:

| Rule ID | Level | Description | MITRE Mapping |
|---|---|---|---|
| 92071 | 12 (high) | A powershell process created by WMI executed a base64 encoded command | T1047 (WMI), T1059.001 (PowerShell) |
| 92027 | 4 | Powershell process spawned powershell instance | T1059.001 |

Sample detected command line:
```
powershell.exe -NoProfile -E VwByAGkAdABlAC0ASABvAHMAdAAgADMAZQA0OTY5ZTYtNzUwYi00MGUzLTkyYjItNTg5NmM4OThjODU0
```

Rule `92071` correctly attributed the process to a WMI-spawned context (`WmiPrvSE.exe` → `powershell.exe`) — a more specific and higher-fidelity detection than a simple keyword match on `-EncodedCommand` would produce.

### Comparison to Project 1 (Splunk)

| | Splunk SIEM Lab | Wazuh EDR Lab |
|---|---|---|
| Detection method | Hand-built SPL `case()` rule flagging EncodedCommand/Bypass/Hidden/WebDownload | Default Sysmon ruleset, zero custom rules needed |
| Data source | Sysmon → Splunk Universal Forwarder | Sysmon → Wazuh agent (native eventchannel) |
| Attribution | Keyword match on command line | Process-lineage aware (flagged WMI as the spawning context) |
| Effort to first alert | Manual rule authoring | Out-of-the-box, configuration-only |

This is the clearest data point so far for why EDR platforms bundle detection logic that a general-purpose SIEM leaves to the analyst to build.

## Next Steps (Part 2+)

- T1003 — LSASS credential access (direct Splunk comparison point)
- T1055 — Process injection (direct Splunk comparison point)
- T1547.001 — Registry Run Key persistence (new: Wazuh registry monitoring)
- T1486 — Simulated ransomware via File Integrity Monitoring (new: FIM, the standout EDR capability this project adds)
- Active response — auto-isolation on a trigger (new: the "R" in EDR that a SIEM can't structurally provide)

---
