# Windows / Active Directory

Custom detection for Windows endpoints and domain controllers. Rules chain onto the
stock Wazuh Windows rulesets (`0575`, `0580`, `0840`, `0915`) and the Windows event-channel decoder.

## Files (load order)

| File | IDs | Purpose |
|---|---|---|
| `100_logon_events.xml` | 100200–100222 | Logon by type/outcome; RDP & interactive brute-force escalation |
| `101_powershell.xml` | 100400–100485 | PowerShell script-block (4104) + module (4103): recon / attack / persistence |
| `102_registry_integrity.xml` | 100500–100557 | Registry persistence & defense-evasion keys (Run, LSA, IFEO, services, DC keys) |
| `103_local_rules.xml` | 60xxx→0 + 110002/110003/100360 | Silences noisy base rules; defines Kerberoasting / Golden / Silver ticket |
| `104_ad_correlation.xml` | 100300–100364 (+60154/59/66/67) | Account lifecycle, group changes, Kerberoasting, DCSync, spray, PsExec, Tier-0 |
| `105_additional_ad_detections.xml` | 100218, 100333–100358 | Kerberos pre-auth spray/brute, username enum, OverPass-the-Hash, AS-REP roasting |
| `107_alert_tuning.xml` | 100601–100610 | Tier-1 composites (RDP-success-after-brute, Defender hard-kill, NTDS dump, webshell) |
| `108_default_overrides.xml` | stock IDs (`overwrite`) | Email-tiering of stock rules without editing the base ruleset |

`103_`, `104_` and `108_` contain content derived from the GPLv2 Wazuh default ruleset —
see `NOTICE.md`. There is no `106_`: those PowerShell module-logging rules were merged
into `101_powershell.xml`, which is why the numbering skips it.

## Telemetry prerequisites (endpoints)

This ruleset is designed to work **without Sysmon** — it runs on the native Security
eventlog, PowerShell operational logging and Wazuh registry FIM. Required:

- **Windows Security** auditing: Logon/Logoff, Account/Group Management, Kerberos
  Auth & Service Ticket, Credential Validation, Detailed Tracking (4688 + command line).
- **PowerShell** operational logging: Script Block Logging (4104) and Module Logging (4103).
- **Registry FIM**: `<windows_registry>` entries under `<syscheck>` in the agent config,
  for the hives `102_registry_integrity.xml` watches. Registry monitoring is scan-based,
  so a value written and deleted between scans is never seen.
- Agent `<localfile>` eventchannel blocks for `Security`, `System` and
  `Microsoft-Windows-PowerShell/Operational`.

**Optional — Sysmon.** Exactly one rule needs it: **100354** (renamed offensive tool by
PE `originalFileName`) chains onto `61603`, Sysmon Event 1. Security event 4688 does not
carry `OriginalFileName`, so without Sysmon — and without a `<localfile>` for
`Microsoft-Windows-Sysmon/Operational` — that one rule is dormant. Rule **100340**
(process name match on 4688) is the Sysmon-free fallback. Every other rule here works
with no Sysmon at all.

## Gotchas

### Load order
`103_` must load before `104_` (the Kerberoasting-burst rule 100331 chains onto 100360,
defined in 103). `107_` must load last. The numeric filename prefixes preserve this —
don't rename them out of order.

### Kerberos roasting detection is tool-agnostic
Detections key on protocol facts, not tool-specific request flags:
- **AS-REP roasting (100358)** → `PreAuthType == 0` on a successful 4768.
- **Kerberoasting (100360 → 100331)** → RC4 (`0x17`) service ticket (4769) for a
  non-machine account; a burst of 8+ from one source escalates to 100331.

Matching on a fixed `ticketOptions` value (e.g. Rubeus' `0x40800010`) is fragile —
impacket sends different values. This ruleset avoids that.

### DCSync (100332) requires DC-side audit config
The rule matches 4662 with the replication GUIDs `1131f6aa` / `1131f6ad`. Those events
are only generated if, on the domain controllers:
1. **Audit Directory Service Access = Success** is enabled (via GPO — a local
   `auditpol` change is reverted on the next Group Policy refresh).
2. The domain NC head has an **audit SACL** for the replication extended rights
   (`Replicating Directory Changes` / `…All`) for the relevant principal.

Without both, DCSync produces no 4662 and the rule cannot fire.

## MITRE ATT&CK
Covers 70+ techniques including credential access (T1003.*, T1558.*, T1552.*),
lateral movement (T1021.*, T1550.002), persistence (T1547.*, T1546.*, T1053.005,
T1136.002), privilege escalation (T1134, T1484.*), and defense evasion
(T1562.*, T1070.001, T1027). Each rule carries its `<mitre><id>` tag.
