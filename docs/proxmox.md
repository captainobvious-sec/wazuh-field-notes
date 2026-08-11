# Proxmox VE + PBS

Detection for Proxmox Virtual Environment and Proxmox Backup Server. Agents run
directly on the PVE nodes and the PBS host; logs are read from syslog.

## Files

| File | IDs | Purpose |
|---|---|---|
| `rules/proxmox/proxmox.xml` | 100800–100867 | PVE auth/brute-force, root@pam login, user mgmt, VM/CT lifecycle, backup, storage/cluster; PBS auth, backup ops, prune/GC, datastore |
| `decoders/proxmox/proxmox.xml` | — | Field-extraction decoders adding `srcip`, `url`, `data.pve.*` (vmid/task/user/status) |

## Gotchas

### Stock rule 87200 shadows custom root rules
Wazuh ships `0495-proxmox-ve_rules.xml`, whose rule **87200** (level 0) groups every
event decoded as `pvedaemon`, with children 87201 (auth fail), 87202 (brute), 87203
(auth success). Wazuh evaluates the **first matching root rule**, and the stock ruleset
loads first — so a plain custom *root* rule for `pvedaemon` events is silently swallowed
at level 0 and never fires.

All `pvedaemon`-sourced rules here therefore chain via `<if_sid>` onto **87200 / 87201 /
87203** (and stock **2501** for `pveproxy` auth failures). Rules for daemons with no
stock coverage (`pveum`, `pvescheduler`, `vzdump`, `pvestatd`, `corosync`, `pmxcfs`,
`proxmox-backup-proxy`) remain root rules. Don't convert the chained rules back to roots.

### PVE quotes usernames
PVE logs quote the account, e.g. `successful auth for user 'root@pam'`. The root@pam
detection matches the quoted form.

### Field-extraction decoder is additive
The decoders only *add* fields (`srcip`, `data.pve.*`); they don't consume the log or
stop rules from firing, and they run before `no_full_log` strips `full_log`. Enabling
them lets you build dashboard panels on `data.srcip` / `data.pve.vmid` etc.

## MITRE ATT&CK
Brute force (T1110/T1110.001), valid accounts (T1078/T1078.003), account manipulation
& creation (T1098/T1136), data destruction / inhibit recovery (T1485/T1490), and
exfiltration over migration (T1041).
