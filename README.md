# Wazuh Custom Rules, Decoders & Dashboards

Custom Wazuh detection content for **Windows / Active Directory**, **Linux (Rocky / RHEL-family)**, **Proxmox VE + PBS**, and **UniFi** networks, plus OpenSearch Dashboards visualizations. Tested on **Wazuh 4.14.x**.

All detections use custom rule-ID ranges reserved to avoid collisions with the stock Wazuh ruleset.

## Repository layout

```
rules/
  windows/   100_ … 108_   Logon, PowerShell, registry, AD correlation, tuning, overrides
  linux/     110_ … 115_   Auth correlation, privesc, persistence, lateral movement, evasion
  proxmox/                 Proxmox VE + PBS auth, VM/backup ops, storage
  unifi/                   UniFi firewall, IDS/IPS, WiFi/RADIUS, admin
decoders/
  proxmox/                 PVE/PBS field-extraction decoders
  unifi/                   UniFi CEF + firewall + hostapd decoders
                           (Windows and Linux use the stock decoders — none needed)
dashboards/                OpenSearch Dashboards saved-object exports (.ndjson)
  windows/  linux/  proxmox/  unifi/   — see dashboards/README.md before importing
ingest/                    Collection-side config
  linux/                   agent.conf, auditd rules, syscheck scope
  unifi/                   rsyslog relay + localfile
docs/                      Per-platform notes, gotchas, MITRE mapping
experimental/              Known-incomplete work — NOT deployed, see its README
```

## Rule-ID range map

| Range | Platform / file |
|---|---|
| 100200–100222 | Windows logon events (`100_logon_events.xml`) |
| 100300–100364 | Windows AD correlation (`104_ad_correlation.xml`) |
| 100218, 100333–100358 | Windows additional AD / Kerberos (`105_additional_ad_detections.xml`) |
| 100400–100485 | Windows PowerShell (`101_powershell.xml`) |
| 100500–100557 | Windows registry integrity (`102_registry_integrity.xml`) |
| 100601–100610 | Windows alert tuning (`107_alert_tuning.xml`) |
| 110002/110003/100360 | Kerberoasting / Golden / Silver ticket (`103_local_rules.xml`) |
| 60xxx/91xxx/92xxx (overwrite) | Stock-rule routing overrides (`108_default_overrides.xml`) |
| 100700–100765 | UniFi (`unifi.xml`) |
| 111000–111030 | Linux auth correlation (`110_auth_correlation.xml`) |
| 111100–111151 | Linux privilege escalation (`111_privilege_escalation.xml`) |
| 111200–111250 | Linux persistence (`112_persistence.xml`) |
| 111300–111331 | Linux lateral movement / credential access (`113_lateral_movement.xml`) |
| 111400–111470 | Linux defense evasion (`114_defense_evasion.xml`) |
| 100800–100867 | Proxmox VE + PBS (`proxmox.xml`) |
| 129000–129013 | Cross-device correlation (`experimental/cross_device_correlation.xml`) |

## Deployment

Run on the manager:

```bash
# rules + decoders
sudo install -o wazuh -g wazuh -m 660 \
     rules/windows/*.xml rules/linux/*.xml rules/proxmox/*.xml rules/unifi/*.xml \
     /var/ossec/etc/rules/
sudo install -o wazuh -g wazuh -m 660 \
     decoders/proxmox/*.xml decoders/unifi/*.xml /var/ossec/etc/decoders/

sudo /var/ossec/bin/wazuh-analysisd -t          # must exit 0
sudo systemctl restart wazuh-manager
```

Nothing in `experimental/` is deployed by those commands — that is deliberate. Read
`experimental/README.md` before touching it; both files there have known limitations on
4.14.x and one of them will make `wazuh-analysisd -t` fail.

Rules alone are not enough for two platforms. **UniFi** needs a syslog relay and a
`<localfile>` entry; **Linux** needs auditd rules and a FIM scope, without which 32 of its
40 rules stay silent. Both are in `ingest/README.md`.

Dashboards are imported through the web UI. **The Windows exports ship with
index-pattern-id placeholders that you must substitute first** — see
`dashboards/README.md`.

### Load order matters

Wazuh loads rule files alphabetically, across every file in `/var/ossec/etc/rules/`. The
numeric prefixes encode required dependency orders.

**Linux** (`110_` … `115_`): `111_privilege_escalation.xml` excludes the attack-tool
basenames so a dropped `ncat` falls through to rule 111250 in `112_persistence.xml`.

**Windows** (`100_` … `108_`):
- `103_local_rules.xml` defines `100360` (RC4 TGS) and silences stock base rules; it must load **before** `104_ad_correlation.xml`, whose Kerberoasting-burst rule chains onto `100360`.
- `107_alert_tuning.xml` chains onto parents in `100_–105_` and must load **last** of the Windows set.

Do not rename the Windows files in a way that changes their alphabetical order.

## Requirements / notes

- **Windows** rules need the Windows Security eventlog + PowerShell operational logging on the endpoints. **Sysmon is not required** — exactly one rule (100354) uses it. See `docs/windows.md`.
- **Linux** rules split into a syslog core that works on a default agent (8 rules) and an advanced tier needing auditd + FIM (32 rules). Written for RHEL-family; see `docs/linux.md`.
- **DCSync (rule 100332)** needs "Audit Directory Service Access" and a replication-rights SACL on the domain object — see `docs/windows.md`.
- **Proxmox** rules chain onto the stock `0495-proxmox-ve_rules.xml` (rule 87200) — see `docs/proxmox.md`.
- **UniFi** logs arrive via a syslog relay forwarding CEF to a Wazuh agent — config in `ingest/unifi/`, background in `docs/unifi.md`.

## Licensing

MIT (`LICENSE`), **except** three Windows rule files — `103_local_rules.xml`,
`104_ad_correlation.xml` and `108_default_overrides.xml` — which reproduce rule bodies
from the GPLv2 Wazuh default ruleset and are therefore distributed under the GPLv2
(`LICENSE.GPL-2.0`). `NOTICE.md` lists the exact rule ids and the nature of each
derivation.

See `CHANGELOG.md` for version history.
