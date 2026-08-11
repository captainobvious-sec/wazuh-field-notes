# Wazuh Custom Rules, Decoders & Dashboards

Custom Wazuh detection content for **Windows / Active Directory**, **Proxmox VE + PBS**, and **UniFi** networks, plus **cross-platform correlation** rules and OpenSearch Dashboards visualizations. Tested on **Wazuh 4.14.x**.

All detections use custom rule-ID ranges reserved to avoid collisions with the stock Wazuh ruleset.

## Repository layout

```
rules/
  windows/    100_ … 108_    Logon, PowerShell, registry, AD correlation, tuning, overrides
  proxmox/                    Proxmox VE + PBS auth, VM/backup ops, storage
  unifi/                      UniFi firewall, IDS/IPS, WiFi/RADIUS, admin
  common/                    Cross-device correlation (multi-platform)
decoders/
  windows/    windows_normalize.xml (optional field-normalization for cross-platform correlation)
  proxmox/                    PVE/PBS field-extraction decoders
  unifi/                      UniFi CEF + firewall + hostapd decoders
  common/
dashboards/
  windows/  proxmox/  unifi/  OpenSearch Dashboards saved-object exports (.ndjson)
docs/         windows.md  proxmox.md  unifi.md    Per-platform notes, gotchas, MITRE mapping
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
| 100800–100867 | Proxmox VE + PBS (`proxmox.xml`) |
| 129000–129013 | Cross-device correlation (`cross_device_correlation.xml`) |

## Deployment

```bash
# rules
sudo cp rules/windows/*.xml rules/proxmox/*.xml rules/unifi/*.xml rules/common/*.xml \
        /var/ossec/etc/rules/
# decoders
sudo cp decoders/proxmox/*.xml decoders/unifi/*.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/rules/*.xml /var/ossec/etc/decoders/*.xml
sudo chmod 660        /var/ossec/etc/rules/*.xml /var/ossec/etc/decoders/*.xml

sudo /var/ossec/bin/wazuh-analysisd -t          # must exit 0
sudo systemctl restart wazuh-manager
```

Dashboards are imported through the web UI: **Dashboards → Stack Management → Saved Objects → Import**. Keep the `wazuh-alerts-*` index pattern; the UniFi/Proxmox exports bundle their own `wazuh-alerts-4.x-*` pattern.

### Load order matters

Wazuh loads rule files alphabetically. The Windows filename prefixes (`100_`, `101_`, … `108_`) encode a required dependency order:
- `103_local_rules.xml` defines `100360` (RC4 TGS) and silences stock base rules; it must load **before** `104_ad_correlation.xml`, whose Kerberoasting-burst rule chains onto `100360`.
- `107_alert_tuning.xml` chains onto parents in `100_–105_` and must load **last** of the Windows set.

Do not rename the Windows files in a way that changes their alphabetical order.

## Requirements / notes

- **Windows** rules require Sysmon + Windows Security + PowerShell operational logging on the endpoints (see `docs/windows.md`).
- **DCSync (rule 100332)** needs "Audit Directory Service Access" and a replication-rights SACL on the domain object — see `docs/windows.md`.
- **Proxmox** rules chain onto the stock `0495-proxmox-ve_rules.xml` (rule 87200) — see `docs/proxmox.md`.
- **UniFi** logs are expected via a syslog relay forwarding CEF to a Wazuh agent — see `docs/unifi.md`.

See `CHANGELOG.md` for version history.
