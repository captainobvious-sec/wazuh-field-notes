# Changelog

## v1.0.0 — Initial public release

Custom Wazuh rules, decoders, and dashboards for Windows/AD, Proxmox VE+PBS, UniFi,
and cross-platform correlation. Validated on Wazuh 4.14.x.

### Detection coverage
- **Windows / AD** — logon events & brute-force, PowerShell (script-block + module),
  registry integrity/persistence, AD correlation (account lifecycle, group changes,
  Kerberoasting, DCSync, AS-REP roasting, spray, lateral movement), Tier-0 group
  monitoring, alert tuning and default-rule routing overrides.
- **Proxmox VE + PBS** — authentication & brute-force, VM/CT lifecycle, backup
  success/failure, storage & cluster health, plus field-extraction decoders.
- **UniFi** — firewall (LAN→WAN / inter-VLAN), IDS/IPS, WiFi/RADIUS auth, admin
  config changes, with CEF + netfilter + hostapd decoders.
- **Cross-device** — multi-platform brute-force / account-takeover correlation on
  normalized `srcip` / `srcuser` fields.

### Validated fixes (purple-team tested)
- **AS-REP Roasting (100358)** — now keys on `PreAuthType == 0` instead of a
  hardcoded `ticketOptions` value, so it detects impacket and Rubeus alike.
- **Kerberoasting burst (100331)** — re-pointed to the RC4-TGS catch-all (100360);
  the previous feeder required a tool-specific `ticketOptions` value and never fired.
- **DCSync (100332)** — rule confirmed correct; documented the DC-side audit
  prerequisites (Directory Service Access auditing + replication SACL) required to
  generate the underlying 4662 events.
