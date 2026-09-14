# UniFi

Detection for UniFi networks (UniFi OS / Network). UniFi devices can't run a Wazuh
agent, so logs are forwarded via a syslog relay to a host that does. UniFi emits **CEF**
(not netfilter-style kernel logs), plus firewall syslog and hostapd for WiFi.

## Files

| File | IDs | Purpose |
|---|---|---|
| `rules/unifi/unifi.xml` | 100700–100765 | Firewall LAN→WAN / inter-VLAN drops, IDS/IPS signatures, WiFi RADIUS auth & brute-force, admin config changes, SSH |
| `decoders/unifi/unifi.xml` | — | CEF base + KV fields, LAN_LAN / LAN_WAN firewall, hostapd (RADIUS/STA) decoders |
| `ingest/unifi/10-unifi.conf` | — | rsyslog relay: rewrites double-headed CEF to one clean header |
| `ingest/unifi/localfile-snippet.xml` | — | agent `<localfile>` for `/var/log/unifi/unifi.log` |

## Decoder field names
Rules use the verbatim decoded field names (no `data.` prefix, no `.keyword` suffix):
`type`, `srcprt`, `dstprt`, `proto`, `srcip`, `dstip`, `uni_sigid`, `uni_risk`,
`uni_signature`, `uni_changeagent`, `uni_changedsection`, `uni_radius_result`,
`srcmac`, `uni_action`, `uni_cat`, `uni_subcat`, etc.

## Gotchas

### CEF program_name quirk
Clean UniFi CEF arrives with `program_name="CEF"`, but forwarded UniFi OS lines can have
a double timestamp, so the predecoder picks up the second timestamp's date-hour as the
program_name. The base decoder matches both (`^CEF$` or `^\d{4}-\d{2}-\d{2}T\d{2}$`)
with an `Ubiquiti` content guard. `ingest/unifi/10-unifi.conf` fixes it at the relay
instead, which is cleaner — the decoder tolerance is the safety net.

### UniFi OS has no `src=` field
On UniFi OS (e.g. UNAS), the real client/admin IP is only inside `msg` as
`Source IP: X`; a decoder pulls it into `srcip` and overrides `src=` when both exist.

### IDS/IPS is not Suricata-decoded
UniFi threat-management alerts are tiered by `uni_risk` and matched on `uni_signature`
text (C2 / malware / exploit), not Suricata priority levels.

## MITRE ATT&CK
Exfiltration / C2 (T1048, T1071), lateral movement & recon (T1021, T1595.001),
exploitation (T1190, T1203), brute force (T1110.001), defense/config tampering
(T1562.001, T1565), and valid accounts (T1078.004).
