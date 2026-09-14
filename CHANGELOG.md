# Changelog

## v1.2.0 — Linux (Rocky / RHEL-family)

### Added
- **`rules/linux/`** — 40 rules, `111000`–`111470`, across five load-ordered files plus a
  documentation-only tuning file. No custom decoders; everything chains onto the stock
  sshd / PAM / syslog / auditd / syscheck rulesets.
  - `110_auth_correlation.xml` — SSH brute-force-then-**success**, distributed brute
    force, sudo and PAM escalation, off-hours and weekend logins, privileged-group adds
  - `111_privilege_escalation.xml` — sudoers, SUID/SGID, kernel modules, ptrace, setcap,
    pkexec (PwnKit)
  - `112_persistence.xml` — authorized_keys, cron, systemd units, shell profiles, PAM
    modules, attack tools on disk
  - `113_lateral_movement.xml` — scanners, reverse/bind shells, service-account shells,
    SSH pivoting, shadow and SSH-key reads
  - `114_defense_evasion.xml` — auditd/SELinux/firewall tampering, Wazuh removal, log and
    history deletion, timestomping, binary replacement
  - `115_alert_tuning.xml` — notes and one staged composite, zero active rules
- **`ingest/linux/`** — the collection config the advanced tier needs: shared `agent.conf`,
  the auditd ruleset whose keys the rules match on, and a `<syscheck>` scope.
- **`dashboards/linux/`** — security and syslog dashboards (29 saved objects).
- **`docs/linux.md`** — the two-tier split, the `audit.key` contract, and the gotchas that
  cost the most time: `if_sid` matches the *same* event rather than "afterwards",
  `frequency` fires around the (N+4)th event and `frequency="1"` is rejected outright,
  static fields need `<same_srcip />` rather than `<same_field>`, and `if_matched_*`
  composites cannot be exercised in `wazuh-logtest`.

### Note on coverage
8 of the 40 rules are a syslog core that works on a default agent. The other 32 need
auditd and/or FIM and stay silent without `ingest/linux/` — this is called out in the
README, `docs/linux.md` and `ingest/README.md` rather than left to be discovered.

The Linux leg of `experimental/cross_device_correlation.xml` now has shipped rules behind
it; its Windows and appliance legs remain unavailable.

## v1.1.0 — Publication cleanup

### Fixed
- **`windows_normalize.xml` no longer sits in the deploy path.** It is rejected by Wazuh
  4.14.x (`Parent decoder name invalid: windows_eventchannel` — plugin decoders take no
  XML children), which makes `wazuh-analysisd -t` fail and blocks a manager restart. Moved
  to `experimental/` with the tested failure documented; the old `decoders/common/README.md`
  had described it as merely optional.
- **`cross_device_correlation.xml` moved to `experimental/`.** Rules 129001/129002 chain
  onto ESXi/vCenter/McAfee appliance rulesets that this repo does not ship, and its Windows
  leg depends on the decoder above. Only the Linux leg works; that is now stated up front.
- **Dashboard index-pattern ids replaced with placeholders.** The Windows exports carried
  one manager's ids, inconsistently: `01`/`02`/`04` used the legacy double-prefixed
  `index-pattern:wazuh-alerts-*` while `03` used `wazuh-alerts-*`, so at least one file
  could not resolve its references on import anywhere. Now `WAZUH_ALERTS_IP_ID` /
  `WAZUH_MONITORING_IP_ID`, with substitution documented in `dashboards/README.md`.
- **Stale cross-references removed** — comments pointed at an internal deploy script and at
  sibling filenames from a different repository layout (`104-ad_correlation_rules.xml`,
  `107-alert_tuning_windows.xml`, `Linux/0110-rocky_auth_correlation.xml`, and others).

### Added
- `NOTICE.md` — GPLv2 provenance for the stock rule bodies reproduced under
  `overwrite="yes"` in `103_`, `104_` and `108_`. Those three files are GPLv2; the rest of
  the repository stays MIT.
- `ingest/unifi/` — the rsyslog relay config that fixes UniFi's double CEF header, plus the
  agent `<localfile>` snippet. `docs/unifi.md` described this step but shipped no config.
- `dashboards/README.md` — import procedure, field-schema check, timezone note.
- `.gitattributes` — normalizes line endings (one rule file had shipped as CRLF).
- `LICENSE.GPL-2.0` — the GPLv2 text itself. The licence requires it to accompany the
  code, and the three GPLv2 files were shipped without it.

### Note on `LICENSE`
An explanatory preamble had been prepended to the MIT text. That dropped the file below
GitHub's license-matching threshold, so the repository was detected as "Other /
NOASSERTION" instead of MIT. `LICENSE` is now the unmodified MIT text again; the
GPLv2 carve-out lives in `NOTICE.md`, `README.md` and the headers of the three affected
rule files, which is where it belongs.

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
