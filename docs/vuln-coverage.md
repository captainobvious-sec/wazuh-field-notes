# Vulnerability and attack-technique coverage (2026-11 review)

Rules added after a review of the technologies in this homelab against recent
vulnerabilities and attack techniques. Every rule here is written for **Wazuh 4.14.x**
(XML). None of them has been run against a live host: the log formats come from vendor
source code, advisories and public write-ups, and each rule needs one `wazuh-logtest`
check with a real line (and ideally one real trigger) before it is trusted.

Confidence column: **H** = documented event or vendor source, **M** = technique well known,
exact string composed from the record shape, **L** = generic signal, expect tuning.

## What was added

| Rule(s) | Detects | Basis | Conf. | Needs |
|---|---|---|---|---|
| 116000 | `sudo` with the chroot option (`-R` / long form) — CVE-2025-32463 (CISA KEV) | SUDO_ASKPASS="$__hermes_sudo_dir/a" sudo "${__hermes_sudo_o[@]}" NEWS, advisory; sudo's own log line is unreliable here, so auditd EXECVE | H | `ingest/linux/wazuh-linux.rules` (generic execve) |
| 116001 | non-root AF_ALG socket (kernel crypto LPE class) | public exploit reporting (secondary sources) | L | `rocky_priv_afalg` audit key |
| 116002 | `/etc/ld.so.preload` created/changed | MITRE T1574.006 | H | FIM entry in `syscheck-snippet.xml` |
| 116003, 116004 | docker started privileged / with host root or `docker.sock` mounted | container-escape staging | M | `docker` exe audit rule |
| 116005–116007 | logging/audit service stopped, `truncate` on `/var/log`, `journalctl --vacuum` | T1562 / T1070 | M | generic execve |
| 116008 | rsyslog config changed | the relay is what makes UniFi/OMV visible | H | FIM |
| 116009 | Wazuh agent `ossec.conf` / `client.keys` changed | T1562.001 | M | FIM on `/var/ossec/etc` |
| 116010 | `sshd_config` changed | T1098.004 | H | FIM (`/etc/ssh` already realtime) |
| 116011 | `fstab` / NFS exports changed | new mounts and exports | M | FIM |
| 116100, 116101 | UniFi OS rogue admin names (`unifi_support`, `supports_unifi_system`), IPS signature naming the exploited CVEs | Ubiquiti SAB-064, CISA KEV 2026-06-23; account names from incident reports | M | existing UniFi CEF feed |
| 116200, 116201 | Zerologon: Netlogon 5827/5828/5830/5831 (attempt) and 5829 (allowed) | Microsoft KB4557222 | H | System log from the DC |
| 116202 | noPac: computer account renamed without `$` | public write-ups | M | Audit Computer Account Management |
| 116203, 116204, 116206 | RBCD attribute, shadow credentials (`msDS-KeyCredentialLink`), BadSuccessor link | 5136 attribute names | M | Audit Directory Service Changes |
| 116205, 116209 | AD CS template/CA tampering (5136 on template objects, CA events 4898–4900) | ESC4/ESC5 | M | CA role in the lab; CA auditing |
| 116207 | dMSA object created (5137) | CVE-2025-53779, Server 2025 DCs only | M | Audit Directory Service Changes |
| 116208 | PetitPotam-style access to the `efsrpc` pipe | public write-ups | M/L | Audit Detailed File Share (very noisy) |
| 116210, 116211 | AnyDesk installed as a service (7045); run with unattended switches (4688) | T1219 | H / M | process-creation auditing + command line |
| 100880–100883 | PBS API: backup group/snapshot delete, mass deletion, prune/GC, ACL/user/API-token changes | PBS source: these are direct API calls with **no** log line other than the access log | M | `ingest/proxmox/localfile-snippet.xml` |
| 116300–116307 | Wazuh authd/remoted: wrong enrolment password, duplicate name/IP, path-like agent names, new key issued, wrong key, replayed counter | wazuh v4.14.10 source | M | `ingest/wazuh/localfile-snippet.xml` on the manager |
| 116310, 116311 | Samba: rename to ransomware extension, ransom-note file | `vfs_full_audit` source | M | `ingest/apps/smb-full-audit.conf.snippet` |
| 116320–116322 | Jellyfin failed login (+burst), ffmpeg file-read arguments (GHSA-jh22-fw8w-2v9x) | Jellyfin source + advisory | M | `ingest/apps/localfile-snippet.xml` |
| 116325–116327 | qBittorrent WebUI failed login, burst, IP ban | qBittorrent source | M | file logging enabled; English locale |
| 116330, 116331 | Seerr failed sign-in, burst | Seerr source | M | text log from the config volume |
| 116335, 116336 | n8n failed login (audit event) and burst | n8n source: **only** in the event log | M | `n8nEventLog.log` |

New decoders: `decoders/homelab/apps.xml` (Jellyfin, qBittorrent, Seerr, Samba audit, Wazuh
`ossec.log`) and `decoders/proxmox/pbs_access.xml`.

## Deliberately not covered (and why)

| Item | Reason |
|---|---|
| Pi-hole v6 failed web logins | Not logged at the default level (only at `debug.api`). Needs a reverse-proxy log or debug logging. |
| Wiki.js 2.x failed login | No log line exists. Only the HTTP response carries the error. |
| n8n unauthenticated file read (CVE-2026-21858) | Visible only with a reverse-proxy log that records `Content-Type`. No such log exists here. |
| cloudflared `--token` rogue tunnel | The token is in argv, so an execve rule would copy the secret into the Wazuh index. No log line distinguishes token mode. |
| Tailscale key theft, subnet-router abuse | Happens in the control plane (admin audit log). Nothing local to match. |
| Cloudflare DDNS API-token misuse | Visible only in the Cloudflare audit log. |
| UniFi OS root implant (cron, spoofed process) | No shell telemetry from the console. Only the rogue-admin indicator (116100) is observable. |
| regreSSHion (CVE-2024-6387) | The indicator string was never confirmed from a primary source. |
| Mass unlink on SMB shares | Backup garbage collection deletes chunks in bulk; a rule would fire on every GC. |
| LSASS access | Needs Sysmon, which the Windows ruleset deliberately does not require. |

## Rollout and test status (2026-11-20)

Deployed to the 4.14.3 manager and to the agents listed below, then triggered for real.
Every row marked **fired** produced the expected alert from a genuine log line.

| Rules | Where | Result |
|---|---|---|
| 116002, 116008 | Docker VM, `Linux` group (`/etc` realtime) | **fired** (create/delete `ld.so.preload`, new file in `rsyslog.d`) |
| 116001, 116003, 116004 | Docker VM, auditd with `wazuh-docker-host.rules` | **fired** (AF_ALG socket, `docker run --privileged`, docker.sock mount) |
| 116320 | Jellyfin VM | **fired** (one wrong login) |
| 116325 | Torrent VM (qBittorrent) | **fired** |
| 116330, 116335 | Docker VM (Seerr, n8n event log) | **fired** |
| 116300–116307 | manager `ossec.log` collected | rules unit-tested only: no enrolment has happened since |
| 116009–116011 | `Linux` group FIM | logic tested, not triggered live |
| 100880–100883 | PBS | **not rolled out**: no access to the PBS hosts |
| 116310, 116311 | OpenMediaVault Samba | **not rolled out**: OMV is stopped, agent disconnected |
| 116200–116211 | LAB-DC / LAB-W11 | **not rolled out**: lab VMs are stopped |
| 116000 | Docker VM | **not applicable**: this host runs sudo-rs, which has no `-R` |

Findings from the real logs: the Jellyfin file template of this build has no thread id or
source context (decoder fixed), and on Ubuntu the enriched auditd format makes the stock rule
92600 claim SYSCALL records, so key-based rules must chain onto `80700,92600` (116001 does;
the older `111xxx` key rules chain onto 80700 only).

## Known limits

- **Tested on a 4.14.3 manager.** `wazuh-analysisd -t` passes and 50 synthetic events through
  `wazuh-logtest` fire the expected rule (including negative cases). That caught four defects
  before the live rollout: PCRE groups without `type="pcre2"` (analysisd rejected the file;
  `lint_ruleset.py` now checks for this), a stock `smbd` decoder that swallowed the Samba lines,
  stock rule 2501 claiming qBittorrent failures first, and a Seerr prematch defeated by the
  syslog predecoder.
- **Windows rules are unexercised.** `wazuh-logtest` cannot feed `eventchannel` events, so their
  field and regex logic was tested on a temporary copy that used the `json` decoder in place of
  the stock parents. The parent chain (60103 / 60002 / 60230 / 100350) was not exercised, and the
  lab domain controller is powered off.
- Frequency (`if_matched_sid`) rules do not accumulate in logtest and were not triggered live.
- **Windows event parents.** Rules chain onto stock 60103, 60230 and 60002 and onto
  custom 100350. The stock parent for a given event ID was read from the 4.14.3 manager.
- **Wazuh enrolment is passwordless** on this manager (`<use_password>no`), so the 2026 authd
  advisories are reachable by any host that can reach port 1515. Rules 116300–116307 only
  detect it; setting an enrolment password closes it.
- **Sources are HEAD, not your versions.** Log text was read from current source trees.
  Confirm it against the versions you actually run.
- **Wazuh 5.** `ossec.log` enrolment lines differ in 5.x (one is no longer logged at INFO),
  and rules in 5.x are Sigma YAML evaluated on the indexer, with no `frequency` support. The
  correlation rules here (`if_matched_sid`) have no 5.x equivalent.
- **Exposure not checked.** Whether the homelab runs vulnerable versions of UniFi OS, n8n,
  Wazuh (4.14.3 predates most 2026 fixes), Jellyfin, Seerr or Ghost was not verified; that
  is a patching question the rules do not answer.
