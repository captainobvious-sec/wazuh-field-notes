# Linux (Rocky / RHEL-family)

Detection for Rocky Linux and its RHEL-family siblings (AlmaLinux, RHEL, CentOS Stream).
Several rules are deliberately RHEL-specific — `dnf`/`rpm`, `firewalld`, SELinux, the
`wheel` group, `pkexec`, `/var/log/secure`. On Debian/Ubuntu the auth correlation still
works (it rides the stock sshd/PAM rules) but the package, SELinux and firewall rules
will not fire as written.

Everything chains onto the **stock** Wazuh rulesets — there are no custom Linux decoders.

## Two tiers

The set splits cleanly by what telemetry it needs. This matters: deploy the whole thing
on a default agent and two thirds of it is silent, which looks like a broken ruleset.

| Tier | Files | Rules | Needs |
|---|---|---|---|
| **Syslog core** | `110_auth_correlation.xml` | 8 | Nothing beyond a default agent |
| **Advanced** | `111_`, `112_`, `113_`, `114_` | 32 | auditd and/or FIM — see `ingest/linux/` |

## Files (load order)

| File | IDs | Stock parents | Purpose |
|---|---|---|---|
| `110_auth_correlation.xml` | 111000–111030 | 5715, 5760, 5401–5403, 5501, 5503 | SSH brute-force-then-**success**, distributed brute force, sudo/PAM escalation, off-hours and weekend logins, privileged-group adds |
| `111_privilege_escalation.xml` | 111100–111151 | 550/553/554, 80700, 5401 | sudoers tampering, SUID/SGID, kernel modules, ptrace, setcap, pkexec (PwnKit) |
| `112_persistence.xml` | 111200–111250 | 550/553/554 | `authorized_keys` backdoors, cron, systemd units, shell profiles, PAM modules, attack tools on disk |
| `113_lateral_movement.xml` | 111300–111331 | 80700, 80792 | Scanner execution, reverse/bind shells, service-account shells, SSH pivoting, shadow and SSH-key reads |
| `114_defense_evasion.xml` | 111400–111470 | 550/553/554, 80700, 80792 | auditd/SELinux/firewall tampering, Wazuh removal, log and history deletion, timestomping, binary replacement |
| `115_alert_tuning.xml` | — | — | Documentation only: tiering notes and one staged composite kept as a comment. Zero active rules |

The numeric prefixes encode a real dependency: `111_` excludes the attack-tool basenames
so that a dropped `ncat` falls through to the more specific rule 111250 in `112_`. Keep
them in alphabetical order.

## Collection setup

Three files in `ingest/linux/`, none of which are optional if you want the advanced tier:

| File | Where | Gates |
|---|---|---|
| `agent.conf.snippet.xml` | manager, `/var/ossec/etc/shared/<linux_group>/agent.conf` | everything — reads `/var/log/secure`, `/var/log/audit/audit.log`, and sets the FIM scope |
| `wazuh-linux.rules` | agent, `/etc/audit/rules.d/`, then `augenrules --load` | every `[AUDIT]` rule |
| `syscheck-snippet.xml` | agent, merged into an existing `<syscheck>` in `ossec.conf` | every `[FIM]` rule — an alternative to the agent.conf route, not an addition |

Put the Linux agents in their **own agent group** so Windows agents do not inherit the
`<syscheck>` scope.

The `audit.key` values in `wazuh-linux.rules` must match the `<field name="audit.key">`
values in the rules exactly: `rocky_priv_setuid_file`, `rocky_priv_kmod`,
`rocky_priv_ptrace`, `rocky_priv_setcap`, `rocky_priv_pkexec`, `rocky_cred_shadow`,
`rocky_cred_sshkey`, `rocky_evasion_logdel`. Rename in both places or in neither.

## Gotchas

### `if_sid` / `if_group` match the *same* event, not "afterwards"
This is the mistake that silently killed most of an earlier version of this ruleset. A
rule like `<if_group>authentication_success</if_group>` + `<match>systemctl stop auditd</match>`
needs **one** log line that is simultaneously a successful login and an auditd stop — it
can never fire. "B after A" is:

```xml
<if_sid>B</if_sid>                              <!-- the current event -->
<if_matched_sid>A</if_matched_sid>              <!-- A happened recently -->
<same_srcip />                                  <!-- correlate the two -->
```

### `frequency` fires later than it reads
Empirically a composite fires around the **(N+4)th** matching event, not the Nth. Rule
111000 uses `frequency="3"` to catch a realistic ~7-failure burst. Budget for the offset
when tuning rather than taking the number literally, and note that `frequency="1"` is
**rejected** by the manager — the valid range is 2–9999, and a `1` surfaces as a cryptic
`1113 XML syntax error`.

### Correlate on static fields with the operators, not `same_field`
`srcip`, `srcuser` and `dstuser` are static fields. `<same_field>` only works on dynamic
ones, so these rules use `<same_srcip />`, `<same_srcuser />`, `<same_user />` (which
compares `dstuser`) and `<different_srcip />`.

### `if_matched_*` composites can't be exercised in `wazuh-logtest`
They accumulate on the live manager but not inside logtest. Confirm them with a
live-traffic soak; a silent logtest run is not evidence the rule is broken.

### Rule 111020 excludes cron on purpose
The stock Debian-format ignore rule 5521 does not catch Rocky's
`pam_unix(crond:session): session opened`, so root's periodic cron jobs satisfied the
"session opened" leg and produced level-12 "brute force succeeded" false positives every
few minutes. The rule is constrained to interactive PAM services.

### Rule 111311 needs your service UIDs
It matches the fixed RPM UIDs `48` (apache), `26` (postgres), `27` (mysql). nginx, tomcat
and application accounts get **dynamic** UIDs — read yours from `/etc/passwd` and add
them, or the webshell detection will not cover them.

### Rule 111470 is level 10 by design
`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` are in the default FIM set, so every `dnf update`
rewrites hundreds of them. At level 13 that was a patch-day storm. For a genuine
high-severity signal, enable syscheck `whodata` on those directories and add a level-0
child for when the modifying process is `dnf`/`rpm`/`systemd`.

### Reverse-shell one-liners are partly invisible
`bash -c "... /dev/tcp/ ..."` is a single argv token containing spaces, which auditd
hex-encodes. Rule 111310 matches raw argv tokens and cannot see the hex form. Either
accept the gap or add a decoder for it.

## Cross-platform correlation

`experimental/cross_device_correlation.xml` correlates these Linux events with other
platforms on the normalized `srcip` / `srcuser` fields. The Linux leg of that file works
— it is the Windows and appliance legs that do not. See `experimental/README.md`.

## MITRE ATT&CK
Brute force and valid accounts (T1110.001, T1078, T1078.003), privilege escalation
(T1548.001/.003, T1068, T1055.008), persistence (T1098.004, T1053.003, T1543.002,
T1546.004, T1556.003), credential access (T1003.008, T1552.004), defense evasion
(T1562.001/.004/.006, T1070.002/.003/.006, T1554, T1036.005), discovery and lateral
movement (T1046, T1018, T1021.004, T1059.004, T1571, T1190).
