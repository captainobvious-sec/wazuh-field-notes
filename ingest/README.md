# Ingest

Collection-side configuration — what has to be true on the agents and relays before the
rules have anything to fire on.

## Linux

The Linux syslog core works on a default agent. The other 32 rules do not: they need
auditd and a FIM scope that a stock agent does not have.

| File | Install to | Gates |
|---|---|---|
| `linux/agent.conf.snippet.xml` | manager: `/var/ossec/etc/shared/<linux_group>/agent.conf` | everything — `/var/log/secure`, `/var/log/audit/audit.log`, and the FIM scope in one place |
| `linux/wazuh-linux.rules` | agent: `/etc/audit/rules.d/wazuh-linux.rules` | every `[AUDIT]` rule |
| `linux/syscheck-snippet.xml` | agent: merge into `<syscheck>` in `ossec.conf` | every `[FIM]` rule — an **alternative** to the agent.conf route, not an addition |

Put Linux agents in their own agent group first, or Windows agents inherit the FIM scope.

```bash
# on each Linux agent
sudo install -m 640 linux/wazuh-linux.rules /etc/audit/rules.d/wazuh-linux.rules
sudo augenrules --load && sudo auditctl -l      # confirm the rules are loaded
```

Then put `linux/agent.conf.snippet.xml` into the group's `agent.conf` on the manager and
restart `wazuh-manager`. Agents pull it on the next sync — confirm in the agent's
`/var/ossec/logs/ossec.log` ("Agent configuration ... merged").

`whodata="yes"` needs auditd running **and** a non-immutable audit ruleset (`-e 1`, not
`-e 2`). The `audit.key` values in `wazuh-linux.rules` must match the
`<field name="audit.key">` values in `rules/linux/` exactly — rename in both or neither.

## UniFi

UniFi devices cannot run a Wazuh agent, so they syslog to a relay host that does.

**The problem this solves:** UniFi OS / UNAS devices emit CEF with their *own*
`timestamp hostname` header, and a plain rsyslog relay prepends *another* timestamp.
The resulting double header makes Wazuh's predecoder read `program_name` as the inner
timestamp (e.g. `2026-06-04T21`) instead of `CEF`, and the UniFi decoder never fires.
`10-unifi.conf` rewrites CEF lines to a single clean header.

| File | Install to | Notes |
|---|---|---|
| `unifi/10-unifi.conf` | `/etc/rsyslog.d/10-unifi.conf` on the relay host | Listens on UDP+TCP 514. Change the port if something else already binds it. |
| `unifi/localfile-snippet.xml` | merge into `/var/ossec/etc/ossec.conf` on the same host | Points the agent at `/var/log/unifi/unifi.log` |

```bash
sudo install -m 644 unifi/10-unifi.conf /etc/rsyslog.d/10-unifi.conf
sudo systemctl restart rsyslog
# then add the <localfile> block to ossec.conf and:
sudo systemctl restart wazuh-agent
```

Point your UniFi controller's remote-syslog setting at this host, then confirm lines
are landing:

```bash
tail -f /var/log/unifi/unifi.log
/var/ossec/bin/wazuh-logtest      # paste a line; decoder should be "unifi"
```

The base decoder tolerates both header forms (`^CEF$` and `^\d{4}-\d{2}-\d{2}T\d{2}$`)
with an `Ubiquiti` content guard, so it still works if your relay is configured
differently — but the rewrite above is the cleaner path.
