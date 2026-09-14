# Ingest

Collection-side configuration. These files get UniFi log lines into a shape the
decoders in `decoders/` can actually parse. Nothing here runs on the Wazuh manager.

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
