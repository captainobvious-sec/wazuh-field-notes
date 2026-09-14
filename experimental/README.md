# Experimental — do NOT deploy as-is

Everything in this folder is kept for reference and future work. It is **not** part of
the normal deployment, and the main `README.md` deploy commands deliberately skip it.
Both files below have known, tested limitations on Wazuh 4.14.x.

---

## `windows_normalize.xml` — REJECTED by Wazuh 4.14.x

**Do not copy this into `/var/ossec/etc/decoders/`.** On Wazuh 4.14.3 it is rejected at
load time and `wazuh-analysisd -t` fails, which will stop `wazuh-manager` from restarting:

```
Parent decoder name invalid: windows_eventchannel
```

The cause: `windows_eventchannel` is a **plugin decoder**, and plugin decoders accept no
XML child decoders. The technique in this file — attaching `<parent>windows_eventchannel</parent>`
children to copy `win.eventdata.ipAddress` / `win.eventdata.targetUserName` into the
normalized `srcip` / `srcuser` fields — is therefore not available on 4.14.x.

It is kept here because the *intent* is still valid: cross-platform correlation needs
Windows events to expose `srcip` / `srcuser` under the same field names Linux and the
appliances use. A working implementation would need a different mechanism (for example
a manager-side integration or a rule-level field alias), not a child decoder.

If you want to test it on another Wazuh build, copy it to a **non-production** manager
first and confirm `wazuh-analysisd -t` exits 0 before restarting anything.

## `cross_device_correlation.xml` — incomplete dependencies

These `129xxx` rules correlate authentication and attack activity **across** platforms.
They are not self-contained in this repository:

- `129001` / `129002` chain onto appliance rules — ESXi (`120xxx`), vCenter (`121xxx`)
  and McAfee NSP IPS (`133xxx`) — **none of which ship here**. Those two rules cannot fire.
- The Windows leg depends on `windows_normalize.xml` above, which does not load on
  4.14.x. Windows events therefore never participate.
- What remains working is the Linux leg: the `srcip` rules (`129000`, `129003`) and the
  user rules (`129010`–`129013`) fire on SSH/PAM/sudo/su events from the stock Linux
  rulesets — and therefore alongside `rules/linux/`, which is shipped and supported.

If you only run Linux agents alongside Windows, expect roughly half of this file to be
inert. Deploy it knowingly, or use it as a template for your own correlation layer.
