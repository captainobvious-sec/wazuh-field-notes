# Dashboards

OpenSearch Dashboards saved-object exports. Built as classic Visualize / TSVB /
saved-search objects — **not** Lens, which does not exist in OpenSearch Dashboards.

| File | Dashboard | Index pattern | Default range |
|---|---|---|---|
| `windows/01-security-overview.ndjson` | Wazuh - Security Overview | `wazuh-alerts-*` (placeholder) | 24h |
| `windows/02-windows-security.ndjson` | Wazuh - Windows Security | `wazuh-alerts-*` (placeholder) | 24h |
| `windows/03-mitre-attack.ndjson` | Wazuh - MITRE ATT&CK (all platforms) | `wazuh-alerts-*` (placeholder) | 7d |
| `windows/04-operational-health.ndjson` | Wazuh - Operational Health | `wazuh-alerts-*` + `wazuh-monitoring-*` (placeholders) | 24h, 300s auto-refresh |
| `unifi/unifi.ndjson` | UniFi - Network Security | `wazuh-alerts-4.x-*` (**bundled**) | — |
| `proxmox/proxmox.ndjson` | Proxmox VE + PBS - Infrastructure | `wazuh-alerts-4.x-*` (**bundled**) | — |

## 1. Substitute the index-pattern IDs (Windows dashboards only)

NDJSON links visualizations to index patterns by **saved-object id**, not by title, and
that id is not the same on every installation — depending on how the Wazuh dashboard
plugin created it, it may be `wazuh-alerts-*` or the legacy double-prefixed
`index-pattern:wazuh-alerts-*`. The four Windows files therefore ship with placeholders:

- `WAZUH_ALERTS_IP_ID` → your `wazuh-alerts-*` index-pattern id
- `WAZUH_MONITORING_IP_ID` → your `wazuh-monitoring-*` index-pattern id

Find the real ids in **Stack Management → Saved Objects** (inspect the index pattern and
copy the id out of the URL), or from Dev Tools:

```
GET .kibana/_search?q=type:index-pattern&_source=index-pattern.title&size=50
```

Then substitute, from the `dashboards/windows/` folder:

```bash
sed -i 's/WAZUH_ALERTS_IP_ID/<real-alerts-id>/g; s/WAZUH_MONITORING_IP_ID/<real-monitoring-id>/g' 0*.ndjson
```

(on macOS use `sed -i ''`). TSVB panels reference the index by **title** internally, so
they need no substitution.

The UniFi and Proxmox files bundle their own `wazuh-alerts-4.x-*` index pattern and are
self-contained — import them as-is. Both patterns point at the same alert data.

## 2. Check the Windows field schema

`02-windows-security.ndjson` uses the standard Wazuh nested alert schema —
`data.win.system.eventID`, `data.win.eventdata.targetUserName.keyword`,
`data.win.eventdata.subjectUserName.keyword`. (Rules use the un-prefixed `win.*` form;
alert *documents* carry the `data.` prefix. Both are correct in their own context.)

Open **Discover**, look at a real 4625 alert, and if your index genuinely uses the
un-prefixed form:

```bash
sed -i 's/data\.win\./win./g' 02-windows-security.ndjson
```

## 3. Set the timezone

**Stack Management → Advanced Settings → `dateFormat:tz`** — otherwise every time-based
panel and any hour-of-day analysis is offset. Before concluding a panel is broken,
confirm today's index exists: `GET /_cat/indices/wazuh-alerts-*?v`.

## 4. Import

**Stack Management → Saved Objects → Import**, one file at a time, with
"Automatically overwrite conflicts". Order does not matter — each file is self-contained.
The index patterns must already exist.
