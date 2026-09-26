# Rule diagrams

Pictures of how the detections in this repository fit together: where each platform's
events come from, and how every rule chains onto its parents. GitHub renders the
diagrams inline.

| Page | Covers |
|---|---|
| [Windows / Active Directory](windows.md) | `rules/windows/` — 8 files, load-order chains between them |
| [Linux (Rocky / RHEL-family)](linux.md) | `rules/linux/` — syslog core vs. auditd / FIM tier |
| [Proxmox VE + PBS](proxmox.md) | `rules/proxmox/` — stock 87200 tree vs. `program_name` roots |
| [UniFi](unifi.md) | `rules/unifi/` — CEF, firewall and hostapd decoders |
| [Experimental](experimental.md) | `experimental/` — cross-device correlation, **not deployed** |

Each page opens with a **file map** (which stock rulesets feed which file, and which
files chain onto each other) and then has one **chain diagram** per rule file.

The platform pages are generated from the rule XML by
[`.github/scripts/rule_diagrams.py`](../../.github/scripts/rule_diagrams.py) — do not edit
them by hand. After changing a rule file:

```bash
python3 .github/scripts/rule_diagrams.py            # rewrite the pages
python3 .github/scripts/rule_diagrams.py --check    # what CI runs: fails if a page is stale
```

This page — the legend and the collection paths below — is hand-written.

## Legend

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 400}}}%%
flowchart LR
  subgraph F["the rule file the diagram is about"]
    r111000["<b>111000</b> · L13<br/>SSH: login SUCCEEDED after a<br/>brute-force burst"]:::sev12
    r111001["<b>111001</b> · L14<br/>SSH: ROOT login succeeded after<br/>brute force"]:::sev12
    r111010["<b>111010</b> · L12 · no email<br/>Sudo: escalated to root after<br/>repeated sudo failures"]:::sev12
  end
  s5715("<b>5715</b> · stock<br/>sshd: authentication success"):::stock
  s5760("<b>5760</b> · stock<br/>sshd: failed password"):::stock
  any[["any of<br/><b>5402</b> sudo: successful sudo to root<br/><b>5403</b> sudo: first time user ran sudo"]]:::stock
  s5401("<b>5401</b> · stock<br/>sudo: failed attempt"):::stock
  s5715 --> r111000
  s5760 -.->|"freq 3 · 300s<br/>same_srcip"| r111000
  r111000 --> r111001
  any --> r111010
  s5401 -.->|"freq 2 · 300s<br/>same_srcuser"| r111010
  classDef sev12 fill:#fed7aa,stroke:#ea580c,color:#7c2d12
  classDef stock fill:#e5e7eb,stroke:#6b7280,color:#111827
```

Read that as: *111000 fires on an sshd success (5715) when 5760 has also matched from the
same source IP within 300 s; 111001 is the subset of those that were root logins.*

**Arrows**

| Arrow | XML | Meaning |
|---|---|---|
| solid `A → B` | `<if_sid>A</if_sid>` / `<if_group>` / `<decoded_as>` | B looks at the **same event** A matched and narrows it down. |
| dotted, labelled `A ⇢ B` | `<if_matched_sid>A</if_matched_sid>` / `<if_matched_group>` | A matched on **earlier events**. The label is the rule's `frequency` / `timeframe` and the `same_*` / `different_*` fields that tie those events together. |
| thick, file map only | — | a file chains onto a custom rule defined in another file, so the arrow's tail must load first. |
| dotted "overwrites", file map only | `overwrite="yes"` | one file re-levels stock rules that another file's rules hang off. |

The solid/dotted split is the gotcha in [`docs/linux.md`](../linux.md#if_sid--if_group-match-the-same-event-not-afterwards):
a chain of solid arrows never means "B happened after A". Also note that `frequency`
fires later than the number reads — see
[the same doc](../linux.md#frequency-fires-later-than-it-reads).

**Boxes**

| Box | Meaning |
|---|---|
| grey, rounded | stock Wazuh rule, labelled from the 4.14.3 ruleset |
| grey, double-sided "any of" | a multi-id `<if_sid>` list — any one of these parents |
| violet | a rule from another file in this repo, or a stock rule this repo overwrites |
| teal parallelogram | the decoder or `program_name` a root rule matches on |
| teal hexagon | a rule group (`if_group` / `if_matched_group`) |
| `no email` | `<options>no_email_alert</options>` — dashboard only |
| `overwrite` | `overwrite="yes"` — this rule replaces a stock rule's definition |

**Colour = level**, using Wazuh's own bands:

```mermaid
flowchart LR
  a["<b>L0</b><br/>silenced"]:::sev0 ~~~ b["<b>L1–6</b><br/>low"]:::sev1 ~~~ c["<b>L7–11</b><br/>medium"]:::sev7 ~~~ d["<b>L12–14</b><br/>high importance"]:::sev12 ~~~ e["<b>L15–16</b><br/>severe attack"]:::sev15
  classDef sev0 fill:#f3f4f6,stroke:#9ca3af,color:#374151,stroke-dasharray:4 3
  classDef sev1 fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
  classDef sev7 fill:#fef3c7,stroke:#d97706,color:#78350f
  classDef sev12 fill:#fed7aa,stroke:#ea580c,color:#7c2d12
  classDef sev15 fill:#fecaca,stroke:#dc2626,color:#7f1d1d,stroke-width:2px
```

Descriptions are shortened for the diagram: `$(field)` interpolations are dropped, or
kept as `‹field›` where the sentence needs them. The rule file is always the source of
truth.

## How events reach the rules

Rules only fire on events the collection side delivers. These are the paths each
platform's events take before they reach a chain diagram — hand-drawn from
[`ingest/`](../../ingest/README.md) and the per-platform docs.

### Windows / Active Directory

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 400}}}%%
flowchart LR
  subgraph EP["Windows endpoint or DC · Wazuh agent"]
    SEC["<b>Security</b> eventlog<br/>logon · account · group · Kerberos<br/>4662 · 4688 + command line · 1102"]
    PSO["<b>PowerShell/Operational</b><br/>4103 module · 4104 script block"]
    SYS["<b>System</b> eventlog<br/>7045 service installed"]
    REG["<b>Registry FIM</b><br/>windows_registry in syscheck"]
    SMN["<b>Sysmon/Operational</b><br/>optional — rule 100354 only"]
  end
  EC[/"windows_eventchannel<br/>stock decoder"/]:::src
  SC[/"syscheck<br/>stock decoder"/]:::src
  SEC & PSO & SYS & SMN --> EC
  REG --> SC
  EC --> S1("stock 0580 · 0610 · 0840<br/>Security channel"):::stock
  EC --> S2("stock 0915<br/>PowerShell"):::stock
  EC --> S3("stock 0590 · 0575<br/>System · any-channel errors"):::stock
  EC --> S4("stock 0595<br/>Sysmon"):::stock
  SC --> S5("stock 0015<br/>registry FIM 594–598 · 750–752"):::stock
  S1 --> W1["100_ · 103_ · 104_ · 105_ · 107_ · 108_"]:::file
  S2 --> W2["101_ · 108_"]:::file
  S3 --> W3["108_"]:::file
  S4 --> W4["104_"]:::file
  S5 --> W5["102_"]:::file
  classDef stock fill:#e5e7eb,stroke:#6b7280,color:#111827
  classDef src fill:#ccfbf1,stroke:#0d9488,color:#134e4a
  classDef file fill:#ede9fe,stroke:#7c3aed,color:#3b0764,stroke-width:2px
```

No Sysmon needed except for 100354. DCSync (100332, event 4662) also needs DC-side audit
config — see [`docs/windows.md`](../windows.md#dcsync-100332-requires-dc-side-audit-config).

### Linux (Rocky / RHEL-family)

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 400}}}%%
flowchart LR
  subgraph AG["Rocky / RHEL host · Wazuh agent"]
    SEC["<b>/var/log/secure</b><br/>sshd · sudo · su · PAM · usermod"]
    AUD["<b>/var/log/audit/audit.log</b><br/>auditd with ingest/linux/wazuh-linux.rules"]
    FIM["<b>syscheck FIM</b><br/>scope from ingest/linux/"]
  end
  SEC --> S1("stock sshd · sudo · PAM<br/>5715 5760 · 5401–5403 · 5501 5503"):::stock
  AUD --> S2("stock auditd<br/>80700 · 80792"):::stock
  FIM --> S3("stock FIM<br/>550 · 553 · 554"):::stock
  S1 --> T1["110_auth_correlation.xml<br/><b>syslog core</b> — default agent"]:::file
  S2 --> T2["111_ · 113_ · 114_<br/><b>advanced tier</b>"]:::file
  S3 --> T3["111_ · 112_ · 114_<br/><b>advanced tier</b>"]:::file
  S1 -.->|"5401 → 111151"| T2
  classDef stock fill:#e5e7eb,stroke:#6b7280,color:#111827
  classDef file fill:#ede9fe,stroke:#7c3aed,color:#3b0764,stroke-width:2px
```

Without the auditd rules and FIM scope from [`ingest/linux/`](../../ingest/README.md#linux),
32 of the 40 Linux rules stay silent. The `audit.key` values in `wazuh-linux.rules` must match
the rules exactly.

### Proxmox VE + PBS

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 400}}}%%
flowchart LR
  subgraph PX["PVE node / PBS host · Wazuh agent · syslog"]
    PD["<b>pvedaemon</b>"]
    PP["<b>pveproxy</b>"]
    OT["<b>pveum · pvescheduler · vzdump · pvestatd<br/>corosync · pmxcfs · proxmox-backup-proxy</b>"]
  end
  PD --> D1[/"pvedaemon<br/>stock decoder"/]:::src --> S1("stock 87200 tree<br/>87201 auth fail · 87203 auth success"):::stock
  PP --> S2("stock 2501<br/>syslog auth failure"):::stock
  S1 --> R1["<b>chained rules</b> and their children<br/>100800 · 100805 · 100815–100818<br/>100820 · 100828 · 100829"]:::file
  S2 --> R1
  OT --> R2["<b>root rules</b><br/>matched by program_name"]:::file
  classDef stock fill:#e5e7eb,stroke:#6b7280,color:#111827
  classDef src fill:#ccfbf1,stroke:#0d9488,color:#134e4a
  classDef file fill:#ede9fe,stroke:#7c3aed,color:#3b0764,stroke-width:2px
```

Stock 87200 claims every pvedaemon event first, so a custom *root* rule for pvedaemon
would never fire — which is why that half of `proxmox.xml` chains instead. See
[`docs/proxmox.md`](../proxmox.md#stock-rule-87200-shadows-custom-root-rules). The optional
`decoders/proxmox/` adds fields for the dashboards; no rule here uses `decoded_as` on it.

### UniFi

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 400}}}%%
flowchart LR
  U["<b>UniFi gateway · APs · UniFi OS</b><br/>CEF · firewall syslog · hostapd"]
  R["<b>rsyslog relay</b><br/>ingest/unifi/10-unifi.conf<br/>rewrites the double CEF header"]
  L["<b>/var/log/unifi/unifi.log</b><br/>agent localfile-snippet.xml"]
  U -->|"syslog UDP/TCP 514"| R --> L
  L --> D1[/"<b>unifi</b><br/>CEF: IDS/IPS · admin · WiFi"/]:::src
  L --> D2[/"<b>unifi-lan2wan · unifi-lan2lan</b><br/>firewall LAN_WAN · LAN_LAN"/]:::src
  L --> D3[/"<b>unifi-hostapd</b><br/>RADIUS · STA"/]:::src
  D1 & D2 & D3 --> RU["rules/unifi/unifi.xml"]:::file
  SSH["sshd on any agent host"] --> S1("stock sshd<br/>5710 5715 5716 5760"):::stock --> RU
  classDef stock fill:#e5e7eb,stroke:#6b7280,color:#111827
  classDef src fill:#ccfbf1,stroke:#0d9488,color:#134e4a
  classDef file fill:#ede9fe,stroke:#7c3aed,color:#3b0764,stroke-width:2px
```

UniFi devices cannot run an agent, so everything goes through the relay. The decoders
live in [`decoders/unifi/unifi.xml`](../../decoders/unifi/unifi.xml). Rules 100720 / 100725
are generic sshd rules that happen to live in this file — they are not UniFi-specific.
