#!/usr/bin/env python3
"""Generate Mermaid rule-chain diagrams from the Wazuh rule files.

Writes one page per platform to docs/diagrams/: a file map (which stock rulesets
and decoders each rule file hangs off, and which files chain onto each other),
then one flowchart per rule file showing every rule and what it chains onto.

The pages are derived data — edit the rule XML, then regenerate:

    python3 .github/scripts/rule_diagrams.py            # rewrite docs/diagrams/<platform>.md
    python3 .github/scripts/rule_diagrams.py --check    # exit 1 if a page is stale (CI)

docs/diagrams/README.md (legend, collection paths) is hand-written and not touched.
"""
import argparse
import pathlib
import re
import sys
import textwrap
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "diagrams"

# (page, title, rule directory)
PAGES = [
    ("windows", "Windows / Active Directory", "rules/windows"),
    ("linux", "Linux (Rocky / RHEL-family)", "rules/linux"),
    ("proxmox", "Proxmox VE + PBS", "rules/proxmox"),
    ("unifi", "UniFi", "rules/unifi"),
    ("experimental", "Experimental — not deployed", "experimental"),
]

# Stock rules this ruleset chains onto or overwrites: id -> (upstream file, label).
# Labels are condensed from the Wazuh 4.14.3 ruleset (ruleset/rules/), the version
# CI pins. A referenced id missing here still renders, as a bare id, with a warning.
STOCK = {
    "550": ("0015-ossec_rules.xml", "FIM: file checksum changed"),
    "553": ("0015-ossec_rules.xml", "FIM: file deleted"),
    "554": ("0015-ossec_rules.xml", "FIM: file added"),
    "594": ("0015-ossec_rules.xml", "FIM: registry key changed"),
    "597": ("0015-ossec_rules.xml", "FIM: registry key deleted"),
    "598": ("0015-ossec_rules.xml", "FIM: registry key added"),
    "750": ("0015-ossec_rules.xml", "FIM: registry value changed"),
    "751": ("0015-ossec_rules.xml", "FIM: registry value deleted"),
    "752": ("0015-ossec_rules.xml", "FIM: registry value added"),
    "2501": ("0020-syslog_rules.xml", "syslog: user authentication failure"),
    "5401": ("0020-syslog_rules.xml", "sudo: failed attempt"),
    "5402": ("0020-syslog_rules.xml", "sudo: successful sudo to root"),
    "5403": ("0020-syslog_rules.xml", "sudo: first time user ran sudo"),
    "5501": ("0085-pam_rules.xml", "PAM: login session opened"),
    "5503": ("0085-pam_rules.xml", "PAM: user login failed"),
    "5710": ("0095-sshd_rules.xml", "sshd: login as non-existent user"),
    "5715": ("0095-sshd_rules.xml", "sshd: authentication success"),
    "5716": ("0095-sshd_rules.xml", "sshd: authentication failed"),
    "5760": ("0095-sshd_rules.xml", "sshd: failed password / keyboard-interactive"),
    "60011": ("0575-win-base_rules.xml", "Windows error-severity event"),
    "60012": ("0575-win-base_rules.xml", "Windows critical-severity event"),
    "60015": ("0575-win-base_rules.xml", "Multiple Windows critical events"),
    "60100": ("0580-win-security_rules.xml", "Security channel: informational event"),
    "60103": ("0580-win-security_rules.xml", "Security channel: audit success"),
    "60104": ("0580-win-security_rules.xml", "Security channel: audit failure"),
    "60105": ("0580-win-security_rules.xml", "Windows logon failure (4625)"),
    "60106": ("0580-win-security_rules.xml", "Windows logon success (4624, 4769)"),
    "60109": ("0580-win-security_rules.xml", "User account created or enabled (4720, 4722)"),
    "60111": ("0580-win-security_rules.xml", "User account disabled or deleted (4725, 4726)"),
    "60112": ("0580-win-security_rules.xml", "Audit policy changed (4719, 4907, 4912)"),
    "60113": ("0580-win-security_rules.xml", "Group account changed"),
    "60115": ("0580-win-security_rules.xml", "User account locked out (4740)"),
    "60117": ("0580-win-security_rules.xml", "Windows audit log cleared"),
    "60122": ("0580-win-security_rules.xml", "Logon failure: unknown user or bad password"),
    "60137": ("0580-win-security_rules.xml", "User logoff (4634, 4647)"),
    "60141": ("0580-win-security_rules.xml", "Global group member added"),
    "60142": ("0580-win-security_rules.xml", "Global group member removed"),
    "60144": ("0580-win-security_rules.xml", "Local group member added"),
    "60145": ("0580-win-security_rules.xml", "Local group member removed"),
    "60149": ("0580-win-security_rules.xml", "Universal group created (4754)"),
    "60150": ("0580-win-security_rules.xml", "Universal group changed (4755)"),
    "60151": ("0580-win-security_rules.xml", "Universal group member added"),
    "60152": ("0580-win-security_rules.xml", "Universal group member removed"),
    "60154": ("0580-win-security_rules.xml", "Administrators group changed"),
    "60159": ("0580-win-security_rules.xml", "Domain Admins group changed"),
    "60162": ("0580-win-security_rules.xml", "Domain Guests group changed"),
    "60166": ("0580-win-security_rules.xml", "Schema Admins group changed"),
    "60167": ("0580-win-security_rules.xml", "Enterprise Admins group changed"),
    "60171": ("0580-win-security_rules.xml", "Guests group changed"),
    "60187": ("0580-win-security_rules.xml", "Enterprise RODC group changed"),
    "60188": ("0580-win-security_rules.xml", "RODC group changed"),
    "60189": ("0580-win-security_rules.xml", "Cryptographic Operators group changed"),
    "60228": ("0580-win-security_rules.xml", "Scheduled task created (4698)"),
    "60229": ("0580-win-security_rules.xml", "Directory service object modified (5136)"),
    "61138": ("0590-win-system_rules.xml", "New Windows service created (7045)"),
    "61603": ("0595-win-sysmon_rules.xml", "Sysmon event 1: process creation"),
    "63103": ("0610-win-ms_logs_rules.xml", "Audit log cleared (1102)"),
    "80700": ("0365-auditd_rules.xml", "auditd: messages grouped"),
    "80792": ("0365-auditd_rules.xml", "auditd: command executed"),
    "87200": ("0495-proxmox-ve_rules.xml", "pvedaemon: messages grouped"),
    "87201": ("0495-proxmox-ve_rules.xml", "Proxmox VE: authentication failed"),
    "87203": ("0495-proxmox-ve_rules.xml", "Proxmox VE: authentication succeeded"),
    "91801": ("0915-win-powershell_rules.xml", "PowerShell/Operational channel"),
    "91802": ("0915-win-powershell_rules.xml", "PowerShell script block (4104)"),
    "91803": ("0915-win-powershell_rules.xml", "Screen capture from PowerShell"),
    "91822": ("0915-win-powershell_rules.xml", "Invoke-Command sub-script"),
    "91823": ("0915-win-powershell_rules.xml", "Invoke-Command on remote computer"),
    "92650": ("0840-win_event_channel.xml", "Service created from Windows root path"),
    "92651": ("0840-win_event_channel.xml", "Successful remote logon"),
    "92653": ("0840-win_event_channel.xml", "RDP logon (logon type 10)"),
    "92655": ("0840-win_event_channel.xml", "Printer driver load failure (PrintNightmare)"),
}

MISSING = "stock rule {} has no label in STOCK — add it from the upstream ruleset"

# Wazuh's own level bands: 0 ignored, 12+ "high importance", 15 "severe attack".
SEVERITY = [(0, 0, "sev0"), (1, 6, "sev1"), (7, 11, "sev7"), (12, 14, "sev12"), (15, 16, "sev15")]

CLASSDEFS = """\
  classDef sev0 fill:#f3f4f6,stroke:#9ca3af,color:#374151,stroke-dasharray:4 3
  classDef sev1 fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
  classDef sev7 fill:#fef3c7,stroke:#d97706,color:#78350f
  classDef sev12 fill:#fed7aa,stroke:#ea580c,color:#7c2d12
  classDef sev15 fill:#fecaca,stroke:#dc2626,color:#7f1d1d,stroke-width:2px
  classDef stock fill:#e5e7eb,stroke:#6b7280,color:#111827
  classDef xfile fill:#ede9fe,stroke:#7c3aed,color:#3b0764
  classDef src fill:#ccfbf1,stroke:#0d9488,color:#134e4a"""

WRAP = 34
MAX_LINES = 3
# Labels are pre-wrapped at WRAP characters; stop Mermaid re-wrapping them at 200px.
INIT = '%%{init: {"flowchart": {"wrappingWidth": 400}}}%%'


@dataclass
class Rule:
    id: str
    level: int
    path: pathlib.Path
    description: str
    overwrite: bool
    no_email: bool
    frequency: str = ""
    timeframe: str = ""
    if_sid: list = field(default_factory=list)
    if_matched_sid: list = field(default_factory=list)
    if_group: list = field(default_factory=list)
    if_matched_group: list = field(default_factory=list)
    decoded_as: str = ""
    program_name: str = ""
    correlate: list = field(default_factory=list)

    @property
    def is_root(self):
        return not (self.if_sid or self.if_matched_sid or self.if_group
                    or self.if_matched_group or self.decoded_as)


def split_ids(text):
    return [t for t in re.split(r"[,\s]+", (text or "").strip()) if t]


def load_rules(path):
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", path.read_text(encoding="utf-8"))
    root = ET.fromstring(f"<root>{text}</root>")
    rules = []
    for el in root.iter("rule"):
        r = Rule(
            id=el.get("id"),
            level=int(el.get("level", "0")),
            path=path,
            description=el.findtext("description", ""),
            overwrite=el.get("overwrite") == "yes",
            no_email=any("no_email_alert" in (o.text or "") for o in el.iter("options")),
            frequency=el.get("frequency", ""),
            timeframe=el.get("timeframe", ""),
        )
        for child in el:
            tag, value = child.tag, (child.text or "").strip()
            if tag in ("if_sid", "if_matched_sid", "if_group", "if_matched_group"):
                getattr(r, tag).extend(split_ids(value))
            elif tag in ("decoded_as", "program_name"):
                setattr(r, tag, value)
            elif re.match(r"(same|different|not_same)_", tag):
                # <same_srcip />, <same_user />, <same_field>x.y.z</same_field>, …
                r.correlate.append(f"{tag} {value.split('.')[-1]}" if value else tag)
        rules.append(r)
    return rules


# --- label text ---------------------------------------------------------------

PH = r"\$\([^)]*\)"


def clean_description(text):
    """Drop the $(field) interpolations a diagram cannot show, keep the sentence."""
    s = " ".join(text.split())
    s = re.sub(r"\s*\bNOTE:.*$", "", s)
    s = re.sub(rf"\(\s*{PH}\s*\)", "", s)
    s = re.sub(rf"\s*\b(?:run by|reset by|used creds of|from|on|by|for|against|of|to|in"
               rf"|at|with)\s+(?:DC\s+|SID\s+|uid\s+)?{PH}", "", s)
    s = re.sub(rf"([—–\-,(]\s*)(?:member|group|status|subject|target|uid|user)[:=]?\s*{PH}",
               r"\1", s)
    # a placeholder that is the subject of the sentence stays, as a short token
    s = re.sub(r"\$\((?:\w+\.)*(\w+)\)(?=\s+\w)", r"‹\1›", s)
    s = re.sub(rf"\s*{PH}", "", s)
    s = re.sub(r"\(\s*\)", "", s)
    s = re.sub(r"\s+([,.;:)])", r"\1", s)
    s = re.sub(r"(\s*[-—–,:])+\s*$", "", s)
    s = re.sub(r"(\s[-—–])(\s*[-—–,])+", r"\1", s)
    s = re.sub(r"\s{2,}", " ", s)
    return s.strip(" -—–,:")


def wrap(text, width=WRAP, max_lines=MAX_LINES):
    lines = textwrap.wrap(text, width, break_on_hyphens=False) or [""]
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1].rstrip(" ,;:-—–") + "…"
    return lines


def esc(text):
    """Escape text for a double-quoted Mermaid label (HTML tags are added after)."""
    return (text.replace("&", "#amp;").replace("<", "#lt;").replace(">", "#gt;")
            .replace('"', "#quot;"))


def label(*lines):
    return '"' + "<br/>".join(lines) + '"'


def severity_class(level):
    return next(c for lo, hi, c in SEVERITY if lo <= level <= hi)


def level_tags(r):
    tags = [f"L{r.level}"]
    if r.overwrite:
        tags.append("overwrite")
    if r.no_email:
        tags.append("no email")
    return " · ".join(tags)


def correlation_text(r):
    parts = []
    if r.frequency:
        parts.append(f"freq {r.frequency} · {r.timeframe}s" if r.timeframe
                     else f"freq {r.frequency}")
    elif r.timeframe:
        parts.append(f"within {r.timeframe}s")
    parts.extend(r.correlate)
    return "<br/>".join(esc(p) for p in parts)


def program_text(pattern):
    p = re.sub(r"^\(\?i\)", "", pattern).strip("^$")
    if p.startswith("(") and p.endswith(")"):
        p = p[1:-1]
    return p.replace("|", " | ")


def slug(text):
    return re.sub(r"\W+", "_", text).strip("_")


# --- per-file chain diagram -----------------------------------------------------

class Chain:
    """Mermaid flowchart for one rule file."""

    def __init__(self, path, rules, repo, warnings):
        self.path, self.rules, self.repo, self.warnings = path, rules, repo, warnings
        self.local = {r.id for r in rules}
        self.external = {}      # node id -> declaration, in first-seen order
        self.edges = []

    # node ids ---------------------------------------------------------------
    def rule_node(self, rid):
        if rid in self.local:
            return f"r{rid}"
        if rid in self.repo:
            self._declare_repo(rid)
            return f"r{rid}"
        self._declare_stock(rid)
        return f"s{rid}"

    def _declare_repo(self, rid):
        r = self.repo[rid]
        where = f"<i>{esc(r.path.name)}</i>"
        if r.overwrite:
            head = f"<b>{rid}</b> · stock, overwritten"
            text = [f"to L{r.level} in {where}",
                    *map(esc, wrap(stock_label(rid, self.warnings)))]
        else:
            head = f"<b>{rid}</b> · {level_tags(r)}"
            text = [where, *map(esc, wrap(clean_description(r.description)))]
        self.external.setdefault(f"r{rid}", f"r{rid}({label(head, *text)}):::xfile")

    def _declare_stock(self, rid):
        text = map(esc, wrap(stock_label(rid, self.warnings)))
        self.external.setdefault(
            f"s{rid}", f"s{rid}({label(f'<b>{rid}</b> · stock', *text)}):::stock")

    def parents(self, ids):
        """Node ids for an if_sid / if_matched_sid list.

        Several parents that all live outside this file collapse into one "any of"
        node — that is what the list means, and it keeps a six-parent FIM rule from
        drawing six edges per child.
        """
        if len(ids) > 1 and not any(i in self.local for i in ids):
            nid = "any_" + "_".join(ids)
            lines = ["any of"]
            overwritten = {}    # file -> ids it overwrites
            for i in ids:
                lines.append(f"<b>{i}</b> {esc(stock_label(i, self.warnings, self.repo))}")
                if i in self.repo and self.repo[i].overwrite:
                    overwritten.setdefault(self.repo[i].path.name, []).append(i)
            cls = "stock"
            if overwritten or any(i in self.repo for i in ids):
                cls = "xfile"
                for name, which in sorted(overwritten.items()):
                    who = "" if len(which) == len(ids) else ", ".join(which) + " "
                    lines.append(f"<i>{who}overwritten in {esc(name)}</i>")
            self.external.setdefault(nid, f"{nid}[[{label(*lines)}]]:::{cls}")
            return [nid]
        return [self.rule_node(i) for i in ids]

    def source(self, kind, value):
        nid = f"{kind[0]}_{slug(value)}"
        if kind == "group":
            decl = f'{nid}{{{{{label("any rule in group", f"<b>{esc(value)}</b>")}}}}}:::src'
        else:
            decl = f"{nid}[/{label(kind, f'<b>{esc(value)}</b>')}/]:::src"
        self.external.setdefault(nid, decl)
        return nid

    # build ----------------------------------------------------------------------
    def render(self):
        for r in self.rules:
            me = f"r{r.id}"
            corr = correlation_text(r)
            for p in self.parents(r.if_sid):
                self.edges.append(f"{p} --> {me}")
            for g in r.if_group:
                self.edges.append(f"{self.source('group', g)} --> {me}")
            for p in self.parents(r.if_matched_sid):
                self.edges.append(f'{p} -.->|"{corr}"| {me}' if corr else f"{p} -.-> {me}")
            for g in r.if_matched_group:
                src = self.source("group", g)
                self.edges.append(f'{src} -.->|"{corr}"| {me}' if corr else f"{src} -.-> {me}")
            if r.decoded_as:
                self.edges.append(f"{self.source('decoder', r.decoded_as)} --> {me}")
            if r.is_root and r.program_name:
                src = self.source("program_name", program_text(r.program_name))
                self.edges.append(f"{src} --> {me}")

        out = ["```mermaid", INIT, "flowchart LR"]
        out.append(f'  subgraph F["{esc(self.path.name)}"]')
        for r in self.rules:
            text = [f"<b>{r.id}</b> · {level_tags(r)}",
                    *map(esc, wrap(clean_description(r.description)))]
            out.append(f"    r{r.id}[{label(*text)}]:::{severity_class(r.level)}")
        out.append("  end")
        out += [f"  {decl}" for decl in self.external.values()]
        out += [f"  {e}" for e in self.edges]
        out += [CLASSDEFS, "```"]
        return "\n".join(out)


def stock_label(rid, warnings, repo=None):
    if rid in STOCK:
        return STOCK[rid][1]
    if repo and rid in repo:
        return clean_description(repo[rid].description)
    warnings.add(MISSING.format(rid))
    return "stock rule"


# --- per-platform file map --------------------------------------------------------

def file_map(files, rules_by_file, repo, decoders, warnings):
    """Which upstream sources feed each file, and which files chain onto each other."""
    upstream, sources, loads, relevels = {}, {}, {}, {}
    for path in files:
        for r in rules_by_file[path]:
            for pid in r.if_sid + r.if_matched_sid:
                owner = repo.get(pid)
                if owner and not owner.overwrite:
                    if owner.path != path:
                        loads.setdefault((owner.path, path), set()).add(pid)
                    continue
                if owner and owner.overwrite and owner.path != path:
                    relevels.setdefault((owner.path, path), set()).add(pid)
                if pid in STOCK:
                    upstream.setdefault(STOCK[pid][0], {}).setdefault(path, set()).add(pid)
                else:
                    warnings.add(MISSING.format(pid))
            if r.decoded_as:
                src = decoders.get(r.decoded_as, "stock decoder")
                sources.setdefault(("decoder", src), {}).setdefault(path, set()).add(r.decoded_as)
            for g in r.if_group + r.if_matched_group:
                sources.setdefault(("group", "rule groups"), {}).setdefault(path, set()).add(g)
            if r.is_root and r.program_name:
                sources.setdefault(("program", "program_name match"), {}) \
                    .setdefault(path, set()).add(program_text(r.program_name))

    fid = {p: f"f{i}" for i, p in enumerate(files)}
    out = ["```mermaid", INIT, "flowchart LR"]
    # No subgraph containers here: with them Mermaid routes every stock -> file edge
    # around both boxes. Without, each stock file sits next to the files that use it.
    for i, name in enumerate(sorted(upstream)):
        used = sorted({x for s in upstream[name].values() for x in s}, key=int)
        ids = [" ".join(used[k:k + 5]) for k in range(0, len(used), 5)]
        out.append(f"  u{i}({label(f'<b>{esc(name)}</b>', 'stock', *ids)}):::stock")
    for i, ((kind, name), per_file) in enumerate(sorted(sources.items())):
        values = sorted({x for s in per_file.values() for x in s})
        head = f"<b>{esc(name)}</b>"
        lines = [esc(v) for v in values] if len(values) <= 6 else [f"{len(values)} patterns"]
        shape = ("{{", "}}") if kind == "group" else ("[/", "/]")
        out.append(f"  x{i}{shape[0]}{label(head, *lines)}{shape[1]}:::src")
    for p in files:
        n = len(rules_by_file[p])
        count = f"{n} rule" + ("s" if n != 1 else "")
        out.append(f"  {fid[p]}[{label(f'<b>{esc(p.name)}</b>', count)}]:::file")
    for i, name in enumerate(sorted(upstream)):
        for p in files:
            if p in upstream[name]:
                out.append(f"  u{i} --> {fid[p]}")
    for i, (_, per_file) in enumerate(sorted(sources.items())):
        for p in files:
            if p in per_file:
                out.append(f"  x{i} --> {fid[p]}")
    for (a, b), ids in sorted(loads.items()):
        out.append(f'  {fid[a]} ==>|"{" ".join(sorted(ids, key=int))}"| {fid[b]}')
    for (a, b), ids in sorted(relevels.items()):
        ids = sorted(ids, key=int)
        rows = "<br/>".join(" ".join(ids[k:k + 4]) for k in range(0, len(ids), 4))
        out.append(f'  {fid[a]} -.->|"overwrites<br/>{rows}"| {fid[b]}')
    out += ["  classDef stock fill:#e5e7eb,stroke:#6b7280,color:#111827",
            "  classDef src fill:#ccfbf1,stroke:#0d9488,color:#134e4a",
            "  classDef file fill:#ede9fe,stroke:#7c3aed,color:#3b0764,stroke-width:2px", "```"]
    return "\n".join(out), bool(loads)


# --- page ---------------------------------------------------------------------------

def anchor(heading):
    return re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")


def build_page(page, title, src_dir, repo, decoders, warnings):
    src = ROOT / src_dir
    files, empty = [], []
    rules_by_file = {}
    for p in sorted(src.glob("*.xml")):
        rules = load_rules(p)
        if rules:
            files.append(p)
            rules_by_file[p] = rules
        elif "<rule" in p.read_text(encoding="utf-8"):
            empty.append(p)   # rule file whose rules are all commented out

    rel = src.relative_to(ROOT).as_posix()
    out = [
        f"<!-- Generated by .github/scripts/rule_diagrams.py from {rel}/ — "
        "do not edit by hand. -->",
        f"# {title} — rule chains",
        "",
        f"Every rule in [`{rel}/`](../../{rel}/) and what it chains onto. Read the "
        "[legend](README.md#legend) first; regenerate with "
        "`python3 .github/scripts/rule_diagrams.py` after changing a rule file.",
        "",
    ]
    if page == "experimental":
        out += ["> **Not deployed.** These rules are kept for reference and have known gaps "
                "on 4.14.x — see [`experimental/README.md`](../../experimental/README.md).", ""]

    out += ["| File | Rules | Correlation | Overwrite | Levels |", "|---|---:|---:|---:|---|"]
    for p in files:
        rs = rules_by_file[p]
        corr = sum(1 for r in rs if r.frequency or r.if_matched_sid or r.if_matched_group)
        ow = sum(1 for r in rs if r.overwrite)
        levels = f"{min(r.level for r in rs)}–{max(r.level for r in rs)}"
        out.append(f"| [`{p.name}`](#{anchor(p.name)}) | {len(rs)} | {corr} | {ow} | {levels} |")
    for p in empty:
        out.append(f"| `{p.name}` | 0 | — | — | no active rules |")
    out.append("")

    fmap, has_loads = file_map(files, rules_by_file, repo, decoders, warnings)
    intro = ["Where each file's events come from."]
    if has_loads:
        intro.append("Thick arrows are chains onto a custom rule in another file, so the "
                     "arrow's tail must load first — Wazuh loads rule files alphabetically.")
    if "-.->" in fmap:
        intro.append("Dotted arrows mark stock rules that one file overwrites and another "
                     "file's rules hang off.")
    out += ["## File map", "", " ".join(intro), "", fmap, ""]

    for p in files:
        rs = rules_by_file[p]
        out += [f"## {p.name}", "",
                f"[`{p.relative_to(ROOT).as_posix()}`](../../{p.relative_to(ROOT).as_posix()}) · "
                f"{len(rs)} rules", "",
                Chain(p, rs, repo, warnings).render(), ""]
    return "\n".join(out).rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if a generated page differs from what is committed")
    args = ap.parse_args()

    repo = {}
    for _, _, src_dir in PAGES:
        for p in sorted((ROOT / src_dir).glob("*.xml")):
            for r in load_rules(p):
                repo[r.id] = r

    decoders = {}
    for p in sorted((ROOT / "decoders").rglob("*.xml")):
        for name in re.findall(r'<decoder name="([^"]+)"', p.read_text(encoding="utf-8")):
            decoders.setdefault(name, p.relative_to(ROOT).as_posix())

    warnings, stale = set(), []
    for page, title, src_dir in PAGES:
        target = OUT / f"{page}.md"
        text = build_page(page, title, src_dir, repo, decoders, warnings)
        current = target.read_text(encoding="utf-8") if target.exists() else None
        if text == current:
            continue
        if args.check:
            stale.append(target.relative_to(ROOT))
        else:
            OUT.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            print(f"wrote {target.relative_to(ROOT)}")

    for w in sorted(warnings):
        print(f"warning  {w}")
    if stale:
        for s in stale:
            print(f"stale    {s}")
        print("\nRule diagrams are out of date — run: python3 .github/scripts/rule_diagrams.py")
        return 1
    if args.check:
        print(f"OK  {len(PAGES)} diagram pages up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
