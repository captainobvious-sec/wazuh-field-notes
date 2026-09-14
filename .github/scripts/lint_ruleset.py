#!/usr/bin/env python3
"""Structural checks for the Wazuh ruleset.

Runs with no Wazuh install and no container, so it gives feedback in seconds.
It does NOT replace `wazuh-analysisd -t` — that is the authoritative check and
runs in the other CI job. This catches the classes of mistake that are easy to
make by hand and silent at load time.

Exits non-zero on the first category that fails, printing every finding.
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
RULE_DIRS = ["rules"]
DECODER_DIRS = ["decoders"]
# experimental/ is deliberately excluded: it is documented as not deployable and
# windows_normalize.xml is rejected by analysisd on 4.14.x by design.

STATIC_FIELDS = {"srcip", "srcuser", "dstuser", "url", "id", "status",
                 "srcport", "dstport", "protocol", "action", "data"}

# Strings that must never reappear — regression guard for the sanitisation pass.
FORBIDDEN = re.compile(
    r"(?i)\bmfin\w*|ministarstvo|\bvinci\b|udr7|WIFIbaby|LAB-DC1|\bMF\d{2,}\b"
    r"|\b(?:10\.4\.\d{1,3}|10\.27\.27|172\.20\.0|192\.168\.10|192\.168\.50)\.\d{1,3}\b"
)

findings = []


def note(category, path, line, msg):
    findings.append((category, f"{path}:{line}" if line else str(path), msg))


def strip_comments(text):
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def xml_files(dirs):
    for d in dirs:
        yield from sorted((ROOT / d).rglob("*.xml"))


def rel(p):
    return p.relative_to(ROOT)


def check_wellformed(paths):
    """Wazuh rule/decoder files have multiple top-level elements, so wrap them."""
    for p in paths:
        wrapped = b"<root>" + p.read_bytes() + b"</root>"
        r = subprocess.run(["xmllint", "--noout", "-"], input=wrapped,
                           capture_output=True)
        if r.returncode:
            note("xml", rel(p), None, r.stderr.decode().strip().splitlines()[0])


def check_rules():
    defined, seen = {}, {}
    for p in xml_files(RULE_DIRS):
        text = strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        for m in re.finditer(r'<rule id="(\d+)"([^>]*)>(.*?)</rule>', text, re.S):
            rid, attrs, body = m.groups()
            line = text[:m.start()].count("\n") + 1
            if rid in seen and seen[rid] != p:
                note("duplicate-id", rel(p), line,
                     f"rule {rid} also defined in {rel(seen[rid])}")
            seen[rid] = p
            defined[rid] = p

            level = re.search(r'level="(\d+)"', attrs)
            if level and not 0 <= int(level.group(1)) <= 16:
                note("level", rel(p), line,
                     f"rule {rid}: level {level.group(1)} outside 0-16")

            freq = re.search(r'frequency="(\d+)"', attrs)
            if freq:
                if int(freq.group(1)) < 2:
                    note("frequency", rel(p), line,
                         f'rule {rid}: frequency="{freq.group(1)}" is rejected by '
                         "the manager (valid range 2-9999)")
                if not re.search(r"if_matched_(sid|group)", body):
                    note("frequency", rel(p), line,
                         f"rule {rid}: frequency= without <if_matched_sid|group>, "
                         "so it can never accumulate")

            for sf in re.findall(r"<same_field>(\w+)</same_field>", body):
                if sf in STATIC_FIELDS:
                    note("same_field", rel(p), line,
                         f"rule {rid}: <same_field>{sf}</same_field> is a static "
                         "field; use the <same_*/> operator instead")

            for rx in re.findall(r'type="pcre2">(.*?)</', body, re.S):
                try:
                    re.compile(rx)
                except re.error as exc:
                    note("regex", rel(p), line, f"rule {rid}: {exc}")

    # Custom parents must resolve inside the deployed set.
    for p in xml_files(RULE_DIRS):
        text = strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        for tag in ("if_sid", "if_matched_sid"):
            for m in re.finditer(rf"<{tag}>([^<]+)</{tag}>", text):
                line = text[:m.start()].count("\n") + 1
                for ref in re.split(r"[,\s]+", m.group(1).strip()):
                    if ref.isdigit() and int(ref) >= 100000 and ref not in defined:
                        note("dangling-parent", rel(p), line,
                             f"<{tag}>{ref}</{tag}> is not defined in rules/")


def check_decoders():
    names = set()
    for p in xml_files(DECODER_DIRS):
        names |= set(re.findall(r'<decoder name="([^"]+)"',
                                p.read_text(encoding="utf-8", errors="replace")))
    for p in xml_files(RULE_DIRS):
        text = strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        for m in re.finditer(r"<decoded_as>([^<]+)</decoded_as>", text):
            line = text[:m.start()].count("\n") + 1
            for part in m.group(1).split("/"):
                if part.strip() and part.strip() not in names:
                    note("decoded_as", rel(p), line,
                         f"decoded_as '{part.strip()}' matches no decoder in decoders/")


def check_dashboards():
    for p in sorted((ROOT / "dashboards").rglob("*.ndjson")):
        ids, refs = set(), []
        for n, raw in enumerate(p.read_text(encoding="utf-8", errors="replace")
                                .splitlines(), 1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                note("ndjson", rel(p), n, f"invalid JSON: {exc}")
                continue
            if "id" in obj and "type" in obj:
                ids.add((obj["type"], obj["id"]))
            for r in obj.get("references") or []:
                refs.append((r.get("type"), r.get("id")))
        for t, i in refs:
            # index-pattern refs are resolved at import time (placeholders) — skip.
            if t != "index-pattern" and (t, i) not in ids:
                note("ndjson", rel(p), None, f"panel references missing object {t}:{i}")


def check_forbidden():
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file() or ".git/" in str(p) or ".github/scripts" in str(p):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for m in FORBIDDEN.finditer(text):
            note("leak", rel(p), text[:m.start()].count("\n") + 1,
                 f"forbidden string {m.group(0)!r} (sanitisation regression)")


def main():
    paths = list(xml_files(RULE_DIRS)) + list(xml_files(DECODER_DIRS))
    check_wellformed(paths)
    check_rules()
    check_decoders()
    check_dashboards()
    check_forbidden()

    if not findings:
        print(f"OK  {len(paths)} XML files, "
              f"{len(list((ROOT / 'dashboards').rglob('*.ndjson')))} dashboards, "
              "no structural findings")
        return 0

    width = max(len(c) for c, _, _ in findings)
    for category, where, msg in findings:
        print(f"{category:<{width}}  {where}: {msg}")
    print(f"\n{len(findings)} finding(s)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
