# Third-party content and licensing

The bulk of this repository — the `100xxx`, `110xxx` and `129xxx` custom rules, the
Proxmox and UniFi decoders, the dashboards and the documentation — is original work,
licensed under the MIT License in `LICENSE`.

Three files additionally contain content derived from the **Wazuh default ruleset**
([wazuh/wazuh](https://github.com/wazuh/wazuh), `ruleset/rules/`), which is licensed
under the **GNU General Public License v2**. Those files are distributed under the
GPLv2, not MIT.

| File | Stock rule IDs | Nature of the derivation |
|---|---|---|
| `rules/windows/108_default_overrides.xml` | 60015, 60162, 60171, 60187, 60188, 60189, 91803, 91822, 91823, 92650, 92655 | **Verbatim copies** of the shipped rule bodies (description, `<group>` compliance strings, `<if_sid>`, `<field>`, `<mitre>`) with a single routing option added |
| `rules/windows/103_local_rules.xml` | 60106, 60109, 60111, 60112, 60115, 60117, 60122, 60137, 60141, 60142, 60144, 60145, 60151, 60152, 60229, 92651 | Match conditions (`<if_sid>`, `<field>`) retained from the stock rules; descriptions and levels rewritten |
| `rules/windows/104_ad_correlation.xml` | 60154, 60159, 60166, 60167 | Match conditions retained from the stock rules; descriptions, groups and MITRE tags rewritten |

`overwrite="yes"` requires the rule id and, in practice, the parent/match conditions of
the stock rule — so reproducing that much is unavoidable for this technique to work.

Rule bodies were last reconciled against Wazuh **4.14.3** (`0575-win-base_rules.xml`,
`0580-win-security_rules.xml`, `0840-win_event_channel.xml`,
`0915-win-powershell_rules.xml`). If a later Wazuh release changes one of these bodies,
re-copy it so the override stays faithful.

## Other references

- **MITRE ATT&CK®** technique identifiers are used under the
  [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/).
  ATT&CK® is a registered trademark of The MITRE Corporation.
- Product names (Wazuh, Proxmox, Ubiquiti/UniFi, Microsoft Windows) are trademarks of
  their respective owners and are used here for identification only.
