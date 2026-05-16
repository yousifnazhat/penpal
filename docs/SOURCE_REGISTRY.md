# Source Registry

This registry tracks sources that can inform PenPal rules, command templates, parsers, and methodology.

Status meanings:

- `verified`: URL checked and source is suitable for reference.
- `needs_review`: useful source, but needs review before rules are derived.
- `legacy`: useful for context, but not primary for current syntax.
- `community`: valuable, but should be cross-checked before deterministic use.

## Official And Canonical Sources

| Area | Source | URL | Status | Use |
| --- | --- | --- | --- | --- |
| Nmap | Official docs | https://nmap.org/docs.html | verified | Documentation index and official references |
| Nmap | Nmap Network Scanning book | https://nmap.org/book/ | verified | Nmap methodology, features, and official guidance |
| Nmap | Reference guide / manpage | https://nmap.org/book/man.html | verified | Command flags and syntax |
| BloodHound | BloodHound CE docs | https://bloodhound.specterops.io/ | verified | BloodHound terminology, collection workflow, graph concepts |
| BloodHound | Legacy docs | https://bloodhound.readthedocs.io/ | legacy | Older BloodHound behavior and migration context |
| Impacket | Fortra Impacket GitHub | https://github.com/fortra/impacket | verified | Current examples, scripts, usage, protocol tooling |
| NetExec | Official wiki | https://www.netexec.wiki/ | verified | NetExec usage and modules |
| NetExec | GitHub wiki backing repo | https://github.com/Pennyw0rth/NetExec-Wiki | needs_review | Source-backed wiki edits and references |
| CrackMapExec | Legacy repository | https://github.com/byt3bl33d3r/CrackMapExec | legacy | Historical CME syntax only |
| ffuf | GitHub repository | https://github.com/ffuf/ffuf | verified | ffuf syntax and examples |
| feroxbuster | GitHub repository | https://github.com/epi052/feroxbuster | verified | Source and releases |
| feroxbuster | Official docs | https://epi052.github.io/feroxbuster-docs/ | verified | feroxbuster syntax and examples |
| Burp Suite | Documentation | https://portswigger.net/burp/documentation | verified | Burp features and workflows |
| OWASP | Web Security Testing Guide | https://owasp.org/www-project-web-security-testing-guide/ | verified | Web testing methodology |
| MITRE | ATT&CK | https://attack.mitre.org/ | verified | Technique taxonomy and mapping |
| Microsoft | Active Directory security best practices | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn487446%28v%3Dws.11%29 | verified | AD security concepts and defensive context |

## Training And Methodology Sources

| Area | Source | URL | Status | Use |
| --- | --- | --- | --- | --- |
| Web | PortSwigger Web Security Academy | https://portswigger.net/web-security | verified | Web vulnerability methodology and labs |
| Labs | HTB Academy | https://academy.hackthebox.com/ | needs_review | User course notes and module-derived playbooks |
| Methodology | TCM Security PNPT | https://certifications.tcm-sec.com/pnpt/ | verified | Professional pentest flow and reporting expectations |
| Methodology | OffSec PEN-200 public materials | https://help.offsec.com/hc/en-us/sections/6970444968596-Penetration-Testing-with-Kali-Linux-PEN-200 | needs_review | High-level OSCP/PEN-200 methodology only |
| Internal | User HTB/OSCP/CPTS notes | local notes workspace | needs_review | Primary personal playbook source |

## Community References

| Area | Source | URL | Status | Use |
| --- | --- | --- | --- | --- |
| General | HackTricks | https://book.hacktricks.xyz/ | community | Idea generation and checklist expansion |
| Payloads | PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | community | Payload ideas and bypass research |
| Payloads | Rendered PayloadsAllTheThings site | https://swisskyrepo.github.io/PayloadsAllTheThings/ | community | Browsable payload reference |

## How Sources Become PenPal Intelligence

```text
source -> extracted checks -> command templates -> evidence parser -> path rule -> tests -> reviewed rule
```

Rules derived from community references should stay `draft` until verified against official docs or manual testing.

