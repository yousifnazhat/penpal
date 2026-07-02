# Source Policy

PenPal should become smarter from professional sources, course notes, and field use. The rule is simple:

```text
official/canonical sources -> methodology sources -> community idea sources -> user field evidence
```

The LLM can help summarize and connect ideas, but it should not be the authority for command syntax, tool behavior, or enterprise claims.

## Source Priority

### Tier 1: Official Or Canonical

Use these for:

- exact command syntax
- flags and options
- supported output formats
- tool behavior
- standards terminology
- enterprise security concepts

Examples:

- Nmap official docs and book
- BloodHound documentation
- Impacket GitHub repository
- NetExec wiki
- ffuf GitHub repository
- feroxbuster docs
- Burp Suite docs
- OWASP WSTG
- MITRE ATT&CK
- Microsoft Learn

### Tier 2: Professional Methodology

Use these for:

- workflow design
- reporting expectations
- engagement-style methodology
- web testing sequence
- AD assessment thinking
- lab-to-real-world translation

Examples:

- PortSwigger Web Security Academy
- HTB Academy
- TCM Security PNPT materials and public methodology
- OffSec/PEN-200 high-level public material
- user-owned course notes

### Tier 3: Community References

Use these for:

- idea generation
- checklist expansion
- payload discovery
- "what else should I try?" exploration

Examples:

- HackTricks
- PayloadsAllTheThings
- legacy CrackMapExec references
- trusted blog posts and writeups

Community references are useful, but they are not gospel. Verify syntax against official docs and mark community-derived logic clearly.

## Source Datasets

Treat notes and professional documentation as source datasets, not copied corpora.

- Personal notes: scan only a user-provided vault path with `python -m penpal notes <vault>`. PenPal should extract explicit `penpal:*` blocks and source labels, not bulk-copy private notes into the repo.
- Professional documentation: record the source in `SOURCE_REGISTRY.md`, then extract small facts such as command syntax, prerequisites, output formats, and expected evidence.
- Community references: use for ideas and checklist expansion, then verify syntax or deterministic behavior against official docs or manual testing.
- Playbooks: cite source titles or URLs with optional `source_tier`, `sources`, and `review_status` fields.

The crawl seed manifest lives in `SOURCE_SEEDS.json`. Raw crawl caches should stay outside git in `.penpal-source-cache/`; committed data should be small, cited, reviewed extractions.

Free-to-read documentation is not the same as permission to republish full text. PenPal should keep source URLs and extracted facts, not mirrored documentation pages.

Start with one source at a time:

```bash
python -m penpal sources list
python -m penpal sources fetch nmap --url https://nmap.org/docs.html --json
```

Fetched pages may emit `candidate` command or workflow facts; promote them into playbooks only after review against the cited source.

## Rule Requirements

Every PenPal rule or playbook entry should eventually include:

```yaml
id: snmp_mail_remote_access
name: SNMP to Mail to Remote Access
source_tier: methodology
sources:
  - title: User HTB Academy note - Footprinting SNMP
    type: internal_note
  - title: Nmap Reference Guide
    type: official
    url: https://nmap.org/book/man.html
confidence: medium
review_status: draft
```

## LLM Grounding

LLM-assisted suggestions must:

- separate confirmed facts from hypotheses
- cite supporting PenPal evidence
- cite rule/source names when available
- avoid inventing open ports, credentials, or tool output
- prefer official docs for syntax and flags
- clearly label community-inspired ideas

Good:

```text
Suggested because tcp/143 IMAP and tcp/3389 RDP are open, udp/161 SNMP is open, and SNMP output produced username daniel.
Source: PenPal rule snmp_mail_remote_access, user HTB Academy SNMP notes.
```

Bad:

```text
Try RDP because it might work.
```

## Import Workflow

When adding a source:

1. Record the source in `SOURCE_REGISTRY.md`.
2. Extract commands, flags, prerequisites, output formats, and expected evidence.
3. Mark whether the source is official, methodology, community, or internal.
4. Convert useful material into draft rules or check templates.
5. Add tests for command syntax and rule triggering.
6. Promote from draft only after manual review.

## Verification Cadence

- Official tool docs: verify when adding or changing command templates.
- Community references: verify before converting to deterministic rules.
- Training notes: keep source labels but avoid copying copyrighted course text.
- Enterprise claims: prefer vendor documentation, standards, and defensible evidence.
