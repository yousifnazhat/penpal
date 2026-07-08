# PenPal Roadmap

## North Star

Build an authorized enumeration assistant that helps connect discovered facts into likely next steps.

The tool should not only say:

> Port 161 is open. Run SNMP checks.

It should eventually say:

> SNMP is open and mail services are exposed. SNMP may reveal usernames, service strings, hostnames, process names, or cleartext configuration. If usernames or mail credentials appear, test them against IMAP/POP3, then consider whether the same credentials unlock RDP, WinRM, SMB, or SSH.

The goal is a smart methodology engine: ports become services, services produce facts, facts produce hypotheses, and hypotheses produce next checks.

## Core Principles

- Stay focused on authorized labs, exams, and owned environments.
- Keep commands visible and reproducible.
- Prefer evidence-backed suggestions over black-box automation.
- Prefer official or canonical sources for syntax and tool behavior.
- Make the tool explain why a next step is suggested.
- Separate "what we know" from "what might be true."
- Let course notes become playbooks over time.
- Make every feature useful from the CLI before building the frontend.

## Product Architecture Roadmap

Build in this order:

```text
PenPal core -> context contract -> PI cockpit -> playbook ecosystem -> MCP portability -> later harnesses
```

1. **PenPal core**: keep services, evidence, parameters, suggestions, masking, and playbook matching deterministic.
2. **Context contract**: stabilize `penpal-context-v1` so agents and frontends consume the same facts.
3. **PI cockpit**: make PI the first operator harness with read-only tools first and operator-approved ingest later.
4. **Evaluation corpus**: add sample target contexts, expected top suggestions, and safety assertions.
5. **Community playbooks**: grow the schema, validator, examples, template, and contribution workflow.
6. **MCP portability**: expose the same safe read-only tools to other agent clients.
7. **Public v1**: ship docs, CI, security policy, release checklist, and a safe demo flow.
8. **Post-v1 automation**: add scope model, audit log, review workflow, and approved mutating actions.
9. **Later harnesses**: consider Hermes for long-running copilot workflows and OpenClaw for chat/channel gateways only after schemas, evaluations, and approval gates are stable.

Status snapshot, last updated 2026-07-08:

| Stage | Status | What proves it | Next step |
| --- | --- | --- | --- |
| PenPal core | Stable foundation, ongoing hardening | CLI/API, workspace storage, evidence ingest, masking, suggestions, and playbook matching are covered by tests | Keep changes deterministic and evidence-backed |
| Context contract | Active hardening | Contract fixtures protect context, evidence, service, suggestion, masking, matched-signal, and CLI JSON shapes | Add new fixture cases only when a real contract risk appears |
| PI cockpit | Release candidate ready | PI smoke tests cover read-only tools, `penpal_ingest` is disabled by default with operator approval, and project-local PI package loading works without `-e` | Keep PI surface read-only by default through release |
| Evaluation corpus | Active now | Demo fixtures and source-backed eval cases assert expected IDs, types, masking, suggestion order, reviewed source facts, and safety assertions | Add the next service-chain eval only after this one stays stable |
| Community playbooks | Active now | Validator, examples, template, docs, source facts, and tests prove reviewed material stays cited before promotion | Improve contributor authoring errors and review guidance |
| MCP portability | Queued | `docs/MCP_ADAPTER.md` defines the safe read-only plan | Build only after contracts/evals are stable enough to preserve |
| Public v1 | Prerelease published | `v0.1.0` is tagged and published as a GitHub prerelease with release-tarball smoke complete | Collect onboarding friction before expanding distribution or adapter surfaces |
| Post-v1 automation | Deferred | Roadmap lists scope, audit log, review workflow, and approved mutating actions | Start after public v1 |
| Later harnesses | Deferred | Harness strategy defers Hermes/OpenClaw | Revisit only after schemas, evals, and approval gates are stable |

Do not let any harness become the source of truth. Harnesses read PenPal facts, explain them, and submit new data back through PenPal.

## Enterprise Direction

This tool should grow beyond exam prep into an enterprise-ready enumeration and assessment assistant.

Enterprise priorities:

- Scope enforcement: targets, CIDRs, domains, and excluded assets should be explicit.
- Auditability: every command, suggestion, parameter change, and evidence item should have a timestamp and source.
- Secret handling: credentials should eventually live in an OS keychain or enterprise vault, not plaintext project files.
- Evidence provenance: every fact should trace back to a command, pasted output, manual note, screenshot, or imported file.
- Review workflow: candidate evidence should be confirmable, rejectable, and commentable.
- Risk modes: passive, normal, aggressive, and approval-required checks should be separated.
- Multi-target support: assessments should group multiple hosts, domains, and services into one engagement.
- Reporting: export findings, evidence, and methodology into client-ready Markdown/HTML/PDF.
- Integrations: future connectors may include ticketing, vaults, asset inventory, SIEM, and vulnerability management platforms.
- Team usage: role-based access, shared workspaces, and safe collaboration are future concerns.

The current backend is still a local-first prototype. Sensitive parameters are masked in output by default, but they are stored locally in `parameters.json` until a proper secrets backend is added.

## Intelligence Model

The smart layer should be built as a graph.

### Fact Nodes

Facts are things the tool has observed or the user has entered.

Examples:

- `service: tcp/161 snmp`
- `service: tcp/110 pop3`
- `service: tcp/143 imap`
- `service: tcp/3389 rdp`
- `artifact: username list`
- `artifact: email address`
- `artifact: credential`
- `artifact: domain name`
- `artifact: hostname`
- `finding: anonymous ftp allowed`
- `finding: smb share readable`
- `finding: snmp community valid`

### Hypothesis Nodes

Hypotheses are possible next opportunities.

Examples:

- `SNMP may expose usernames or service configuration.`
- `Mail credentials may be reused for remote login.`
- `SMB readable shares may contain config files or passwords.`
- `HTTP virtual hosts may reveal hidden applications.`
- `LDAP may expose domain users and password policy.`

### Action Nodes

Actions are safe, visible enumeration checks.

Examples:

- `Run snmpwalk with discovered community.`
- `Extract usernames from SNMP output.`
- `Check IMAP/POP3 login with known credentials.`
- `Check RDP/WinRM/SSH only with known valid credentials.`
- `Run directory discovery against HTTP service.`
- `Check SMB share listing.`

### Edges

Edges connect facts, hypotheses, and actions.

Example:

```text
tcp/161 snmp
  -> run SNMP community checks
  -> snmpwalk output
  -> extract usernames/config/processes
  -> try discovered mail creds against IMAP/POP3
  -> if valid creds, check RDP/WinRM/SMB/SSH
```

## Example Chains

These are not exploitation recipes. They are enumeration reasoning paths that help avoid missing obvious pivots.

### SNMP to Mail to Remote Access

Signals:

- `161/udp snmp`
- `110/tcp pop3`, `143/tcp imap`, `993/tcp imaps`, or `995/tcp pop3s`
- `3389/tcp rdp`, `5985/tcp winrm`, `445/tcp smb`, or `22/tcp ssh`

Reasoning:

- SNMP can expose users, processes, installed software, network interfaces, and sometimes configuration.
- Mail services can validate discovered usernames or credentials.
- Credentials may be reused for remote access services.

Suggested path:

1. Enumerate SNMP safely.
2. Extract usernames, hostnames, domains, emails, and config hints.
3. Check mail services with known or discovered credentials when allowed.
4. If credentials are valid, check RDP, WinRM, SMB, or SSH as credentialed follow-up.

### SMB to Configs to Credentials

Signals:

- `139/tcp netbios-ssn`
- `445/tcp smb`
- readable SMB shares

Reasoning:

- Shares may contain config files, scripts, backups, deployment files, or user documents.
- Files can reveal usernames, passwords, hostnames, service URLs, and app versions.

Suggested path:

1. Enumerate shares and permissions.
2. Download only relevant readable files into `loot/`.
3. Parse filenames and file contents for usernames, domains, connection strings, and credentials.
4. Feed discovered facts back into service-specific checks.

### HTTP to Virtual Hosts to Hidden Apps

Signals:

- `80/tcp http`
- `443/tcp https`
- certificate names
- redirects to hostnames
- DNS service exposed

Reasoning:

- Web servers often host multiple applications by hostname.
- TLS certificates, redirects, headers, and DNS can reveal names.

Suggested path:

1. Fingerprint HTTP service.
2. Capture screenshot and headers.
3. Extract hostnames from certificates, redirects, pages, and notes.
4. Add discovered hostnames to target facts.
5. Run vhost discovery when a domain is known.

### DNS to Web and AD Context

Signals:

- `53/tcp dns` or `53/udp dns`
- domain name discovered
- LDAP/Kerberos/SMB services exposed

Reasoning:

- DNS can reveal hostnames and service roles.
- In Windows environments, DNS names can point to domain controllers and internal apps.

Suggested path:

1. Try zone transfer against in-scope nameservers.
2. Brute-force subdomains only when allowed.
3. Feed hostnames into HTTP vhost checks.
4. Use domain names to guide LDAP, Kerberos, SMB, and certificate review.

### FTP/NFS to Files to Credentials

Signals:

- `21/tcp ftp`
- `2049/tcp nfs`
- anonymous FTP or exported NFS shares

Reasoning:

- Exposed files often contain backups, configs, scripts, SSH keys, logs, and application secrets.

Suggested path:

1. Check anonymous or unauthenticated access.
2. List readable files.
3. Pull relevant files into `loot/`.
4. Extract users, paths, services, versions, and credential-looking strings.
5. Feed extracted facts into HTTP, SSH, SMB, database, or remote access checks.

### LDAP/Kerberos/SMB to AD Map

Signals:

- `389/tcp ldap`
- `636/tcp ldaps`
- `88/tcp kerberos`
- `445/tcp smb`

Reasoning:

- These often indicate Active Directory.
- Anonymous or credentialed LDAP/SMB enumeration can reveal users, groups, password policy, hostnames, and domain structure.

Suggested path:

1. Identify domain and naming contexts.
2. Check anonymous bind posture.
3. Capture users, groups, password policy, and hostnames when readable.
4. Use valid credentials for deeper enumeration only after they are discovered.

## LLM Role

The LLM should act as a reasoning assistant, not a blind executor.

Good LLM tasks:

- Explain why a path is suggested.
- Rank next checks by likely value.
- Summarize what is known and what is missing.
- Convert course notes into playbook rules.
- Parse messy tool output into candidate facts.
- Detect "you skipped this obvious check" situations.
- Generate a human-readable enumeration strategy.

Things the LLM should not do automatically:

- Invent facts that are not in the evidence store.
- Run commands without showing them first.
- Treat guesses as confirmed findings.
- Hide risky or aggressive behavior behind a button.

Every LLM suggestion should include:

- supporting facts
- confidence
- why it matters
- suggested safe next command or manual check
- exact command syntax with placeholders for unknown values
- what evidence would confirm or reject it

## Planned Backend Features

### Phase 1: Strong Foundation

- Target workspaces
- Nmap scan planning
- Nmap XML parsing
- Service database
- Notes summary generation
- JSON API

Status: initial version complete.

### Phase 2: Evidence Store

Add structured storage for:

- usernames
- passwords and hashes
- credentials
- domains
- hostnames
- URLs
- web paths
- files downloaded
- screenshots
- interesting strings
- possible vulnerabilities
- command history

Status: initial paste-to-evidence ingestion and parameter storage added.

### Phase 3: Service Modules

Add modules that create command plans and parse output:

- `web`
- `smb`
- `dns`
- `snmp`
- `ftp`
- `nfs`
- `ldap`
- `mail`
- `rdp`
- `winrm`
- `ssh`
- `databases`

Each module should support:

- dry-run planning
- optional execution
- output storage
- basic parsing
- fact extraction

### Phase 4: Path Engine

Add a deterministic rules engine that maps facts to possible paths.

Rules should include source metadata from `SOURCE_POLICY.md` and `SOURCE_REGISTRY.md`.

Example output:

```json
{
  "path": "SNMP -> Mail -> Remote Access",
  "confidence": "medium",
  "supporting_facts": ["161/udp snmp", "143/tcp imap", "3389/tcp rdp"],
  "missing_facts": ["valid SNMP community", "usernames", "mail credentials"],
  "next_actions": ["snmp community check", "snmpwalk", "extract usernames"]
}
```

### Phase 5: Stuck Mode

Add:

```powershell
python -m penpal stuck <target>
```

It should answer:

- What services are open?
- What checks have already run?
- What evidence has been found?
- What high-value checks are missing?
- What chains are possible?
- What is the next safest thing to try?

### Phase 6: LLM-Assisted Strategy

Add optional LLM support after the evidence model exists.

Inputs:

- services
- evidence
- command history
- completed checks
- notes/playbooks

Outputs:

- ranked next steps
- path explanations
- missing checks
- writeup-ready summaries
- possible chains to investigate

### Phase 7: Frontend

Build a local dashboard over the API.

Views:

- target overview
- service table
- path graph
- evidence board
- command history
- module launcher
- stuck mode
- notes/report preview

## What Can Be Improved

The most important improvement is to avoid thinking only in ports.

Ports are the starting point, but the real workflow is:

```text
ports -> services -> facts -> hypotheses -> checks -> evidence -> paths
```

Other improvements:

- Track completed checks so suggestions do not repeat forever.
- Track negative findings because "anonymous SMB failed" is still useful.
- Keep a confidence score for every suggested chain.
- Let users manually add facts from course notes or observations.
- Store source information for every fact.
- Add a rules/playbook format that can grow from notes.
- Support "known creds" carefully as a first-class object.
- Make all aggressive checks opt-in.
- Build importers for existing notes over time.

## Near-Term Implementation Order

1. Expand evidence extraction quality.
2. Command history and check status.
3. Service module interface.
4. SNMP, mail, SMB, and HTTP modules.
5. Path engine with a small starter ruleset.
6. `stuck` command.
7. Optional LLM strategy layer.
8. Frontend dashboard.
