# Intelligence Loop

## Goal

The tool should compound intelligence over time.

Every box, module, failed check, successful chain, and course note should make future enumeration sharper.

The system should become smarter in two ways:

1. Deterministic intelligence: rules, facts, paths, checklists, and parsers that behave the same way every time.
2. Assisted intelligence: optional LLM reasoning that explains, ranks, summarizes, and helps turn messy notes into better rules.

The deterministic layer should be the source of truth. The LLM layer should sit on top as an analyst, not as the database.

## Core Loop

```text
learn -> run manually -> capture evidence -> extract facts -> create rule -> test rule -> reuse rule
```

More concretely:

```text
course note
  -> playbook check
  -> command plan
  -> tool output
  -> pasted or imported output
  -> parsed facts
  -> suggested paths
  -> user confirms useful/not useful
  -> rule gets refined
```

## What Gets Stored

### Facts

Facts are observed and source-backed.

Examples:

- `tcp/80 is open`
- `http title is "Nibbleblog"`
- `SNMP community public worked`
- `username daniel found in snmpwalk`
- `credential source: config.php`
- `SMB anonymous listing failed`
- `RDP is exposed`

Every fact should store:

- value
- type
- source command or manual note
- timestamp
- confidence
- target
- related service

### Negative Facts

Negative results matter.

Examples:

- `anonymous FTP failed`
- `SMB null session failed`
- `robots.txt not found`
- `vhost fuzzing found no hits`
- `SNMP public failed`

These prevent the tool from repeating stale suggestions forever.

### Checks

A check is an action the tool knows how to suggest or run.

Examples:

- `http_headers`
- `http_directory_discovery`
- `smb_share_list`
- `snmp_community_check`
- `snmp_walk`
- `mail_login_known_creds`
- `rdp_known_creds_check`

Each check should declare:

- required facts
- optional facts
- output parsers
- risk level
- service family
- what it may reveal

### Paths

A path is a chain of facts and checks.

Example:

```text
SNMP exposed
  -> SNMP community works
  -> SNMP output reveals usernames
  -> mail service exposed
  -> known credential works for mail
  -> remote login service exposed
  -> credentialed remote access check
```

Each path should store:

- name
- supporting facts
- missing facts
- next action
- confidence
- explanation
- source notes or examples

## Deterministic Rule Design

Rules should be small and inspectable.

Example rule:

```yaml
id: snmp_mail_remote_access
name: SNMP to Mail to Remote Access
requires_any:
  - service: snmp
requires_all:
  - service_family: mail
  - service_family: remote_access
suggest:
  - check: snmp_community_check
  - check: snmp_walk_if_community_known
  - check: extract_identities_from_snmp
explain: >
  SNMP may expose usernames, process details, hostnames, or configuration.
  If mail and remote access are also exposed, discovered identities or credentials
  can guide authorized credential checks.
```

Rules should not need the LLM to fire. The LLM can explain or rank the result, but the rule engine should produce the candidate path.

## Scoring

Every suggested move should get a score.

Signals that increase score:

- required facts are present
- previous related checks found useful data
- the service is commonly fruitful in labs
- credentials or usernames are already known
- the check has not been run yet
- the path has worked before in similar boxes

Signals that decrease score:

- the check already failed
- required facts are missing
- the target is out of scope
- the check is aggressive and current mode is conservative
- many similar checks produced no evidence

Suggested score fields:

- `confidence`: low, medium, high
- `value`: low, medium, high
- `risk`: passive, normal, aggressive
- `status`: ready, blocked, already_done

Every suggested move should also include exact syntax.

Good command examples:

```text
snmpwalk -v2c -c <community> 10.10.10.5
curl --url "imap://10.10.10.5:143/INBOX" --user "<known_user>:<known_password>" --verbose
xfreerdp /v:10.10.10.5 /u:<known_user> /p:<known_password> /cert:ignore
```

Rules:

- Fill in target host and known ports when available.
- Use explicit placeholders for unknown values.
- Fill placeholders from per-target parameters when they are known.
- Mask sensitive values by default and reveal only on explicit request.
- Prefer commands that preserve evidence and can be ingested back into the tool.
- Keep credentialed syntax framed around known valid credentials.

## Feedback Loop

After each check, the user should be able to mark:

- useful
- not useful
- false positive
- already knew this
- add to notes
- promote to rule

This turns experience into intelligence.

Example:

```powershell
python -m penpal feedback nibbles --check snmp_walk --useful --note "Found users and running services"
```

Over time, this creates a personal dataset of what works for your methodology.

## LLM Improvement Strategy

Do not start with fine-tuning.

Start with structured memory and retrieval:

1. Store facts, checks, paths, and notes cleanly.
2. Retrieve relevant notes and past paths for the current target.
3. Ask the LLM to rank and explain candidate paths.
4. Require the LLM to cite supporting facts from the evidence store.
5. Save user feedback on whether the suggestion helped.

Good LLM prompt shape:

```text
You are advising on authorized enumeration.
Use only the supplied facts and notes.
Separate confirmed facts from hypotheses.
Rank next checks by value and safety.
Explain what evidence supports each suggestion.
Do not invent open ports, credentials, or findings.
```

## Compounding From Course Notes

When a new course note is added:

1. Extract service families mentioned.
2. Extract commands.
3. Extract what each command reveals.
4. Extract prerequisites.
5. Extract follow-up decisions.
6. Convert those into draft playbook rules.
7. Review manually before enabling.

Example:

```text
Note: Footprinting SNMP
  -> services: snmp
  -> commands: onesixtyone, snmpwalk
  -> reveals: users, processes, software, interfaces
  -> paths: snmp -> users -> mail/ssh/rdp credential checks
```

## Paste-to-Evidence Workflow

The user should be able to run a command manually, paste or import its output, and have the tool extract key observations.

Example:

```powershell
python -m penpal ingest nibbles --file .\snmpwalk.txt --source snmpwalk --service udp/161
```

This should:

1. Store the raw source label and related service.
2. Extract candidate facts such as usernames, domains, hostnames, paths, URLs, interesting files, and credential-looking strings.
3. Preserve the context line so the user can verify the finding.
4. Add evidence to the target.
5. Re-run deterministic suggestions.

Important behavior:

- Extracted evidence is a candidate until confirmed.
- Credential-looking strings should be marked as sensitive.
- The tool should show why a suggested next move appeared.
- Duplicates should be ignored.
- The source output should stay traceable.

## Regression Scenarios

Every important chain should become a test scenario.

Example:

```json
{
  "name": "snmp_mail_rdp",
  "facts": [
    {"type": "service", "value": "snmp"},
    {"type": "service", "value": "imap"},
    {"type": "service", "value": "rdp"}
  ],
  "expected_paths": ["snmp_mail_remote_access"]
}
```

This protects the intelligence layer from getting worse as new rules are added.

## Near-Term Build Order

1. Add fact and evidence storage.
2. Add check status tracking, including negative results.
3. Add a small YAML rule format.
4. Add a deterministic path evaluator.
5. Add starter path rules:
   - SNMP -> Mail -> Remote Access
   - SMB -> Files -> Credentials
   - HTTP -> Vhosts -> Hidden Apps
   - DNS -> Hostnames -> Web/AD
   - FTP/NFS -> Files -> Credentials
   - LDAP/Kerberos/SMB -> AD Map
6. Add `stuck` command that prints ranked next moves.
7. Add feedback commands.
8. Add LLM ranking and explanation after deterministic paths work.
