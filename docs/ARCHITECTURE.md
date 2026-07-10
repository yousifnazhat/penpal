# PenPal Architecture

PenPal is an authorized enumeration assistant for pentesters. It should behave like a careful partner: organize the workspace, extract evidence, explain why a path matters, and provide exact syntax without hiding what it is doing.

## Design Goals

- Product-quality codebase that can grow into a public GitHub project.
- Clear boundaries between storage, parsing, planning, advising, CLI, and API.
- Deterministic intelligence first; LLM assistance later.
- Commands are visible, reproducible, and explainable.
- Evidence is source-backed and auditable.
- Sensitive values are masked by default.
- Frontend can consume the same backend primitives as the CLI.
- Rules and command syntax should trace back to professional or canonical sources.

## Current Layers

```text
penpal/
  cli.py              User-facing command line interface
  api.py              Local JSON API for the future frontend
  workspace.py        Target workspace persistence
  models.py           Data models shared across layers
  scan_profiles.py    Scan planning and command construction
  runner.py           Command execution and job recording
  nmap_parser.py      Nmap XML parser
  ingest.py           Raw output to candidate evidence extraction
  advisor.py          Deterministic suggestions and command syntax
  playbooks.py        Community playbook validation and loading
  context.py          PI/frontend context snapshot
  recommendations.py  Simple service-specific checklist guidance
  summary.py          Markdown notes generation
```

The current structure is intentionally small. As modules grow, move code by responsibility, not by novelty.

## Future Package Shape

When the codebase becomes larger, evolve toward:

```text
penpal/
  app/
    cli.py
    api.py
  core/
    models.py
    workspace.py
    parameters.py
  execution/
    scan_profiles.py
    runner.py
    jobs.py
  parsers/
    nmap.py
    web.py
    smb.py
    snmp.py
  intelligence/
    advisor.py
    rules.py
    scoring.py
    paths.py
  modules/
    web.py
    smb.py
    dns.py
    snmp.py
    mail.py
  reporting/
    summary.py
    markdown.py
```

Do not split files just to look sophisticated. Split when a file has multiple reasons to change.

## Core Data Flow

```text
target -> scan plan -> command/job output -> parser/ingest -> evidence
evidence + services + parameters -> suggestions -> exact syntax -> more evidence
```

The source of truth should be persisted data, not terminal output.

## Harness Boundary

PenPal should stay harness-neutral at the core. PI is the first v1 cockpit, MCP is the portability layer, Hermes is a later long-running copilot option, and OpenClaw is a later channel gateway. Harnesses consume PenPal facts; they do not create facts without feeding data back through PenPal.

## Data Objects

### Engagement Scope

Represents the operator-approved hosts, networks, and wildcard subdomains for one workspace. It is stored at `penpal-workspace/scope.json`; exclusions take precedence, and configured scope is checked whenever a target is created or used by a target operation.

### Target

Represents an in-scope host or named asset.

Stored in:

```text
penpal-workspace/targets/<target>/target.json
```

### Service

Represents an observed open service, usually from Nmap XML.

Stored in:

```text
services.json
```

### Evidence

Represents source-backed candidate or confirmed facts.

Examples:

- username
- hostname
- domain
- URL
- web path
- interesting file
- credential candidate

Stored in:

```text
evidence.json
```

### Parameter

Represents reusable target-specific values for command placeholders.

Examples:

- `community`
- `known_user`
- `known_password`
- `domain`
- `wordlist`

Stored in:

```text
parameters.json
```

Sensitive parameters are masked in output by default. Environment-backed parameters store only a variable reference in `penpal-parameters-v2` and resolve the value in memory. OS keychain and managed-vault adapters can build on this boundary later.

### Suggestion

Represents a deterministic next move.

Every suggestion should include:

- title
- reason
- confidence
- value
- risk
- supporting facts
- next actions
- exact command syntax

## Intelligence Rule

PenPal should always be able to answer:

> Why are you suggesting this?

Good:

```text
Because udp/161 SNMP, tcp/143 IMAP, and tcp/3389 RDP are open, and SNMP output produced a username and credential candidate.
```

Bad:

```text
The model thinks this is interesting.
```

## No Redundancy Rule

Before adding a feature, decide where it belongs:

- Does it create or mutate persistent state? Put it near `workspace.py` or a future storage module.
- Does it parse tool output? Put it in a parser or `ingest.py`.
- Does it choose what to do next? Put it in `advisor.py` or future rules/scoring modules.
- Does it run commands? Put it in execution/runner code.
- Does it only display data? Keep it in CLI/API/frontend.

Avoid duplicate command templates across modules. Prefer one source of command syntax per check or suggestion.

## Enterprise Readiness Path

Before PenPal is enterprise-grade, it needs:

- explicit engagement/scope model
- command audit log
- check status and negative finding storage
- evidence review workflow
- pluggable secret backend
- role-aware frontend
- exportable reports
- clear risk modes
- integration-safe API contracts

## Testing Strategy

Every parser or intelligence rule should have tests.

Minimum test coverage for new features:

- model serialization/deserialization
- parser extraction behavior
- false-positive regression cases
- suggestion/rule triggering
- command syntax rendering
- sensitive value masking
- source labels for deterministic rules

## Naming

- Product name: `PenPal`
- Python package: `penpal`
- CLI command: `penpal`
- Default workspace: `penpal-workspace`
