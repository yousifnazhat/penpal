# PenPal v1 Plan

## Goal

Ship a public contributor-ready release in three months: PI as the agentic harness, PenPal as the deterministic enumeration and attack-vector recommendation core, and community playbooks as the scaling loop.

## v1 pillars

1. Deterministic evidence loop: services, evidence, parameters, suggestions, syntax, more evidence.
2. Community playbooks: stable format, validator, examples, and contribution docs.
3. PI harness: LLM-assisted reasoning around PenPal data, not hidden autonomous execution.
4. Safety and auditability: visible commands, masked secrets, operator approval, and authorized-use defaults.

## First milestone

A new contributor can clone the repo, run tests, validate `playbooks/`, and submit a useful playbook without needing private context.

Use [v1 Release Checklist](V1_RELEASE_CHECKLIST.md) before cutting the first public release.

## PI integration target

PI should start by wrapping `penpal context <target> --json` and the local context API. The adapter contract lives in [PI Adapter Contract](PI_ADAPTER.md).

PenPal should stay harness-neutral at the core: use PI as the first operator cockpit, MCP as the next portability layer, Hermes later for long-running copilot workflows, and OpenClaw only if channel gateway support becomes important. See [Harness Strategy](HARNESS_STRATEGY.md).

MCP should start as a read-only portability adapter over the same context and suggestion commands. See [MCP Adapter Plan](MCP_ADAPTER.md).

## Not yet

Direct C2 tasking, exploit execution, and autonomous credential use are valid product directions, but they are not required for the first public contributor-ready release.
