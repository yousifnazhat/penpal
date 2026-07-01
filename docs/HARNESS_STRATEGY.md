# Harness Strategy

PenPal should be harness-neutral at the core and opinionated at the edge.

## Decision

```text
PenPal core -> PI first -> MCP second -> Hermes later -> OpenClaw optional
```

- **PenPal core** is the source of truth for targets, services, evidence, parameters, playbooks, masking, and deterministic suggestions.
- **PI** is the first operator cockpit for v1: read context, explain recommendations, ask for missing evidence, and request approval before mutating actions.
- **MCP** is the portability layer so other agents can call the same safe PenPal tools without custom adapters.
- **Hermes** is a later long-running copilot option once PenPal has stable schemas, evaluations, and approval gates.
- **OpenClaw** is a later channel gateway if PenPal needs Slack, Discord, Telegram, WhatsApp, or always-on chat surfaces.

## Architecture rule

Agent harnesses must consume PenPal facts. They must not become the facts.

Good:

```text
PI reads penpal-context-v1 -> cites matched signals -> asks operator to approve ingest
```

Bad:

```text
Harness memory invents a target fact -> hidden tool runs a credentialed check
```

## v1 build order

1. Keep improving the deterministic Python CLI/API.
2. Harden `penpal context <target> --json` as the read-only harness contract.
3. Keep the PI extension read-only by default.
4. Add operator-approved `ingest` only after approval UX is tested.
5. Add MCP only after the context/suggestion schema is stable enough to preserve.

The MCP adapter plan lives in [MCP Adapter Plan](MCP_ADAPTER.md).

## Not v1

- Direct C2 tasking.
- Exploit execution.
- Autonomous credential use.
- Multi-agent orchestration as the source of recommendations.
- Channel-gateway work before the operator cockpit works locally.
