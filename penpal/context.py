from __future__ import annotations

from typing import Any

from .advisor import build_suggestions
from .playbooks import load_playbooks
from .summary import render_summary
from .workspace import Workspace


def build_context(
    workspace: Workspace,
    name: str,
    playbooks_path: str = "playbooks",
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    target = workspace.require_target(name)
    services = workspace.load_services(target.name)
    evidence = workspace.load_evidence(target.name)
    parameters = workspace.load_parameters(target.name)
    suggestions = build_suggestions(
        services,
        evidence,
        target_host=target.host,
        target_name=target.name,
        parameters=parameters,
        reveal_secrets=reveal_secrets,
        playbooks=load_playbooks(playbooks_path),
    )
    return {
        "schema": "penpal-context-v1",
        "target": target.to_dict(),
        "services": [service.to_dict() for service in services],
        "evidence": [item.to_dict(reveal=reveal_secrets) for item in evidence],
        "parameters": [item.to_dict(reveal=reveal_secrets) for item in parameters.values()],
        "suggestions": [suggestion.to_dict() for suggestion in suggestions],
        "summary": render_summary(target, services),
    }
