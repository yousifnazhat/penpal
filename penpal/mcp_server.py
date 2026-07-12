from __future__ import annotations

import json
from typing import Annotated, Any, Callable

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .advisor import build_suggestions
from .context import build_context
from .playbooks import DEFAULT_PLAYBOOKS_PATH, find_playbook, load_playbooks, scan_playbooks
from .service_modules import build_module_plan, get_module, module_matches_services, module_names
from .workspace import Workspace, WorkspaceError


MAX_RESPONSE_CHARS = 25_000
READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
TargetName = Annotated[str, Field(min_length=1, max_length=120, description="PenPal target name")]
ModuleName = Annotated[str, Field(min_length=1, max_length=40, description="Service module name")]
PlaybookId = Annotated[str, Field(min_length=1, max_length=120, description="Validated playbook id")]


def run_mcp(workspace: Workspace) -> None:
    """Run PenPal's local, read-only MCP server using stdio."""
    mcp = FastMCP("penpal_mcp", json_response=True)

    @mcp.tool(name="penpal_context", annotations=READ_ONLY)
    def penpal_context(target: TargetName) -> str:
        """Read a masked deterministic context snapshot for one PenPal target."""
        return _read(lambda: build_context(workspace, target))

    @mcp.tool(name="penpal_suggest", annotations=READ_ONLY)
    def penpal_suggest(target: TargetName) -> str:
        """Read masked, deterministic next-step suggestions for one PenPal target."""
        def operation() -> dict[str, Any]:
            record = workspace.require_target(target)
            suggestions = build_suggestions(
                workspace.load_services(record.name),
                workspace.load_evidence(record.name),
                target_host=record.host,
                target_name=record.name,
                parameters=workspace.load_parameters(record.name),
                playbooks=load_playbooks(),
            )
            return {"suggestions": [suggestion.to_dict() for suggestion in suggestions]}

        return _read(operation)

    @mcp.tool(name="penpal_evidence", annotations=READ_ONLY)
    def penpal_evidence(
        target: TargetName,
        limit: Annotated[int, Field(ge=1, le=100, description="Maximum evidence items to return")] = 50,
        offset: Annotated[int, Field(ge=0, description="Evidence items to skip")] = 0,
    ) -> str:
        """Read masked evidence for a target with offset pagination."""
        def operation() -> dict[str, Any]:
            workspace.require_target(target)
            evidence = [item.to_dict(reveal=False) for item in workspace.load_evidence(target)]
            return _evidence_page(target, evidence, limit, offset)

        return _read(operation)

    @mcp.tool(name="penpal_playbooks_validate", annotations=READ_ONLY)
    def penpal_playbooks_validate() -> str:
        """Validate the bundled PenPal playbooks without modifying them."""
        return _read(lambda: scan_playbooks(DEFAULT_PLAYBOOKS_PATH).to_dict())

    @mcp.tool(name="penpal_playbook_show", annotations=READ_ONLY)
    def penpal_playbook_show(id: PlaybookId) -> str:
        """Read one validated bundled playbook by id."""
        return _read(lambda: find_playbook(load_playbooks(), id))

    @mcp.tool(name="penpal_modules_list", annotations=READ_ONLY)
    def penpal_modules_list() -> str:
        """List source-backed PenPal service modules and their visible commands."""
        return _read(lambda: {"modules": [_module_to_dict(get_module(name)) for name in module_names()]})

    @mcp.tool(name="penpal_module_plan", annotations=READ_ONLY)
    def penpal_module_plan(target: TargetName, module: ModuleName) -> str:
        """Plan one masked, source-backed module without executing or writing commands."""
        def operation() -> dict[str, Any]:
            record = workspace.require_target(target)
            services = workspace.load_services(record.name)
            selected = get_module(module)
            commands = build_module_plan(
                module,
                record,
                workspace.target_path(record.name),
                services,
                workspace.load_parameters(record.name),
            )
            return {
                "target": record.to_dict(),
                "module": _module_to_dict(selected),
                "matched_services": module_matches_services(module, services),
                "commands": [command.to_dict() for command in commands],
            }

        return _read(operation)

    mcp.run(transport="stdio")


def _read(operation: Callable[[], dict[str, Any]]) -> str:
    try:
        return _render(operation())
    except (WorkspaceError, ValueError) as exc:
        return _render({"error": str(exc), "next_step": "Check the target name and run penpal doctor for local diagnostics."})


def _evidence_page(target: str, evidence: list[dict[str, Any]], limit: int, offset: int) -> dict[str, Any]:
    page = evidence[offset : offset + limit]
    while page and len(json.dumps(page)) > MAX_RESPONSE_CHARS // 2:
        page.pop()
    next_offset = offset + len(page)
    return {
        "target": target,
        "total": len(evidence),
        "count": len(page),
        "offset": offset,
        "evidence": page,
        "has_more": next_offset < len(evidence),
        "next_offset": next_offset if next_offset < len(evidence) else None,
    }


def _render(payload: dict[str, Any]) -> str:
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if len(rendered) <= MAX_RESPONSE_CHARS:
        return rendered
    return json.dumps(
        {
            "truncated": True,
            "message": "Response exceeds the MCP limit. Use penpal_evidence with limit and offset, or penpal_suggest for a smaller result.",
            "schema": payload.get("schema"),
            "target": payload.get("target"),
        },
        indent=2,
        sort_keys=True,
    )


def _module_to_dict(module: Any) -> dict[str, Any]:
    return {
        "name": module.name,
        "description": module.description,
        "ports": list(module.ports),
        "service_names": list(module.service_names),
        "commands": [
            {
                "id": template.id,
                "label": template.label,
                "source_label": template.source_label,
                "risk": template.risk,
                "tags": list(template.tags),
                "sources": [source.to_dict() for source in template.sources],
            }
            for template in module.templates
        ],
    }
