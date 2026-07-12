from __future__ import annotations

import asyncio
import json
import sys
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from penpal.ingest import extract_evidence
from penpal.models import Service
from penpal.workspace import Workspace


EXPECTED_TOOLS = {
    "penpal_context",
    "penpal_suggest",
    "penpal_evidence",
    "penpal_playbooks_validate",
    "penpal_playbook_show",
    "penpal_modules_list",
    "penpal_module_plan",
}
SECRET = "Winter2024!"


async def check() -> None:
    with TemporaryDirectory(prefix="penpal-mcp-") as temp_dir:
        workspace = Workspace(temp_dir)
        target = workspace.create_target("10.10.10.5", name="demo")
        workspace.merge_services(
            target.name,
            [
                Service(port=143, protocol="tcp", name="imap"),
                Service(port=3389, protocol="tcp", name="ms-wbt-server"),
                Service(port=161, protocol="udp", name="snmp"),
            ],
        )
        workspace.append_evidence(
            target.name, extract_evidence(f"User: daniel\npassword={SECRET}\n", source="smoke").evidence
        )
        workspace.set_parameter(target.name, "known_password", SECRET, sensitive=True)

        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "penpal", "--workspace", temp_dir, "mcp"],
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} == EXPECTED_TOOLS

                context = await call(session, "penpal_context", {"target": target.name})
                assert context["schema"] == "penpal-context-v1"
                assert SECRET not in json.dumps(context)

                evidence = await call(session, "penpal_evidence", {"target": target.name, "limit": 1})
                assert evidence["count"] == 1
                assert evidence["total"] >= 2
                assert SECRET not in json.dumps(evidence)

                plan = await call(session, "penpal_module_plan", {"target": target.name, "module": "snmp"})
                assert plan["matched_services"] is True
                assert not (workspace.target_path(target.name) / "modules" / "snmp").exists()


async def call(session: ClientSession, name: str, arguments: dict[str, object]) -> dict[str, object]:
    result = await session.call_tool(name, arguments)
    text = next((item.text for item in result.content if getattr(item, "type", "") == "text"), None)
    assert text is not None, f"{name} returned no text result"
    payload = json.loads(text)
    assert "error" not in payload, payload.get("error")
    return payload


if __name__ == "__main__":
    asyncio.run(check())
    print("MCP stdio harness: passed")
