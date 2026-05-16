from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from .models import CommandSpec, utc_now
from .nmap_parser import parse_nmap_xml
from .workspace import Workspace


class RunnerError(RuntimeError):
    pass


def run_plan(
    workspace: Workspace,
    target_name: str,
    plan: list[CommandSpec],
    timeout: int | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for command in plan:
        results.append(run_command(workspace, target_name, command, timeout=timeout))
    return results


def run_command(
    workspace: Workspace,
    target_name: str,
    command: CommandSpec,
    timeout: int | None = None,
) -> dict[str, Any]:
    executable = command.args[0]
    if shutil.which(executable) is None:
        raise RunnerError(f"Required executable not found on PATH: {executable}")

    started_at = utc_now()
    completed = subprocess.run(
        command.args,
        cwd=command.cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    finished_at = utc_now()
    job = {
        "id": f"{command.id}-{started_at}",
        "command": command.to_dict(),
        "started_at": started_at,
        "finished_at": finished_at,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    workspace.append_job(target_name, job)

    if command.parser == "nmap_xml" and command.output_prefix:
        xml_path = Path(f"{command.output_prefix}.xml")
        if xml_path.exists():
            parsed = parse_nmap_xml(xml_path)
            workspace.merge_services(target_name, parsed)
            job["parsed_services"] = [service.to_dict() for service in parsed]

    return job

