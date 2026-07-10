from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .models import Evidence, Parameter, Service, Target, utc_now


DEFAULT_WORKSPACE = "penpal-workspace"
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class WorkspaceError(RuntimeError):
    pass


def safe_target_name(value: str) -> str:
    safe = SAFE_NAME_RE.sub("_", value.strip()).strip("._-")
    return safe or "target"


class Workspace:
    def __init__(self, root: str | Path = DEFAULT_WORKSPACE):
        self.root = Path(root)
        self.targets_dir = self.root / "targets"

    def ensure(self) -> None:
        self.targets_dir.mkdir(parents=True, exist_ok=True)

    def target_path(self, name: str) -> Path:
        return self.targets_dir / safe_target_name(name)

    def create_target(self, host: str, name: str | None = None, force: bool = False) -> Target:
        self.ensure()
        target_name = safe_target_name(name or host)
        target_dir = self.target_path(target_name)
        if target_dir.exists() and not force:
            raise WorkspaceError(f"Target already exists: {target_name}")

        for child in [
            target_dir / "scans" / "nmap",
            target_dir / "jobs",
            target_dir / "loot",
            target_dir / "screenshots",
            target_dir / "web",
        ]:
            child.mkdir(parents=True, exist_ok=True)

        target = Target(name=target_name, host=host)
        self.save_target(target)
        self.save_services(target_name, [])
        self.save_evidence(target_name, [])
        self.save_parameters(
            target_name,
            {
                "target_host": Parameter(name="target_host", value=host, source="target"),
                "target_name": Parameter(name="target_name", value=target_name, source="target"),
            },
        )

        notes_path = target_dir / "notes.md"
        if not notes_path.exists():
            notes_path.write_text(f"# {target_name}\n\nHost: `{host}`\n\n", encoding="utf-8")

        return target

    def require_target(self, name: str) -> Target:
        path = self.target_path(name) / "target.json"
        if not path.exists():
            raise WorkspaceError(f"Unknown target: {name}")
        return Target.from_dict(read_json(path))

    def save_target(self, target: Target) -> None:
        self.ensure()
        target.updated_at = utc_now()
        target_dir = self.target_path(target.name)
        target_dir.mkdir(parents=True, exist_ok=True)
        write_json(target_dir / "target.json", target.to_dict())

    def list_targets(self) -> list[Target]:
        self.ensure()
        targets: list[Target] = []
        for path in sorted(self.targets_dir.glob("*/target.json")):
            targets.append(Target.from_dict(read_json(path)))
        return targets

    def services_path(self, name: str) -> Path:
        return self.target_path(name) / "services.json"

    def load_services(self, name: str) -> list[Service]:
        path = self.services_path(name)
        if not path.exists():
            return []
        data = read_json(path)
        return [Service.from_dict(item) for item in data.get("services", [])]

    def save_services(self, name: str, services: list[Service]) -> None:
        target = self.require_target(name)
        ordered = sorted(services, key=lambda svc: (svc.protocol, svc.port))
        write_json(
            self.services_path(name),
            {
                "updated_at": utc_now(),
                "services": [service.to_dict() for service in ordered],
            },
        )
        self.save_target(target)

    def merge_services(self, name: str, parsed: list[Service]) -> list[Service]:
        merged = {service.key: service for service in self.load_services(name)}
        for service in parsed:
            merged[service.key] = service
        services = sorted(merged.values(), key=lambda svc: (svc.protocol, svc.port))
        self.save_services(name, services)
        return services

    def evidence_path(self, name: str) -> Path:
        return self.target_path(name) / "evidence.json"

    def load_evidence(self, name: str) -> list[Evidence]:
        path = self.evidence_path(name)
        if not path.exists():
            return []
        data = read_json(path)
        return [Evidence.from_dict(item) for item in data.get("evidence", [])]

    def save_evidence(self, name: str, evidence: list[Evidence]) -> None:
        target = self.require_target(name)
        ordered = sorted(evidence, key=lambda item: (item.created_at, item.type, item.value))
        write_json(
            self.evidence_path(name),
            {
                "updated_at": utc_now(),
                "evidence": [item.to_dict() for item in ordered],
            },
        )
        self.save_target(target)

    def append_evidence(self, name: str, evidence: list[Evidence]) -> list[Evidence]:
        merged = {item.id: item for item in self.load_evidence(name)}
        for item in evidence:
            merged[item.id] = item
        saved = sorted(merged.values(), key=lambda item: (item.created_at, item.type, item.value))
        self.save_evidence(name, saved)
        return saved

    def parameters_path(self, name: str) -> Path:
        return self.target_path(name) / "parameters.json"

    def load_parameters(self, name: str) -> dict[str, Parameter]:
        path = self.parameters_path(name)
        if not path.exists():
            return {}
        data = read_json(path)
        return {item["name"]: Parameter.from_dict(item) for item in data.get("parameters", [])}

    def save_parameters(self, name: str, parameters: dict[str, Parameter]) -> None:
        target = self.require_target(name)
        ordered = sorted(parameters.values(), key=lambda item: item.name)
        write_json(
            self.parameters_path(name),
            {
                "updated_at": utc_now(),
                "parameters": [item.to_dict(reveal=True) for item in ordered],
            },
        )
        self.save_target(target)

    def set_parameter(
        self,
        name: str,
        parameter_name: str,
        value: str,
        sensitive: bool = False,
        source: str = "manual",
    ) -> Parameter:
        parameters = self.load_parameters(name)
        existing = parameters.get(parameter_name)
        parameter = Parameter(
            name=parameter_name,
            value=value,
            sensitive=sensitive,
            source=source,
            created_at=existing.created_at if existing else utc_now(),
            updated_at=utc_now(),
        )
        parameters[parameter_name] = parameter
        self.save_parameters(name, parameters)
        return parameter

    def unset_parameter(self, name: str, parameter_name: str) -> bool:
        parameters = self.load_parameters(name)
        existed = parameter_name in parameters
        if existed:
            del parameters[parameter_name]
            self.save_parameters(name, parameters)
        return existed

    def append_job(self, name: str, job: dict[str, Any]) -> Path:
        target = self.require_target(name)
        job_id = safe_target_name(str(job.get("id") or utc_now().replace(":", "").replace("+", "Z")))
        job["id"] = job_id
        job["target"] = target.name
        job["host"] = target.host
        job["created_at"] = job.get("created_at") or utc_now()
        path = self.target_path(name) / "jobs" / f"{job_id}.json"
        write_json(path, job)
        return path


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
