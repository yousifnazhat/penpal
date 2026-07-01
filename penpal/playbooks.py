from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any


PENPAL_FRONTMATTER_RE = re.compile(r"^---\s*\n(?P<body>[\s\S]*?)\n---\s*", re.MULTILINE)
PENPAL_BLOCKS = {
    "methodology": (
        "<!-- penpal:methodology:start -->",
        "<!-- penpal:methodology:end -->",
        "penpal-methodology-v1",
    ),
    "evidence_rules": (
        "<!-- penpal:evidence_rules:start -->",
        "<!-- penpal:evidence_rules:end -->",
        "penpal-evidence-rules-v1",
    ),
}
FENCED_JSON_RE = re.compile(r"^```(?:json)?\s*\n(?P<body>[\s\S]*?)\n```\s*$", re.IGNORECASE)
PLAYBOOK_SCHEMA = "penpal-playbook-v1"
PLAYBOOK_RISKS = {"passive", "normal", "aggressive", "approval_required"}
SERVICE_SIGNAL_TYPES = {"service", "service_any"}


@dataclass
class PenpalBlock:
    kind: str
    path: str
    line: int
    data: Any | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "line": self.line,
            "ok": self.ok,
            "error": self.error,
            "data": self.data,
        }


@dataclass
class NoteScanReport:
    vault: str
    markdown_files: int = 0
    penpal_notes: int = 0
    methodology_blocks: int = 0
    evidence_rule_blocks: int = 0
    blocks: list[PenpalBlock] = field(default_factory=list)

    @property
    def errors(self) -> list[PenpalBlock]:
        return [block for block in self.blocks if not block.ok]

    def to_dict(self, include_blocks: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "vault": self.vault,
            "markdown_files": self.markdown_files,
            "penpal_notes": self.penpal_notes,
            "methodology_blocks": self.methodology_blocks,
            "evidence_rule_blocks": self.evidence_rule_blocks,
            "valid_blocks": len([block for block in self.blocks if block.ok]),
            "invalid_blocks": len(self.errors),
        }
        if include_blocks:
            data["blocks"] = [block.to_dict() for block in self.blocks]
        return data


@dataclass
class PlaybookFile:
    path: str
    data: Any | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "ok": self.ok,
            "error": self.error,
            "data": self.data,
        }


@dataclass
class PlaybookScanReport:
    root: str
    json_files: int = 0
    playbooks: list[PlaybookFile] = field(default_factory=list)

    @property
    def errors(self) -> list[PlaybookFile]:
        return [playbook for playbook in self.playbooks if not playbook.ok]

    @property
    def valid_playbooks(self) -> int:
        return len([playbook for playbook in self.playbooks if playbook.ok])

    def to_dict(self, include_playbooks: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "root": self.root,
            "json_files": self.json_files,
            "valid_playbooks": self.valid_playbooks,
            "invalid_playbooks": len(self.errors),
        }
        if include_playbooks:
            data["playbooks"] = [playbook.to_dict() for playbook in self.playbooks]
        return data


def scan_notes_vault(vault: str | Path) -> NoteScanReport:
    vault_path = Path(vault).expanduser().resolve()
    if not vault_path.exists():
        raise ValueError(f"Notes vault not found: {vault_path}")
    if not vault_path.is_dir():
        raise ValueError(f"Notes vault must be a directory: {vault_path}")

    report = NoteScanReport(vault=str(vault_path))
    for note_path in _markdown_files(vault_path):
        report.markdown_files += 1
        text = note_path.read_text(encoding="utf-8-sig")
        blocks = extract_penpal_blocks(text, note_path.relative_to(vault_path).as_posix())
        if _has_penpal_frontmatter(text) or blocks:
            report.penpal_notes += 1
        for block in blocks:
            report.blocks.append(block)
            if block.kind == "methodology":
                report.methodology_blocks += 1
            elif block.kind == "evidence_rules":
                report.evidence_rule_blocks += 1
    return report


def scan_playbooks(path: str | Path) -> PlaybookScanReport:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise ValueError(f"Playbook path not found: {root}")

    report = PlaybookScanReport(root=str(root))
    files = [root] if root.is_file() else _json_files(root)
    for playbook_path in files:
        report.json_files += 1
        relative_path = playbook_path.name if root.is_file() else playbook_path.relative_to(root).as_posix()
        try:
            data = json.loads(playbook_path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            report.playbooks.append(PlaybookFile(path=relative_path, error=f"invalid JSON: {exc.msg}"))
            continue

        error = validate_playbook(data)
        report.playbooks.append(PlaybookFile(path=relative_path, data=data, error=error))
    return report


def load_playbooks(path: str | Path = "playbooks") -> list[dict[str, Any]]:
    root = Path(path).expanduser()
    if not root.exists():
        return []

    report = scan_playbooks(root)
    if report.errors:
        first = report.errors[0]
        raise ValueError(f"Invalid playbook {first.path}: {first.error}")
    return [playbook.data for playbook in report.playbooks if isinstance(playbook.data, dict)]


def find_playbook(playbooks: list[dict[str, Any]], playbook_id: str) -> dict[str, Any]:
    for playbook in playbooks:
        if playbook.get("id") == playbook_id:
            return playbook
    raise ValueError(f"Playbook not found: {playbook_id}")


def format_playbook(playbook: dict[str, Any]) -> str:
    lines = [
        f"{playbook['title']} ({playbook['id']})",
        str(playbook["description"]),
        "",
        f"Tags: {', '.join(playbook.get('tags', []))}",
        "",
        "Signals:",
    ]
    lines.extend(f"- {_format_signal(signal)}" for signal in playbook.get("signals", []))
    lines.extend(["", "Actions:"])
    for action in playbook.get("actions", []):
        lines.append(f"- {action['id']} [{action['risk']}]: {action['description']}")
        for command in action.get("commands", []):
            lines.append(f"  - {command}")
    lines.extend(
        [
            "",
            "Safety:",
            f"- authorized_use_only: {str(playbook.get('safety', {}).get('authorized_use_only')).lower()}",
            f"- requires_operator_approval: {str(playbook.get('safety', {}).get('requires_operator_approval')).lower()}",
        ]
    )
    return "\n".join(lines)


def validate_playbook(data: Any) -> str:
    if not isinstance(data, dict):
        return "expected JSON object"
    if data.get("schema") != PLAYBOOK_SCHEMA:
        return f"expected schema {PLAYBOOK_SCHEMA}, found {data.get('schema') or '<missing>'}"

    for name in ["id", "title", "description"]:
        if not _nonempty_string(data.get(name)):
            return f"{name} must be a non-empty string"
    if not _string_list(data.get("tags")):
        return "tags must be a non-empty list of strings"

    signals = data.get("signals")
    if not _dict_list(signals):
        return "signals must be a non-empty list of objects"
    for index, signal in enumerate(signals):
        if not _nonempty_string(signal.get("type")):
            return f"signals[{index}].type must be a non-empty string"
        error = _validate_signal(signal, index)
        if error:
            return error

    actions = data.get("actions")
    if not _dict_list(actions):
        return "actions must be a non-empty list of objects"
    for index, action in enumerate(actions):
        for name in ["id", "description", "risk"]:
            if not _nonempty_string(action.get(name)):
                return f"actions[{index}].{name} must be a non-empty string"
        if action["risk"] not in PLAYBOOK_RISKS:
            return f"actions[{index}].risk must be one of {sorted(PLAYBOOK_RISKS)}"
        if not _string_list(action.get("commands")):
            return f"actions[{index}].commands must be a non-empty list of strings"
        if any("\n" in command or "\r" in command for command in action["commands"]):
            return f"actions[{index}].commands must be single-line strings"

    safety = data.get("safety")
    if not isinstance(safety, dict):
        return "safety must be an object"
    if safety.get("authorized_use_only") is not True:
        return "safety.authorized_use_only must be true"
    if safety.get("requires_operator_approval") is not True:
        return "safety.requires_operator_approval must be true"
    return ""


def extract_penpal_blocks(text: str, relative_path: str) -> list[PenpalBlock]:
    blocks: list[PenpalBlock] = []
    for kind, (start_marker, end_marker, expected_schema) in PENPAL_BLOCKS.items():
        cursor = 0
        while True:
            start = text.find(start_marker, cursor)
            if start == -1:
                break
            payload_start = start + len(start_marker)
            end = text.find(end_marker, payload_start)
            line = text.count("\n", 0, start) + 1
            if end == -1:
                blocks.append(PenpalBlock(kind=kind, path=relative_path, line=line, error="missing end marker"))
                break

            payload = _strip_markdown_json_fence(text[payload_start:end].strip())
            try:
                data = json.loads(payload)
            except json.JSONDecodeError as exc:
                blocks.append(PenpalBlock(kind=kind, path=relative_path, line=line, error=f"invalid JSON: {exc.msg}"))
                cursor = end + len(end_marker)
                continue

            schema = _schema_for(data)
            if kind == "evidence_rules" and isinstance(data, list):
                blocks.append(PenpalBlock(kind=kind, path=relative_path, line=line, data=data))
            elif schema != expected_schema:
                blocks.append(
                    PenpalBlock(
                        kind=kind,
                        path=relative_path,
                        line=line,
                        data=data,
                        error=f"expected schema {expected_schema}, found {schema or '<missing>'}",
                    )
                )
            else:
                blocks.append(PenpalBlock(kind=kind, path=relative_path, line=line, data=data))
            cursor = end + len(end_marker)
    return blocks


def _markdown_files(vault_path: Path) -> list[Path]:
    return sorted(
        path
        for path in vault_path.rglob("*.md")
        if ".obsidian" not in path.relative_to(vault_path).parts
    )


def _json_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.json")
        if not any(part.startswith(".") for part in path.relative_to(root).parts)
    )


def _has_penpal_frontmatter(text: str) -> bool:
    match = PENPAL_FRONTMATTER_RE.match(text)
    return bool(match and re.search(r"(?m)^penpal:\s*$", match.group("body")))


def _strip_markdown_json_fence(payload: str) -> str:
    match = FENCED_JSON_RE.match(payload)
    if match:
        return match.group("body").strip()
    return payload


def _schema_for(data: Any) -> str:
    if isinstance(data, dict):
        return str(data.get("schema", ""))
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return str(data[0].get("schema", ""))
    if isinstance(data, list):
        return "penpal-evidence-rules-v1"
    return ""


def _validate_signal(signal: dict[str, Any], index: int) -> str:
    signal_type = signal["type"]
    if signal_type == "service":
        if "port" not in signal and "name" not in signal:
            return f"signals[{index}] service signal needs port or name"
        if "port" in signal and not _valid_port(signal["port"]):
            return f"signals[{index}].port must be 1-65535"
    elif signal_type == "service_any":
        ports = signal.get("ports", [])
        names = signal.get("names", [])
        if not ports and not names:
            return f"signals[{index}] service_any signal needs ports or names"
        if ports and (not isinstance(ports, list) or not all(_valid_port(port) for port in ports)):
            return f"signals[{index}].ports must be a list of 1-65535 integers"
        if names and not _string_list(names):
            return f"signals[{index}].names must be a non-empty list of strings"
    elif signal_type == "evidence":
        if not _nonempty_string(signal.get("evidence_type")):
            return f"signals[{index}].evidence_type must be a non-empty string"
    elif signal_type not in SERVICE_SIGNAL_TYPES:
        return f"signals[{index}].type must be service, service_any, or evidence"
    return ""


def _format_signal(signal: dict[str, Any]) -> str:
    signal_type = signal["type"]
    if signal_type == "service":
        bits = [signal_type]
        if "protocol" in signal:
            bits.append(str(signal["protocol"]))
        if "port" in signal:
            bits.append(str(signal["port"]))
        if "name" in signal:
            bits.append(str(signal["name"]))
        return " ".join(bits)
    if signal_type == "service_any":
        ports = ", ".join(str(port) for port in signal.get("ports", []))
        names = ", ".join(str(name) for name in signal.get("names", []))
        parts = [part for part in [f"ports: {ports}" if ports else "", f"names: {names}" if names else ""] if part]
        return f"service_any ({'; '.join(parts)})"
    if signal_type == "evidence":
        return f"evidence {signal['evidence_type']}"
    return signal_type


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_nonempty_string(item) for item in value)


def _dict_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, dict) for item in value)


def _valid_port(value: Any) -> bool:
    return isinstance(value, int) and 1 <= value <= 65535
