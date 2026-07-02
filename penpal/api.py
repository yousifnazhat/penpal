from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .advisor import build_suggestions
from .context import build_context
from .ingest import extract_evidence
from .nmap_parser import parse_nmap_xml
from .summary import render_summary
from .workspace import Workspace, WorkspaceError


def serve(workspace: Workspace, host: str = "127.0.0.1", port: int = 8765) -> None:
    handler = make_handler(workspace)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"PenPal API listening on http://{host}:{port}")
    server.serve_forever()


def make_handler(workspace: Workspace) -> type[BaseHTTPRequestHandler]:
    class PenPalHandler(BaseHTTPRequestHandler):
        server_version = "PenPal/0.1"

        def do_GET(self) -> None:
            try:
                path = _parts(self.path)
                if path == ["api", "health"]:
                    self._json({"ok": True})
                elif path == ["api", "targets"]:
                    self._json({"targets": [target.to_dict() for target in workspace.list_targets()]})
                elif len(path) == 3 and path[:2] == ["api", "targets"]:
                    target = workspace.require_target(path[2])
                    self._json({"target": target.to_dict()})
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "services":
                    services = workspace.load_services(path[2])
                    self._json({"services": [service.to_dict() for service in services]})
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "evidence":
                    evidence = workspace.load_evidence(path[2])
                    self._json({"evidence": [item.to_dict() for item in evidence]})
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "parameters":
                    workspace.require_target(path[2])
                    reveal = _query_bool(self.path, "reveal_secrets")
                    parameters = workspace.load_parameters(path[2])
                    self._json({"parameters": [item.to_dict(reveal=reveal) for item in parameters.values()]})
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "suggestions":
                    target = workspace.require_target(path[2])
                    suggestions = build_suggestions(
                        workspace.load_services(path[2]),
                        workspace.load_evidence(path[2]),
                        target_host=target.host,
                        target_name=target.name,
                        parameters=workspace.load_parameters(path[2]),
                        reveal_secrets=_query_bool(self.path, "reveal_secrets"),
                    )
                    self._json({"suggestions": [suggestion.to_dict() for suggestion in suggestions]})
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "context":
                    self._json(build_context(workspace, path[2], reveal_secrets=_query_bool(self.path, "reveal_secrets")))
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "summary":
                    target = workspace.require_target(path[2])
                    services = workspace.load_services(path[2])
                    self._json({"summary": render_summary(target, services)})
                else:
                    self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except WorkspaceError as exc:
                self._json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except Exception as exc:
                self._json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        def do_POST(self) -> None:
            try:
                path = _parts(self.path)
                body = self._read_body()
                if path == ["api", "targets"]:
                    target = workspace.create_target(
                        host=str(body["host"]),
                        name=body.get("name"),
                        force=bool(body.get("force", False)),
                    )
                    self._json({"target": target.to_dict()}, HTTPStatus.CREATED)
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "parse-nmap":
                    workspace.require_target(path[2])
                    xml_path = Path(str(body["path"]))
                    services = workspace.merge_services(path[2], parse_nmap_xml(xml_path))
                    self._json({"services": [service.to_dict() for service in services]})
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "ingest":
                    target = workspace.require_target(path[2])
                    text = str(body.get("text", ""))
                    if body.get("path"):
                        text = Path(str(body["path"])).read_text(encoding="utf-8")
                    existing_ids = {item.id for item in workspace.load_evidence(path[2])}
                    result = extract_evidence(
                        text,
                        source=str(body.get("source", "paste")),
                        service_key=str(body.get("service", "")),
                        existing_ids=existing_ids,
                    )
                    saved = workspace.append_evidence(path[2], result.evidence)
                    suggestions = build_suggestions(
                        workspace.load_services(path[2]),
                        saved,
                        target_host=target.host,
                        target_name=target.name,
                        parameters=workspace.load_parameters(path[2]),
                        reveal_secrets=bool(body.get("reveal_secrets", False)),
                    )
                    self._json(
                        {
                            "added": [item.to_dict() for item in result.evidence],
                            "ignored_duplicates": result.ignored_duplicates,
                            "suggestions": [suggestion.to_dict() for suggestion in suggestions],
                        }
                    )
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "parameters":
                    workspace.require_target(path[2])
                    parameter = workspace.set_parameter(
                        path[2],
                        str(body["key"]),
                        str(body["value"]),
                        sensitive=bool(body.get("sensitive", False)) or _looks_sensitive(str(body["key"])),
                        source=str(body.get("source", "manual")),
                    )
                    self._json({"parameter": parameter.to_dict(reveal=bool(body.get("reveal_secrets", False)))})
                else:
                    self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except WorkspaceError as exc:
                self._json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except KeyError as exc:
                self._json({"error": f"missing field: {exc}"}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self._json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _read_body(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw)

        def _json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
            encoded = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(encoded)

    return PenPalHandler


def _parts(raw_path: str) -> list[str]:
    parsed = urlparse(raw_path)
    return [unquote(part) for part in parsed.path.strip("/").split("/") if part]


def _query_bool(raw_path: str, key: str) -> bool:
    values = parse_qs(urlparse(raw_path).query).get(key, [])
    return any(value.lower() in {"1", "true", "yes", "on"} for value in values)


def _looks_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ["pass", "password", "secret", "token", "key", "hash"])
