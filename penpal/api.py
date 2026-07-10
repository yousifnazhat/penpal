from __future__ import annotations

import ipaddress
import json
import logging
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .advisor import build_suggestions
from .context import build_context
from .ingest import extract_evidence
from .nmap_parser import NmapParseError, parse_nmap_xml
from .scope import ScopeViolationError
from .summary import render_summary
from .workspace import TargetExistsError, TargetNotFoundError, Workspace, WorkspaceError


LOGGER = logging.getLogger(__name__)
MAX_REQUEST_BODY_BYTES = 1024 * 1024


class ApiRequestError(ValueError):
    def __init__(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


def serve(
    workspace: Workspace,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    allow_remote: bool = False,
) -> None:
    remote = not _is_loopback_host(host)
    if remote and not allow_remote:
        raise ValueError(
            f"refusing to bind the unauthenticated API to non-loopback host {host!r}; "
            "use --allow-remote only on an isolated, trusted network"
        )
    if remote:
        print(
            "WARNING: PenPal's API has no authentication or TLS; remote clients can request unmasked workspace data.",
            file=sys.stderr,
        )

    handler = make_handler(workspace)
    server = ThreadingHTTPServer((host, port), handler)
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    print(f"PenPal API listening on http://{display_host}:{port}")
    try:
        server.serve_forever()
    finally:
        server.server_close()


def make_handler(workspace: Workspace) -> type[BaseHTTPRequestHandler]:
    class PenPalHandler(BaseHTTPRequestHandler):
        server_version = "PenPal/0.1"

        def version_string(self) -> str:
            return self.server_version

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
                    reveal = _query_bool(self.path, "reveal_secrets")
                    evidence = workspace.load_evidence(path[2])
                    self._json({"evidence": [item.to_dict(reveal=reveal) for item in evidence]})
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
                    self._json(
                        build_context(workspace, path[2], reveal_secrets=_query_bool(self.path, "reveal_secrets"))
                    )
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "summary":
                    target = workspace.require_target(path[2])
                    services = workspace.load_services(path[2])
                    self._json({"summary": render_summary(target, services)})
                else:
                    self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except ScopeViolationError as exc:
                self._json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
            except TargetNotFoundError as exc:
                self._json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except WorkspaceError:
                self._internal_error()
            except Exception:
                self._internal_error()

        def do_POST(self) -> None:
            try:
                path = _parts(self.path)
                body = self._read_body()
                if path == ["api", "targets"]:
                    host = _required_text(body, "host")
                    name = None if body.get("name") is None else _required_text(body, "name")
                    target = workspace.create_target(
                        host=host,
                        name=name,
                        force=_optional_bool(body, "force"),
                    )
                    self._json({"target": target.to_dict()}, HTTPStatus.CREATED)
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "parse-nmap":
                    workspace.require_target(path[2])
                    xml_path = Path(_required_text(body, "path"))
                    try:
                        parsed = parse_nmap_xml(xml_path)
                    except (NmapParseError, OSError) as exc:
                        raise ApiRequestError(f"unable to parse Nmap XML: {exc}") from exc
                    services = workspace.merge_services(path[2], parsed)
                    self._json({"services": [service.to_dict() for service in services]})
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "ingest":
                    target = workspace.require_target(path[2])
                    if "path" in body:
                        raise ApiRequestError("body.path is not supported; send tool output in body.text")
                    text = _optional_text(body, "text", default="", allow_empty=True)
                    reveal_secrets = _optional_bool(body, "reveal_secrets")
                    existing_ids = {item.id for item in workspace.load_evidence(path[2])}
                    result = extract_evidence(
                        text,
                        source=_optional_text(body, "source", default="paste"),
                        service_key=_optional_text(body, "service", default="", allow_empty=True),
                        existing_ids=existing_ids,
                    )
                    saved = workspace.append_evidence(path[2], result.evidence)
                    suggestions = build_suggestions(
                        workspace.load_services(path[2]),
                        saved,
                        target_host=target.host,
                        target_name=target.name,
                        parameters=workspace.load_parameters(path[2]),
                        reveal_secrets=reveal_secrets,
                    )
                    self._json(
                        {
                            "added": [item.to_dict(reveal=reveal_secrets) for item in result.evidence],
                            "ignored_duplicates": result.ignored_duplicates,
                            "suggestions": [suggestion.to_dict() for suggestion in suggestions],
                        }
                    )
                elif len(path) == 4 and path[:2] == ["api", "targets"] and path[3] == "parameters":
                    workspace.require_target(path[2])
                    key = _required_text(body, "key")
                    reveal_secrets = _optional_bool(body, "reveal_secrets")
                    parameter = workspace.set_parameter(
                        path[2],
                        key,
                        _required_text(body, "value", allow_empty=True),
                        sensitive=_optional_bool(body, "sensitive") or _looks_sensitive(key),
                        source=_optional_text(body, "source", default="manual"),
                    )
                    self._json({"parameter": parameter.to_dict(reveal=reveal_secrets)})
                else:
                    self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except ScopeViolationError as exc:
                self._json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
            except TargetExistsError as exc:
                self._json({"error": str(exc)}, HTTPStatus.CONFLICT)
            except TargetNotFoundError as exc:
                self._json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except ApiRequestError as exc:
                self._json({"error": str(exc)}, exc.status)
            except Exception:
                self._internal_error()

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _read_body(self) -> dict[str, object]:
            if self.headers.get("Transfer-Encoding"):
                self.close_connection = True
                raise ApiRequestError("transfer-encoded request bodies are not supported")

            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                return {}
            if not raw_length.isdigit():
                self.close_connection = True
                raise ApiRequestError("Content-Length must be a non-negative integer")

            try:
                length = int(raw_length)
            except ValueError as exc:
                self.close_connection = True
                raise ApiRequestError("Content-Length must be a non-negative integer") from exc
            if length > MAX_REQUEST_BODY_BYTES:
                self.close_connection = True
                raise ApiRequestError(
                    f"request body exceeds the {MAX_REQUEST_BODY_BYTES}-byte limit",
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
            if length == 0:
                return {}

            raw = self.rfile.read(length)
            if len(raw) != length:
                self.close_connection = True
                raise ApiRequestError("request body ended before Content-Length bytes were received")
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ApiRequestError("request body must be UTF-8") from exc
            try:
                body = json.loads(decoded)
            except (json.JSONDecodeError, RecursionError) as exc:
                raise ApiRequestError("request body must contain valid JSON") from exc
            if not isinstance(body, dict):
                raise ApiRequestError("expected JSON object")
            return body

        def _json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
            encoded = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)

        def _internal_error(self) -> None:
            LOGGER.exception("Unhandled PenPal API error")
            self._json({"error": "internal server error"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    return PenPalHandler


def _parts(raw_path: str) -> list[str]:
    parsed = urlparse(raw_path)
    return [unquote(part) for part in parsed.path.strip("/").split("/") if part]


def _query_bool(raw_path: str, key: str) -> bool:
    values = parse_qs(urlparse(raw_path).query).get(key, [])
    return any(value.lower() in {"1", "true", "yes", "on"} for value in values)


def _is_loopback_host(host: str) -> bool:
    candidate = host.strip()
    if candidate.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _required_text(body: dict[str, object], key: str, *, allow_empty: bool = False) -> str:
    if key not in body:
        raise ApiRequestError(f"missing field: {key}")
    return _text_value(body[key], key, allow_empty=allow_empty)


def _optional_text(
    body: dict[str, object],
    key: str,
    *,
    default: str,
    allow_empty: bool = False,
) -> str:
    if key not in body:
        return default
    return _text_value(body[key], key, allow_empty=allow_empty)


def _text_value(value: object, key: str, *, allow_empty: bool) -> str:
    if not isinstance(value, str):
        raise ApiRequestError(f"field {key} must be a string")
    if not allow_empty and not value.strip():
        raise ApiRequestError(f"field {key} must not be empty")
    return value


def _optional_bool(body: dict[str, object], key: str) -> bool:
    value = body.get(key, False)
    if not isinstance(value, bool):
        raise ApiRequestError(f"field {key} must be a boolean")
    return value


def _looks_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ["pass", "password", "secret", "token", "key", "hash"])
