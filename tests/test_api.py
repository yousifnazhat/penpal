from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from penpal.api import MAX_REQUEST_BODY_BYTES, _is_loopback_host, make_handler, serve
from penpal.ingest import extract_evidence
from penpal.models import Evidence, Service
from penpal.workspace import Workspace


class ApiTests(unittest.TestCase):
    def test_environment_parameter_api_never_persists_the_resolved_secret(self) -> None:
        secret = "Winter2024!"
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir, environment={"PENPAL_API_SECRET": secret})
            workspace.create_target("10.10.10.5", name="chain")
            server, thread = _start_server(workspace)
            try:
                status, _, masked = _post_json(
                    f"http://127.0.0.1:{server.server_port}/api/targets/chain/parameters",
                    {"key": "known_password", "env_var": "PENPAL_API_SECRET"},
                    origin="https://example.invalid",
                )
                revealed = _get_json(
                    f"http://127.0.0.1:{server.server_port}/api/targets/chain/parameters?reveal_secrets=true"
                )
                stored = workspace.parameters_path("chain").read_text(encoding="utf-8")
            finally:
                _stop_server(server, thread)

        parameter = next(item for item in revealed["parameters"] if item["name"] == "known_password")
        self.assertEqual(status, 200)
        self.assertEqual(masked["parameter"]["value"], "<sensitive>")
        self.assertEqual(masked["parameter"]["source"], "env:PENPAL_API_SECRET")
        self.assertEqual(parameter["value"], secret)
        self.assertNotIn(secret, stored)
        self.assertIn('"env_var": "PENPAL_API_SECRET"', stored)

    def test_environment_parameter_api_rejects_invalid_or_ambiguous_references(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir, environment={})
            workspace.create_target("10.10.10.5", name="chain")
            server, thread = _start_server(workspace)
            try:
                invalid_status, _, invalid = _post_json(
                    f"http://127.0.0.1:{server.server_port}/api/targets/chain/parameters",
                    {"key": "known_password", "env_var": "INVALID-NAME"},
                    origin="https://example.invalid",
                )
                ambiguous_status, _, ambiguous = _post_json(
                    f"http://127.0.0.1:{server.server_port}/api/targets/chain/parameters",
                    {"key": "known_password", "env_var": "PENPAL_SECRET", "value": "plaintext"},
                    origin="https://example.invalid",
                )
            finally:
                _stop_server(server, thread)

        self.assertEqual(invalid_status, 400)
        self.assertIn("invalid environment variable name", invalid["error"])
        self.assertEqual(ambiguous_status, 400)
        self.assertIn("value or env_var, not both", ambiguous["error"])

    def test_api_rejects_explicit_substitution_when_environment_value_is_missing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir, environment={})
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.merge_services(target.name, [Service(port=80, protocol="tcp", name="http")])
            workspace.append_evidence(
                target.name,
                [
                    Evidence(
                        id="hostname-candidate",
                        type="hostname",
                        value="portal.example.test",
                        source="test",
                    )
                ],
            )
            workspace.set_environment_parameter(target.name, "domain", "PENPAL_MISSING_DOMAIN")
            server, thread = _start_server(workspace)
            try:
                masked_status, _, _ = _raw_request(
                    server,
                    "GET",
                    "/api/targets/chain/suggestions",
                    b"",
                    {},
                )
                reveal_status, _, payload = _raw_request(
                    server,
                    "GET",
                    "/api/targets/chain/suggestions?reveal_secrets=true",
                    b"",
                    {},
                )
            finally:
                _stop_server(server, thread)

        self.assertEqual(masked_status, 200)
        self.assertEqual(reveal_status, 409)
        self.assertIn("PENPAL_MISSING_DOMAIN", payload["error"])

    def test_target_creation_respects_configured_engagement_scope(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            workspace.create_target("192.0.2.5", name="quarantined")
            workspace.set_scope(["10.10.10.0/24"])
            server, thread = _start_server(workspace)
            try:
                status, _, payload = _post_json(
                    f"http://127.0.0.1:{server.server_port}/api/targets",
                    {"host": "192.0.2.10", "name": "blocked"},
                    origin="https://example.invalid",
                )
                read_status, _, read_payload = _raw_request(
                    server,
                    "GET",
                    "/api/targets/quarantined",
                    b"",
                    {},
                )
                blocked_exists = (workspace.targets_dir / "blocked").exists()
            finally:
                _stop_server(server, thread)

        self.assertEqual(status, 403)
        self.assertIn("outside engagement scope", payload["error"])
        self.assertEqual(read_status, 403)
        self.assertIn("outside engagement scope", read_payload["error"])
        self.assertFalse(blocked_exists)

    def test_unknown_targets_return_404(self) -> None:
        with TemporaryDirectory() as temp_dir:
            server, thread = _start_server(Workspace(temp_dir))
            try:
                status, _, payload = _raw_request(server, "GET", "/api/targets/missing", b"", {})
            finally:
                _stop_server(server, thread)

        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "Unknown target: missing")

    def test_response_headers_disable_caching_and_hide_runtime_version(self) -> None:
        with TemporaryDirectory() as temp_dir:
            server, thread = _start_server(Workspace(temp_dir))
            try:
                status, headers, _ = _raw_request(server, "GET", "/api/health", b"", {})
            finally:
                _stop_server(server, thread)

        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Server"], "PenPal/0.1")

    def test_internal_errors_do_not_leak_exception_details(self) -> None:
        class FailingWorkspace(Workspace):
            def list_targets(self):
                raise RuntimeError("private filesystem detail")

        with TemporaryDirectory() as temp_dir:
            server, thread = _start_server(FailingWorkspace(temp_dir))
            try:
                with self.assertLogs("penpal.api", level="ERROR"):
                    status, _, payload = _raw_request(server, "GET", "/api/targets", b"", {})
            finally:
                _stop_server(server, thread)

        self.assertEqual(status, 500)
        self.assertEqual(payload["error"], "internal server error")
        self.assertNotIn("private filesystem detail", json.dumps(payload))

    def test_request_body_errors_return_specific_client_statuses(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            server, thread = _start_server(workspace)
            try:
                cases = [
                    (b"{", {}, 400, "request body must contain valid JSON"),
                    (b"[]", {}, 400, "expected JSON object"),
                    (b"\xff", {}, 400, "request body must be UTF-8"),
                    (b"{}", {"Content-Length": "invalid"}, 400, "Content-Length must be a non-negative integer"),
                    (
                        b"{}",
                        {"Content-Length": str(MAX_REQUEST_BODY_BYTES + 1)},
                        413,
                        f"request body exceeds the {MAX_REQUEST_BODY_BYTES}-byte limit",
                    ),
                ]
                for body, headers, expected_status, expected_error in cases:
                    with self.subTest(expected_error=expected_error):
                        status, _, payload = _raw_request(server, "POST", "/api/targets", body, headers)
                        self.assertEqual(status, expected_status)
                        self.assertEqual(payload["error"], expected_error)
            finally:
                _stop_server(server, thread)

    def test_target_conflicts_return_409(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            workspace.create_target("10.10.10.5", name="chain")
            server, thread = _start_server(workspace)
            try:
                status, _, payload = _post_json(
                    f"http://127.0.0.1:{server.server_port}/api/targets",
                    {"host": "10.10.10.5", "name": "chain"},
                    origin="https://example.invalid",
                )
            finally:
                _stop_server(server, thread)

        self.assertEqual(status, 409)
        self.assertEqual(payload["error"], "Target already exists: chain")

    def test_request_fields_are_type_checked_instead_of_coerced(self) -> None:
        with TemporaryDirectory() as temp_dir:
            server, thread = _start_server(Workspace(temp_dir))
            try:
                status, _, payload = _post_json(
                    f"http://127.0.0.1:{server.server_port}/api/targets",
                    {"host": "10.10.10.5", "force": "false"},
                    origin="https://example.invalid",
                )
            finally:
                _stop_server(server, thread)

        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "field force must be a boolean")

    def test_api_bind_defaults_to_loopback_only(self) -> None:
        self.assertTrue(_is_loopback_host("127.0.0.1"))
        self.assertTrue(_is_loopback_host("::1"))
        self.assertTrue(_is_loopback_host("localhost"))
        self.assertFalse(_is_loopback_host("0.0.0.0"))
        self.assertFalse(_is_loopback_host("192.0.2.10"))

        with TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "refusing to bind"):
                serve(Workspace(temp_dir), host="0.0.0.0", port=0)

    def test_context_endpoint_masks_sensitive_values(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.merge_services(target.name, [Service(port=3389, protocol="tcp", name="ms-wbt-server")])
            workspace.append_evidence(
                target.name,
                extract_evidence("User: daniel\npassword=Winter2024!\n", source="note").evidence,
            )
            workspace.set_parameter(target.name, "known_password", "Winter2024!", sensitive=True)

            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(workspace))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                payload = _get_json(f"http://127.0.0.1:{server.server_port}/api/targets/chain/context")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        body = json.dumps(payload)
        self.assertEqual(payload["schema"], "penpal-context-v1")
        self.assertIn("<sensitive>", body)
        self.assertNotIn("Winter2024!", body)

    def test_evidence_endpoint_masks_sensitive_values_by_default(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.append_evidence(
                target.name,
                extract_evidence("password=Winter2024!\n", source="note").evidence,
            )

            server, thread = _start_server(workspace)
            try:
                masked = _get_json(f"http://127.0.0.1:{server.server_port}/api/targets/chain/evidence")
                revealed = _get_json(
                    f"http://127.0.0.1:{server.server_port}/api/targets/chain/evidence?reveal_secrets=true"
                )
            finally:
                _stop_server(server, thread)

        self.assertEqual(masked["evidence"][0]["value"], "<sensitive>")
        self.assertEqual(revealed["evidence"][0]["value"], "Winter2024!")

    def test_ingest_rejects_file_paths_and_does_not_allow_cross_origin_reads(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            workspace.create_target("10.10.10.5", name="chain")

            server, thread = _start_server(workspace)
            try:
                status, headers, payload = _post_json(
                    f"http://127.0.0.1:{server.server_port}/api/targets/chain/ingest",
                    {"path": str(Path(temp_dir) / "outside-workspace.txt")},
                    origin="https://example.invalid",
                )
            finally:
                _stop_server(server, thread)

        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "body.path is not supported; send tool output in body.text")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_ingest_response_masks_sensitive_values_unless_revealed(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            workspace.create_target("10.10.10.5", name="masked")

            server, thread = _start_server(workspace)
            try:
                base_url = f"http://127.0.0.1:{server.server_port}/api/targets/masked/ingest"
                _, _, masked = _post_json(
                    base_url,
                    {"text": "password=Winter2024!\n", "source": "masked-response"},
                    origin="https://example.invalid",
                )
                _, _, revealed = _post_json(
                    base_url,
                    {"text": "password=Winter2024!\n", "source": "revealed-response", "reveal_secrets": True},
                    origin="https://example.invalid",
                )
            finally:
                _stop_server(server, thread)

        self.assertEqual(masked["added"][0]["value"], "<sensitive>")
        self.assertEqual(revealed["added"][0]["value"], "Winter2024!")


def _get_json(url: str) -> dict[str, object]:
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json(url: str, payload: dict[str, object], origin: str) -> tuple[int, object, dict[str, object]]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "text/plain", "Origin": origin},
        method="POST",
    )
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, response.headers, json.loads(response.read().decode("utf-8"))


def _start_server(workspace: Workspace) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(workspace))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _raw_request(
    server: ThreadingHTTPServer,
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
) -> tuple[int, object, dict[str, object]]:
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    request_headers = {"Content-Type": "application/json", "Connection": "close", **headers}
    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        return response.status, response.headers, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def _stop_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
