from http.server import ThreadingHTTPServer
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from penpal.api import make_handler
from penpal.ingest import extract_evidence
from penpal.models import Service
from penpal.workspace import Workspace


class ApiTests(unittest.TestCase):
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


def _stop_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
