from http.server import ThreadingHTTPServer
import json
from tempfile import TemporaryDirectory
import threading
import unittest
from urllib.request import urlopen

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


def _get_json(url: str) -> dict[str, object]:
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
