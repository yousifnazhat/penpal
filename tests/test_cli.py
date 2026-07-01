from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from penpal.cli import main
from penpal.models import Service
from penpal.workspace import Workspace


class CliTests(unittest.TestCase):
    def test_suggest_explains_playbook_matches(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="chain")
            workspace.merge_services(
                target.name,
                [
                    Service(port=161, protocol="udp", name="snmp"),
                    Service(port=143, protocol="tcp", name="imap"),
                    Service(port=3389, protocol="tcp", name="ms-wbt-server"),
                ],
            )

            playbooks = Path(__file__).resolve().parents[1] / "playbooks"
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = main(["--workspace", temp_dir, "suggest", target.name, "--playbooks", str(playbooks)])

        output = stdout.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("Why this fired:", output)
        self.assertIn("- service: udp/161 snmp", output)
        self.assertIn("- service_any: tcp/143 imap", output)


if __name__ == "__main__":
    unittest.main()
