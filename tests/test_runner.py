import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from penpal.models import CommandSpec
from penpal.runner import run_command
from penpal.workspace import Workspace


NMAP_XML = """<?xml version=\"1.0\"?>
<nmaprun>
  <host>
    <ports>
      <port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\"/></port>
    </ports>
  </host>
</nmaprun>
"""


class RunnerTests(unittest.TestCase):
    def test_nmap_parse_results_are_persisted_with_the_job(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="demo")
            output_prefix = Path(temp_dir) / "scan"
            Path(f"{output_prefix}.xml").write_text(NMAP_XML, encoding="utf-8")
            command = CommandSpec(
                id="recorded-scan",
                label="Record scan",
                args=[sys.executable, "-c", "pass"],
                cwd=temp_dir,
                output_prefix=str(output_prefix),
                parser="nmap_xml",
            )

            result = run_command(workspace, target.name, command)
            job_path = next((workspace.target_path(target.name) / "jobs").glob("*.json"))
            job = json.loads(job_path.read_text(encoding="utf-8"))

        expected = [
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "name": "http",
                "product": "",
                "version": "",
                "extrainfo": "",
                "tunnel": "",
                "scripts": {},
            }
        ]
        self.assertEqual(result["parsed_services"], expected)
        self.assertEqual(job["parsed_services"], expected)


if __name__ == "__main__":
    unittest.main()
