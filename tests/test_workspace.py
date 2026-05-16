from tempfile import TemporaryDirectory
import unittest

from penpal.models import Service
from penpal.workspace import Workspace


class WorkspaceTests(unittest.TestCase):
    def test_create_target_and_merge_services(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="nibbles")

            services = workspace.merge_services(
                target.name,
                [Service(port=80, protocol="tcp", name="http")],
            )

            self.assertEqual(target.name, "nibbles")
            self.assertTrue((workspace.target_path("nibbles") / "notes.md").exists())
            self.assertEqual(len(services), 1)
            self.assertEqual(workspace.load_services("nibbles")[0].name, "http")


if __name__ == "__main__":
    unittest.main()

