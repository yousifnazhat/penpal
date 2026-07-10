import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

from penpal.models import Evidence, Parameter, Service
from penpal.workspace import (
    EVIDENCE_STORAGE_SCHEMA,
    JOB_STORAGE_SCHEMA,
    PARAMETERS_STORAGE_SCHEMA,
    SERVICES_STORAGE_SCHEMA,
    TARGET_STORAGE_SCHEMA,
    Workspace,
    WorkspaceError,
    write_json,
)


class SlowEvidenceWorkspace(Workspace):
    def load_evidence(self, name: str) -> list[Evidence]:
        evidence = super().load_evidence(name)
        time.sleep(0.01)
        return evidence


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

    def test_write_json_replaces_the_complete_file_and_cleans_up_temporary_data(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "state.json"
            path.write_text('{"old": true}\n', encoding="utf-8")

            write_json(path, {"new": True})

            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"new": True})
            self.assertEqual(list(path.parent.glob(".state.json.*.tmp")), [])

    def test_write_json_preserves_the_previous_file_when_replacement_fails(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "state.json"
            path.write_text('{"old": true}\n', encoding="utf-8")

            with patch("penpal.workspace.os.replace", side_effect=OSError("replacement failed")):
                with self.assertRaises(OSError):
                    write_json(path, {"new": True})

            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"old": True})
            self.assertEqual(list(path.parent.glob(".state.json.*.tmp")), [])

    def test_save_operations_reject_unknown_targets_before_creating_data_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)

            with self.assertRaises(WorkspaceError):
                workspace.save_services("missing", [Service(port=80, protocol="tcp", name="http")])
            with self.assertRaises(WorkspaceError):
                workspace.save_evidence("missing", [Evidence(id="one", type="note", value="value", source="test")])
            with self.assertRaises(WorkspaceError):
                workspace.save_parameters("missing", {"name": Parameter(name="name", value="value")})

            target_dir = workspace.target_path("missing")
            self.assertFalse((target_dir / "services.json").exists())
            self.assertFalse((target_dir / "evidence.json").exists())
            self.assertFalse((target_dir / "parameters.json").exists())

    def test_append_job_normalizes_the_stored_id_and_filename_together(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="nibbles")

            path = workspace.append_job(target.name, {"id": "quick/2026:07:09"})
            job = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(path.name, "quick_2026_07_09.json")
        self.assertEqual(job["id"], "quick_2026_07_09")
        self.assertEqual(job["schema"], JOB_STORAGE_SCHEMA)

    def test_workspace_files_have_versioned_storage_schemas(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="nibbles")
            target_dir = workspace.target_path(target.name)

            schemas = {
                "target.json": TARGET_STORAGE_SCHEMA,
                "services.json": SERVICES_STORAGE_SCHEMA,
                "evidence.json": EVIDENCE_STORAGE_SCHEMA,
                "parameters.json": PARAMETERS_STORAGE_SCHEMA,
            }
            stored = {
                filename: json.loads((target_dir / filename).read_text(encoding="utf-8"))["schema"]
                for filename in schemas
            }

        self.assertEqual(stored, schemas)

    def test_legacy_storage_without_schema_loads_and_upgrades_on_write(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="nibbles")
            path = workspace.services_path(target.name)
            write_json(path, {"services": []})

            services = workspace.load_services(target.name)
            workspace.save_services(target.name, services)
            upgraded = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(services, [])
        self.assertEqual(upgraded["schema"], SERVICES_STORAGE_SCHEMA)

    def test_unknown_storage_schema_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="nibbles")
            write_json(workspace.evidence_path(target.name), {"schema": "penpal-evidence-v99", "evidence": []})

            with self.assertRaisesRegex(WorkspaceError, "Unsupported storage schema"):
                workspace.load_evidence(target.name)

    def test_concurrent_evidence_appends_preserve_every_item(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = SlowEvidenceWorkspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="nibbles")
            barrier = threading.Barrier(8)
            errors: list[Exception] = []

            def append(index: int) -> None:
                try:
                    barrier.wait()
                    workspace.append_evidence(
                        target.name,
                        [Evidence(id=f"item-{index}", type="note", value=str(index), source="thread-test")],
                    )
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=append, args=(index,)) for index in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)

            evidence = workspace.load_evidence(target.name)

        self.assertEqual(errors, [])
        self.assertEqual({item.id for item in evidence}, {f"item-{index}" for index in range(8)})


if __name__ == "__main__":
    unittest.main()
