import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

from penpal.models import Evidence, Parameter, ParameterResolutionError, Service, Target
from penpal.scope import SCOPE_SCHEMA, ScopeViolationError
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
    def test_scope_is_optional_until_configured_then_enforced(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            workspace.create_target("192.0.2.10", name="legacy")
            scope = workspace.set_scope(["10.10.10.0/24", "*.lab.example"], ["10.10.10.9"])
            allowed = workspace.create_target("10.10.10.5", name="allowed")

            with self.assertRaisesRegex(ScopeViolationError, "did not match an include rule"):
                workspace.create_target("192.0.2.20", name="blocked")
            with self.assertRaisesRegex(ScopeViolationError, "excluded by 10.10.10.9"):
                workspace.create_target("10.10.10.9", name="excluded")
            with self.assertRaises(ScopeViolationError):
                workspace.require_target("legacy")
            with self.assertRaises(ScopeViolationError):
                workspace.save_target(Target(name="direct", host="192.0.2.30"))

            stored = json.loads(workspace.scope_path().read_text(encoding="utf-8"))
            blocked_exists = (workspace.targets_dir / "blocked").exists()

        self.assertEqual(allowed.host, "10.10.10.5")
        self.assertEqual(scope.includes, ("10.10.10.0/24", "*.lab.example"))
        self.assertEqual(stored["schema"], SCOPE_SCHEMA)
        self.assertFalse(blocked_exists)

    def test_clearing_scope_restores_access_to_quarantined_targets(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("192.0.2.10", name="legacy")
            workspace.set_scope(["10.10.10.0/24"])

            with self.assertRaises(ScopeViolationError):
                workspace.require_target(target.name)
            self.assertTrue(workspace.clear_scope())
            restored = workspace.require_target(target.name)

        self.assertEqual(restored.host, "192.0.2.10")

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

    def test_environment_parameters_resolve_without_persisting_values(self) -> None:
        secret = "Winter2024!"
        environment = {"PENPAL_TEST_SECRET": secret}
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir, environment=environment)
            target = workspace.create_target("10.10.10.5", name="nibbles")
            parameter = workspace.set_environment_parameter(
                target.name,
                "known_password",
                "PENPAL_TEST_SECRET",
            )
            stored_text = workspace.parameters_path(target.name).read_text(encoding="utf-8")
            stored = json.loads(stored_text)
            stored_parameter = next(item for item in stored["parameters"] if item["name"] == "known_password")

            environment["PENPAL_TEST_SECRET"] = "Spring2026!"
            reloaded = workspace.load_parameters(target.name)["known_password"]

        self.assertTrue(parameter.resolved)
        self.assertEqual(parameter.to_dict(reveal=False)["value"], "<sensitive>")
        self.assertEqual(stored["schema"], PARAMETERS_STORAGE_SCHEMA)
        self.assertEqual(stored_parameter["env_var"], "PENPAL_TEST_SECRET")
        self.assertNotIn("value", stored_parameter)
        self.assertNotIn(secret, stored_text)
        self.assertEqual(reloaded.require_value(), "Spring2026!")
        self.assertEqual(reloaded.to_dict()["source"], "env:PENPAL_TEST_SECRET")

    def test_missing_environment_parameter_is_visible_but_never_rendered_empty(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir, environment={})
            target = workspace.create_target("10.10.10.5", name="nibbles")
            workspace.set_environment_parameter(target.name, "known_password", "PENPAL_MISSING_SECRET")
            parameter = workspace.load_parameters(target.name)["known_password"]

        self.assertFalse(parameter.resolved)
        self.assertEqual(parameter.to_dict(reveal=True)["value"], "<missing>")
        with self.assertRaisesRegex(ParameterResolutionError, "PENPAL_MISSING_SECRET"):
            parameter.require_value()

    def test_invalid_environment_variable_names_are_rejected_before_storage_changes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir, environment={})
            target = workspace.create_target("10.10.10.5", name="nibbles")
            original = workspace.parameters_path(target.name).read_text(encoding="utf-8")

            for env_var in ["", "9INVALID", "INVALID-NAME", "INVALID NAME"]:
                with self.subTest(env_var=env_var):
                    with self.assertRaisesRegex(ValueError, "invalid environment variable name"):
                        workspace.set_environment_parameter(target.name, "known_password", env_var)

            unchanged = workspace.parameters_path(target.name).read_text(encoding="utf-8")

        self.assertEqual(unchanged, original)

    def test_v1_parameter_storage_loads_and_upgrades_to_v2(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="nibbles")
            write_json(
                workspace.parameters_path(target.name),
                {
                    "schema": "penpal-parameters-v1",
                    "parameters": [
                        {
                            "name": "known_password",
                            "value": "legacy-secret",
                            "sensitive": True,
                            "source": "manual",
                        }
                    ],
                },
            )

            parameters = workspace.load_parameters(target.name)
            workspace.save_parameters(target.name, parameters)
            upgraded = json.loads(workspace.parameters_path(target.name).read_text(encoding="utf-8"))

        self.assertEqual(parameters["known_password"].value, "legacy-secret")
        self.assertEqual(upgraded["schema"], PARAMETERS_STORAGE_SCHEMA)

    def test_environment_parameter_storage_rejects_embedded_values(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir, environment={"PENPAL_TEST_SECRET": "runtime-secret"})
            target = workspace.create_target("10.10.10.5", name="nibbles")
            write_json(
                workspace.parameters_path(target.name),
                {
                    "schema": PARAMETERS_STORAGE_SCHEMA,
                    "parameters": [
                        {
                            "name": "known_password",
                            "env_var": "PENPAL_TEST_SECRET",
                            "value": "must-not-coexist",
                            "sensitive": True,
                        }
                    ],
                },
            )

            with self.assertRaisesRegex(ValueError, "must not store a value"):
                workspace.load_parameters(target.name)

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

    def test_v010_workspace_loads_and_upgrades_on_write(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = Workspace(temp_dir)
            target = workspace.create_target("10.10.10.5", name="nibbles")
            paths = {
                "target": workspace.target_path(target.name) / "target.json",
                "services": workspace.services_path(target.name),
                "evidence": workspace.evidence_path(target.name),
                "parameters": workspace.parameters_path(target.name),
            }
            for path in paths.values():
                data = json.loads(path.read_text(encoding="utf-8"))
                del data["schema"]
                write_json(path, data)

            loaded_target = workspace.require_target(target.name)
            services = workspace.load_services(target.name)
            evidence = workspace.load_evidence(target.name)
            parameters = workspace.load_parameters(target.name)
            workspace.save_target(loaded_target)
            workspace.save_services(target.name, services)
            workspace.save_evidence(target.name, evidence)
            workspace.save_parameters(target.name, parameters)
            upgraded = {name: json.loads(path.read_text(encoding="utf-8"))["schema"] for name, path in paths.items()}

        self.assertEqual(loaded_target.host, "10.10.10.5")
        self.assertEqual(parameters["target_host"].value, "10.10.10.5")
        self.assertEqual(
            upgraded,
            {
                "target": TARGET_STORAGE_SCHEMA,
                "services": SERVICES_STORAGE_SCHEMA,
                "evidence": EVIDENCE_STORAGE_SCHEMA,
                "parameters": PARAMETERS_STORAGE_SCHEMA,
            },
        )

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
