from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from penpal.models import Parameter, Service, Target
from penpal.service_modules import build_module_plan, module_matches_services, module_names


class ServiceModuleTests(unittest.TestCase):
    def test_module_registry_contains_initial_modules(self) -> None:
        self.assertEqual(set(module_names()), {"dns", "smb", "snmp", "web"})

    def test_snmp_plan_renders_sources_and_parameters(self) -> None:
        target = Target(name="box", host="10.10.10.5")
        services = [Service(port=161, protocol="udp", name="snmp")]
        params = {"community": Parameter(name="community", value="public")}

        with TemporaryDirectory() as temp_dir:
            plan = build_module_plan("snmp", target, Path(temp_dir), services, params)

        walk = next(command for command in plan if command.id == "snmp-walk")
        self.assertIn("public", walk.args)
        self.assertEqual(walk.service_key, "udp/161")
        self.assertTrue(any(source["source_tier"] in {"official", "internal"} for source in walk.sources))

    def test_sensitive_parameters_are_masked_by_default(self) -> None:
        target = Target(name="box", host="10.10.10.5")
        services = [Service(port=445, protocol="tcp", name="microsoft-ds")]
        params = {
            "known_user": Parameter(name="known_user", value="daniel"),
            "known_password": Parameter(name="known_password", value="Winter2024!", sensitive=True),
        }

        with TemporaryDirectory() as temp_dir:
            masked = build_module_plan("smb", target, Path(temp_dir), services, params)
            revealed = build_module_plan(
                "smb",
                target,
                Path(temp_dir),
                services,
                params,
                reveal_secrets=True,
            )

        masked_auth = next(command for command in masked if command.id == "smb-auth-shares")
        revealed_auth = next(command for command in revealed if command.id == "smb-auth-shares")
        self.assertIn("<known_password>", masked_auth.args)
        self.assertIn("Winter2024!", revealed_auth.args)

    def test_web_module_matches_http_service(self) -> None:
        services = [Service(port=8080, protocol="tcp", name="http")]
        self.assertTrue(module_matches_services("web", services))


if __name__ == "__main__":
    unittest.main()
