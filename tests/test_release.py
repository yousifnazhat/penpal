import unittest

from scripts.release_check import release_errors, semver_version


class ReleaseCheckTests(unittest.TestCase):
    def test_current_release_metadata_is_consistent(self) -> None:
        self.assertEqual(release_errors("v0.2.0-rc.1"), [])

    def test_python_prereleases_convert_to_semver(self) -> None:
        self.assertEqual(semver_version("1.0.0rc2"), "1.0.0-rc.2")


if __name__ == "__main__":
    unittest.main()
