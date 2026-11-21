"""Tests for wheelgate.requirements (FR-02 requirement parser)."""
import unittest

from wheelgate.requirements import (
    diff_requirements,
    normalize_package_name,
    parse_requirements,
)


class RequirementsParserTests(unittest.TestCase):
    def test_normalize_package_name(self):
        self.assertEqual(normalize_package_name("Sample_Pkg.Foo"), "sample-pkg-foo")
        self.assertEqual(normalize_package_name("my_package"), "my-package")

    def test_parse_valid_pinned_lines(self):
        content = """
        # Comment line
        requests == 2.31.0
        urllib3==2.0.7

        # Another comment
        charset_normalizer == 3.3.2
        """
        pkgs, unsupported, warnings = parse_requirements(content)
        self.assertEqual(len(unsupported), 0)
        self.assertEqual(pkgs["requests"], "2.31.0")
        self.assertEqual(pkgs["urllib3"], "2.0.7")
        self.assertEqual(pkgs["charset-normalizer"], "3.3.2")

    def test_parse_unsupported_flags(self):
        for flag in ["-r other.txt", "--requirement base.txt", "-e .", "--editable foo", "-i https://pypi.org/simple"]:
            pkgs, unsupported, _ = parse_requirements(flag)
            self.assertTrue(len(unsupported) > 0, f"Failed to flag {flag}")

    def test_parse_unsupported_operators_and_markers(self):
        for line in ["requests >= 2.0", "requests ~= 2.31", "requests != 2.30", "requests; python_version >= '3.10'"]:
            pkgs, unsupported, _ = parse_requirements(line)
            self.assertTrue(len(unsupported) > 0, f"Failed to flag {line}")

    def test_diff_exact_single_version_bump(self):
        old = "samplepkg == 1.0.0\nurllib3 == 2.0.0\n"
        new = "samplepkg == 1.0.1\nurllib3 == 2.0.0\n"
        diff = diff_requirements(old, new)
        self.assertTrue(diff.valid)
        self.assertEqual(diff.package, "samplepkg")
        self.assertEqual(diff.from_version, "1.0.0")
        self.assertEqual(diff.to_version, "1.0.1")
        self.assertIn("REQUIREMENT_UPDATE_PARSED", diff.reason_codes)

    def test_diff_no_change(self):
        old = "samplepkg == 1.0.0\n"
        new = "samplepkg == 1.0.0\n# comment change\n"
        diff = diff_requirements(old, new)
        self.assertFalse(diff.valid)
        self.assertIn("NO_REQUIREMENT_CHANGED", diff.reason_codes)

    def test_diff_multiple_changes(self):
        old = "pkg-a == 1.0.0\npkg-b == 1.0.0\n"
        new = "pkg-a == 1.0.1\npkg-b == 1.0.1\n"
        diff = diff_requirements(old, new)
        self.assertFalse(diff.valid)
        self.assertIn("MULTIPLE_REQUIREMENTS_CHANGED", diff.reason_codes)

    def test_diff_unsupported_syntax_fails(self):
        old = "samplepkg == 1.0.0\n"
        new = "samplepkg == 1.0.1\n-r base.txt\n"
        diff = diff_requirements(old, new)
        self.assertFalse(diff.valid)
        self.assertIn("UNSUPPORTED_REQUIREMENT_SYNTAX", diff.reason_codes)


if __name__ == "__main__":
    unittest.main()
