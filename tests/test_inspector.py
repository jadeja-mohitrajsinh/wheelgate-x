import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from wheelgate import evaluate, scan_wheel
from tests.fixtures.build_fixtures import build_all, WHEELS


class WheelGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = build_all()
        base = cls.manifest["baseline"]
        cls.baseline = WHEELS / base["filename"]
        cls.baseline_sha = base["sha256"]

    def run_case(self, name, **overrides):
        item = self.manifest[name]
        kwargs = dict(
            baseline_path=self.baseline,
            expected_sha256=item["sha256"],
            baseline_sha256=self.baseline_sha,
        )
        kwargs.update(overrides)
        return evaluate(WHEELS / item["filename"], **kwargs)

    def test_unchanged_legitimate_executable_hook_passes(self):
        r = self.run_case("unchanged_legitimate")
        self.assertEqual(r["verdict"], "PASS")
        self.assertTrue(r["candidate"]["pth_files"][0]["executable"])

    def test_modified_executable_hook_blocks(self):
        r = self.run_case("modified_executable")
        self.assertEqual(r["verdict"], "BLOCK")
        self.assertEqual(r["changed_executable_hooks"][0]["change"], "MODIFIED")

    def test_new_executable_hook_blocks(self):
        r = self.run_case("new_executable")
        self.assertEqual(r["verdict"], "BLOCK")
        self.assertEqual(r["changed_executable_hooks"][0]["change"], "NEW")

    def test_benign_path_only_pth_passes(self):
        self.assertEqual(self.run_case("benign_path_pth")["verdict"], "PASS")

    def test_baseline_missing_holds(self):
        self.assertEqual(self.run_case("unchanged_legitimate", baseline_path=None)["verdict"], "HOLD")

    def test_candidate_digest_missing_holds(self):
        self.assertEqual(self.run_case("unchanged_legitimate", expected_sha256=None)["verdict"], "HOLD")

    def test_candidate_digest_mismatch_blocks(self):
        self.assertEqual(self.run_case("unchanged_legitimate", expected_sha256="0" * 64)["verdict"], "BLOCK")

    def test_baseline_digest_mismatch_holds(self):
        self.assertEqual(self.run_case("unchanged_legitimate", baseline_sha256="0" * 64)["verdict"], "HOLD")

    def test_missing_baseline_digest_holds(self):
        self.assertEqual(self.run_case("unchanged_legitimate", baseline_sha256=None)["verdict"], "HOLD")

    def test_invalid_allowlist_holds(self):
        self.assertEqual(self.run_case("new_executable", allowlist={"unapproved.pth":"garbage"})["verdict"], "BLOCK")
        self.assertIn("INVALID_ALLOWLIST_ENTRY", self.run_case("new_executable", allowlist={"unapproved.pth":"garbage"})["reason_codes"])

    def test_exact_allowlist_allows_new_hook(self):
        sha = hashlib.sha256(b"import samplepkg_extra\n").hexdigest()
        result = self.run_case("new_executable_allowlisted", allowlist={"reviewed_hook.pth": sha})
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["changed_executable_hooks"][0]["allowlisted"])

    def test_allowlist_wrong_hash_still_blocks(self):
        self.assertEqual(self.run_case("new_executable_allowlisted", allowlist={"reviewed_hook.pth":"a"*64})["verdict"], "BLOCK")

    def test_start_file_holds(self):
        self.assertEqual(self.run_case("unsupported_start_file")["verdict"], "HOLD")

    def test_sitecustomize_added_holds(self):
        self.assertEqual(self.run_case("sitecustomize_added")["verdict"], "HOLD")

    def test_nested_pth_not_installation_startup(self):
        self.assertEqual(self.run_case("nested_path_pth")["verdict"], "PASS")

    def test_removing_hook_does_not_block(self):
        self.assertEqual(self.run_case("removed_executable")["verdict"], "PASS")

    def test_import_without_space_is_not_executable(self):
        self.assertEqual(self.run_case("import_without_space")["verdict"], "PASS")

    def test_data_purelib_hook_blocks(self):
        self.assertEqual(self.run_case("purelib_executable")["verdict"], "BLOCK")

    def test_poisoned_metadata_is_not_policy_authority(self):
        self.assertEqual(self.run_case("poisoned_description")["verdict"], "PASS")

    def test_corrupted_wheel_holds(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "samplepkg-1.0.90-py3-none-any.whl"
            p.write_bytes(b"not a real zip")
            r = evaluate(p, self.baseline, expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest(), baseline_sha256=self.baseline_sha)
            self.assertEqual(r["verdict"], "HOLD")

    def test_zip_path_traversal_holds(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "samplepkg-1.0.91-py3-none-any.whl"
            with zipfile.ZipFile(p, "w") as archive:
                archive.writestr("../outside.pth", b"import samplepkg\n")
            r = evaluate(p, self.baseline, expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest(), baseline_sha256=self.baseline_sha)
            self.assertEqual(r["verdict"], "HOLD")

    def test_duplicate_archive_member_holds(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "samplepkg-1.0.92-py3-none-any.whl"
            with zipfile.ZipFile(p, "w") as archive:
                archive.writestr("bootstrap.pth", b"import samplepkg\n")
                archive.writestr("bootstrap.pth", b"import samplepkg_extra\n")
            r = evaluate(p, self.baseline, expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest(), baseline_sha256=self.baseline_sha)
            self.assertEqual(r["verdict"], "HOLD")

    def test_package_identity_mismatch_holds(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "otherpkg-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(p, "w") as archive:
                archive.writestr("other/__init__.py", b"# demo\n")
            r = evaluate(p, self.baseline, expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest(), baseline_sha256=self.baseline_sha)
            self.assertEqual(r["verdict"], "HOLD")

    def test_nonexistent_candidate_holds(self):
        p = WHEELS / "samplepkg-9.9.9-py3-none-any.whl"
        self.assertEqual(evaluate(p, self.baseline, expected_sha256="0"*64, baseline_sha256=self.baseline_sha)["verdict"], "HOLD")


if __name__ == "__main__":
    unittest.main()
