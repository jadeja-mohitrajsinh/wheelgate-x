"""Tests for WheelGate X wheel metadata (FR-07) and RECORD (FR-19) verification."""
import base64
import csv
import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from wheelgate.inspector import evaluate, scan_wheel
from tests.fixtures.build_fixtures import build_all, WHEELS


class MetadataAndRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = build_all()
        base = cls.manifest["baseline"]
        cls.baseline = WHEELS / base["filename"]
        cls.baseline_sha = base["sha256"]

    def test_valid_fixture_has_metadata_and_record(self):
        ev = scan_wheel(self.baseline)
        self.assertTrue(ev.wheel_metadata_valid)
        self.assertTrue(ev.record_valid)
        self.assertEqual(ev.metadata_package, "samplepkg")
        self.assertEqual(ev.metadata_version, "1.0.0")
        self.assertGreater(ev.record_entries_count, 0)

    def test_metadata_name_mismatch_fails_hold(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "samplepkg-1.0.95-py3-none-any.whl"
            prefix = "samplepkg-1.0.95.dist-info"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("samplepkg/__init__.py", b"")
                z.writestr(f"{prefix}/WHEEL", b"Wheel-Version: 1.0\n")
                z.writestr(f"{prefix}/METADATA", b"Metadata-Version: 2.1\nName: wrongpkg\nVersion: 1.0.95\n")
                z.writestr(f"{prefix}/RECORD", b"")
            ev = scan_wheel(p)
            self.assertFalse(ev.wheel_metadata_valid)
            r = evaluate(p, self.baseline, expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest(), baseline_sha256=self.baseline_sha)
            self.assertEqual(r["verdict"], "HOLD")
            self.assertIn("IDENTITY_OR_METADATA_UNVERIFIED", r["reason_codes"])

    def test_missing_wheel_metadata_file_holds(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "samplepkg-1.0.96-py3-none-any.whl"
            prefix = "samplepkg-1.0.96.dist-info"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("samplepkg/__init__.py", b"")
                z.writestr(f"{prefix}/METADATA", b"Metadata-Version: 2.1\nName: samplepkg\nVersion: 1.0.96\n")
                z.writestr(f"{prefix}/RECORD", b"")
            ev = scan_wheel(p)
            self.assertFalse(ev.wheel_metadata_valid)
            r = evaluate(p, self.baseline, expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest(), baseline_sha256=self.baseline_sha)
            self.assertEqual(r["verdict"], "HOLD")
            self.assertIn("IDENTITY_OR_METADATA_UNVERIFIED", r["reason_codes"])

    def test_record_digest_tampering_holds(self):
        """FR-19: tampered archive member not matching RECORD digest produces nonpassing result."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "samplepkg-1.0.97-py3-none-any.whl"
            prefix = "samplepkg-1.0.97.dist-info"
            bogus_hash = base64.urlsafe_b64encode(hashlib.sha256(b"original").digest()).rstrip(b"=").decode()
            record_content = f"samplepkg/__init__.py,sha256={bogus_hash},8\n{prefix}/RECORD,,\n"
            with zipfile.ZipFile(p, "w") as z:
                # Tampered content b"tampered" does not match hash of b"original"
                z.writestr("samplepkg/__init__.py", b"tampered")
                z.writestr(f"{prefix}/WHEEL", b"Wheel-Version: 1.0\n")
                z.writestr(f"{prefix}/METADATA", b"Metadata-Version: 2.1\nName: samplepkg\nVersion: 1.0.97\n")
                z.writestr(f"{prefix}/RECORD", record_content.encode())
            ev = scan_wheel(p)
            self.assertFalse(ev.record_valid)
            r = evaluate(p, self.baseline, expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest(), baseline_sha256=self.baseline_sha)
            self.assertEqual(r["verdict"], "HOLD")
            self.assertIn("RECORD_DIGEST_MISMATCH", r["reason_codes"])


if __name__ == "__main__":
    unittest.main()
