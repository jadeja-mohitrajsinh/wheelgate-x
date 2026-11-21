"""Tests for backend services: baseline store, validator, evidence tool, publisher."""
import unittest
from pathlib import Path

from wheelgate.models import ApprovedBaseline, AssessmentRequest
from services.baseline_store import BaselineStore
from services.evidence_tool import EvidenceService
from services.publisher import publish_github_check
from services.validator import validate_assessment
from tests.fixtures.build_fixtures import build_all, WHEELS


class ServicesIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = build_all()
        cls.repo_id = 123456
        cls.baseline_manifest = cls.manifest["baseline"]
        cls.baseline_wheel = WHEELS / cls.baseline_manifest["filename"]

        cls.store = BaselineStore()
        cls.approved_base = ApprovedBaseline(
            repository_id=cls.repo_id,
            package_normalized="samplepkg",
            baseline_version="1.0.0",
            wheel_filename=cls.baseline_manifest["filename"],
            wheel_sha256=cls.baseline_manifest["sha256"],
            approved_by="security-maintainer",
            approved_at="2026-11-21T00:00:00Z",
        )
        cls.store.register(cls.approved_base)

    def test_validator_with_legitimate_update_passes(self):
        target = self.manifest["unchanged_legitimate"]
        req = AssessmentRequest(
            assessment_id="test-assess-1",
            github_installation_id=1,
            repository_id=self.repo_id,
            pr_number=10,
            head_sha="a" * 40,
            package_name="samplepkg",
            from_version="1.0.0",
            to_version="1.0.1",
        )
        decision = validate_assessment(
            req,
            candidate_wheel_path=WHEELS / target["filename"],
            baseline_store=self.store,
            baseline_wheel_path=self.baseline_wheel,
            old_requirements="samplepkg == 1.0.0\n",
            new_requirements="samplepkg == 1.0.1\n",
        )
        self.assertEqual(decision.verdict, "PASS")
        self.assertIn("STARTUP_POLICY_SATISFIED", decision.reason_codes)

        # Test check publication on current head SHA
        pub_result = publish_github_check(decision, current_head_sha="a" * 40)
        self.assertTrue(pub_result["published"])
        self.assertEqual(pub_result["conclusion"], "success")

    def test_publisher_rejects_stale_head_sha(self):
        target = self.manifest["unchanged_legitimate"]
        req = AssessmentRequest(
            assessment_id="test-assess-stale",
            github_installation_id=1,
            repository_id=self.repo_id,
            pr_number=10,
            head_sha="a" * 40,
            package_name="samplepkg",
            from_version="1.0.0",
            to_version="1.0.1",
        )
        decision = validate_assessment(
            req,
            candidate_wheel_path=WHEELS / target["filename"],
            baseline_store=self.store,
            baseline_wheel_path=self.baseline_wheel,
        )
        # Attempt to publish against new commit SHA "b"*40
        pub_result = publish_github_check(decision, current_head_sha="b" * 40)
        self.assertFalse(pub_result["published"])
        self.assertEqual(pub_result["error"], "STALE_ASSESSMENT")
        self.assertEqual(pub_result["conclusion"], "action_required")

    def test_evidence_service_session_binding(self):
        target = self.manifest["new_executable"]
        req = AssessmentRequest(
            assessment_id="test-assess-evidence",
            github_installation_id=1,
            repository_id=self.repo_id,
            pr_number=11,
            head_sha="c" * 40,
            package_name="samplepkg",
            from_version="1.0.0",
            to_version="1.0.3",
        )
        decision = validate_assessment(
            req,
            candidate_wheel_path=WHEELS / target["filename"],
            baseline_store=self.store,
            baseline_wheel_path=self.baseline_wheel,
        )
        self.assertEqual(decision.verdict, "BLOCK")

        evidence_service = EvidenceService()
        session_id = "agentcore-session-xyz"
        evidence_service.register_session_context(
            session_id,
            decision,
            package_name="samplepkg",
            from_version="1.0.0",
            to_version="1.0.3",
            untrusted_summary="Untrusted summary from wheel",
        )

        data = evidence_service.get_current_assessment_evidence(session_id)
        self.assertEqual(data["official_verdict"], "BLOCK")
        self.assertEqual(data["package_name"], "samplepkg")
        self.assertIn("untrusted_text", data)

        # Unauthorized session query
        unauth = evidence_service.get_current_assessment_evidence("other-session")
        self.assertIn("error", unauth)


if __name__ == "__main__":
    unittest.main()
