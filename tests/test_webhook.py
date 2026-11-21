"""Tests for services.webhook (FR-01 GitHub webhook intake)."""
import hashlib
import hmac
import json
import unittest

from services.webhook import handle_webhook_intake, verify_webhook_signature


class WebhookIntakeTests(unittest.TestCase):
    def setUp(self):
        self.secret = "test-webhook-secret-12345"
        self.allowed_repo_id = 999888777

    def _sign(self, body: bytes) -> str:
        digest = hmac.new(self.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def test_valid_webhook_accepted(self):
        payload = {
            "action": "synchronize",
            "repository": {"id": self.allowed_repo_id, "full_name": "org/repo"},
            "pull_request": {
                "number": 42,
                "head": {"sha": "a" * 40},
            },
            "installation": {"id": 12345},
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "X-Hub-Signature-256": self._sign(body),
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-uuid-1",
        }
        status, resp = handle_webhook_intake(
            body, headers, webhook_secret=self.secret, allowed_repository_id=self.allowed_repo_id
        )
        self.assertEqual(status, 202)
        self.assertEqual(resp["status"], "ACCEPTED")
        self.assertEqual(resp["pr_number"], 42)
        self.assertEqual(resp["head_sha"], "a" * 40)

    def test_invalid_signature_rejected(self):
        body = b'{"action":"opened"}'
        headers = {
            "X-Hub-Signature-256": "sha256=invalidhex00000000000000000000000000000000000000000000000000000000",
            "X-GitHub-Event": "pull_request",
        }
        status, resp = handle_webhook_intake(
            body, headers, webhook_secret=self.secret, allowed_repository_id=self.allowed_repo_id
        )
        self.assertEqual(status, 401)
        self.assertEqual(resp["error"], "INVALID_SIGNATURE")

    def test_unauthorized_repository_rejected(self):
        payload = {
            "action": "opened",
            "repository": {"id": 111111111},
            "pull_request": {"number": 1, "head": {"sha": "b" * 40}},
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "X-Hub-Signature-256": self._sign(body),
            "X-GitHub-Event": "pull_request",
        }
        status, resp = handle_webhook_intake(
            body, headers, webhook_secret=self.secret, allowed_repository_id=self.allowed_repo_id
        )
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "UNAUTHORIZED_REPOSITORY")

    def test_unsupported_event_rejected(self):
        body = b'{"ref": "refs/heads/main"}'
        headers = {
            "X-Hub-Signature-256": self._sign(body),
            "X-GitHub-Event": "push",
        }
        status, resp = handle_webhook_intake(
            body, headers, webhook_secret=self.secret, allowed_repository_id=self.allowed_repo_id
        )
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "UNSUPPORTED_EVENT")


if __name__ == "__main__":
    unittest.main()
