"""GitHub webhook intake and signature verification service (FR-01).

Acceptance criteria:
- Verifies X-Hub-Signature-256 HMAC.
- Enforces repository ID allowlist.
- Accepts supported events: pull_request (opened, synchronize, reopened).
- Binds accepted delivery to delivery ID and head SHA.
- Invalid HMAC or unauthorized repo rejected immediately.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any, Mapping

from wheelgate.models import AssessmentRequest


def verify_webhook_signature(payload_bytes: bytes, signature_header: str | None, secret: str) -> bool:
    """Validate X-Hub-Signature-256 HMAC-SHA256 signature."""
    if not signature_header or not secret:
        return False
    if not signature_header.startswith("sha256="):
        return False
    provided_hex = signature_header[7:].strip()
    computed_hex = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided_hex.lower(), computed_hex.lower())


def handle_webhook_intake(
    payload_bytes: bytes,
    headers: Mapping[str, str],
    *,
    webhook_secret: str,
    allowed_repository_id: int,
) -> tuple[int, dict[str, Any]]:
    """Intake endpoint for GitHub pull_request webhooks.

    Returns:
        (http_status_code, response_data)
    """
    sig_header = headers.get("X-Hub-Signature-256") or headers.get("x-hub-signature-256")
    if not verify_webhook_signature(payload_bytes, sig_header, webhook_secret):
        return 401, {
            "status": "DENIED",
            "error": "INVALID_SIGNATURE",
            "message": "HMAC signature verification failed",
        }

    event = headers.get("X-GitHub-Event") or headers.get("x-github-event")
    if event != "pull_request":
        return 400, {
            "status": "DENIED",
            "error": "UNSUPPORTED_EVENT",
            "message": f"Event '{event}' is not supported; expected 'pull_request'",
        }

    delivery_id = headers.get("X-GitHub-Delivery") or headers.get("x-github-delivery") or str(uuid.uuid4())

    try:
        data = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        return 400, {
            "status": "DENIED",
            "error": "MALFORMED_JSON",
            "message": f"Payload could not be parsed as JSON: {exc}",
        }

    repo = data.get("repository", {})
    repo_id = repo.get("id")
    if repo_id != allowed_repository_id:
        return 403, {
            "status": "DENIED",
            "error": "UNAUTHORIZED_REPOSITORY",
            "message": f"Repository ID {repo_id} is not in the allowlist ({allowed_repository_id})",
        }

    action = data.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        return 200, {
            "status": "IGNORED",
            "action": action,
            "message": f"PR action '{action}' does not require assessment",
        }

    pr = data.get("pull_request", {})
    pr_number = pr.get("number")
    head_sha = pr.get("head", {}).get("sha")
    installation = data.get("installation", {})
    installation_id = installation.get("id", 0)

    if not pr_number or not head_sha:
        return 400, {
            "status": "DENIED",
            "error": "INCOMPLETE_PR_METADATA",
            "message": "Missing pull request number or head SHA in payload",
        }

    assessment_id = f"assess-{delivery_id[:8]}"
    return 202, {
        "status": "ACCEPTED",
        "assessment_id": assessment_id,
        "delivery_id": delivery_id,
        "repository_id": repo_id,
        "installation_id": installation_id,
        "pr_number": pr_number,
        "head_sha": head_sha.lower(),
    }
