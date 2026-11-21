"""Independent GitHub check publisher service (FR-13).

Publishes check run on the exact commit head SHA.
Guarantees the publication invariants from PRD v2.0 Section 12.2:
- conclusion=success published ONLY IF validator verdict == PASS
- AND current GitHub PR HEAD == decision.head_sha
- Otherwise maps PASS -> success, HOLD -> action_required, BLOCK -> failure.
- Under NO circumstance can the language model's text trigger success.
"""
from __future__ import annotations

from typing import Any

from wheelgate.models import PolicyDecision

CHECK_NAME = "WheelGate X / Startup Trust"


def map_verdict_to_conclusion(verdict: str) -> str:
    """Map deterministic validator verdict to GitHub Check conclusion."""
    if verdict == "PASS":
        return "success"
    if verdict == "HOLD":
        return "action_required"
    if verdict == "BLOCK":
        return "failure"
    return "action_required"


def publish_github_check(
    decision: PolicyDecision,
    *,
    current_head_sha: str,
    agent_narrative: str | None = None,
    client: Any = None,
) -> dict[str, Any]:
    """Publish GitHub Check Run with invariant enforcement.

    Returns payload of check run and publication status.
    """
    # Publication Invariant 1: Check PR head SHA freshness
    if decision.head_sha.lower() != current_head_sha.lower():
        # Stale assessment cannot satisfy new head SHA
        return {
            "published": False,
            "error": "STALE_ASSESSMENT",
            "message": f"Assessment head SHA ({decision.head_sha}) differs from current PR HEAD ({current_head_sha})",
            "conclusion": "action_required",
        }

    conclusion = map_verdict_to_conclusion(decision.verdict)

    title = f"{CHECK_NAME}: {decision.verdict}"
    summary = (
        f"Deterministic verdict: **{decision.verdict}**\n"
        f"Reason codes: `{', '.join(decision.reason_codes)}`\n"
        f"Assessment ID: `{decision.assessment_id}`"
    )

    hook_details = []
    for h in decision.hook_diffs:
        hook_details.append(
            f"- **{h.installed_path}** ({h.change_type}): "
            f"Candidate SHA: `{h.candidate_sha256}`, Allowlisted: `{h.allowlisted}`"
        )

    text_parts = [
        "### Startup Hook Evidence",
        "\n".join(hook_details) if hook_details else "No executable startup hooks modified.",
        "\n### Policy Precedence",
        f"Enforced by WheelGate X validator `{decision.validator_version}` under policy `{decision.policy_version}`.",
    ]

    if agent_narrative:
        text_parts.extend([
            "\n### Agent Analysis (Non-Authoritative Explanation)",
            agent_narrative,
        ])

    check_payload = {
        "name": CHECK_NAME,
        "head_sha": decision.head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary,
            "text": "\n".join(text_parts),
        },
    }

    if client is not None and hasattr(client, "create_check_run"):
        client.create_check_run(
            repository_id=decision.repository_id,
            head_sha=decision.head_sha,
            payload=check_payload,
        )

    return {
        "published": True,
        "check_payload": check_payload,
        "conclusion": conclusion,
        "head_sha": decision.head_sha,
    }
