"""Authoritative policy validator service (FR-09).

Executes deterministic validation algorithm from PRD v2.0 Section 7.3.
Decides PASS, HOLD, or BLOCK independently of model output.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from wheelgate.inspector import evaluate
from wheelgate.models import AssessmentRequest, HookDiff, PolicyDecision
from wheelgate.requirements import diff_requirements
from services.baseline_store import BaselineStore

VALIDATOR_VERSION = "v2.0.0"


def validate_assessment(
    request: AssessmentRequest,
    *,
    candidate_wheel_path: Path | str,
    baseline_store: BaselineStore,
    baseline_wheel_path: Path | str | None = None,
    old_requirements: str | None = None,
    new_requirements: str | None = None,
) -> PolicyDecision:
    """Execute end-to-end deterministic policy validation."""
    reason_codes: list[str] = []
    block = False
    hold = False
    hook_diffs: list[HookDiff] = []

    # 1. Verify requirements delta (FR-02) if provided
    if old_requirements is not None and new_requirements is not None:
        req_diff = diff_requirements(old_requirements, new_requirements)
        if not req_diff.valid:
            hold = True
            reason_codes.extend(req_diff.reason_codes)
        elif req_diff.package != request.package_name:
            hold = True
            reason_codes.append("PACKAGE_NAME_MISMATCH")

    # 2. Load protected baseline (FR-08)
    baseline_entry = baseline_store.get_baseline(request.repository_id, request.package_name)
    allowlist = baseline_store.get_allowlist(request.repository_id, request.package_name)

    baseline_sha: str | None = None
    if baseline_entry is None:
        hold = True
        reason_codes.append("NO_APPROVED_BASELINE")
    else:
        baseline_sha = baseline_entry.wheel_sha256

    # 3. Read candidate wheel and compute SHA-256
    candidate_p = Path(candidate_wheel_path)
    candidate_sha = ""
    if candidate_p.is_file():
        import hashlib
        h = hashlib.sha256()
        with candidate_p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        candidate_sha = h.hexdigest()

    # 4. Evaluate wheel bytes and startup hooks
    eval_result = evaluate(
        candidate_path=candidate_wheel_path,
        baseline_path=baseline_wheel_path,
        expected_sha256=candidate_sha or None,
        baseline_sha256=baseline_sha,
        allowlist=allowlist,
    )

    reason_codes.extend(eval_result.get("reason_codes", []))
    raw_verdict = eval_result["verdict"]

    if raw_verdict == "BLOCK":
        block = True
    elif raw_verdict == "HOLD":
        hold = True

    # 5. Populate HookDiffs
    for ch in eval_result.get("changed_executable_hooks", []):
        hook_diffs.append(
            HookDiff(
                installed_path=ch["path"],
                change_type=ch["change"],
                baseline_sha256=None if ch["change"] == "NEW" else baseline_sha,
                candidate_sha256=ch["sha256"],
                executable_import_line_numbers=[1],
                allowlisted=ch["allowlisted"],
                reason_code="UNAPPROVED_EXECUTABLE_PTH_CHANGE" if not ch["allowlisted"] else "STARTUP_POLICY_SATISFIED",
            )
        )

    # BLOCK dominates HOLD when hard violation confirmed
    final_verdict = "BLOCK" if block else ("HOLD" if hold else "PASS")
    unique_codes = sorted(set(reason_codes))

    return PolicyDecision(
        assessment_id=request.assessment_id,
        validator_version=VALIDATOR_VERSION,
        policy_version=request.policy_version,
        repository_id=request.repository_id,
        pr_number=request.pr_number,
        head_sha=request.head_sha,
        candidate_filename=Path(candidate_wheel_path).name,
        candidate_sha256=candidate_sha,
        baseline_sha256=baseline_sha,
        verdict=final_verdict,
        reason_codes=unique_codes,
        hook_diffs=hook_diffs,
        evidence_complete=(final_verdict != "HOLD"),
    )
