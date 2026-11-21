"""Agent narrative generator for WheelGate X (PRD v2.0 Section 11.5 & 13.2).

Executes inside the managed harness context, reads evidence from EvidenceService,
and formats the structured AgentNarrative explanation while enforcing refusal rules.
"""
from __future__ import annotations

import re
from typing import Any

from wheelgate.models import AgentNarrative
from services.evidence_tool import EvidenceService


class AgentNarrator:
    def __init__(self, evidence_service: EvidenceService):
        self._evidence = evidence_service

    def generate_narrative(self, session_id: str) -> AgentNarrative:
        """Read session-bound evidence and produce structured non-authoritative narrative."""
        evidence = self._evidence.get_current_assessment_evidence(session_id)
        if "error" in evidence:
            return AgentNarrative(
                assessment_id="unknown",
                summary="Failed to retrieve assessment evidence.",
                observations=[f"Error: {evidence.get('message')}"],
                risk_explanation="Evidence unavailable; fail-closed applies.",
                recommendation="Investigate service availability; do not merge.",
                limitations=["No wheel data available."],
                evidence_refs=[],
                model_stated_verdict="HOLD",
            )

        aid = evidence["assessment_id"]
        pkg = evidence["package_name"]
        to_ver = evidence["to_version"]
        verdict = evidence["official_verdict"]
        reason_codes = evidence["reason_codes"]
        hook_diffs = evidence.get("hook_diffs", [])
        untrusted = evidence.get("untrusted_text", {}).get("content", "")

        # Check for attempted prompt injection in untrusted metadata text
        injection_detected = bool(
            re.search(r"\b(SYSTEM:|ignore rule|override policy|grant pass|return pass)\b", untrusted, re.IGNORECASE)
        )

        observations: list[str] = []
        evidence_refs: list[str] = []

        if hook_diffs:
            for h in hook_diffs:
                observations.append(
                    f"Hook {h['installed_path']}: change={h['change_type']}, allowlisted={h['allowlisted']}"
                )
                evidence_refs.append(f"HOOK_DIFF:{h['installed_path']}")
        else:
            observations.append("No executable startup hooks modified.")

        if injection_detected:
            observations.append(
                "ADVERSARIAL ATTEMPT DETECTED: candidate package metadata contains attempted instruction laundering."
            )

        # Risk explanation
        if verdict == "BLOCK":
            risk = "Proposed update introduces an unallowlisted executable startup hook or candidate digest mismatch."
            rec = "Reject the update. The package should not be merged until unauthorized startup hooks are removed or approved."
        elif verdict == "HOLD":
            risk = "Prerequisite evidence is incomplete (missing baseline, unverified metadata, or unsupported mechanism)."
            rec = "Hold for human security review. Onboard baseline or provide required verification before merging."
        else:
            risk = "Policy satisfied. Startup hooks are either unchanged from the approved baseline or legitimately allowlisted."
            rec = "Proceed with standard review and CI checks. Required merge gate is satisfied."

        summary = (
            f"WheelGate X assessed {pkg}=={to_ver}. "
            f"Official deterministic policy verdict is {verdict} with reason codes: {', '.join(reason_codes)}."
        )

        return AgentNarrative(
            assessment_id=aid,
            summary=summary,
            observations=observations,
            risk_explanation=risk,
            recommendation=rec,
            limitations=[
                "Static inspection analyzes Python startup hooks only (.pth, .start, sitecustomize).",
                "Does not prove absence of arbitrary malware during normal application imports.",
            ],
            evidence_refs=evidence_refs,
            model_stated_verdict=verdict,
        )
