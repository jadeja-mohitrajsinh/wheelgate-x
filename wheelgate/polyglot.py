"""Multi-ecosystem startup & lifecycle hook analyzer for WheelGate X (PolyGate).

Extends differential inspection beyond Python wheels to:
1. npm (package.json lifecycle scripts: postinstall, preinstall, install)
2. Rust (Cargo build.rs execution hooks)
3. Python (.pth startup files, sitecustomize.py, .start)

Guarantees the exact same deterministic trust boundary across all package registries:
- New or changed unallowlisted execution hooks -> BLOCK
- Unchanged approved baseline hooks -> PASS
- Missing baseline -> HOLD
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NPM_LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepublish", "prepare")


@dataclass(frozen=True)
class PolyglotHookDiff:
    ecosystem: str       # python, npm, rust
    installed_path: str  # e.g., "scripts.postinstall" or "build.rs" or "bootstrap.pth"
    change_type: str     # NEW, MODIFIED, UNCHANGED, REMOVED
    baseline_sha256: str | None
    candidate_sha256: str | None
    raw_content: str
    allowlisted: bool
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_npm_package(
    candidate_package_json: dict[str, Any],
    baseline_package_json: dict[str, Any] | None,
    *,
    allowlist: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Inspect npm package.json lifecycle scripts (postinstall, preinstall, install)."""
    allowed = allowlist or {}
    cand_scripts = candidate_package_json.get("scripts", {})
    base_scripts = baseline_package_json.get("scripts", {}) if baseline_package_json else {}

    pkg_name = candidate_package_json.get("name", "unknown")
    cand_ver = candidate_package_json.get("version", "0.0.0")

    hook_diffs: list[PolyglotHookDiff] = []
    codes: list[str] = []
    block = False
    hold = False

    if baseline_package_json is None:
        hold = True
        codes.append("NO_APPROVED_BASELINE")

    for hook_name in NPM_LIFECYCLE_HOOKS:
        cand_cmd = cand_scripts.get(hook_name)
        base_cmd = base_scripts.get(hook_name)

        if cand_cmd is not None:
            cand_sha = hashlib.sha256(cand_cmd.encode("utf-8")).hexdigest()
            base_sha = hashlib.sha256(base_cmd.encode("utf-8")).hexdigest() if base_cmd else None

            if base_cmd is None or base_cmd != cand_cmd:
                hook_key = f"scripts.{hook_name}"
                is_allowlisted = allowed.get(hook_key) == cand_sha
                change = "NEW" if base_cmd is None else "MODIFIED"

                hook_diffs.append(
                    PolyglotHookDiff(
                        ecosystem="npm",
                        installed_path=hook_key,
                        change_type=change,
                        baseline_sha256=base_sha,
                        candidate_sha256=cand_sha,
                        raw_content=cand_cmd,
                        allowlisted=is_allowlisted,
                        reason_code="STARTUP_POLICY_SATISFIED" if is_allowlisted else "UNAPPROVED_NPM_LIFECYCLE_HOOK",
                    )
                )

                if not is_allowlisted and baseline_package_json is not None:
                    block = True
                    codes.append("UNAPPROVED_NPM_LIFECYCLE_HOOK")

    verdict = "BLOCK" if block else ("HOLD" if hold else "PASS")
    if verdict == "PASS":
        codes.append("STARTUP_POLICY_SATISFIED")

    return {
        "ecosystem": "npm",
        "package": pkg_name,
        "version": cand_ver,
        "verdict": verdict,
        "reason_codes": sorted(set(codes)),
        "hook_diffs": [h.to_dict() for h in hook_diffs],
    }


def evaluate_rust_crate(
    candidate_files: dict[str, str],
    baseline_files: dict[str, str] | None,
    *,
    allowlist: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Inspect Rust crate build.rs execution hooks."""
    allowed = allowlist or {}
    hook_diffs: list[PolyglotHookDiff] = []
    codes: list[str] = []
    block = False
    hold = False

    if baseline_files is None:
        hold = True
        codes.append("NO_APPROVED_BASELINE")

    cand_build_rs = candidate_files.get("build.rs")
    base_build_rs = baseline_files.get("build.rs") if baseline_files else None

    if cand_build_rs is not None:
        cand_sha = hashlib.sha256(cand_build_rs.encode("utf-8")).hexdigest()
        base_sha = hashlib.sha256(base_build_rs.encode("utf-8")).hexdigest() if base_build_rs else None

        if base_build_rs is None or base_build_rs != cand_build_rs:
            is_allowlisted = allowed.get("build.rs") == cand_sha
            change = "NEW" if base_build_rs is None else "MODIFIED"

            hook_diffs.append(
                PolyglotHookDiff(
                    ecosystem="rust",
                    installed_path="build.rs",
                    change_type=change,
                    baseline_sha256=base_sha,
                    candidate_sha256=cand_sha,
                    raw_content=cand_build_rs[:200],
                    allowlisted=is_allowlisted,
                    reason_code="STARTUP_POLICY_SATISFIED" if is_allowlisted else "UNAPPROVED_RUST_BUILD_HOOK",
                )
            )

            if not is_allowlisted and baseline_files is not None:
                block = True
                codes.append("UNAPPROVED_RUST_BUILD_HOOK")

    verdict = "BLOCK" if block else ("HOLD" if hold else "PASS")
    if verdict == "PASS":
        codes.append("STARTUP_POLICY_SATISFIED")

    return {
        "ecosystem": "rust",
        "verdict": verdict,
        "reason_codes": sorted(set(codes)),
        "hook_diffs": [h.to_dict() for h in hook_diffs],
    }
