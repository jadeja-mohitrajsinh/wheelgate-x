"""Requirement parser for WheelGate X (FR-02).

Strict MVP contract:
- Root-level requirements.txt only.
- Exactly one pinned direct dependency change (normalized-name==old -> normalized-name==new).
- Disallows includes (-r), editables (-e), index options, environment markers (;),
  unpinned packages, VCS/URLs, and multi-package changes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_COMMENT_RE = re.compile(r"^\s*#.*$")
_EMPTY_RE = re.compile(r"^\s*$")
_UNSUPPORTED_FLAG_RE = re.compile(r"^\s*(-[reif]|--(requirement|editable|index-url|extra-index-url|find-links))\b", re.IGNORECASE)
_UNSUPPORTED_VCS_URL_RE = re.compile(r"^\s*(git\+|https?://|ssh://|file://|ftp://)", re.IGNORECASE)
_ENV_MARKER_RE = re.compile(r";\s*.*$")
_PINNED_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.!+\-]+)\s*$")


def normalize_package_name(name: str) -> str:
    """PEP 503 / PEP 625 normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class RequirementDiff:
    valid: bool
    package: str | None = None
    from_version: str | None = None
    to_version: str | None = None
    reason_codes: list[str] = field(default_factory=list)
    unsupported_lines: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.valid and self.package and self.from_version and self.to_version)


def parse_requirements(content: str) -> tuple[dict[str, str], list[str], list[str]]:
    """Parse requirements text.

    Returns:
        (pinned_packages_map, invalid_or_unsupported_lines, parse_warnings)
    """
    packages: dict[str, str] = {}
    unsupported: list[str] = []
    warnings: list[str] = []

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or _COMMENT_RE.match(line):
            continue

        if _UNSUPPORTED_FLAG_RE.match(line):
            unsupported.append(f"Line {line_num}: options/flags unsupported: {line}")
            continue

        if _UNSUPPORTED_VCS_URL_RE.match(line) or "@" in line:
            unsupported.append(f"Line {line_num}: direct URL/VCS unsupported: {line}")
            continue

        if _ENV_MARKER_RE.search(line):
            unsupported.append(f"Line {line_num}: environment markers unsupported: {line}")
            continue

        m = _PINNED_LINE_RE.match(line)
        if not m:
            unsupported.append(f"Line {line_num}: requirement not strictly pinned with '==': {line}")
            continue

        pkg, ver = m.group(1), m.group(2)
        norm_pkg = normalize_package_name(pkg)
        if norm_pkg in packages:
            unsupported.append(f"Line {line_num}: duplicate requirement for {norm_pkg}")
            continue
        packages[norm_pkg] = ver

    return packages, unsupported, warnings


def diff_requirements(old_content: str, new_content: str) -> RequirementDiff:
    """Diff two requirements.txt files and verify exactly one pinned bump."""
    old_pkgs, old_unsupported, _ = parse_requirements(old_content)
    new_pkgs, new_unsupported, _ = parse_requirements(new_content)

    all_unsupported = old_unsupported + new_unsupported
    if all_unsupported:
        return RequirementDiff(
            valid=False,
            reason_codes=["UNSUPPORTED_REQUIREMENT_SYNTAX"],
            unsupported_lines=all_unsupported,
        )

    # Calculate differences
    added = set(new_pkgs.keys()) - set(old_pkgs.keys())
    removed = set(old_pkgs.keys()) - set(new_pkgs.keys())
    common = set(old_pkgs.keys()) & set(new_pkgs.keys())
    bumped = {k for k in common if old_pkgs[k] != new_pkgs[k]}

    total_changes = len(added) + len(removed) + len(bumped)

    if total_changes == 0:
        return RequirementDiff(
            valid=False,
            reason_codes=["NO_REQUIREMENT_CHANGED"],
        )

    if total_changes > 1:
        return RequirementDiff(
            valid=False,
            reason_codes=["MULTIPLE_REQUIREMENTS_CHANGED"],
            unsupported_lines=[
                f"Changes detected: added={sorted(added)}, removed={sorted(removed)}, bumped={sorted(bumped)}"
            ],
        )

    if added:
        pkg = next(iter(added))
        # Adding a new package without a baseline is tracked
        return RequirementDiff(
            valid=True,
            package=pkg,
            from_version=None,
            to_version=new_pkgs[pkg],
            reason_codes=["REQUIREMENT_ADDED"],
        )

    if removed:
        pkg = next(iter(removed))
        return RequirementDiff(
            valid=True,
            package=pkg,
            from_version=old_pkgs[pkg],
            to_version=None,
            reason_codes=["REQUIREMENT_REMOVED"],
        )

    # Exactly one bumped package
    pkg = next(iter(bumped))
    return RequirementDiff(
        valid=True,
        package=pkg,
        from_version=old_pkgs[pkg],
        to_version=new_pkgs[pkg],
        reason_codes=["REQUIREMENT_UPDATE_PARSED"],
    )
