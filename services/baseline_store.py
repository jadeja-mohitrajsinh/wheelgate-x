"""Protected baseline store service (FR-08).

Stores independently approved baseline digests and allowlisted startup hooks.
This configuration is isolated and cannot be altered by PR text or language models.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from wheelgate.models import ApprovedBaseline


class BaselineStore:
    def __init__(self, baselines: Mapping[tuple[int, str], ApprovedBaseline] | None = None):
        self._baselines: dict[tuple[int, str], ApprovedBaseline] = dict(baselines or {})

    def register(self, baseline: ApprovedBaseline) -> None:
        key = (baseline.repository_id, baseline.package_normalized)
        self._baselines[key] = baseline

    def get_baseline(self, repository_id: int, package_normalized: str) -> ApprovedBaseline | None:
        return self._baselines.get((repository_id, package_normalized.lower()))

    def get_allowlist(self, repository_id: int, package_normalized: str) -> dict[str, str]:
        base = self.get_baseline(repository_id, package_normalized)
        return dict(base.allowlisted_hooks) if base else {}

    @classmethod
    def from_json_file(cls, path: str | Path) -> BaselineStore:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        store = cls()
        for item in data:
            baseline = ApprovedBaseline(
                repository_id=item["repository_id"],
                package_normalized=item["package_normalized"],
                baseline_version=item["baseline_version"],
                wheel_filename=item["wheel_filename"],
                wheel_sha256=item["wheel_sha256"],
                approved_by=item["approved_by"],
                approved_at=item["approved_at"],
                policy_version=item.get("policy_version", "startup-v1"),
                allowlisted_hooks=item.get("allowlisted_hooks", {}),
            )
            store.register(baseline)
        return store
