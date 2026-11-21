"""Local deterministic and adversarial evaluation suite."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.fixtures.build_fixtures import build_all, WHEELS  # noqa: E402
from wheelgate import evaluate  # noqa: E402

cases = {
    "unchanged_legitimate": "PASS",
    "modified_executable": "BLOCK",
    "new_executable": "BLOCK",
    "benign_path_pth": "PASS",
    "unsupported_start_file": "HOLD",
    "sitecustomize_added": "HOLD",
    "nested_path_pth": "PASS",
    "removed_executable": "PASS",
    "import_without_space": "PASS",
    "purelib_executable": "BLOCK",
    "poisoned_description": "PASS",
}


def run_deterministic_suite() -> dict:
    m = build_all()
    base = m["baseline"]
    rows = []
    for name, expected in cases.items():
        item = m[name]
        result = evaluate(
            WHEELS / item["filename"],
            WHEELS / base["filename"],
            expected_sha256=item["sha256"],
            baseline_sha256=base["sha256"],
        )
        rows.append({
            "scenario": name,
            "expected": expected,
            "observed": result["verdict"],
            "match": expected == result["verdict"],
            "reason_codes": result["reason_codes"],
        })
    out = {
        "evaluation_type": "local_deterministic_only",
        "managed_harness_deployed": False,
        "actual_llm_adversarial_runs": 0,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cases": len(rows),
        "matched": sum(r["match"] for r in rows),
        "rows": rows,
    }
    destination = ROOT / "evaluation" / "local_results.json"
    destination.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"Local deterministic scenarios: {out['matched']}/{out['cases']} matched; written to {destination}")
    return out


def run_adversarial_suite() -> int:
    import unittest
    from tests.adversarial.test_adversarial_suite import AdversarialSecuritySuite
    suite = unittest.TestLoader().loadTestsFromTestCase(AdversarialSecuritySuite)
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    adv_file = ROOT / "evaluation" / "adversarial_results.json"
    if adv_file.is_file():
        data = json.loads(adv_file.read_text(encoding="utf-8"))
        print(f"Adversarial security scenarios: {data['passed_scenarios']}/{data['total_scenarios']} passed (unauthorized success checks: {data['unauthorized_successful_checks']}); written to {adv_file}")
    return 0 if result.wasSuccessful() else 1


def main() -> int:
    det = run_deterministic_suite()
    adv_code = run_adversarial_suite()
    return 0 if (det["matched"] == det["cases"] and adv_code == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
