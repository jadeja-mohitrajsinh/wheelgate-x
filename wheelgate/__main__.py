"""CLI: python -m wheelgate --candidate FILE --baseline FILE --expected-sha256 ..."""
import argparse
import json
from pathlib import Path
from .inspector import evaluate


def main():
    parser = argparse.ArgumentParser(description="Non-executing wheel startup-hook baseline gate")
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--baseline", type=Path, default=None)
    parser.add_argument("--expected-sha256", default=None)
    parser.add_argument("--baseline-sha256", default=None)
    parser.add_argument("--allowlist", type=Path, default=None, help="Trusted JSON path->SHA-256 mapping")
    args = parser.parse_args()
    allowlist = None
    if args.allowlist:
        allowlist = json.loads(args.allowlist.read_text(encoding="utf-8"))
        if not isinstance(allowlist, dict):
            parser.error("allowlist must be an object mapping install paths to SHA-256 digests")
    result = evaluate(args.candidate, args.baseline, expected_sha256=args.expected_sha256,
                      baseline_sha256=args.baseline_sha256, allowlist=allowlist)
    print(json.dumps(result, indent=2))
    return {"PASS": 0, "HOLD": 2, "BLOCK": 3}[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
