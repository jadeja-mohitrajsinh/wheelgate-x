# WheelGate X — Scope, Assumptions & Limitations

## 1. Scope Contract

WheelGate X is engineered specifically as a **differential startup-hook trust gate for single pinned Python dependency updates**.

### In Scope:
- Pull requests modifying a single dependency line in root `requirements.txt` from `name==old` to `name==new`.
- Python wheels (`.whl`) matching standard distribution filename conventions.
- Inspection of top-level installation startup hooks: `.pth` files in wheel root or `.data/{purelib,platlib}` mapped to `site-packages`.
- Detection of other startup hooks: `sitecustomize.py`, `usercustomize.py`, `.start` files.
- Cryptographic verification of candidate and approved baseline wheel digests.
- Wheel metadata verification (`.dist-info/WHEEL`, `METADATA`, `RECORD`).
- Independent publishing of GitHub Merge Checks via an isolated backend.

## 2. Technical Limitations & Non-Goals

### 2.1 Not a Malware Classifier
- Passing the WheelGate X policy does **not** certify that a Python wheel is free of malicious code.
- Static inspection analyzes Python startup hooks; it does not detect arbitrary malicious payloads executing during regular application imports (e.g., inside `package/__init__.py` or submodules).

### 2.2 Does Not Block Un-gated CI Jobs
- A passing or failing GitHub check serves as a required branch protection merge boundary.
- It does **not** prevent unrelated CI workflow steps or developer workstations from executing `pip install` directly if repository branch protections or workflow gates are misconfigured.

### 2.3 Single Direct Dependency Focus
- Transitive dependencies (dependencies of dependencies) are outside the MVP contract.
- Complex requirement formats (VCS URLs, direct archive links, environment markers, constraint files, `-r includes`) fail closed with `HOLD` (`UNSUPPORTED_REQUIREMENT_SYNTAX`).

### 2.4 Baseline Precondition
- First-time dependencies without an independently approved baseline cannot pass automatically. They yield `HOLD` (`NO_APPROVED_BASELINE`) until human security reviewers approve an initial baseline digest.

### 2.5 Archive Inspection Bounds
- Wheel archive inspection applies engineering bounds:
  - Max compressed wheel: 40 MiB
  - Max uncompressed size: 100 MiB
  - Max archive entries: 3,000
  - Max single entry size: 10 MiB
  - Max startup hook size: 256 KiB
- Archives exceeding these limits fail closed with `HOLD`.
