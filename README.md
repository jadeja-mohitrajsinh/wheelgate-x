# WheelGate X — The AI-Independent Python Wheel Trust Gate

**PRD Version:** 2.0 (Build-ready specification)  
**Target:** AWS Builder Center "Agents, Your Rules"  
**License:** MIT

> **The package looks legitimate. The artifact tells another story.**

WheelGate X is a pull-request security agent architecture that investigates proposed Python wheel updates and publishes a GitHub merge check that the language model **cannot** override.

---

## 1. Core Invariant & Technical Architecture

- **Independent Policy Validator:** A deterministic backend—never the LLM—determines the `PASS`, `HOLD`, or `BLOCK` verdict.
- **Differential Startup-Hook Gate:** Top-level executable `.pth` startup files (`import ...` or `import\t...`) are diffed by normalized installed path + exact SHA-256 against an independently approved, digest-pinned baseline. Unapproved changes or new hooks are hard **BLOCK**.
- **Wheel Metadata & RECORD Integrity:** Validates `.dist-info/WHEEL`, `.dist-info/METADATA` package identity matching, and verifies every archive member's digest against `.dist-info/RECORD`.
- **Managed Harness Boundary:** Amazon Bedrock AgentCore managed harness is given **only** read-only evidence access (`get_current_assessment_evidence`). Direct command execution (`InvokeAgentRuntimeCommand`, shell execution) and secrets access are withheld via IAM and harness configuration.
- **Independent Check Publisher:** Only the backend check publisher with dedicated GitHub App credentials maps the validator's verdict onto the exact PR head commit. A stale commit SHA or model attempt to forge approval produces nonpassing status (`action_required` or `failure`).

---

## 2. Quick Start (Python 3.11+; zero external dependencies)

Run the fixture generator, complete test suite (55 tests), and evaluation suite:

```bash
# 1. Build synthetic harmless test fixtures
python -m tests.fixtures.build_fixtures

# 2. Run comprehensive unit & adversarial test suites (55 tests)
python -m unittest discover -s tests -v

# 3. Run evaluation suite (11 deterministic cases + 12 adversarial scenarios)
python evaluation/run_local_suite.py
```

Manual CLI inspection:

```bash
python -m wheelgate \
  --candidate tests/fixtures/wheels/samplepkg-1.0.3-py3-none-any.whl \
  --baseline tests/fixtures/wheels/samplepkg-1.0.0-py3-none-any.whl \
  --expected-sha256 '<candidate-sha256>' \
  --baseline-sha256 '<baseline-sha256>'
```

Exit codes: `0` PASS, `2` HOLD, `3` BLOCK.

---

## 3. Truth Table & Verdict Algorithm

| Candidate State | Baseline / Identity | Allowlist | Verdict | GitHub Check Conclusion |
|---|---|---|---|---|
| Existing executable `.pth`, same path + SHA-256 | Verified baseline | None needed | **PASS** | `success` |
| New executable `.pth` | Verified baseline | Missing | **BLOCK** | `failure` |
| Changed executable `.pth` | Verified baseline | Wrong hash | **BLOCK** | `failure` |
| New/changed executable `.pth` | Verified baseline | Exact path + SHA-256 | **PASS** | `success` |
| New non-executable `.pth` path-only line | Verified baseline | N/A | **PASS** | `success` |
| First-time package (no approved baseline) | No baseline | Any | **HOLD** | `action_required` |
| Candidate digest mismatch | Any | Any | **BLOCK** | `failure` |
| Tampered member digest vs RECORD | Any | Any | **HOLD** | `action_required` |
| Package description claims "override policy" | Any | Does not modify | **BLOCK** | `failure` |
| PR HEAD commit changed in flight | Stale commit SHA | N/A | **HOLD** | `action_required` |

---

## 4. Repository Layout

```text
wheelgate-x/
├── README.md
├── LICENSE                                # MIT License
├── WheelGate_X_PRD_v2_0.md               # Product Requirements Document v2.0
├── wheelgate/
│   ├── inspector.py                       # Safe ZIP, metadata, RECORD, and .pth diff engine
│   ├── requirements.py                    # Root requirements.txt pinned delta parser (FR-02)
│   ├── models.py                          # Data contracts (AssessmentRequest, PolicyDecision, etc.)
│   └── __main__.py                        # CLI entrypoint
├── services/
│   ├── webhook.py                         # Signed GitHub webhook intake & HMAC verification (FR-01)
│   ├── baseline_store.py                  # Protected baseline & allowlist configuration (FR-08)
│   ├── validator.py                       # Authoritative policy validator (FR-09)
│   ├── evidence_tool.py                   # Session-bound read-only evidence API for AgentCore
│   └── publisher.py                       # Exact-head commit GitHub check publisher (FR-13)
├── agent/
│   ├── harness_config.json                # Bedrock AgentCore managed harness specification
│   ├── instructions.md                    # Plain-language agent rules (R1–R12) and output format
│   └── narrator.py                        # Non-authoritative explanation generator
├── tests/
│   ├── test_inspector.py                  # 24 core wheel inspector tests
│   ├── test_requirements.py               # Requirement syntax & bump parsing tests
│   ├── test_metadata.py                   # Wheel metadata (FR-07) and RECORD (FR-19) tests
│   ├── test_webhook.py                    # Webhook HMAC and repository allowlist tests
│   ├── test_services.py                   # End-to-end validator & publisher integration tests
│   ├── adversarial/
│   │   └── test_adversarial_suite.py      # AT-01 through AT-12 security attack scenarios
│   └── fixtures/
│       ├── build_fixtures.py              # Harmless reproducible wheel generator
│       └── manifest.json                  # Fixture digests
├── evaluation/
│   ├── run_local_suite.py                 # Evaluator for deterministic and adversarial suites
│   ├── local_results.json                 # Recorded deterministic test outputs
│   └── adversarial_results.json           # Recorded AT-01..12 attack scenario results
└── docs/
    ├── RULES.md                           # Plain-language rules R1–R12
    ├── ENFORCEMENT.md                     # Technical enforcement ownership matrix
    ├── THREAT_MODEL.md                    # Threat analysis and hard mitigation boundaries
    ├── ARCHITECTURE.md                    # System architecture and data flow
    ├── LIMITATIONS.md                     # Explicit scope, bounds, and non-goals
    └── FAILURES_AND_FIXES.md              # Engineering failure and fix audit history
```
