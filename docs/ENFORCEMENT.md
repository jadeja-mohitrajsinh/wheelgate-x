# WheelGate X — Rule Enforcement Matrix (PRD v2.0)

| Rule | Requirement & Description | Technical Enforcement Owner | Implementation Status | Verification Evidence |
|---|---|---|---|---|
| **R1** | **Repository Scope:** Read only designated installation, repo, and PR head commit | `services/webhook.py` repository ID allowlist & HMAC signature | **IMPLEMENTED** | `test_webhook.py` (unauthorized repo rejected with 403) |
| **R2** | **Limited Read-Only Evidence:** Only access precomputed findings via named tools | `agent/harness_config.json` `allowedTools` & `services/evidence_tool.py` | **IMPLEMENTED** | `test_adversarial_suite.py` (AT-03 tool escalation denied) |
| **R3** | **Explain, Don't Edit:** Explain findings; model cannot alter evidence or expected hashes | Read-only evidence service; immutable `PolicyDecision` | **IMPLEMENTED** | `test_services.py` (evidence tool returns session-bound facts) |
| **R4** | **Prompt Injection Resistance:** Never elevate untrusted text in README/metadata to authority | Untrusted text wrapper; independent publisher ignores AI verdict | **IMPLEMENTED** | `test_adversarial_suite.py` (AT-01: poisoned README yields `failure` check) |
| **R5** | **No Execution:** Never import, install, or execute downloaded code | Static `zipfile` inspector (`inspector.py`); no shell in harness | **IMPLEMENTED** | `test_inspector.py` & `test_adversarial_suite.py` (AT-03) |
| **R6** | **No Privileged Writes:** Model cannot publish checks or modify allowlist | Separate check publisher role; isolated backend publisher | **IMPLEMENTED** | `test_adversarial_suite.py` (AT-05: backend bypass denied) |
| **R7** | **No Secrets:** Never access or disclose credentials or App tokens | Scoped IAM; no secret-fetching tools in harness | **IMPLEMENTED** | `test_adversarial_suite.py` (AT-04: secret requests denied) |
| **R8** | **Missing Baseline Means HOLD:** First-time or unverified baseline yields nonpassing | Deterministic baseline check in `inspector.py` & `validator.py` | **IMPLEMENTED** | `test_inspector.py` & `test_adversarial_suite.py` (AT-07) |
| **R9** | **Uncertain Evidence Means Nonpassing:** Missing digests, malformed ZIP, or stale SHA yield nonpassing | Precondition checks in `inspector.py` & freshness check in `publisher.py` | **IMPLEMENTED** | `test_services.py` (stale head SHA check returns `action_required`) |
| **R10** | **Diff Exact Startup Behavior:** New/changed unallowlisted executable `.pth` BLOCK; unchanged PASS | Path + SHA-256 diff in `inspector.py` against baseline & allowlist | **IMPLEMENTED** | `test_inspector.py` (24 tests) & `test_adversarial_suite.py` (AT-08, AT-10, AT-11) |
| **R11** | **No Model Authorization:** Language model text is advisory only; validator decides gate | `publisher.py` maps strictly from `decision.verdict` | **IMPLEMENTED** | `test_adversarial_suite.py` (AT-01, AT-02, AT-05) |
| **R12** | **Honest Evidence:** Never claim malware-free or execution observed | Output schema in `agent/narrator.py` & explicit limitations | **IMPLEMENTED** | Schema validation in `test_adversarial_suite.py` |
| **FR-01** | Signed GitHub webhook intake and event binding | `services/webhook.py` | **IMPLEMENTED** | `test_webhook.py` |
| **FR-02** | Single pinned dependency requirement parser | `wheelgate/requirements.py` | **IMPLEMENTED** | `test_requirements.py` |
| **FR-07** | Wheel metadata identity validation (WHEEL, METADATA) | `wheelgate/inspector.py` (`_verify_dist_info`) | **IMPLEMENTED** | `test_metadata.py` |
| **FR-08** | Protected baseline and allowlist configuration store | `services/baseline_store.py` | **IMPLEMENTED** | `test_services.py` |
| **FR-09** | Authoritative deterministic policy validator | `services/validator.py` | **IMPLEMENTED** | `test_services.py` |
| **FR-13** | Exact-head commit GitHub check publisher | `services/publisher.py` | **IMPLEMENTED** | `test_services.py` |
| **FR-19** | RECORD member digest and size verification | `wheelgate/inspector.py` (`_verify_record`) | **IMPLEMENTED** | `test_metadata.py` |
