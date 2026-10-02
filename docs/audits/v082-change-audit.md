# CSSwitch v0.8.2 change audit

> Audit status: historical change audit based only on the supplied Sol xhigh-reviewed facts. The confirmed transaction and release-gate weaknesses remain `BLOCK`; this file does not claim a build, test, app, provider, database, signing, or live run.

## 1. Scope and baseline

- **Scope:** v0.8.2 source changes, state mutation/identity boundaries, and the release-evidence escape paths identified in the supplied review.
- **Baseline:** `4e0af6ba7909dca22f1257b168172ecbe4af4836`.
- **Change size:** 43 paths, approximately `+3590/-326`.
- **Tag object:** `3e54ed969163392c2e718d1af3c0035f16c757b6`.
- **Peeled tag commit:** merge `0e740814c5cb30d7623757231ced882767f28a53`.
- **Actual source commit:** `b2adc095af3d57ce7daf6ee24906037968dcc4d3`.
- **Outcome:** confirmed BLOCK. The sandbox session can persist OAuth state before SSH preparation fails, and the supplied release gates allow multiple false-green paths.

### Evidence vocabulary

- **confirmed:** directly stated in the supplied facts.
- **inferred:** bounded consequence of a confirmed fact; not an additional execution result.
- **unknown:** not established by the supplied facts.
- **NOT-RUN:** deliberately not executed in this documentation-only pass.

## 2. Release identity and lineage

| Item | Value | Status |
|---|---|---|
| Baseline | `4e0af6ba7909dca22f1257b168172ecbe4af4836` | confirmed |
| Release | `v0.8.2` | confirmed |
| Tag object | `3e54ed969163392c2e718d1af3c0035f16c757b6` | confirmed |
| Peeled commit | merge `0e740814c5cb30d7623757231ced882767f28a53` | confirmed |
| Actual source commit | `b2adc095af3d57ce7daf6ee24906037968dcc4d3` | confirmed |
| Changed paths | 43 | confirmed |
| Approximate diff | `+3590/-326` | confirmed |
| Final artifact identity | Not supplied | unknown / NOT-RUN |
| Installed/live/signing/public state | Not supplied | unknown / NOT-RUN |

The merge commit and the actual source commit are retained as distinct identities. A source result at `b2adc095af3d57ce7daf6ee24906037968dcc4d3` is not automatically a final-app, DMG, installed, live, signing, or public-release result.

## 3. Findings

### P0 — confirmed BLOCKs

#### V082-P0-01 — Sandbox session mutates OAuth state before SSH preparation can fail

- **classification:** confirmed BLOCK; cross-step transaction/rollback gap.
- **subsystem**
  - **introduced_version:** v0.8.2
  - **introducing_commit:** actual source `b2adc095af3d57ce7daf6ee24906037968dcc4d3`; exact feature commit unknown
  - **release_tag:** `v0.8.2` / tag object `3e54ed969163392c2e718d1af3c0035f16c757b6`
  - **affected_paths:** `sandbox_session`, `ensure_virtual_login`, `prepare_science_ssh_bridge`, OAuth persistence, and Science SSH preparation; exact file paths not supplied
  - **intended_behavior:** OAuth, SSH bridge, Skill, and Gateway state changes should be coordinated by one transaction or by explicit compensating recovery, with no committed partial state after a later required step fails
  - **actual_behavior:** `sandbox_session` calls `ensure_virtual_login` before `prepare_science_ssh_bridge`; SSH failure can occur after OAuth has already been written
  - **tests_added:** an SSH E2E path existed in the supplied review context, but it copied the wrong order and only exercised success
  - **tests_missing:** OAuth-success/SSH-failure rollback, retry after partial state, Skill/Gateway compensation, and cross-step transaction invariant tests
  - **artifact_or_runtime_evidence:** source/control-flow fact; no final artifact or live Science evidence supplied
  - **related_user_issue:** partial sandbox login/SSH state after setup failure; issue identifier not supplied
  - **confidence:** high

#### V082-P0-02 — Production identity eligibility can be bypassed by synthetic/default test paths

- **classification:** confirmed BLOCK; release/identity gate is not a reliable production predicate.
- **subsystem**
  - **introduced_version:** v0.8.2
  - **introducing_commit:** `b2adc095af3d57ce7daf6ee24906037968dcc4d3`; exact feature commit unknown
  - **release_tag:** `v0.8.2`
  - **affected_paths:** local identity verification, `codesign -d` parsing, Science production eligibility, synthetic test runner, and ignored real-identity tests
  - **intended_behavior:** production eligibility must fail closed on exact app identity/signing evidence and must not be satisfiable by a synthetic binary or a default-off identity check
  - **actual_behavior:** eligibility depends on exact `codesign -d` stderr `Identifier/Team` text; the default synthetic test uses `verify_local_identity=false`; the real `true` path is ignored; a fake `SCIENCE_BIN` can bypass the production predicate
  - **tests_added:** synthetic identity test path is confirmed; real-identity test exists but is ignored
  - **tests_missing:** non-bypassable production Mach-O regression, real identity positive/negative matrix, fail-closed parser tests, and gate assertion that the tested binary is the release binary
  - **artifact_or_runtime_evidence:** no final Mach-O/signing proof; the concrete candidate's failure point among magic/command/text is unknown
  - **related_user_issue:** Science production eligibility/identity acceptance; issue identifier not supplied
  - **confidence:** high for the gate weakness; unknown for the candidate's exact parser failure point

#### V082-P0-03 — Release evidence can report green while the child test exits nonzero

- **classification:** confirmed false-green BLOCK; cross-release test-system consequence recorded in the v0.8.2 facts.
- **subsystem**
  - **introduced_version:** v0.8.2 evidence/gate state
  - **introducing_commit:** exact gate commit unknown; source context is `b2adc095af3d57ce7daf6ee24906037968dcc4d3`
  - **release_tag:** `v0.8.2`
  - **affected_paths:** `run_all` aggregator, release-ready marker/exit handling, fake Science runner, ignored tests, SSH E2E, OpenCode mock, UI smoke, and post-tag evidence collection
  - **intended_behavior:** a release gate must fail on the real child exit code and must not promote synthetic/mock/ignored/post-tag evidence to release readiness
  - **actual_behavior:** a fake runner emitted pass then exited 7; `run_all` still reported release-ready green and exited 0 because it lost the child return code. Other escape factors were fake `SCIENCE_BIN`, ignored critical tests, wrong-order success-only SSH E2E, local-mock-only OpenCode, insufficient UI smoke, and post-tag evidence
  - **tests_added:** aggregator self-test existed but did not assert the child return code and was not in the gate
  - **tests_missing:** real-return-code assertion, typed result aggregation, no-bypass production predicate, failure-order SSH test, live-vs-local-mock distinction, UI-layer coverage, and tag-time evidence binding
  - **artifact_or_runtime_evidence:** release-ready green plus nonzero-child probe are supplied historical evidence; no new run here
  - **related_user_issue:** false release-ready result; issue identifier not supplied
  - **confidence:** high

### P1 — state consistency and acceptance-scope gaps

#### V082-P1-01 — SSH bridge and local-MCP merges use read→temp rename without CAS

- **classification:** confirmed P1 concurrent-state integrity risk.
- **subsystem**
  - **introduced_version:** v0.8.2
  - **introducing_commit:** `b2adc095af3d57ce7daf6ee24906037968dcc4d3`; exact feature commit unknown
  - **release_tag:** `v0.8.2`
  - **affected_paths:** SSH bridge config merge and local-MCP merge; exact file paths not supplied
  - **intended_behavior:** detect stale reads and reject or reconcile concurrent writers using CAS/version checks before replacing configuration
  - **actual_behavior:** both paths perform read→temporary-file rename without CAS
  - **tests_added:** unknown
  - **tests_missing:** two-writer stale-read race, version conflict, interrupted rename, retry/recovery, and preservation-of-unrelated-fields tests
  - **artifact_or_runtime_evidence:** source/control-flow fact only; no live concurrent-writer run supplied
  - **related_user_issue:** concurrent SSH/local-MCP configuration loss or overwrite; issue identifier not supplied
  - **confidence:** high for missing CAS; runtime frequency unknown

#### V082-P1-02 — Release gate coverage excludes artifact and late-failure layers

- **classification:** confirmed acceptance-scope gap; it makes the P0 paths above promotable unless independently guarded.
- **subsystem**
  - **introduced_version:** v0.8.2 release-gate state
  - **introducing_commit:** exact gate commit unknown
  - **release_tag:** `v0.8.2`
  - **affected_paths:** release-ready aggregation, DMG/artifact checks, Mach-O production predicate, SSH late-failure transaction path, and evidence promotion
  - **intended_behavior:** release readiness must include source tests plus final DMG, Mach-O identity, SSH rollback, and correctly bound evidence layers
  - **actual_behavior:** artifact/DMG was not in the total gate; Mach-O production predicate could be bypassed; SSH late failure had no transaction test
  - **tests_added:** partial source/synthetic coverage is confirmed
  - **tests_missing:** final-DMG contents, Mach-O identity/signing, OAuth→SSH failure order, and multi-layer evidence promotion
  - **artifact_or_runtime_evidence:** only source/test and local-mock evidence were supplied; final artifact/live/signing/public layers are unknown
  - **related_user_issue:** release-ready does not represent the claimed release surface; issue identifier not supplied
  - **confidence:** high

### P2 — explicit unknown/boundary records

#### V082-P2-01 — SQLite production ownership is unknown

- **classification:** confirmed evidence boundary, not a confirmed DB bug.
- **subsystem**
  - **introduced_version:** v0.8.2 audit scope
  - **introducing_commit:** `b2adc095af3d57ce7daf6ee24906037968dcc4d3`; exact DB commit unknown
  - **release_tag:** `v0.8.2`
  - **affected_paths:** SQLite/database ownership and production access boundary; exact paths not supplied
  - **intended_behavior:** identify the authoritative owner, schema, migration boundary, and permitted access path before making DB claims
  - **actual_behavior:** v0.8.2 has no direct SQLite production access; ownership is unknown
  - **tests_added:** unknown
  - **tests_missing:** ownership/authority test, migration/locking contract, and evidence proving which runtime owns the production DB
  - **artifact_or_runtime_evidence:** no direct SQLite production access was observed in the supplied facts; no DB run here
  - **related_user_issue:** database ownership or state-mutation responsibility; issue identifier not supplied
  - **confidence:** high for “no direct access” as supplied; unknown for ownership

#### V082-P2-02 — Skill SHA identity is a record, not proof of usable installed runtime state

- **classification:** confirmed evidence boundary.
- **subsystem**
  - **introduced_version:** v0.8.2 audit scope
  - **introducing_commit:** `b2adc095af3d57ce7daf6ee24906037968dcc4d3`; exact feature commit unknown
  - **release_tag:** `v0.8.2`
  - **affected_paths:** Skill identity/SHA record, installation/attachment, and invocation paths; exact paths not supplied
  - **intended_behavior:** bind a Skill SHA to the installed/attached content and then prove invocation separately
  - **actual_behavior:** Skill SHA identity was recorded; no supplied evidence promotes it to installed, attached, or live invocation proof
  - **tests_added:** unknown
  - **tests_missing:** SHA-to-content, attachment, wrong-SHA rejection, and runtime invocation tests
  - **artifact_or_runtime_evidence:** source/evidence record only; no final/live Skill execution supplied
  - **related_user_issue:** Skill identity versus runtime usability; issue identifier not supplied
  - **confidence:** high for the boundary, unknown for implementation completeness

#### V082-P2-03 — OpenCode pruning and Codex Python/dynamic-catalog behavior need separate proof

- **classification:** confirmed scope/boundary record; no new runtime failure asserted.
- **subsystem**
  - **introduced_version:** v0.8.2 audit scope
  - **introducing_commit:** `b2adc095af3d57ce7daf6ee24906037968dcc4d3`; exact feature commits unknown
  - **release_tag:** `v0.8.2`
  - **affected_paths:** OpenCode route pruning and Codex Python/dynamic catalog paths; exact paths not supplied
  - **intended_behavior:** prune only replaced/obsolete OpenCode routes, preserve live routes, and keep Codex dynamic catalog/runtime behavior bound to the selected release
  - **actual_behavior:** both boundaries were recorded for review; the supplied facts do not establish live OpenCode or packaged Codex behavior
  - **tests_added:** unknown
  - **tests_missing:** stale-route replacement, keep-live-route, live OpenCode, dynamic-directory timeout, and final-artifact runtime-fingerprint tests
  - **artifact_or_runtime_evidence:** source/local-mock boundary only; live and final-artifact evidence not supplied
  - **related_user_issue:** stale OpenCode/Codex dynamic catalog behavior; issue identifier not supplied
  - **confidence:** confirmed scope, unknown runtime outcome

## 4. Confirmed false-green escape paths

The following are retained as separate, confirmed escape factors rather than collapsed into a claim that all provider behavior failed:

1. **Fake `SCIENCE_BIN`:** synthetic binary path bypassed the intended production identity check.
2. **Ignored critical tests:** real identity tests were ignored, so their absence did not prevent green.
3. **SSH E2E ordering:** the E2E copied the wrong operation order and tested success only; it did not exercise OAuth-written/SSH-failed recovery.
4. **OpenCode local mock:** local mock coverage was not live OpenCode proof.
5. **UI smoke level:** the smoke test did not reach the required acceptance layer.
6. **Post-tag evidence:** evidence created after the tag could be read as release closure unless explicitly bound to its later commit.

These are evidence/gate facts. They do not by themselves establish that every real provider or Science path is broken.

## 5. Evidence-layer boundaries

| Layer | Established by this audit | Not established by this audit |
|---|---|---|
| Source/tag | v0.8.2 identity, source commit, transaction order, merge strategy, and gate escape mechanisms | Built app, DMG, installed/live behavior |
| Isolated Test App | Only an explicitly identified isolated run | Final DMG, public asset, real provider/Science state |
| Final DMG | No final-DMG result supplied | Installed/live/signing/public behavior |
| Installed final | No installed-final result supplied | Source correctness or public asset identity |
| Live | No real provider/Science/SSH/DB run supplied | Artifact or tag reproducibility |
| Signing/Mach-O | Predicate shape and bypass risk are known; successful final signing is not | Live compatibility, notarization/Gatekeeper, public equality |
| Public | No public redownload result supplied | Local source/runtime state |

“No direct SQLite production access” is not equivalent to “database ownership is known.” “Skill SHA recorded” is not equivalent to “Skill is attached and invokable.” “OpenCode local mock” is not equivalent to “live OpenCode.”

## 6. Command and exit-code summary

Exact command lines and most exit codes were not supplied. The observations below are therefore marked `UNKNOWN` where the fact packet did not state an exit code. No command was rerun in this pass.

| Command/probe | Purpose | Supplied observation | Exit code | This pass |
|---|---|---|---:|---|
| `sandbox_session` → `ensure_virtual_login` → `prepare_science_ssh_bridge` | Check cross-step mutation order | OAuth can be written before SSH fails | UNKNOWN | NOT-RUN |
| SSH failure-after-OAuth rollback probe | Check transaction recovery | Missing | NOT-APPLICABLE | NOT-RUN |
| SSH bridge config read→temp rename | Check concurrent state update | No CAS | UNKNOWN | NOT-RUN |
| local-MCP merge | Check concurrent state update | Same no-CAS risk | UNKNOWN | NOT-RUN |
| `codesign -d` identity predicate | Check production Mach-O identity | Depends on exact stderr `Identifier/Team` text | UNKNOWN | NOT-RUN |
| Synthetic identity test | Check default test path | `verify_local_identity=false` by default | UNKNOWN | NOT-RUN |
| Real identity test | Check production predicate | `verify_local_identity=true` test is ignored | UNKNOWN | NOT-RUN |
| Fake `SCIENCE_BIN` path | Check bypass resistance | Can bypass production predicate | UNKNOWN | NOT-RUN |
| OpenCode local mock | Check provider behavior | Mock only, not live | UNKNOWN | NOT-RUN |
| Release-ready/evidence closure | Check layer promotion | Green escape factors listed above | UNKNOWN | NOT-RUN |

## 7. Audit conclusion

v0.8.2 cannot be accepted as a release-ready transaction/identity closure from the supplied evidence. The OAuth-before-SSH order creates a confirmed partial-state path with no cross-OAuth/SSH/Skill/Gateway recovery. The production identity predicate and current aggregate can be bypassed by synthetic, ignored, local-mock, wrong-order, insufficient-smoke, and post-tag evidence paths. The next gate must require real child status, typed evidence, fail-closed Mach-O identity, late-failure transaction tests, and explicit source/artifact/installed/live/signing/public separation.
