# CSSwitch v0.8.3 test-system audit

> Audit status: `BLOCK`. This is a test-system and evidence-gate audit, not a claim that v0.8.3 was built, installed, run, signed, published, or network-validated in this task.
>
> The probe outcomes below are the supplied historical v0.8.2/v0.8.3 audit facts. They are recorded for traceability and were not rerun while writing this document.

## 1. Scope and baseline

- **Scope:** v0.8.3 test entrypoints, aggregation, retry semantics, ignored/orphan coverage, artifact/identity/SSH regressions, and multi-layer release evidence.
- **Baseline:** `4e0af6ba7909dca22f1257b168172ecbe4af4836`.
- **Target release:** v0.8.3.
- **Historical evidence in scope:** v0.8.2 test-system outcomes, including release-ready green with seven ignored tests.
- **Review input:** supplied facts only; no complete Git review and no new test execution.
- **Decision:** BLOCK. The current gate can produce a release-ready green result while a child exits nonzero, while an arbitrary replacement test command is retried, or while required evidence layers/tests are absent.

### Evidence vocabulary

- **confirmed:** directly stated in the supplied facts.
- **inferred:** bounded consequence of a confirmed fact; not an additional execution result.
- **unknown:** not established by the supplied facts.
- **NOT-RUN:** deliberately not executed in this documentation-only pass.

## 2. Release identity and lineage

| Item | Value | Status |
|---|---|---|
| Baseline | `4e0af6ba7909dca22f1257b168172ecbe4af4836` | confirmed scope baseline |
| Target | `v0.8.3` | confirmed task scope |
| v0.8.3 tag object | Not supplied | unknown / NOT-RUN |
| v0.8.3 peeled/source commit | Not supplied | unknown / NOT-RUN |
| Historical gate evidence | v0.8.2, including seven ignored tests and release-ready green | confirmed supplied fact |
| Final DMG/app/installed/live/signing/public identity | Not supplied | unknown / NOT-RUN |

The v0.8.2 historical result is not silently promoted to v0.8.3 release truth. Source tests, an isolated Test App, a final DMG, an installed final app, live runtime, signing, and public redownload remain distinct evidence layers.

## 3. Findings

### P0 — release gate can be falsely green

#### TEST-P0-01 — `run_all` drops a nonzero child exit code after a pass marker

- **classification:** confirmed P0 false-green gate failure; `BLOCK`.
- **subsystem**
  - **introduced_version:** observed in the supplied v0.8.2 test-system evidence; target v0.8.3 status requires a fresh rerun
  - **introducing_commit:** unknown
  - **release_tag:** historical v0.8.2 evidence; v0.8.3 tag identity unknown
  - **affected_paths:** `run_all` aggregator, offline fake runner, pass marker/result handling, and `test_run_all_aggregator.sh`
  - **intended_behavior:** aggregate the actual child process return code and typed result; a nonzero child must prevent release readiness
  - **actual_behavior:** the offline fake runner printed pass and then exited 7; `run_all` still reported release-ready green and exited 0 because the pipeline lost the child return code
  - **tests_added:** aggregator self-test existed, but it did not assert the child return code and was not in the gate
  - **tests_missing:** real-child-RC regression, marker/RC contradiction regression, malformed/missing-result regression, and gate membership assertion
  - **artifact_or_runtime_evidence:** supplied offline probe result only; no v0.8.3 source/artifact/live result was run here
  - **related_user_issue:** false release-ready signal; issue identifier not supplied
  - **confidence:** high for the supplied historical behavior; current v0.8.3 state is unknown

#### TEST-P0-02 — Loopback retry and `CSSWITCH_LOOPBACK_TEST_CMD` permit failure hiding

- **classification:** confirmed P0 gate-bypass risk; `BLOCK`.
- **subsystem**
  - **introduced_version:** observed in the supplied v0.8.2/v0.8.3 test-system evidence
  - **introducing_commit:** unknown
  - **release_tag:** historical v0.8.2 evidence; v0.8.3 tag identity unknown
  - **affected_paths:** loopback runner, retry policy, `CSSWITCH_LOOPBACK_TEST_CMD`, release gate, and `test_run_loopback_retry.sh`
  - **intended_behavior:** the release gate runs a fixed, versioned test suite with no hidden retries; a diagnostic recovery must remain visible as flaky and non-release-ready
  - **actual_behavior:** the first loopback probe exited 42, the second attempt succeeded, and the final result was exit 0/pass; arbitrary failure is currently retried three times, and `CSSWITCH_LOOPBACK_TEST_CMD` can replace the entire test suite without the release gate forbidding it
  - **tests_added:** retry probe/self-test existed, but `test_run_loopback_retry.sh` was orphaned and did not establish safe release semantics
  - **tests_missing:** default no-retry assertion, command-override denial in release mode, recovered→`FLAKY` promotion, and fixed-entrypoint identity test
  - **artifact_or_runtime_evidence:** supplied loopback probe sequence only; no current run here
  - **related_user_issue:** loopback acceptance can hide a failing test suite; issue identifier not supplied
  - **confidence:** high for the supplied behavior; current v0.8.3 implementation is unknown

#### TEST-P0-03 — Required artifact, Mach-O, and late-SSH evidence is outside the total gate

- **classification:** confirmed P0 acceptance-scope failure; `BLOCK`.
- **subsystem**
  - **introduced_version:** observed in the supplied v0.8.2 release-gate facts
  - **introducing_commit:** unknown
  - **release_tag:** historical v0.8.2 evidence; v0.8.3 tag identity unknown
  - **affected_paths:** total release gate, DMG/artifact verification, Mach-O production identity predicate, and SSH OAuth→failure transaction path
  - **intended_behavior:** release readiness must join source tests with final DMG contents, Mach-O identity, and SSH late-failure recovery evidence
  - **actual_behavior:** DMG/artifact was not in the total gate; the Mach-O production predicate could be bypassed; SSH late failure had no transaction test
  - **tests_added:** partial source/synthetic/local-mock checks are confirmed
  - **tests_missing:** DMG app-count/identity, final Mach-O non-bypass regression, OAuth-written/SSH-failed rollback, and cross-layer promotion tests
  - **artifact_or_runtime_evidence:** no final DMG, final Mach-O, installed, signing, live, or public evidence supplied for this task
  - **related_user_issue:** release-ready does not cover the artifact and late-failure contract; issue identifier not supplied
  - **confidence:** high for the supplied gate scope; current target implementation unknown

#### TEST-P0-04 — Ignored/skipped and orphaned tests do not reliably surface into readiness

- **classification:** confirmed P0 test-coverage integrity failure; `BLOCK`.
- **subsystem**
  - **introduced_version:** observed in the supplied v0.8.2 test-system facts
  - **introducing_commit:** unknown
  - **release_tag:** historical v0.8.2 evidence; v0.8.3 tag identity unknown
  - **affected_paths:** test discovery, ignored/skipped result aggregation, Python/Shell entrypoint inventory, four Rust manifests, and release-ready reporting
  - **intended_behavior:** every required test is discoverable from a versioned manifest; ignored/skipped/NOT-RUN states are typed and promoted to a non-release-ready result
  - **actual_behavior:** ignored/skipped results did not surface into the gate; v0.8.2 simultaneously recorded release-ready green and seven ignored tests; four orphan entrypoints were outside the gate
  - **tests_added:** the orphan files themselves exist; aggregate inclusion is not demonstrated
  - **tests_missing:** orphan-closure assertion, ignored-count gate assertion, and manifest-to-executed-entrypoint equality test
  - **artifact_or_runtime_evidence:** source/test inventory and supplied release-ready report; no fresh run here
  - **related_user_issue:** green status masks missing/ignored coverage; issue identifier not supplied
  - **confidence:** high for the supplied historical result; current v0.8.3 inventory is unknown

### P1 — incomplete entrypoint and transaction coverage

#### TEST-P1-01 — Rust manifest coverage is incomplete or not surfaced

- **classification:** confirmed P1 coverage gap from the supplied inventory.
- **subsystem**
  - **introduced_version:** observed in the supplied test-system audit
  - **introducing_commit:** unknown
  - **release_tag:** historical v0.8.2 evidence; v0.8.3 tag identity unknown
  - **affected_paths:** four Rust manifests; `codex-network` tests and `skill-package` tests
  - **intended_behavior:** the versioned test entrypoint manifest enumerates all four Rust manifests and their test result totals, including ignored states
  - **actual_behavior:** five `codex-network` tests were missed; `skill-package` has 59 tests, including four ignored, without the required reliable upward aggregation
  - **tests_added:** the underlying Rust tests exist according to the supplied counts
  - **tests_missing:** manifest coverage check, per-manifest executed-count check, and ignored-state promotion
  - **artifact_or_runtime_evidence:** source inventory only; exact manifest paths and current v0.8.3 counts are unknown
  - **related_user_issue:** incomplete Rust coverage under a green gate; issue identifier not supplied
  - **confidence:** high for supplied counts; exact current paths/status unknown

#### TEST-P1-02 — SSH late-failure transaction regression is absent

- **classification:** confirmed P1 missing regression; tied to the v0.8.2 P0 transaction finding.
- **subsystem**
  - **introduced_version:** v0.8.2 behavior under v0.8.3 test-system scope
  - **introducing_commit:** unknown
  - **release_tag:** v0.8.2 historical evidence; v0.8.3 tag identity unknown
  - **affected_paths:** sandbox session, OAuth persistence, SSH bridge preparation, and SSH E2E test entrypoint
  - **intended_behavior:** test the real order where OAuth succeeds, SSH fails late, state is recovered/rolled back, and a retry is deterministic
  - **actual_behavior:** SSH E2E copied the wrong order and only tested success; no late-failure transaction test exists in the supplied evidence
  - **tests_added:** success-only E2E is confirmed
  - **tests_missing:** OAuth-written/SSH-failed, rollback/compensation, retry-after-partial-state, Skill/Gateway consistency tests
  - **artifact_or_runtime_evidence:** source/E2E description only; no live Science or installed-final result
  - **related_user_issue:** partial OAuth/SSH setup state; issue identifier not supplied
  - **confidence:** high

#### TEST-P1-03 — Test entrypoints lack a proven versioned manifest and typed readiness contract

- **classification:** confirmed requirement gap in the supplied audit; implementation presence beyond the observed behavior is unknown.
- **subsystem**
  - **introduced_version:** v0.8.3 test-system remediation scope
  - **introducing_commit:** not yet introduced / unknown
  - **release_tag:** v0.8.3 target; tag identity unknown
  - **affected_paths:** `run_all`, loopback runner, Rust manifests, MJS runner, orphan tests, artifact/Mach-O/SSH gates, and release-ready aggregation
  - **intended_behavior:** a versioned entrypoint manifest names each command, owner, evidence layer, schema, and release-gate role; typed readiness prevents source green from becoming release green
  - **actual_behavior:** no supplied evidence proves such a manifest or typed readiness layer exists; current names/aggregation allow the escape paths above
  - **tests_added:** none supplied for the manifest/meta-layer contract
  - **tests_missing:** manifest closure, schema validation, child-RC/result consistency, evidence-layer promotion, and readiness-state tests
  - **artifact_or_runtime_evidence:** no v0.8.3 artifact/runtime evidence supplied
  - **related_user_issue:** test entrypoint ambiguity and false release status; issue identifier not supplied
  - **confidence:** high for “not evidenced”; unknown for current source presence

### P2 — nonblocking inventory notes that still require closure

#### TEST-P2-01 — MJS has no reported orphan entrypoints, but gate inclusion is not independently proven

- **classification:** confirmed positive inventory fact with a residual evidence gap; not a failure assertion.
- **subsystem**
  - **introduced_version:** supplied test-system audit scope
  - **introducing_commit:** unknown
  - **release_tag:** v0.8.3 target; tag identity unknown
  - **affected_paths:** MJS test entrypoints and their aggregator; exact paths not supplied
  - **intended_behavior:** no orphan MJS tests and every discovered MJS entrypoint is represented in the versioned manifest/gate
  - **actual_behavior:** no MJS orphan was reported; manifest/gate inclusion was not otherwise proved
  - **tests_added:** MJS inventory result is supplied
  - **tests_missing:** discovered-to-executed equality and typed result aggregation for MJS
  - **artifact_or_runtime_evidence:** source inventory only
  - **related_user_issue:** MJS coverage closure; issue identifier not supplied
  - **confidence:** high for “no orphan reported,” unknown for complete gate inclusion

#### TEST-P2-02 — `release-ready` naming conflicts with a source-test gate

- **classification:** confirmed naming/evidence-boundary risk; not a separate runtime failure.
- **subsystem**
  - **introduced_version:** observed in the supplied historical gate
  - **introducing_commit:** unknown
  - **release_tag:** historical v0.8.2 evidence; v0.8.3 tag identity unknown
  - **affected_paths:** `release-ready` status, source-only aggregation, artifact/installed/live/signing/public layers
  - **intended_behavior:** a source-only gate has a source-specific name; `release-ready` is reserved for the composite multi-layer release predicate
  - **actual_behavior:** the name `release-ready` can be emitted by a gate that omits DMG/Mach-O/SSH and can be false-green
  - **tests_added:** unknown
  - **tests_missing:** name-to-layer contract and assertion that release-ready requires every mandatory layer
  - **artifact_or_runtime_evidence:** historical release-ready green with omitted/ignored evidence
  - **related_user_issue:** misleading release status; issue identifier not supplied
  - **confidence:** high

## 4. Complete entrypoint and component table

“Complete” here means complete against every entrypoint/component named in the supplied facts. Where the facts did not provide a path, that omission is explicit rather than filled by guesswork.

| Entrypoint/component | Kind | Supplied inventory/result | Intended evidence layer | Current gate status |
|---|---|---|---|---|
| `run_all` | Shell aggregator | Lost child RC; emitted release-ready green with final exit 0 after child exit 7 | source/test | `BLOCK`, confirmed false green |
| Offline fake runner | Probe/fixture | Printed pass, then exited 7 | source/test | Must be retained as RC regression |
| `test_run_all_aggregator.sh` | Shell self-test | Exists; does not assert child RC; orphan/not in gate | source/test | Missing from gate |
| Loopback runner | Shell/runtime probe | First exit 42, second success, final exit 0/pass | loopback/live-boundary | Retry semantics unsafe |
| `CSSWITCH_LOOPBACK_TEST_CMD` | Environment override | Can replace the entire test suite; release gate does not forbid it | source/test | Ungated bypass |
| `test_run_loopback_retry.sh` | Shell self-test | Exists; orphan/not in gate | source/test | Missing from gate |
| `test_external_skill_install_bridge.py` | Python test | Orphan; supplied count `11` (count unit not specified) | source/test | Missing from gate |
| `test_skill_runtime_boundary.py` | Python test | Orphan; supplied count `11` (count unit not specified) | source/test | Missing from gate |
| Rust manifest 1 | Rust workspace entry | One of four required manifests; exact path not supplied | source/test | Must be in versioned manifest |
| Rust manifest 2 | Rust workspace entry | One of four required manifests; exact path not supplied | source/test | Must be in versioned manifest |
| Rust manifest 3 | Rust workspace entry | One of four required manifests; exact path not supplied | source/test | Must be in versioned manifest |
| Rust manifest 4 | Rust workspace entry | One of four required manifests; exact path not supplied | source/test | Must be in versioned manifest |
| `codex-network` | Rust test group | Five tests omitted from the supplied gate inventory | source/test | P1 coverage gap |
| `skill-package` | Rust test group | 59 tests, four ignored | source/test | Ignored count must surface/block |
| MJS runner | MJS test group | No orphan reported | source/test | Positive inventory only; gate inclusion unknown |
| DMG/artifact checks | Artifact entrypoint | Not in total gate | final DMG/public | P0 missing layer |
| Mach-O production identity | Identity entrypoint | Predicate can be bypassed by fake `SCIENCE_BIN`; real identity test ignored | final app/signing | P0 bypass |
| SSH late-failure transaction | E2E/regression entrypoint | Wrong order and success-only E2E | installed/live/state | P1 missing regression |
| `source-test-gate` | Required replacement name | Must own source-only result after rename | source/test | Required remediation |
| `release-ready` | Composite result | Current name conflicts with omitted layers | all required layers | Must be reserved for composite gate |

## 5. Requirement → test → evidence → gate matrix

| Requirement | Test / entrypoint | Evidence available from supplied facts | Current gate | Required disposition |
|---|---|---|---|---|
| Preserve real child exit code | Offline fake runner + `test_run_all_aggregator.sh` | Marker/pass followed by child RC 7; aggregator did not assert RC | False green, RC 0 | `FAIL`; add `TestResultV1` plus real-RC assertion |
| Reject marker/RC contradiction | Fake runner that emits pass then exits nonzero | Exact contradiction observed | Not rejected | `FAIL` |
| Do not hide loopback failures with default retry | Loopback probe | RC 42, retry success, final pass | Final RC 0/pass | Default no retry; recovered result `FLAKY` and blocks release |
| Forbid replacement test suite in release mode | `CSSWITCH_LOOPBACK_TEST_CMD` | Can replace complete suite; no release prohibition | Ungated | `FAIL` in release mode; allow only explicit diagnostic mode |
| Include aggregator self-test | `test_run_all_aggregator.sh` | Orphan/not in gate | Not executed | Add to versioned manifest and gate |
| Include retry self-test | `test_run_loopback_retry.sh` | Orphan/not in gate | Not executed | Add to versioned manifest and gate |
| Include Skill install/runtime boundary tests | Two orphan Python tests | Both orphan; supplied count 11 each | Not executed | Add to manifest; bind to source-test evidence |
| Cover all Rust manifests | Four Rust manifests | Four required; exact paths not supplied | Incomplete/unknown | Enumerate all four and compare discovered/executed entries |
| Surface `codex-network` tests | Rust group | Five tests omitted | Missing | `FAIL` until included and counted |
| Surface `skill-package` ignored tests | Rust group | 59 total, four ignored | Green did not surface ignored | Ignored > 0 blocks release readiness |
| Surface all ignored/skipped/NOT-RUN | Aggregator meta layer | v0.8.2 green with seven ignored | Not surfaced | Typed status; nonrelease-ready |
| Keep MJS orphan-free and included | MJS runner | No orphan reported | Inclusion not independently proven | Manifest closure assertion |
| Verify final DMG contents | DMG/artifact regression | Not in total gate | No evidence | Add final-DMG gate, app-count/identity/hash checks |
| Verify production Mach-O identity | `codesign -d` predicate and real identity test | Synthetic default false; real true ignored; fake binary bypass | Bypass possible | Fail-closed real-binary regression |
| Exercise SSH late failure | OAuth→SSH E2E | Wrong order; success only | Missing | Add failure-order and rollback test |
| Separate local mock from live OpenCode | OpenCode acceptance | Local mock only | Can read as coverage | Typed evidence layer; live required for live claim |
| Bind evidence to release/tag time | Release closure | Post-tag evidence exists | Promotion ambiguous | Versioned evidence fingerprint and tag-time closure |
| Reserve `release-ready` for composite evidence | Gate naming | Current name used amid omitted layers | Misleading | Rename source gate to `source-test-gate` |

## 6. `TEST-GATE-CORE` required contract

The following is the minimum remediation contract derived from the confirmed failures. It is a required design/acceptance target, not an assertion that it already exists.

### 6.1 Core result and meta-layer

Every entrypoint must emit a versioned `TestResultV1` record and a real process exit code. The `gate-core` meta layer must validate both before aggregation.

At minimum, `TestResultV1` needs typed fields for:

- `schema_version` and stable `entrypoint_id`;
- `status`, with at least `PASS`, `FAIL`, `FLAKY`, `ENV-BLOCKED`, `NOT-RUN`, `IGNORED`, and `SKIPPED`;
- actual `exit_code`;
- attempt count and retry policy;
- evidence layer (`source-test`, `isolated-test-app`, `final-dmg`, `installed-final`, `live`, `signing`, or `public`);
- release/tag/source fingerprint and the command/fixture identity;
- artifact or result references sufficient to re-open the evidence.

`gate-core` must enforce these invariants:

1. A nonzero real child exit code is `FAIL`, regardless of a printed pass marker.
2. Missing, malformed, contradictory, or unversioned `TestResultV1` is `FAIL`/not release-ready.
3. `PASS` requires exit code 0 and a matching typed result.
4. Default release execution performs no retry. An explicit diagnostic retry may collect more evidence, but a recovered result remains `FLAKY` and blocks release readiness.
5. `ENV-BLOCKED`, `NOT-RUN`, `IGNORED`, and `SKIPPED` are never silently converted to `PASS`; they must be visible at aggregate level and must block the composite release gate unless an explicitly named non-release gate says otherwise.
6. A release-mode command override cannot replace the versioned suite. `CSSWITCH_LOOPBACK_TEST_CMD` may exist only under an explicit diagnostic/nonrelease mode and must be recorded in the result.

### 6.2 Versioned entrypoint manifest

Create a versioned manifest that enumerates every required command and component, including:

- `run_all`, the offline fake runner, loopback runner, and both shell self-tests;
- both orphan Python tests;
- all four Rust manifests, with `codex-network` and `skill-package` counts;
- the MJS runner;
- DMG/artifact, Mach-O identity, and SSH late-failure regressions;
- the evidence layer, owner, expected `TestResultV1` schema, and whether the entry is required for `source-test-gate` or composite `release-ready`.

The manifest must be checked in the gate itself: discovered required entries must equal manifest entries, and every manifest entry must produce a result. Exact four-Rust-manifest paths are not supplied in this audit and must be resolved from the current source inventory when implementing the remediation.

### 6.3 Naming and readiness layers

Rename the source-only aggregate to `source-test-gate`. Reserve `release-ready` for a composite predicate over all mandatory evidence layers:

| Readiness layer | Required claim |
|---|---|
| `source-test` | Versioned source entrypoints ran with matching RC/results; no required ignored/NOT-RUN entries |
| `isolated-test-app` | The intended isolated app identity ran the declared tests |
| `final-dmg` | DMG contains the intended app count/identity and matches the selected build fingerprint |
| `installed-final` | The selected final artifact was installed and identified |
| `live` | The intended live provider/Science/SSH paths were exercised separately |
| `signing` | The exact Mach-O/signing predicate for the final app passed |
| `public` | The public redownloaded asset matches the declared release artifact |

No lower layer may be promoted to a higher layer merely because its text says “green.”

### 6.4 Mandatory regression set

The gate must permanently retain regressions for:

- child RC 7 after a pass marker;
- first loopback RC 42 followed by a successful diagnostic retry;
- release-mode `CSSWITCH_LOOPBACK_TEST_CMD` replacement;
- seven ignored tests and any ignored/skipped/NOT-RUN upward propagation;
- orphan-entrypoint closure;
- all four Rust manifests, the five omitted `codex-network` tests, and the 59/4 `skill-package` total/ignored split;
- stale `CSSwitch Test.app` or any extra app in a final DMG;
- fake-binary/Mach-O identity bypass;
- OAuth-written then SSH-failed rollback/compensation;
- local mock versus live provider evidence;
- post-tag evidence incorrectly attributed to a frozen release.

## 7. Evidence-layer boundaries

| Layer | What the test system may claim | What it must not claim without its own evidence |
|---|---|---|
| Source/test | Source entrypoints and their typed results | Final artifact, installed/live, signing, public |
| Isolated Test App | Isolated app identity and run result | Final DMG/public identity |
| Final DMG | Packaged app contents and DMG integrity | Installed/live/provider/signing unless separately run |
| Installed final | Selected installed artifact and runtime identity | Public asset equality or tag reproducibility |
| Live | Actual selected environment/provider/Science behavior | Source/artifact identity without fingerprint |
| Signing | Exact final Mach-O/signing check | Provider/Science compatibility or public equality |
| Public | Redownloaded asset identity/hash at a named time | Local source or a different installed copy |

The release gate must record these layers separately. In particular, a local OpenCode mock, synthetic Science binary, source-level SSH success test, or UI smoke result must not be represented as live/final-artifact acceptance.

## 8. Command and exit-code summary

The following are supplied historical probe outcomes. They were not rerun in this documentation pass.

| Probe/entrypoint | Supplied observation | Final supplied exit/status | This pass |
|---|---|---:|---|
| Offline fake runner | Printed pass marker, then exited 7 | child `7`; aggregate `0` / release-ready green | NOT-RUN |
| `test_run_all_aggregator.sh` | Did not assert child RC; orphan/not in gate | No independent exit supplied | NOT-RUN |
| Loopback probe | First attempt exited 42; second attempt succeeded | final `0` / pass | NOT-RUN |
| Current loopback retry policy | Arbitrary failure retried three times | Recovered result hidden as pass | NOT-RUN |
| `CSSWITCH_LOOPBACK_TEST_CMD` | Can replace complete suite; release gate does not forbid | Depends on replacement command | NOT-RUN |
| v0.8.2 ignored/skipped aggregate | Seven ignored alongside release-ready green | aggregate green despite ignored count | NOT-RUN |
| `codex-network` inventory | Five tests omitted | No aggregate exit supplied | NOT-RUN |
| `skill-package` inventory | 59 tests, four ignored | No aggregate exit supplied | NOT-RUN |
| MJS inventory | No orphan reported | No aggregate exit supplied | NOT-RUN |
| DMG/Mach-O/SSH regressions | Missing from current total gate or missing required scenario | NOT-RUN | NOT-RUN |

No network validation, credential access, real Science state, final DMG build, app launch, signing command, or test command was executed by this documentation pass.

## 9. Audit conclusion

The current test system is not a release gate: it can discard a real child failure, retry and hide an arbitrary replacement suite, ignore missing/ignored coverage, and report readiness without DMG, Mach-O, or late-SSH evidence. The minimum acceptable repair is `TEST-GATE-CORE` with real RC plus `TestResultV1`, a gate-core meta layer, default no-retry with recovered results permanently `FLAKY`, a versioned entrypoint manifest covering four Rust manifests and all orphan tests, ignored/skipped upward propagation, explicit DMG/Mach-O/SSH regressions, `source-test-gate` naming, and separate typed evidence layers. Until those are proven in the target v0.8.3 source/artifact/runtime, status remains `BLOCK`.
