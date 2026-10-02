# CSSwitch v0.8.0 change audit

> Audit status: historical change audit, not a fresh build, install, live-provider, signing, or public-release acceptance run.
>
> Evidence status is intentionally split into `confirmed`, `inferred`, `unknown`, and `NOT-RUN`. The facts below are the four Sol xhigh-reviewed facts supplied for this document task; this document does not claim to have rerun them.

## 1. Scope and baseline

- **Scope:** v0.8.0 changes and the v0.8.0 release/evidence boundary.
- **Baseline:** `4e0af6ba7909dca22f1257b168172ecbe4af4836`.
- **Change size:** 133 files, approximately `+12100/-2403`.
- **Review input:** supplied confirmed facts only; no complete Git re-review was performed in this task.
- **Outcome:** release-integrity and reproducibility defects are confirmed. The first public DMG was not a trustworthy final-artifact proof until its assets were replaced; the tag-contained coverage procedure was not reproducible from the frozen tag.

### Evidence vocabulary

- **confirmed:** directly stated in the supplied audit facts.
- **inferred:** a bounded implication of a confirmed fact; it is not an additional runtime observation.
- **unknown:** the supplied facts do not establish the value.
- **NOT-RUN:** deliberately not executed in this documentation-only pass.

## 2. Release identity and lineage

| Item | Value | Status |
|---|---|---|
| Baseline | `4e0af6ba7909dca22f1257b168172ecbe4af4836` | confirmed |
| Release | `v0.8.0` | confirmed |
| Tag object | `5ceafab7bab61dce8feeba5343e6fca4a06c4414` | confirmed |
| Peeled release commit | `4b163d50178791e7fbf9e085eb06fc2260baed4e` | confirmed |
| v0.7 lineage point | peeled `b8ed8d8a818c38e5b1823c11e357a7fdbda81b85` | confirmed |
| Tag-to-source relationship | Tag object peels to the v0.8.0 release commit; the coverage runner inside the tag used `git archive HEAD` for the supposed old v3 input | confirmed |
| Public asset history | First public DMG contained an unintended stale app; assets were later replaced | confirmed |
| Redownloaded public asset after replacement | Not supplied | unknown / NOT-RUN |

The tag object, peeled commit, source tree, isolated Test App, final DMG, installed final app, live runtime, signing state, and public redownload are separate evidence layers. A hash or test result from one layer does not promote the claim to another layer.

## 3. Findings

### P0 — release integrity and reproducibility

#### V080-P0-01 — First public DMG was polluted by a stale `CSSwitch Test.app`

- **classification:** confirmed finding; release-integrity blocker for the first public asset.
- **subsystem**
  - **introduced_version:** v0.8.0
  - **introducing_commit:** v0.8.0 peeled commit `4b163d50178791e7fbf9e085eb06fc2260baed4e`; exact introducing feature commit is unknown
  - **release_tag:** `v0.8.0` / tag object `5ceafab7bab61dce8feeba5343e6fca4a06c4414`
  - **affected_paths:** persistent `target/release/bundle/macos/` staging directory; DMG packaging input; exact packaging script path is not supplied
  - **intended_behavior:** package one intended release app and the expected installer contents from a clean, explicit staging set
  - **actual_behavior:** the first public DMG was manually staged from the persistent bundle directory and unintentionally included stale `CSSwitch Test.app`
  - **tests_added:** unknown; no supplied evidence establishes a pre-publication app-count/identity regression test
  - **tests_missing:** clean staging allowlist, app-count assertion, formal app identity assertion, mounted-DMG inspection, and redownloaded-public-asset comparison
  - **artifact_or_runtime_evidence:** first public DMG contamination is confirmed; later asset replacement is confirmed; final DMG, installed app, signing, and redownload state are not established here
  - **related_user_issue:** public release asset contained the wrong/stale app; issue identifier not supplied
  - **confidence:** high for the first-public-DMG defect; low/unknown for the post-replacement public state

#### V080-P0-02 — Frozen-tag coverage runner used `git archive HEAD` as the old v3 input

- **classification:** confirmed reproducibility and release-gate integrity finding.
- **subsystem**
  - **introduced_version:** v0.8.0
  - **introducing_commit:** exact introducing commit unknown; the defective runner is inside the frozen v0.8.0 tag
  - **release_tag:** `v0.8.0` / peeled `4b163d50178791e7fbf9e085eb06fc2260baed4e`
  - **affected_paths:** tag-contained v3-to-v4 coverage runner; exact file path is not supplied
  - **intended_behavior:** run v3 coverage against an immutable v3 source snapshot and v4 coverage against the intended v4 source snapshot
  - **actual_behavior:** the runner used `git archive HEAD` to stand in for the old v3 input, so the frozen tag did not reproduce the claimed historical comparison
  - **tests_added:** a coverage runner existed, but its historical-input correctness is not demonstrated
  - **tests_missing:** explicit source-object arguments, independent v3/v4 archive identity checks, and a frozen-tag rerun proving that the inputs differ as intended
  - **artifact_or_runtime_evidence:** tag-contained procedure is the evidence; no fresh rerun was performed
  - **related_user_issue:** release-size/coverage claims may be misattributed across versions; issue identifier not supplied
  - **confidence:** high for the `git archive HEAD` defect; exact downstream coverage numbers are not independently revalidated

### P1 — user-visible runtime/configuration behavior

#### V080-P1-01 — Codex dynamic-directory path used an incorrect 400 ms local timeout

- **classification:** confirmed historical runtime defect; fixed only in v0.8.2 according to the supplied facts.
- **subsystem**
  - **introduced_version:** present in v0.8.0
  - **introducing_commit:** exact commit unknown
  - **release_tag:** `v0.8.0`
  - **affected_paths:** Codex dynamic-directory request/timeout path; exact source path is not supplied
  - **intended_behavior:** allow the dynamic-directory operation the timeout budget required by its local/runtime contract
  - **actual_behavior:** a 400 ms local timeout was used, producing a too-short timeout boundary
  - **tests_added:** unknown
  - **tests_missing:** timeout-boundary test covering slow-but-valid local dynamic-directory completion and a separate genuine timeout
  - **artifact_or_runtime_evidence:** supplied source/change audit says the defect remained until v0.8.2; no v0.8.0 live or installed-app run was performed here
  - **related_user_issue:** Codex dynamic directory timeout/failure; issue identifier not supplied
  - **confidence:** high for the historical code-path fact; exact user-facing frequency is unknown

#### V080-P1-02 — Connection editing retained a replaced catalog route

- **classification:** confirmed historical state-pruning defect; fixed in v0.8.2 according to the supplied facts.
- **subsystem**
  - **introduced_version:** present in v0.8.0
  - **introducing_commit:** exact commit unknown
  - **release_tag:** `v0.8.0`
  - **affected_paths:** connection-edit persistence and catalog-route pruning; exact source paths are not supplied
  - **intended_behavior:** after editing/replacing a connection, obsolete catalog routes must not remain effective
  - **actual_behavior:** connection editing retained the replaced old catalog route
  - **tests_added:** unknown
  - **tests_missing:** edit/replace/delete sequence tests asserting persisted route identity and absence of the old route after reload
  - **artifact_or_runtime_evidence:** supplied audit facts identify the defect and the v0.8.2 prune fix; no installed/live verification was run here
  - **related_user_issue:** stale route after connection edit; issue identifier not supplied
  - **confidence:** high for the historical behavior; exact affected route variants are unknown

#### V080-P1-03 — Preset default/Sonnet state disagreed with the UI summary

- **classification:** confirmed historical UI/invariant defect; v0.8.1 added the invariant/role summary according to the supplied facts.
- **subsystem**
  - **introduced_version:** present in v0.8.0
  - **introducing_commit:** exact commit unknown
  - **release_tag:** `v0.8.0`
  - **affected_paths:** preset defaults, Sonnet role/state mapping, and UI summary; exact source paths are not supplied
  - **intended_behavior:** preset state and the displayed role/summary must describe the same effective configuration
  - **actual_behavior:** preset default/Sonnet state and the UI summary were inconsistent
  - **tests_added:** v0.8.1 invariant/role-summary coverage is mentioned; exact test path and result are unknown
  - **tests_missing:** v0.8.0 regression coverage for default load, edit, reload, and rendered-summary/effective-role equality
  - **artifact_or_runtime_evidence:** source/change fact only; no UI smoke or installed-app evidence was run here
  - **related_user_issue:** preset/Sonnet summary mismatch; issue identifier not supplied
  - **confidence:** high for the historical mismatch; exact UI states and affected presets are unknown

### P2 — evidence and selector boundaries

#### V080-P2-01 — Strict selector must be separated from display/listing

- **classification:** confirmed audit boundary; behavior completeness is unknown, so this is recorded as a P2 control gap rather than a newly asserted runtime failure.
- **subsystem**
  - **introduced_version:** v0.8.0 audit scope
  - **introducing_commit:** unknown
  - **release_tag:** `v0.8.0`
  - **affected_paths:** profile/provider/model selection and any UI/listing-to-runtime bridge; exact paths are not supplied
  - **intended_behavior:** resolve by a stable, exact selector such as profile identity plus the intended adapter/endpoint/model, and reject no-match or ambiguous matches
  - **actual_behavior:** supplied facts require a strict-selector boundary, but do not establish that every runtime path enforces it
  - **tests_added:** unknown
  - **tests_missing:** exact-match, wrong-profile, duplicate/ambiguous-match, stale-route, and display-versus-execution selector tests
  - **artifact_or_runtime_evidence:** no final-artifact or live execution fingerprint proving the selected identity was supplied
  - **related_user_issue:** model/profile switching and display correctness; issue identifier not supplied
  - **confidence:** high for the boundary requirement; unknown for full implementation coverage

#### V080-P2-02 — Runtime fingerprint is required to bind evidence to the executed release

- **classification:** confirmed evidence-boundary requirement; absence of a supplied fingerprint is an unknown, not proof that none exists.
- **subsystem**
  - **introduced_version:** v0.8.0 audit scope
  - **introducing_commit:** unknown
  - **release_tag:** `v0.8.0`
  - **affected_paths:** source/test reports, isolated Test App, final DMG, installed app, and live runtime evidence joins
  - **intended_behavior:** each runtime claim should identify app/version, release tag and peeled commit, artifact hash where applicable, selected profile identity, adapter/endpoint, target model, and evidence layer
  - **actual_behavior:** the supplied facts do not provide one complete runtime fingerprint joining those fields
  - **tests_added:** unknown
  - **tests_missing:** fingerprint emission and equality checks across source, Test App, final DMG, installed final, and public redownload
  - **artifact_or_runtime_evidence:** tag identity is known; installed/live/signing/public fingerprints are not supplied
  - **related_user_issue:** inability to tell which release/runtime produced a reported behavior; issue identifier not supplied
  - **confidence:** high for the evidence rule; unknown for implementation presence

#### V080-P2-03 — Skill/MCP listing is not runtime capability proof

- **classification:** confirmed evidence-layer boundary; not a claim that the listing itself is wrong.
- **subsystem**
  - **introduced_version:** v0.8.0 audit scope
  - **introducing_commit:** unknown
  - **release_tag:** `v0.8.0`
  - **affected_paths:** Skill listing, MCP listing/catalog, attachment/installation state, and runtime invocation paths
  - **intended_behavior:** report listing, installation/attachment, trust/identity, and successful runtime invocation as separate predicates
  - **actual_behavior:** a listing alone cannot prove installability, attachment, invocation, provider reachability, or live compatibility; supplied facts do not promote it across layers
  - **tests_added:** unknown
  - **tests_missing:** listed-but-unattached, attached-but-not-invokable, wrong-identity, stale-catalog, and live invocation tests
  - **artifact_or_runtime_evidence:** no final-artifact/live Skill or MCP execution evidence supplied
  - **related_user_issue:** Skill/MCP visibility versus usability; issue identifier not supplied
  - **confidence:** high for the boundary; unknown for path-by-path enforcement

## 4. Evidence-layer boundaries

The following claims must remain separate:

| Layer | What it can establish here | What it cannot establish here |
|---|---|---|
| Source/tag | v0.8.0 tag object, peeled commit, source change shape, and the defective tag-contained runner | Contents of a built app or DMG; installed/live behavior |
| Isolated Test App | A deliberately isolated app run, if one is supplied | The final DMG or public asset identity |
| Final DMG | The exact packaged contents of that DMG | Installed app state, live providers, signing/notarization, or public redownload |
| Installed final | The app actually installed from a selected artifact | Public release asset or live provider behavior unless separately exercised |
| Live | Runtime behavior against the selected environment/provider | Source/tag reproducibility or public artifact identity |
| Signing | The exact signing predicate that was executed | Live compatibility, notarization/Gatekeeper, or public asset equality unless separately proven |
| Public | The downloaded public asset at a specific time/hash | The local source or a different installed copy |

The first public DMG defect is a public-artifact claim. It must not be diluted into a source-only finding, and the later replacement must not be treated as redownloaded-public proof without that separate evidence.

## 5. Command and exit-code summary

This table records the supplied command/probe boundary. Exact shell command lines or exit codes not present in the input remain `UNKNOWN`; none were rerun in this documentation pass.

| Command/probe | Intended evidence | Supplied observation | Exit code | This pass |
|---|---|---|---:|---|
| `git archive HEAD` inside the tag-contained v3-to-v4 runner | Immutable historical source input | Used as a v3 stand-in; frozen-tag comparison is not reproducible | UNKNOWN | NOT-RUN |
| Manual staging from persistent `target/release/bundle/macos/` | Final DMG input hygiene | Stale `CSSwitch Test.app` entered the first public DMG | UNKNOWN | NOT-RUN |
| Strict selector probe | Exact profile/adapter/endpoint/model execution identity | No exact probe result supplied | UNKNOWN | NOT-RUN |
| Runtime fingerprint probe | Join source/tag/artifact/runtime identity | No complete fingerprint supplied | UNKNOWN | NOT-RUN |
| Skill/MCP listing versus invocation probe | Separate listing from usable capability | No final-artifact/live invocation result supplied | UNKNOWN | NOT-RUN |
| Final DMG, installed final, live, signing, and public redownload checks | Cross-layer release closure | Not part of this task | UNKNOWN | NOT-RUN |

## 6. Audit conclusion

The v0.8.0 source lineage and change magnitude are identifiable, but the first public artifact and the tag-contained historical coverage procedure both failed release-evidence integrity. The runtime/configuration findings are confirmed historical defects later addressed by v0.8.1/v0.8.2. No claim is made here that the replacement DMG, installed final app, live providers, signing, or public redownload now pass.
