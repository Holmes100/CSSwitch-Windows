# CSSwitch v0.8.1 change audit

> Audit status: historical change audit based only on the supplied Sol xhigh-reviewed facts. No provider, Science, SSH-parser, signing, build, install, network, or public-asset validation was run while writing this file.

## 1. Scope and baseline

- **Scope:** v0.8.1 source/release change surface and its release-closure evidence.
- **Baseline:** `4e0af6ba7909dca22f1257b168172ecbe4af4836`.
- **Change size:** 67 paths, approximately `+8978/-897`.
- **Primary source concentration:** `c93c7e64d75703d38f08c385ed94460b5057831b`.
- **Review input:** supplied facts only; this is not a fresh complete Git review.
- **Outcome:** two confirmed P2 findings remain: K3 reasoning HMAC does not bind profile identity, and tag-contained release-state documentation was stale. Several compatibility surfaces were recorded, but final-artifact proof of real provider/Science/SSH/signing behavior is absent.

### Evidence vocabulary

- **confirmed:** directly stated in the supplied facts.
- **inferred:** a bounded implication of a confirmed fact; not an additional execution result.
- **unknown:** not established by the supplied facts.
- **NOT-RUN:** deliberately not executed in this documentation-only pass.

## 2. Release identity and lineage

| Item | Value | Status |
|---|---|---|
| Baseline | `4e0af6ba7909dca22f1257b168172ecbe4af4836` | confirmed |
| Release | `v0.8.1` | confirmed |
| Tag object | `700d955f97584b19ac9f8734c580735db78b503e` | confirmed |
| Peeled release commit | `c93c7e64d75703d38f08c385ed94460b5057831b` | confirmed |
| Main source concentration | `c93c7e64d75703d38f08c385ed94460b5057831b` | confirmed |
| Changed paths | 67 | confirmed |
| Approximate diff | `+8978/-897` | confirmed |
| Post-tag evidence correction | `b7c3d151ff8bc4aae643ab068cb427e66ec74656` | confirmed as after-tag evidence, not tag contents |
| Public redownload/installed/live/signing state | Not supplied | unknown / NOT-RUN |

The post-tag commit is evidence about later documentation/evidence state, not proof that the frozen v0.8.1 tag was internally current. Tag contents, source behavior, final artifact, installed final, live provider behavior, signing, and public release are separate layers.

## 3. Findings

### P0

No additional P0 finding is asserted from the supplied v0.8.1 facts. This is not a PASS: the absence of a newly classified P0 here does not promote any unverified provider, Science, SSH, signing, or public-release claim.

### P1

No additional P1 finding is asserted from the supplied v0.8.1 facts. The coverage register below records important unproven surfaces and their missing evidence rather than upgrading them to confirmed runtime failures.

### P2

#### V081-P2-01 — K3 reasoning HMAC does not bind profile identity

- **classification:** confirmed P2 integrity/isolation finding.
- **subsystem**
  - **introduced_version:** v0.8.1 audit scope
  - **introducing_commit:** main source concentration `c93c7e64d75703d38f08c385ed94460b5057831b`; exact introducing commit unknown
  - **release_tag:** `v0.8.1` / tag object `700d955f97584b19ac9f8734c580735db78b503e`
  - **affected_paths:** K3 reasoning HMAC construction and verification; exact source/test paths are not supplied
  - **intended_behavior:** reasoning authorization must be bound to the key/local token and the complete target contract, including profile identity, endpoint, target model, and signed content
  - **actual_behavior:** the HMAC binds key/local token, contract, endpoint, target model, and content, but not the profile identity itself
  - **tests_added:** a foreign-profile test was present in the reviewed evidence
  - **tests_missing:** a negative test keeping key, endpoint, contract, and target model identical while changing only profile ID
  - **artifact_or_runtime_evidence:** source/test evidence only; no final-artifact or live multi-profile proof was supplied
  - **related_user_issue:** cross-profile reasoning isolation; issue identifier not supplied
  - **confidence:** high

The existing foreign-profile test changed the contract, so it does not isolate the missing profile-identity binding. That test can detect a broader contract mismatch while still missing the exact same-key/same-endpoint/same-contract/same-model/different-profile attack shape.

#### V081-P2-02 — Frozen tag release-state documents were stale

- **classification:** confirmed P2 release-closure/documentation finding.
- **subsystem**
  - **introduced_version:** v0.8.1 tag state
  - **introducing_commit:** exact commit unknown; stale content is confirmed inside the frozen tag
  - **release_tag:** `v0.8.1` / peeled `c93c7e64d75703d38f08c385ed94460b5057831b`
  - **affected_paths:** tag-contained `current-release`, `verified-state`, and `known-issues` documents; exact paths are named by document role, not full paths
  - **intended_behavior:** release-state documents inside the tag must identify v0.8.1 and its actual publication/verification status
  - **actual_behavior:** those documents still said v0.8.0 and/or that the release was not published
  - **tests_added:** unknown
  - **tests_missing:** tag-time version/status consistency check, frozen-tag document check, and a gate preventing post-tag evidence from being silently attributed to tag contents
  - **artifact_or_runtime_evidence:** later evidence at `b7c3d151ff8bc4aae643ab068cb427e66ec74656` exists after the tag; it does not repair the tag retroactively
  - **related_user_issue:** release closure and current-state documentation drift; issue identifier not supplied
  - **confidence:** high

## 4. Subsystem coverage register

The following records preserve the reviewed coverage scope. “Recorded” means the surface was included in the audit facts; it does not mean that a final artifact or live runtime proved it.

### 4.1 Gateway transport and SSE

- **introduced_version:** v0.8.1 audit scope
- **introducing_commit:** `c93c7e64d75703d38f08c385ed94460b5057831b` as the main source concentration; feature commit unknown
- **release_tag:** `v0.8.1`
- **affected_paths:** Gateway transport and SSE streaming paths; exact paths not supplied
- **intended_behavior:** preserve the selected transport contract and streaming/SSE event semantics through the gateway
- **actual_behavior:** Gateway transport/SSE was recorded as a covered surface; live upstream correctness is not established
- **tests_added:** exact tests/counts unknown
- **tests_missing:** final-artifact and live upstream SSE/provider evidence
- **artifact_or_runtime_evidence:** source/test coverage record only; no final-artifact/live result supplied
- **related_user_issue:** streaming/gateway compatibility; issue identifier not supplied
- **confidence:** confirmed coverage, unknown live behavior

### 4.2 OpenAI Chat and K3

- **introduced_version:** v0.8.1 audit scope
- **introducing_commit:** `c93c7e64d75703d38f08c385ed94460b5057831b`; feature commit unknown
- **release_tag:** `v0.8.1`
- **affected_paths:** OpenAI Chat compatibility and K3 reasoning paths; exact paths not supplied
- **intended_behavior:** preserve request/response compatibility and enforce K3 reasoning authorization for the selected profile/contract
- **actual_behavior:** surface was recorded; the K3 profile-identity HMAC gap is confirmed in V081-P2-01
- **tests_added:** exact tests/counts unknown; foreign-profile test was reviewed
- **tests_missing:** same-contract/different-profile-ID negative test and live provider proof
- **artifact_or_runtime_evidence:** source/test evidence only; real provider behavior not proved by final artifact
- **related_user_issue:** OpenAI/K3 reasoning compatibility and isolation; issue identifier not supplied
- **confidence:** high for the HMAC gap; unknown for live provider behavior

### 4.3 Codex Responses

- **introduced_version:** v0.8.1 audit scope
- **introducing_commit:** `c93c7e64d75703d38f08c385ed94460b5057831b`; feature commit unknown
- **release_tag:** `v0.8.1`
- **affected_paths:** Codex Responses adapter/request path; exact paths not supplied
- **intended_behavior:** translate and preserve Codex Responses semantics for the selected runtime identity
- **actual_behavior:** coverage was recorded; no final-artifact/live provider proof was supplied
- **tests_added:** exact tests/counts unknown
- **tests_missing:** final-app and live Codex Responses execution evidence
- **artifact_or_runtime_evidence:** source/test layer only
- **related_user_issue:** Codex Responses compatibility; issue identifier not supplied
- **confidence:** confirmed coverage, unknown runtime behavior

### 4.4 Kimi filtering

- **introduced_version:** v0.8.1 audit scope
- **introducing_commit:** `c93c7e64d75703d38f08c385ed94460b5057831b`; feature commit unknown
- **release_tag:** `v0.8.1`
- **affected_paths:** Kimi request filtering/normalization paths; exact paths not supplied
- **intended_behavior:** apply the intended Kimi filtering rules without altering unrelated provider behavior
- **actual_behavior:** filtering was recorded in the coverage scope; live Kimi behavior is not proven by the final artifact
- **tests_added:** exact tests/counts unknown
- **tests_missing:** live provider and packaged-runtime filtering regressions
- **artifact_or_runtime_evidence:** source/test coverage only
- **related_user_issue:** Kimi compatibility/filtering; issue identifier not supplied
- **confidence:** confirmed coverage, unknown live behavior

### 4.5 DeepSeek DSML

- **introduced_version:** v0.8.1 audit scope
- **introducing_commit:** `c93c7e64d75703d38f08c385ed94460b5057831b`; feature commit unknown
- **release_tag:** `v0.8.1`
- **affected_paths:** DeepSeek DSML compatibility paths; exact paths not supplied
- **intended_behavior:** preserve the DeepSeek DSML request/response contract through the selected adapter
- **actual_behavior:** DSML was recorded as covered; final-artifact/live provider behavior is not established
- **tests_added:** exact tests/counts unknown
- **tests_missing:** packaged and live DeepSeek DSML evidence
- **artifact_or_runtime_evidence:** source/test coverage only
- **related_user_issue:** DeepSeek DSML compatibility; issue identifier not supplied
- **confidence:** confirmed coverage, unknown runtime behavior

### 4.6 OpenCode, Grok, and Gemini

- **introduced_version:** v0.8.1 audit scope
- **introducing_commit:** `c93c7e64d75703d38f08c385ed94460b5057831b`; feature commits unknown
- **release_tag:** `v0.8.1`
- **affected_paths:** OpenCode/Grok/Gemini routing and model handling; exact paths not supplied
- **intended_behavior:** route each supported model/provider through its declared compatibility path and preserve identity in the runtime fingerprint
- **actual_behavior:** the three surfaces were recorded; real-provider and final-artifact behavior were not proved
- **tests_added:** exact tests/counts unknown
- **tests_missing:** real-provider runs, packaged-app runs, and exact-selector assertions per provider
- **artifact_or_runtime_evidence:** source/test layer only
- **related_user_issue:** provider/model routing; issue identifier not supplied
- **confidence:** confirmed coverage, unknown live behavior

### 4.7 Claude Science multiple histories

- **introduced_version:** v0.8.1 audit scope
- **introducing_commit:** `c93c7e64d75703d38f08c385ed94460b5057831b`; feature commit unknown
- **release_tag:** `v0.8.1`
- **affected_paths:** Science history/session handling; exact paths not supplied
- **intended_behavior:** preserve and select the intended history without conflating organizations or sessions
- **actual_behavior:** multiple-history coverage was recorded; multiple-organization behavior was not proved by the final artifact
- **tests_added:** exact tests/counts unknown
- **tests_missing:** real Science multi-organization run, history isolation, and installed-final evidence
- **artifact_or_runtime_evidence:** no final-artifact proof of real Science multi-organization behavior
- **related_user_issue:** Science multi-history/multi-organization behavior; issue identifier not supplied
- **confidence:** confirmed coverage, unknown real-Science behavior

### 4.8 SSH preflight

- **introduced_version:** v0.8.1 audit scope
- **introducing_commit:** `c93c7e64d75703d38f08c385ed94460b5057831b`; feature commit unknown
- **release_tag:** `v0.8.1`
- **affected_paths:** SSH preflight and Science SSH parser boundary; exact paths not supplied
- **intended_behavior:** validate the actual Science SSH configuration/parser contract before declaring the path ready
- **actual_behavior:** SSH preflight was recorded, but Science SSH parser behavior was not proved by the final artifact
- **tests_added:** exact tests/counts unknown
- **tests_missing:** isolated real-Science parser/preflight run and packaged/installed final evidence
- **artifact_or_runtime_evidence:** preflight coverage record only; no final-artifact parser proof
- **related_user_issue:** Science SSH connection/preflight; issue identifier not supplied
- **confidence:** confirmed coverage boundary, unknown real parser behavior

### 4.9 Skill and MCP

- **introduced_version:** v0.8.1 audit scope
- **introducing_commit:** `c93c7e64d75703d38f08c385ed94460b5057831b`; feature commit unknown
- **release_tag:** `v0.8.1`
- **affected_paths:** Skill listing/attachment and MCP listing/runtime bridge; exact paths not supplied
- **intended_behavior:** distinguish discovery, attachment, identity/trust, invocation, and live capability
- **actual_behavior:** Skill/MCP was recorded as a coverage surface; listing or source evidence is not final-artifact/live proof
- **tests_added:** exact tests/counts unknown
- **tests_missing:** installed-final attachment and runtime invocation evidence, plus live provider/connector proof
- **artifact_or_runtime_evidence:** no final-artifact proof supplied
- **related_user_issue:** Skill/MCP visibility versus execution; issue identifier not supplied
- **confidence:** confirmed boundary, unknown runtime behavior

### 4.10 Release closure

- **introduced_version:** v0.8.1 tag/release process
- **introducing_commit:** exact commit unknown; tag peeled commit `c93c7e64d75703d38f08c385ed94460b5057831b`
- **release_tag:** `v0.8.1` / tag object `700d955f97584b19ac9f8734c580735db78b503e`
- **affected_paths:** `current-release`, `verified-state`, `known-issues`, final evidence and publication closure; exact paths not supplied
- **intended_behavior:** tag-contained release state matches the release identity and publication status, with later evidence explicitly marked post-tag
- **actual_behavior:** tag-contained documents still said v0.8.0/未发布; final evidence was only available after tag at `b7c3d151ff8bc4aae643ab068cb427e66ec74656`
- **tests_added:** unknown
- **tests_missing:** immutable-tag closure check and explicit post-tag evidence labeling in the release gate
- **artifact_or_runtime_evidence:** tag identity plus post-tag evidence commit; no public redownload/signing proof
- **related_user_issue:** stale release closure documentation; issue identifier not supplied
- **confidence:** high

## 5. Evidence-layer boundaries

| Layer | Established by this audit | Not established by this audit |
|---|---|---|
| Source/tag | v0.8.1 tag identity, source concentration, change size, K3 HMAC shape, and stale tag docs | Built app, DMG, installed/live behavior |
| Isolated Test App | Only if separately identified and run; none supplied here | Final DMG/public identity |
| Final DMG | No final-DMG result supplied | Real providers, Science organizations, Science SSH parser, signing, public redownload |
| Installed final | No installed-final result supplied | Source/tag correctness or public asset equality |
| Live | No real-provider/Science result supplied | Artifact identity and reproducibility |
| Signing | No signing result supplied | Provider/Science compatibility or notarization/Gatekeeper unless separately tested |
| Public | No public redownload result supplied | Local source/runtime state |

The final artifact cannot be used to claim real provider behavior, Science multi-organization behavior, Science SSH parser behavior, or signing acceptance unless those exact layers are separately captured. A post-tag evidence commit cannot be substituted for tag-contained state.

## 6. Command and exit-code summary

The supplied facts identify outcomes but do not provide a complete command transcript. Exit codes below are therefore `UNKNOWN` unless explicitly stated; no command was rerun in this pass.

| Command/probe | Purpose | Supplied result | Exit code | This pass |
|---|---|---|---:|---|
| K3 foreign-profile test | Check cross-profile reasoning isolation | Test changed contract; it did not isolate same key/endpoint/contract/model with only profile ID changed | UNKNOWN | NOT-RUN |
| Same-contract/different-profile-ID negative test | Required missing regression | No result supplied; test missing | NOT-APPLICABLE | NOT-RUN |
| Gateway transport/SSE coverage | Source/test compatibility record | Recorded, without final/live proof | UNKNOWN | NOT-RUN |
| OpenAI Chat/K3, Codex Responses, Kimi, DeepSeek DSML, OpenCode/Grok/Gemini probes | Provider compatibility | Recorded coverage, real provider not proved by final artifact | UNKNOWN | NOT-RUN |
| Science multiple-history/multiple-organization probe | Real Science state isolation | Multiple histories recorded; multiple organizations not proved | UNKNOWN | NOT-RUN |
| Science SSH parser/preflight probe | Real parser acceptance | Not proved by final artifact | UNKNOWN | NOT-RUN |
| Skill/MCP installed invocation | Runtime capability | Not proved by final artifact/live evidence | UNKNOWN | NOT-RUN |
| Tag document/release closure check | Frozen-tag truth | v0.8.1 tag still said v0.8.0/未发布; later evidence at `b7c3d151ff8bc4aae643ab068cb427e66ec74656` | UNKNOWN | NOT-RUN |
| Signing/public redownload | Public release closure | Not supplied | UNKNOWN | NOT-RUN |

## 7. Audit conclusion

v0.8.1 has a clear tag identity and a substantial source change set. The K3 reasoning HMAC has a specific, reproducible contract gap: profile identity is absent from the signed binding, and the existing foreign-profile test does not isolate that variable. The frozen tag also carried stale release-state documents; later evidence at `b7c3d151ff8bc4aae643ab068cb427e66ec74656` must remain labeled post-tag. Compatibility coverage was recorded broadly, but the real provider, Science multi-organization, Science SSH parser, signing, installed, live, and public layers remain unproven in this task.
