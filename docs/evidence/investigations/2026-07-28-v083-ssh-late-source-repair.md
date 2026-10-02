# v0.8.3 SSH late-failure source repair

Date: 2026-07-28 (Asia/Shanghai)

This record closes only the source-repair phase of `BUG-083-SSH-LATE`. The
product gate remains open until the same contract passes against a fixed
production artifact and isolated runtime. No real SSH config or private key,
real SSH server, installed App, real provider, signing, notarization, public
release, or user credential was read or exercised.

## Identity and scope

```text
worktree       = /private/tmp/CSswitch-v083-core-reliability-doc-governance
branch         = codex/v083-core-reliability-doc-governance
HEAD           = 2fbaefc0f3a9af19da12605ec1a2411f660b2e21
product parent = 24b991056b43fb4323a38d3122cf08b1c205870a
frozen oracle  = 6d8c13261a2eef3d843e254545997efd65dd078c
oracle tree    = b2c4e42ef59f03139aab258db6df9c827f6bf1d7
```

The frozen oracle-to-restored-source product repair changes exactly six
product paths:

- `desktop/src-tauri/src/commands/runtime.rs`
- `desktop/src-tauri/src/config.rs`
- `desktop/src-tauri/src/lib.rs`
- `desktop/src-tauri/src/runtime/sandbox_session.rs`
- `desktop/src-tauri/src/runtime/science.rs`
- `desktop/src-tauri/src/runtime/settings.rs`

The larger worktree diff also contains the frozen oracle tests and their
test-only support. Those are not additional product-repair paths.

## Failure and classification

The exact old product failed the frozen late-transaction assertions with RC
101. The accepted classification was `PRODUCT_DEFECT`: OAuth and runtime
authority could be changed before a later SSH failure without one complete,
serializer-bound compensation contract. The test contract separately required
early SSH prevalidation, precise candidate and prior-runtime rechecks, foreign
state preservation, durable cleanup, credential-free diagnostics, and
idempotent retry.

The restored source repair establishes:

- one operation-scoped Codex proof that includes both the candidate and any
  alive owned prior Gateway rollback context;
- an in-serializer recheck of the prior Gateway child, launch identity, key
  fingerprint, full private launch context, and exact candidate authority;
- an exact private non-Codex `Config` and credential recheck after serializer
  wait;
- all prevalidatable real-config, packaged-wrapper, Science-authority, and
  managed-stub SSH checks before OAuth mutation;
- exact compensation of OAuth, active profile, Gateway, Science, managed stub,
  transaction journal, and durable cleanup state, including preservation of a
  pre-existing exact managed V2 stub;
- typed diagnostics that do not concatenate credentials, private key material,
  private paths, or raw nested rollback errors.

No unexpected final failure remained. The expanded authority-edge matrix passed
28/28 and the prevalidation matrix passed all ten cases. Those two matrix
results are task-record-only command/output records; no standalone repository
log artifact exists.

## Successor oracle

From
`/private/tmp/CSswitch-v083-core-reliability-doc-governance/desktop/src-tauri`,
the two exact successor selectors were:

```zsh
/Users/superjj/.cargo/bin/cargo test --lib \
  commands::runtime::tests::isolated_real_ipc_rechecks_non_codex_credential_after_serializer_wait \
  -- --exact --ignored --nocapture

/Users/superjj/.cargo/bin/cargo test --lib \
  commands::runtime::tests::isolated_late_failure_preserves_preexisting_managed_stub_when_science_stopped \
  -- --exact --ignored --nocapture
```

Both returned RC 0 in the restored state. The first proves that a credential
change after preflight but before serialized commit is rejected as typed
`config_changed_retry` without candidate or authority mutation. The second
proves that a pre-existing exact managed V2 stub is preserved through late
compensation.

## Product-only mutation provenance

Two temporary mutations were applied only to demonstrate that the successor
oracle still distinguishes the repaired behavior. They were then inversely
restored. The mutation transcripts and reviewer messages exist only in the
originating task record, not as repository artifacts.

1. `OneClickCandidateConfigSnapshot::verify_unchanged()` was temporarily
   bypassed inside the serialized closure. The exact non-Codex successor
   returned RC 101 at its target assertion. Inverse restoration returned
   `runtime.rs` to SHA-256
   `6a8a98696903a1b6e865076597cb6325db09713bfed62a0b69e09093439dff25`
   and the selector returned RC 0.
2. `ManagedSshStubBefore::Present` compensation was temporarily changed to
   delete the exact current managed stub, matching the old unconditional-delete
   behavior. The exact stub successor returned RC 101 with
   `exact_stub_preserved=false`. Inverse restoration returned `settings.rs` to
   SHA-256
   `e057e315b7ec98d7db4568776ee10c8dea507db70a5db6f1ba7e66f764c46788`
   and the selector returned RC 0.

Fresh xhigh review treated a same-UID path swap after final validation as a
separate accepted P3 private-root threat-model boundary, not a blocker for this
bug. This window does not create another bug; the maintained boundary remains
linked from the
[runtime security investigation](2026-07-18-v070-ui-redesign-runtime-security-review.md).

## Restored-state source evidence

The following commands ran from
`/private/tmp/CSswitch-v083-core-reliability-doc-governance/desktop/src-tauri`:

| Command | RC | Result |
| --- | ---: | --- |
| `/Users/superjj/.cargo/bin/cargo test --lib --no-run` | 0 | 417 tests compiled |
| `/Users/superjj/.cargo/bin/cargo check --lib` | 0 | passed; two pre-existing `dead_code` warnings |
| `/Users/superjj/.cargo/bin/cargo test --lib` | 0 | 390 passed, 0 failed, 27 ignored |
| `/Users/superjj/.cargo/bin/cargo test --lib commands::runtime::tests:: -- --ignored --nocapture --test-threads=1` | 0 | 20 passed, 0 failed |
| exact non-Codex successor above | 0 | PASS |
| exact managed-stub successor above | 0 | PASS |

The default source identity fixture now records the actual 417 Desktop tests.
It classifies the 18 new ignored `commands::runtime` cases as explicit
Acceptance-boundary tests using temporary HOME, fake credentials, fake Science,
a local Gateway where required, and loopback only. It also records the two
actual ignored `runtime::sandbox_session` SSH prevalidation units with their
exact temp-HOME-only reasons, so all 27 ignored Desktop identities are explicit.
The fixed source catalog still has fifteen suites; no sixteenth source suite was
added.

Two fresh independent final reviewers returned PASS/PASS. Each reran compile,
check, default, or proportionate isolated selectors; one independently recorded
390/0/27 and both covered the serial ignored Acceptance or proportionate exact
selectors. Their messages, the xhigh decision, and the 28/28 and ten-case
matrix transcripts are task-record-only evidence and are not represented as
checked-in logs.

## Explicit evidence boundary

This is source-test and fake/local-loopback evidence only. It does not establish
any of the following:

- a production `CSSwitch.app` artifact or packaged sidecar;
- a temporary or installed production runtime;
- a real provider, real OAuth account, real SSH config, SSH agent, key, or
  server;
- Developer ID signing, notarization, Gatekeeper acceptance, tag, public
  release, or published attachment.

`GATE-SSH-LATE` therefore remains `product-open-not-run`. A later
user-authorized install/live-provider phase belongs to the next release phase,
after an authorized checkpoint, and cannot be inferred from this source
closure.
