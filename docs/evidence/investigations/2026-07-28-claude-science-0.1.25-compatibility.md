# Claude Science 0.1.20 → 0.1.25 compatibility and updater repair

Date: 2026-07-28 (Asia/Shanghai)

This record separates the standalone updater executable from the executable
seeded inside the DMG App. They have different hashes and embedded identifiers
and are not interchangeable evidence. All dynamic checks in this source phase
used temporary HOME/data directories or the two read-only DMG mounts; no real
Science account, organization, config, Keychain item, or existing Science data
was read.

Field follow-up on 2026-07-29 established that the fixed
`~/.claude-science/bin/claude-science` updater path can also contain the
App-seeded executable byte-for-byte. Therefore the fixed-path runtime boundary
must accept both exact identifiers below with the same exact Team ID; the
standalone-download and DMG-seed artifact identities remain distinct evidence.

## Official release identity

| Fact | 0.1.20 | 0.1.25 |
| --- | --- | --- |
| build / `sha8` | `17bca090` | `b7190511` |
| build date | `2026-07-17T01:22:41Z` | `2026-07-24T22:38:53Z` |
| manifest | `operon-releases/17bca090/manifest.json` | `operon-releases/b7190511/manifest.json` |
| arm64 updater SHA-256 | `b806b02f36b46606ce4703c2e2758ae17f0336a41feeeea14f824f93ee1e25f9` | `b0de4c8764c58005738cbcf0d0c111935a2caedb11a05483462be32f5545adb7` |
| arm64 DMG SHA-256 | `eb860b3956a55cfe6b815cc4ca66b88ccf9c8ce2633ddc77c038ab50b7926fba` | `cdc0642061983c80e371cbb529035ac3dd8d341a4a8dfd04c8de3085e12bd6ce` |

The downloaded updater and DMG hashes matched those manifests. Both DMGs also
passed `hdiutil verify`.

## Updater and DMG seed are distinct

| Track | 0.1.20 | 0.1.25 |
| --- | --- | --- |
| standalone size | `118027968` | `118980096` |
| standalone identifier | `com.anthropic.operon` | `com.anthropic.operon` |
| standalone Team ID | `Q6L2SF6YDW` | `Q6L2SF6YDW` |
| DMG-seed CLI SHA-256 | `487784354a6a9f7b40b9ba59515ebe434c20ae1c0f31b727ee514cb1812a894a` | `63b0f57aa3b9588ba9e61433d27c78df788f8fe2c1b51842db107d6697e9c03f` |
| DMG-seed size | `118027984` | `118980112` |
| DMG-seed identifier | `com.anthropic.operon.cli` | `com.anthropic.operon.cli` |
| DMG-seed Team ID | `Q6L2SF6YDW` | `Q6L2SF6YDW` |

Both tracks are arm64 and report their expected public version. The standalone
and seed differ by sixteen bytes and by embedded identifier. Strict
`codesign --verify` failed for both versions and both tracks with `invalid
signature (code or signature have been modified)`. The embedded identifier and
Team ID are therefore only local format/identity guards, not cryptographic
proof of official provenance.

The DMG `Info.plist` changed only the short/build version from `0.1.20` to
`0.1.25`; bundle ID remains `com.anthropic.operon`, minimum macOS remains 13.0,
and the icon hash is unchanged.

## Static compatibility delta

Top-level and per-subcommand help for `serve`, `open`, `url`, `status`, `logs`,
`stop`, `update`, and `import` had no 0.1.20 → 0.1.25 delta. CSSwitch-required
flags remain present: `--data-dir`, `--no-auto-update`, `--no-browser`, and
`--detached`.

Normalized embedded route inventory grew from 324 to 330, with six additions
and no removals:

| Added route | Observed method/schema |
| --- | --- |
| `/api/network/status` | `GET`; optional diagnostic `step` and `cause` query |
| `/api/preferences/auto-switch-on-flag` | `GET`; `PUT {enabled:boolean}` |
| `/api/preferences/conda-mirror/credential` | `PUT` credential; `DELETE` credential |
| `/api/preferences/network-proxy` | `GET`; `PUT {proxy:string|null}` with restart status |
| `/api/projects/:pid/archive` | `POST` |
| `/api/projects/:pid/unarchive` | `POST` |

The 0.1.25 package says its saved network-proxy preference is applied at daemon
startup and exposes redacted status. That is package fact only. Whether the
default/no-setting path preserves CSSwitch's local Gateway routing must still be
proven from installed process connections and target traffic.

CSSwitch dependency markers remain present in both versions:

- `ANTHROPIC_BASE_URL`, `/v1/models`, and `/v1/messages`;
- `POST /api/auth/nonce` and `/api/oauth/operon/client_data`;
- `GET /daemon/update-status`;
- `POST /daemon/check-update` and `POST /daemon/apply-update`, including the
  `x-operon: 1` and same-port origin checks.

These observations establish package compatibility signals, not live request
success.

## Reproduced product defect and repair

Before repair, the official 0.1.25 standalone updater failed the repository's
existing real-updater oracle:

```text
left: None
right: Some(.../.claude-science/bin/claude-science)
```

The cause was `PRODUCT_DEFECT`: CSSwitch required the DMG-seed identifier
`com.anthropic.operon.cli` at the standalone updater path, whose actual
identifier is `com.anthropic.operon`.

The initial repair gave the standalone updater track its exact identifier.
Field evidence on 2026-07-29 then reproduced a second valid fixed-path form:
Science 0.1.25 had seeded that path byte-for-byte from the installed App
(`63b0f57a…9c03f`, `com.anthropic.operon.cli`, Team ID `Q6L2SF6YDW`).
CSSwitch v0.8.3 rejected that valid form. The v0.8.4 hotfix accepts both exact
known identifiers while retaining the fixed path, current-user ownership,
non-group/world-writable directories and file, bounded Mach-O size, exact Team
ID, same-open copy, SHA-256 content-addressed read-only snapshot, source
stability recheck, and snapshot reverification. Parser regressions separately
reject an unknown identifier, wrong Team ID, identifier prefix spoofing, and
Team ID suffix spoofing.

After repair:

- official 0.1.20 updater → `official_updated` snapshot: PASS;
- official 0.1.25 updater → `official_updated` snapshot: PASS;
- App-seeded 0.1.25 fixed-path updater → `official_updated` snapshot: PASS;
- official 0.1.20 DMG seed → `installed_app`: PASS;
- official 0.1.25 DMG seed → `installed_app`: PASS;
- installed-App selection preserved the temporary data-dir marker;
- local priority, fingerprint, historical replacement, symlink, and unsafe
  candidate units passed.

Inside the restricted command sandbox, the focused Science group produced 26
PASS, one permission failure, and two intentionally ignored real-artifact
tests. The exact failed case passed on the host using only temporary state and
loopback; the full host focused group then passed 27/27 with the two
real-artifact tests still intentionally ignored. The sandbox-only result is
classified `ENVIRONMENT_BLOCK`, not a product failure.

Isolated `status` for both updater versions and the 0.1.25 seed returned
`{"running":false}`; isolated `stop` reported no daemon/lockfile. `update
--check` was not run because this binary invokes absolute `/usr/bin/security`
for system certificate/credential helpers and the source-phase safety contract
forbids reading real Keychain state. It is not used as an updater oracle.

## Evidence boundary

This document proves official package identity, static 0.1.20 → 0.1.25
differences, the old source failure, and repaired source-level selection against
the four official executables. It does not yet prove:

- a fixed production CSSwitch artifact or installed CSSwitch runtime;
- installed Science start/reopen/stop/restart, Gateway routing, or model/API
  behavior;
- any real provider, account, quota, or paid request;
- Developer ID signing, notarization, Gatekeeper acceptance, tag, public
  release, or published attachment.

`BUG-083-SCIENCE-UPDATER` is therefore only
`source-fixed-product-pending`. Any post-commit source fix invalidates later
artifact, installed, and live evidence and requires a full rerun.

## Installed restart defect found after the first candidate

The first installed `0.8.3` candidate started official Science `0.1.25`
successfully in an isolated HOME and stopped it through CSSwitch's own
**Stop All** action. A subsequent **One-click Start** failed during the
transaction snapshot prepare stage:

```text
隔离 authority 单文件超过安全上限 67108864 bytes（阶段：prepare）
```

The exact isolated file was
`.claude-science/conda/pkgs/cache/mambafm8uj7td3z6`, an `85,323,776`-byte
Science-created Conda cache file. The failure was classified
`PRODUCT_DEFECT`: the 64 MiB per-file authority snapshot budget was below a
normal Science `0.1.25` managed-state file.

The first repair raised only the per-file authority snapshot limit to 128 MiB. The
16,384-entry limit, 512 MiB total limit, authority-root symlink rejection,
regular-file checks, independent-inode copy, streaming I/O, mode preservation, and
device/inode/size/mtime stability checks remain unchanged. The cache is not
excluded because late-failure rollback promises the exact prior authority
object set and bytes. The existing exact-restore regression now additionally
proves that the observed `85,323,776`-byte size passes and 128 MiB plus one
byte remains fail-closed.

The next installed retry crossed that limit and exposed a second normal
Science runtime object:
`.claude-science/runtime/0.1.25-release/agents/operon/.claude/skills/alphafold2`
is a relative symlink to `../../../../skills/alphafold2`. The old snapshot
walker rejected every symlink, including this package-owned runtime link.
The repair keeps authority *root* symlinks fail-closed and never follows an
internal link. It snapshots an internal symlink as an object using `lstat` and
`read_link`, charges its target bytes to the existing budgets, recreates the
link in the private backup, and rechecks device, inode, size, timestamps, and
target stability. The exact-restore regression now covers a mutated relative
link and separately proves that both a symlinked live authority root and a
private backup root replaced by a symlink are still rejected at the walker's
root `lstat`.

The next installed candidate passed the isolated-HOME restart sequence but
failed during a normal-HOME **One-click Start** with the 128 MiB limit. A
metadata-only aggregate probe (no filenames or file contents recorded) measured the normal
Science data tree at 14,826 entries and 1,004,263,008 logical regular-file
bytes, with a 187,050,734-byte largest file and two files above 128 MiB. Merely
raising the per-file limit would not be sufficient because the same normal
tree also exceeds the old 512 MiB aggregate full-copy budget.

The revised source repair uses APFS `fclonefileat` copy-on-write clones for
regular files. Destination traversal opens the rollback parent component by
component from `/` with `O_NOFOLLOW`, then uses `mkdirat`, `openat`, and
`symlinkat` recursively; it never re-resolves an intermediate destination path.
Source traversal is descriptor-bound too: each directory is enumerated from a
pinned fd, child metadata and links use `fstatat`/`readlinkat`, and regular
files are opened with `openat(O_NOFOLLOW)`. Source membership, identity, mode,
length, modification time, public-parent binding, destination entry,
durability, and parent entry are revalidated without reopening a child path.
The completed rollback root and its parent directory are both synced before
authority mutation may begin. Only
`ENOTSUP` and `EXDEV` may use byte-copy fallback, which retains the old 128 MiB
per-file and 512 MiB per-scope full-copy limits. Other clone errors fail closed,
and a failed fallback unlinks the pinned destination entry.

The next normal-HOME live profile switch crossed the 2 GiB logical-total
boundary after Science's Conda cache grew. A metadata-only diagnostic reported
24,974 entries and 2,147,791,174 logical bytes, only 307,526 bytes above the
old cap, when the bounded walker stopped at the first total-limit violation.
The switch's provider scratch request passed, but the subsequent Science
model-binding restart failed closed with
`authority_snapshot_total_limit` and rolled back to the prior profile. This is
classified `PRODUCT_DEFECT`, not an upstream provider failure.

A complete follow-up metadata probe measured 32,519 entries, 26,784 regular
files, 2,388,270,307 logical regular-file bytes, and a 189,776,400-byte maximum
regular file; zero files exceeded the independent 512 MiB per-file bound. The
old 32,768-entry limit consequently had only 249 entries of headroom.

The first repaired installed candidate then allowed Science 0.1.25 to complete
its first-run R/Conda environment creation. A second metadata-only probe, taken
before the next live DeepSeek-to-Qwen model-binding restart completed, measured
75,588 entries, 66,911 regular files, 4,386,369,604 logical regular-file bytes,
and the same 189,776,400-byte maximum regular file. The transaction then failed
closed at 65,537 observed entries with `authority_snapshot_entry_limit` and
reported incomplete recovery at `science_start`. This later tree exceeded both
the 65,536-entry and 4 GiB logical limits, so that candidate remained a
`PRODUCT_DEFECT`; its source, artifact, installed, and live evidence was
invalidated. The managed processes were stopped before source repair resumed.

The `science_start` recovery degradation exposed a separate control-flow
defect. The inner quiesce/capture path had already restarted and committed a
fresh managed receipt for the exact prior Science process before returning the
capture error. Profile-switch rollback then unconditionally stopped that
healthy recovered process and entered one-click capture a second time, which
repeated the same fail-closed limit error and left Science stopped.

The reconcile boundary now returns a typed disposition:
`PriorScienceRestored` only after pre-mutation capture recovery or complete
post-snapshot compensation has restarted the prior managed Science;
`RestartRequired` covers every other failure. Profile-switch restores the old
config and Gateway first. It skips the former forced restart only when the
typed disposition is restored and the remembered runtime, fresh managed
receipt, and live health all revalidate exactly. Otherwise the existing
fail-closed forced restart remains. A persistent capture-failure Acceptance
regression exercises the real profile-switch transaction and proves the old
profile/journal return, the local Gateway secret may rotate, the fresh receipt
matches the sole listener, the original PID is gone, and the recovered Science
remains safely stoppable without a second capture.

The logical per-scope limits are therefore raised to 131,072 entries and 8 GiB,
while the independent 512 MiB per-regular-file limit remains. The APFS clone
path does not duplicate those logical bytes physically. More importantly, the
non-clone fallback remains limited to 128 MiB per file and 512 MiB per scope,
so this compatibility change does not authorize a multi-GiB byte-copy fallback.
The budget regression covers the latest observed 75,588-entry /
4,386,369,604-byte pair. A separate sparse clone-and-restore regression covers
that logical byte total without allocating the payload physically; it does not
pretend to create 75,588 filesystem entries. Boundary tests
prove exactly 131,072 entries and 8 GiB pass while either limit plus one still
fails closed.

Internal symlinks remain copied as link objects;
authority-root symlinks and special files remain rejected. User-visible walker
diagnostics report stable code, scope, category, numeric bounds, and errno only,
without absolute paths or entry names. Focused tests cover the observed 0.1.25
tree shape with sparse files, independent inode and exact restore behavior,
forced `ENOTSUP`/`EXDEV` fallback, unexpected clone errors, fallback cleanup,
fallback limits, restore fallback, directory mutation, typed prior-Science
recovery reuse, and path/key canaries.
An adversarial regression replaces a destination directory entry with a
symlink during capture: the copy remains bound to the original directory fd,
does not write into the foreign target, and fails closed on final entry
revalidation. A matching restore regression rebinds the live authority parent:
restore stays on the pinned parent, never writes through the foreign symlink,
and fails closed when the public parent binding no longer matches. Restore also
requires every private tree root and its public parent binding to retain the
dev/inode/type identity recorded at capture before and after copying; the
backup walk itself reads only through the pinned parent fd. A backup-parent
replacement regression proves the foreign tree is neither read nor mutated.
Completion sync failure likewise fails closed and registers the rollback root
for cleanup.
Cleanup first atomically renames the exact dev/inode-bound root to a deterministic
managed tombstone, syncs the pinned parent, deletes recursively through dirfds,
and syncs the parent again before clearing the pending manifest. A forced parent
sync failure keeps the manifest and tombstone for a later exact-identity retry,
including the crash window after marker deletion. Registration accepts only the
root dev/inode captured immediately after creation; replacing the public root
before registration cannot add a marker, bless a manifest entry, or delete
either the replacement or displaced original.
Copy-on-write does not reserve the full logical size up front: later writes to
live Science files may materialize shared APFS blocks. An `ENOSPC` from clone,
fallback, permission, or sync work is therefore a disk-capacity environment
failure for the current transaction, not evidence that Science data is corrupt.

This later source repair invalidates every earlier source-gate, artifact,
installed, local-mock, and live-provider result. A new clean commit and complete
rerun are required before the installed restart defect can move beyond
`source-fixed-product-pending`.
