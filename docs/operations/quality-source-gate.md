# Trusted source gate v1

Status: frozen implementation specification for the v0.8.3 regression-hardening
worktree. This document does not assert that the source gate is implemented or
green.

## 1. Goal and evidence boundary

This phase replaces the known-unreliable source-only S0 gate with one fixed,
catalog-bound, multi-suite source gate built on the existing trusted run-evidence
kernel.

A valid PASS completion seal may establish both:

- `RUN-EVIDENCE-GREEN`: every suite in the exact approved source selection has
  one canonical, identity-bound observation and `TestResultV1`, and the sealed
  aggregate is PASS;
- `SOURCE-GREEN`: `RUN-EVIDENCE-GREEN` is bound to the clean exact-HEAD source
  snapshot of the formally frozen detached candidate, the exact source
  catalog/gate/tool/environment inputs, and the `GATE-SOURCE` selection.

No non-PASS seal establishes either green claim. Standard output is only a
summary; the completion seal and its recursively validated artifacts are the
authority.

These claims remain source/unit claims. They do not establish an isolated Test
App, artifact, DMG, installed runtime, live provider or Science behavior,
signing, notarization, Gatekeeper, release readiness, or public release.

## 2. Non-goals

- Do not rebuild or redesign the RUE-01 through RUE-06 contracts, atomic store,
  clean snapshot, fixed RUE05A attempt, retry, single-suite completion, or
  dedicated terminal publication.
- Do not build an App, DMG, or release artifact.
- Do not install or launch CSSwitch or Science.
- Do not access network, real credentials, Keychain, databases, SSH material,
  real Science state, `/Applications`, or port 8765.
- Do not fix model switching, provider, DeepSeek, Science, database, SSH, MCP,
  updater, signing, notarization, packaging, or release defects.
- Do not run ignored real-machine, installed, public-GitHub, provider, or
  Acceptance tests.
- Do not introduce concurrency. Source suites execute sequentially in catalog
  order.
- Do not add public scenario, command, argv, policy, environment, suite, retry,
  or fault-injection overrides.
- Do not attach the formal candidate checkout to a branch, advance any branch
  before final acceptance, or use the candidate checkout for implementation.

Product and late-layer records remain versioned regression inputs. They block
this phase only if they expose a reproducible false green, evidence promotion,
or unsafe failure inside the approved source-gate path.

## 3. Approved catalog disposition

### 3.1 Required executable source selection

`GATE-SOURCE` selects exactly these suites, in this order:

1. `SUITE-QUALITY-METADATA`
2. `SUITE-QUALITY-FOCUSED`
3. `SUITE-RUN-EVIDENCE-CONTRACT`
4. `SUITE-QUALITY-INVENTORY`
5. `SUITE-PY-OFFLINE`
6. `SUITE-RUST-GATEWAY`
7. `SUITE-PY-LOOPBACK`
8. `SUITE-SHELL-SCRIPTS`
9. `SUITE-RUST-DESKTOP`
10. `SUITE-RUST-CODEX-NETWORK`
11. `SUITE-RUST-SKILL-PACKAGE`
12. `SUITE-MJS-FRONTEND`
13. `SUITE-ORPHAN-SKILL-BRIDGE`
14. `SUITE-ORPHAN-SKILL-BOUNDARY`
15. `SUITE-SOURCE-GATE-CONTRACT`

Every selected suite has one fixed `command_argv`, one stable entrypoint ID,
`adapter_protocol=source-observation.v1`, `retry_policy=none`, a bounded timeout,
an exact environment allowlist, exact fixture/build-recipe/source paths, and a
reviewed expected-test identity contract. The public CLI cannot select a subset.

`SUITE-RUST-GATEWAY` precedes `SUITE-PY-LOOPBACK`. The loopback suite consumes
only the exact current-source gateway binary produced at the snapshot-bound
debug path. It cannot use `CSSWITCH_LOOPBACK_TEST_CMD` and has no retry.

The Rust suites enumerate all four desktop Cargo manifests. Their observations
must expose default-run totals and ignored tests. A PASS is allowed only when
the ignored identifiers equal the catalog's explicit source-gate exclusions;
an unknown, missing, or newly ignored test blocks the gate. The exclusions may
contain only tests whose checked-in reason names a real-machine, installed,
public-network, provider, or Acceptance boundary.
Each approved ignored identifier is bound in the snapshot identity inventory
to its exact checked-in reason and one of those five boundary enums. The closed
adapter configuration carries that mapping to the Rust parser; a bare ignored
state, reason drift, missing/extra mapping, or illegal boundary blocks PASS.

Python, Node, Rust, and shell adapters must surface observed skipped, ignored,
todo, not-run, or environment-blocked states. A required unapproved state cannot
be normalized to PASS.

Each framework suite binds the sorted exact discovered test IDs in the catalog.
Python IDs use the full `unittest` test ID; Node IDs include the test file and
reported test name; Rust IDs include the Cargo manifest, test binary/target, and
libtest ID. Shell/meta suites bind a nonempty exact component ID list, with one
component for each directly invoked script or validator command. Discovery and
execution are separate observations: every required discovered ID must execute
exactly once unless it is in an explicitly reviewed exclusion list. Zero
discovery, duplicate IDs, an unknown/missing ID, a discovered/executed mismatch,
or a changed exact count produces typed NOT-RUN/PARTIAL evidence and cannot seal
PASS. A command exit of zero never overrides this predicate.

### 3.2 Replaced or excluded entries

- `SUITE-RUE05A` remains the nonrecursive fixed runner-kernel node. It is not
  re-executed as a nested source suite; `SUITE-RUN-EVIDENCE-CONTRACT` covers its
  source/unit regression tests.
- `SUITE-ORPHAN-AGGREGATOR` and `SUITE-ORPHAN-RETRY` are retired to
  `SUITE-SOURCE-GATE-CONTRACT`. Their historical shell behavior remains
  regression input, not gate authority.
- `SUITE-LEGACY-RUN-ALL` and `GATE-S0-LEGACY` are retired to the new source CLI
  and `GATE-SOURCE`. The compatibility `test/run_all.sh` may only forward the
  exact new CLI invocation and must reject the old `--require-release-ready`
  vocabulary.
- `SUITE-MODEL-CATALOG-ACC` is reclassified as non-source
  `not-yet-automatable` Acceptance/artifact inventory. Its current command
  builds and signs temporary App bundles and therefore must not run in this
  phase.
- `SUITE-QUALITY-ARTIFACT` and all `SUITE-PRODUCT-*` entries remain NOT-RUN and
  outside `GATE-SOURCE`.
- Product gates and `GATE-QUALITY-RELEASE` remain separate. The latter is still
  a source impact-coverage gate, not release readiness.

## 4. Frozen bottom ABI

### 4.1 Existing kernel ABI

The following remain backward compatible and keep all existing RUE05A tests:

- `adapter-result.v1`
- `TestResultV1`
- `run-manifest.v1`
- `evidence-manifest.v1`
- `completion-seal.v1`
- `RunLayout`, clean-commit snapshot, no-clobber publication, first failure,
  and dedicated terminal seal semantics
- RUE05A public CLI, fixed identity, fixed retry, and single-suite claim

Existing RUE05A artifacts remain valid without source-specific fields.

### 4.2 `source-observation.v1`

Each source adapter emits exactly one canonical observation before its adapter
process exits. The closed schema contains:

- `schema`, `run_id`, `suite_id`, `entrypoint_id`, `attempt_index=0`;
- `command_argv_sha256`, `environment_sha256`, and `tool_identity_sha256`;
- the raw test-command process result: exactly one of `process_exit` or
  `process_signal`, or a typed pre-exec/timeout state;
- `adapter_exit`, using the existing normalized runner exit vocabulary;
- observed `executed`, `passed`, `failed`, `skipped`, `ignored`, `todo`, and
  `not_run` counts, each bounded and nonnegative;
- sorted exact `discovered_test_ids`, `executed_test_ids`,
  `failed_test_ids`, and ignored/skipped/todo/not-run identifiers; framework
  adapters must provide identities rather than only summary counts. Failure
  identities are unique top-level catalog IDs: multiple failing subtests of
  one parent remain one failed identity;
- bounded stdout/stderr byte counts, SHA-256 digests, and truncation flags;
- `derived_tool`, which is `null` for every suite except
  `SUITE-PY-LOOPBACK`; that suite binds exactly one held
  `csswitch-gateway` record with its private path, regular-file mode, size, and
  SHA-256;
- `outcome_hint`, `classification_hint`, and `reason_code`.

The parent observes the adapter process status independently. Parent status,
observation `adapter_exit`, raw command state, counts, identity digests, and
approved state table must agree. A marker or observation cannot override a
contradictory process status.

The raw command result is preserved in the observation; `TestResultV1` keeps
the existing normalized runner-exit ABI. The source aggregate pairs exactly one
observation and one `TestResultV1` for each expected suite.

### 4.3 Evidence manifest extension

`evidence-manifest.v1` gains one optional, closed `source_observations` array.
RUE05A omits it. A source run requires it and enforces exact ordered bijections:

```text
run.expected_suites
  == evidence.test_results identities
  == evidence.source_observations identities
  == GATE-SOURCE.required_suite_ids
```

Each observation and result is canonical, no-clobber published under the
existing private run layout, re-read by held publication identity, and bound by
the evidence manifest digest. Completion uses the existing dedicated exclusive
terminal seal publication as the last fallible success operation.

Each `source_observations` item is a closed reference with exactly
`suite_id`, `entrypoint_id`, `path`, and `sha256`. Its path is the fixed
suite-derived `results/SUITE-*.observation.json` leaf. The corresponding
`TestResultV1` remains at `results/SUITE-*.json`. Both use the existing
`results`-area no-clobber publisher and held-publication re-read; the distinct
closed leaf forms cannot collide or substitute for one another. Observation
references and test-result references are independently ordered, unique, and
bijective with `expected_suites`; neither array can substitute for the other.

This layout is an additive consumer of the existing private publisher ABI, not
a `RunLayout` extension. `atomic_store.py`, its descriptor set, publication
algorithm, and public call surfaces remain unchanged.

### 4.4 Aggregate state

- all results PASS: `PASS / runner_exit 0`;
- any test failure: `FAIL / runner_exit 10`;
- any infra failure or hard timeout: `FAIL / runner_exit 12` or `13` according
  to the existing reason table;
- any environment block, real-machine requirement, unapproved skip/ignore,
  not-run, or quarantine: `BLOCKED / runner_exit 11` or `13`;
- missing, duplicate, malformed, contradictory, replayed, late, drifted, or
  partially uncertain authority: no completion seal and fail-closed runner exit.

There is one attempt per source suite and no retry. An implementation test may
simulate a recovered second execution, but it must prove that public source
execution cannot schedule or seal it.

## 5. Execution and authority model

The new source executor reuses the existing bound-fixture copy, process-group
supervision, kqueue exit cutoff, terminal drain, output bound, reaping, and
adapter ACK mechanics. Those mechanics may be extracted into a private shared
primitive while preserving the existing RUE05A call surface and behavior. They
must not be separately reimplemented with a second weaker subprocess loop.
The common timeout clock, kqueue/process-exit observation, process-group cleanup,
and sole reap owner begin immediately after a successful spawn. Any framed
configuration write is nonblocking and occurs inside that same supervised event
loop. A blocked write, `EPIPE`, short/failed write, kqueue setup failure, or any
other post-spawn exception must close the transport, terminate the process
group, drain bounded output, and reap exactly once before returning a typed
non-PASS result.

The fixed source adapter is itself snapshot-bound. It launches only the exact
catalog command with `shell=False`, a canonical repo-root cwd, no stdin, a new
process group owned by the existing supervisor, and a sanitized environment.
Shell entrypoints use the exact `/bin/bash` argv; no `eval`, command string, or
inherited shell function is accepted.

The raw test child and every descendant must have the observation transport,
adapter ACK transport, held fixture FD, and other runner-authority descriptors
closed before exec. Only ordinary captured stdout/stderr descriptors may cross
that boundary. Descriptor inheritance or a descendant retaining an authority
transport is an infra failure and cannot seal.

The source CLI:

```text
/usr/bin/python3 -I test/quality/source_gate/cli.py run \
  --output-root ABS_EMPTY_0700_DIR
```

is the only public entry. Output-root, isolated-Python, dependency, Git,
snapshot, catalog, gates, schemas, runner, fixture, build recipe, toolchain,
environment, and final-input checks follow the fixed RUE05A fail-closed model.
The CLI uses an external, empty, euid-owned `0700` root and leaves evidence in
place.

The public CLI must bind the executable that is actually running the parent
process, not only `sys.executable`, argv text, or the isolated-mode flag. On the
approved macOS source-gate host, Python authority is one closed composite tool
record established before preflight or output-root mutation:

- the fixed `/usr/bin/python3` launcher has its own held/named executable
  identity, size, mode, owner, link policy, and digest; and
- `proc_pidpath(getpid())` supplies the current Mach process-image path, which is
  independently opened and bound by the same fields as a
  `process_executable` subrecord.

The launcher and process image are not required to be the same inode: the
approved system launcher enters the Xcode Python framework image. The current
kernel-reported image must instead equal the frozen `process_executable`
subrecord captured for this invocation, while the launcher must independently
equal the frozen `/usr/bin/python3` record. An alternate process image, a
spoofed argv or `sys.executable`, an unavailable/truncated kernel path, or drift
in either held/named identity returns non-PASS and cannot create a run layout or
seal. The run manifest and tools digest bind both subrecords.

All suites run with a per-run temporary HOME and without proxy, credential,
provider, OAuth, SSH, database, Science, or command-override variables.
Loopback tests may bind only dynamic loopback ports. Rust runs offline. If an
offline, credential-free dependency view cannot be established, the Rust suite
is ENV-BLOCKED rather than reading Cargo credentials or using network.

There is no independent `quality/quality-kernel.v1.json` input. The quality
kernel contract is represented only by the bound
`quality/schema/quality-kernel.v1.schema.json` inside the closed schema bundle.
Production preflight and every recheck must read that real schema path and must
not probe, claim, or synthesize the nonexistent legacy-looking path.

The Cargo view binds the exact recursively inventoried content under
`registry/index`, `registry/cache`, and `registry/src`. If any selected
`Cargo.lock` contains a Git source, `git/db` and `git/checkouts` become
mandatory bound roots as well; a missing root blocks before execution. The
closed inventory orders canonical UTF-8 NFC relative paths by byte order and
binds every directory type/mode plus every regular file mode, size, and
SHA-256. It rejects symlinks, special files, file hardlinks, foreign ownership,
unreviewed modes, unsafe paths, and unstable identities. The fixed bounds are
100,000 entries, 2 GiB total regular bytes, 128 MiB per file, 4,096 UTF-8 bytes
per path, and 64 path components. The gate copies only those held, verified
bytes into the private per-run Cargo home, verifies the source again after the
copy, and requires the private inventory to equal the bound source inventory.
Cargo receives only that private content-bound view and a fixed offline
configuration; credentials and ambient Cargo configuration are not copied or
read, and the real Cargo cache is never a child write target. The fixed
`config.toml` mode, owner, link count, size, and digest are re-read with the
private dependency inventory at every post-materialization recheck.

The selected committed lock inputs are exactly
`desktop/src-tauri/Cargo.lock`, `desktop/gateway/Cargo.lock`, and
`desktop/skill-package/Cargo.lock`. The ignored, uncommitted
`desktop/codex-network/Cargo.lock` is not an input and must not be read or
claimed. The codex-network manifest resolves only from the already bound,
private, offline registry view; creation of ignored Cargo state cannot add
unbound dependency bytes.

`SUITE-PY-LOOPBACK` never consumes a repository `target/`, staged App binary, or
pre-existing gateway. Its single supervised raw command is a snapshot-bound
source-gate driver which:

1. requires a newly created, held, empty per-run gateway target directory under
   the private run layout;
2. runs the bound Cargo executable with `build --offline --locked` for the
   committed `desktop/gateway/Cargo.toml` and `csswitch-gateway` binary, using
   only the private Cargo view and that private target;
3. opens the produced gateway with no symlink following, binds its path,
   regular-file mode, owner, link count, size, and SHA-256 before executing the
   fixed loopback unittest command;
4. keeps the build and unittest descendants in the one outer supervised process
   group and propagates build/spawn/test failure without retry; and
5. emits one framed derived-tool record which the parent independently re-reads
   and re-hashes after the suite. The observation, parent binding, and private
   path must agree before publication.

The fixed driver argv, driver bytes, Cargo/Python identities, manifest and lock,
private target path, environment, and derived gateway record are recursively
bound by the source observation and evidence seal. Ordinary stdout text cannot
create or replace the derived-tool authority.

Tool lookup is fixed-policy, not inherited-PATH authority. The run manifest
binds the selected absolute Python, Bash, Node, Cargo, Rustc, and Git command
paths, resolved executable identities, sizes, modes, owners, link policy, and
digests. The child PATH is constructed only from those selected tool
directories plus system paths.

The source CLI rechecks Git and all bound inputs:

1. before run-layout creation;
2. after clean snapshot publication;
3. before and after every suite;
4. before result/evidence publication;
5. immediately before terminal seal publication.

Any drift prevents green. The worktree must be clean at source CLI start and at
every recheck.

### 5.1 Formal detached candidate authorization

The target implementation worktree remains:

```text
/private/tmp/CSswitch-v083-regression-hardening
```

After Phase C targeted gates and pre-formal targeted review PASS, the
implementation is frozen. A private preparation procedure may then create one
unreferenced candidate commit and one temporary detached checkout solely for
formal clean acceptance. This is the only authorized exception to the
target-worktree-only rule.

Candidate preparation must:

1. recheck the target branch, base HEAD, origin/main, worktree list, index, and
   full status;
2. require that every tracked or untracked change is inside the allowed
   modification set and is a regular file with a supported Git mode; reject
   rename, deletion, submodule, symlink, special file, intent-to-add, conflicted
   index, sparse index, split index, or staged/worktree disagreement;
3. create a private temporary index outside every repository worktree, seed it
   from the unchanged target HEAD, hash the exact held worktree bytes with
   `--no-filters`, and update only the allowlisted candidate paths by explicit
   cacheinfo; no wildcard `git add`, clean/smudge filter, hook, signing, editor,
   or inherited Git configuration is authority;
4. write one candidate tree and one unsigned candidate commit whose sole parent
   is the unchanged target HEAD, without creating or updating a branch, tag, or
   other persistent ref;
5. independently enumerate the candidate tree and prove that each changed blob
   mode, size, and SHA-256 equals the frozen target bytes and that the candidate
   changed-path set equals the reviewed allowlisted diff;
6. create one new path under `/private/tmp` with
   `git worktree add --detach <path> <candidate-commit>`;
7. verify the new checkout is detached, clean, exact candidate HEAD, and not
   shared with or attached to any existing branch.

The candidate commit and detached checkout are a formal-review vehicle, not a
target-branch checkpoint. Before final acceptance they must not update
`codex/v083-regression-hardening`, another branch, a tag, a PR, or a remote.
All formal complete tests, schema checks, evidence readback, code review, root
smoke, and final xhigh acceptance use the detached candidate path explicitly.
Implementation edits remain confined to the target worktree and stop once the
candidate is frozen.

If a formal reviewer returns BLOCK, or either the target frozen bytes or the
detached candidate changes, the candidate review is invalid. Stop with the
detached checkout and target branch preserved. Do not delete, prune, repair,
reattach, reset, or replace the detached checkout without new user direction.

Only after every formal gate and final xhigh acceptance PASS may the target
branch become the reviewed candidate. The finalization procedure must:

1. acquire one explicit finalization lock whose scope is the target worktree
   identity, original base HEAD, accepted candidate commit, and real index path;
   every in-scope target writer and finalization helper must respect this lock;
2. while holding the same lock, prove the target branch still names the
   original base HEAD, the target worktree bytes still equal the candidate
   tree, the detached checkout is clean at the accepted candidate commit, and
   no real-index lock/conflict or other in-scope writer exists;
3. while still holding the lock, populate the target worktree's real index from
   that exact candidate tree;
4. immediately before ref advancement and without releasing the lock, re-read
   the target branch, write/verify the real-index tree equals the candidate
   tree, revalidate the exact target worktree byte/mode identity against that
   index, and prove no unknown/untracked nonignored path or index/worktree drift
   appeared;
5. atomically compare-and-swap only
   `refs/heads/codex/v083-regression-hardening` from the original base HEAD to
   the accepted candidate commit;
6. verify target HEAD, index, and worktree are clean and equal the candidate
   before releasing the finalization lock.

If index preparation or ref compare-and-swap fails, stop and preserve all state;
do not reset, checkout, clean, or synthesize a different commit. The detached
checkout is not automatically removed after PASS.

## 6. Threat model

The gate must prevent these current-scope false-green paths:

- a pass marker or adapter PASS followed by nonzero child status;
- a failing raw test command normalized to adapter PASS;
- missing, malformed, extra, duplicate, late, replayed, or identity-swapped
  observations/results;
- catalog omission, gate omission, unexpected suite, wrong order, command or
  environment override, and nested source-subset execution;
- hidden retry or retry recovery normalized to PASS;
- skipped, ignored, todo, not-run, or env-blocked work silently counted PASS;
- zero-test success, duplicate discovery, or a catalog/discovered/executed test
  identity or exact-count mismatch;
- a fifth Cargo manifest, an omitted registered manifest, an unknown ignored
  Rust test, or source discovery/catalog drift;
- timeout, output overflow, descendant FD leak, process-group survivor,
  incomplete terminal drain, or reaping ambiguity;
- config transport blocking or failing after spawn but before supervision,
  leaving an unreaped adapter or unowned process group;
- a non-bound Python executable invoking the public CLI while evidence falsely
  claims `/usr/bin/python3`;
- source, fixture, build-recipe, schema, catalog, gate, tool, environment, Git
  ref, index, or worktree drift before sealing;
- nested Cargo dependency content added, removed, renamed, replaced, modified
  in place, rebound through a symlink or hardlink, or changed during inventory
  traversal while the parent registry directory identity remains unchanged;
- a stale, pre-existing, staged, repository-target, identity-swapped, or
  unbound gateway executable consumed by loopback tests;
- output-root rebind, result/evidence name preoccupation, partial publication,
  observation/result leaf collision or substitution, completion replay,
  terminal conflict, or post-seal error reversal;
- artifact/Acceptance/product/manual entries promoted into the source claim;
- stdout text upgraded above the recursively validated completion seal.

The gate trusts the OS kernel, the exact bound tool binaries, the snapshot-bound
adapter, and cooperating current-euid writers that obey the run-layout lock. As
with the existing kernel, it does not claim protection from root or a malicious
same-UID actor that bypasses locks and deliberately races arbitrary pathname
syscalls outside the approved APIs. Expanding this boundary requires a concrete
current-scope false-green path.

Framework transcript parsing additionally trusts the snapshot-bound test
program to return normally through the selected framework runner. A descendant
may write ordinary stdout/stderr, so one per-test token is never completion
authority: Python requires one exact, count-consistent terminal unittest footer,
and a descendant-forged footer followed by the real runner footer is rejected
as duplicate. This phase does not claim protection from malicious checked-in
test code that deliberately terminates its own framework process with RC 0
after forging the entire transcript and suppressing the real footer. That is a
different malicious-source threat model and requires a separate non-stdio
framework-result ABI rather than another textual heuristic.

Python `subTest` output is bound to its exact catalog parent identity. A
failing subtest may leave its parent verbose prefix unterminated and concatenate
the next top-level prefix on the same physical line. The parser must recover
both exact identities, count the parent once in `failed_test_ids`, and reconcile
the terminal `failures` and `errors` fields against failure-detail events rather
than unique failed parents. Unknown parents, ambiguous concatenation, missing
failure-detail authority, or event/footer disagreement remain malformed. Raw
stdout/stderr content is not published because it may contain secrets; only
bounded byte counts, digests, and truncation flags are retained.

On Darwin, the source runner supplies every suite with the shared private
`<output-root>/state/t` directory as `TMPDIR`. This deliberately short path
leaves a fixed 64-byte descendant budget beneath Darwin's 103-byte AF_UNIX
pathname limit. Before creating `state`, `evidence`, or any run record, the
runner rejects an output root whose filesystem-encoded `state/t` path plus that
budget exceeds 103 bytes. The directory is created mode `0700` through held
output-root and state-directory FDs, then its directory type, current-euid
ownership, mode, device and inode identity are checked through the held FD,
pathname, and a no-follow reopen. Those bindings are checked after planning,
before and after every suite, before evidence aggregation, and immediately
before seal. Ordinary suite-created children may appear and disappear; a
chmod, rename, replacement, symlink, or binding loss fails closed. `HOME` and
`CARGO_HOME` remain private per-run directories. This is a source-test runtime
capacity rule and does not change product provider behavior or a public CLI.

## 7. Fault-injection boundary

Fault injection is allowed only in source-gate unit/E2E tests through private
dependency seams and versioned fake fixtures. It may replace spawn/wait/kqueue,
adapter bytes, tool inventory, Git responses, catalog/gate bytes, filesystem
stat/open/read/fstat/rename/fsync/close results, and time.

The private Cargo dependency-inventory seam exposes only fixed traversal
events (`before-list`, `after-list`, `before-closing-list`, `before-open`,
`before-read`, and `after-read`) to temporary-fixture tests. It cannot change
roots, limits, commands, environment, or public CLI behavior. Tests use it to
inject add/remove/rename, name rebind, and in-place mutation races; production
passes no hook. The initial canonical inventory and digest are recomputed and
compared after snapshot, around every suite, before evidence, and immediately
before seal.

Closure tests may additionally inject bounded failures through private seams at
post-spawn config write/kqueue/reap transitions, kernel process-executable
identity lookup, private gateway-target creation, Cargo build/spawn/RC, and
pre/post-test gateway stat/open/read/fstat/path binding. They also cover the
Darwin source-TMPDIR byte boundary and held-directory chmod, rename,
replacement, symlink, and per-suite recheck failures. These seams cannot change
public argv, commands, tools, paths, environment, retry policy, or production
behavior.

Fault injection must use temporary roots, fake repositories, fake tools, and
fake suite commands. It must not be exposed through the public CLI, inherited
environment, catalog command strings, real product entrypoints, network,
credentials, installed apps, Science, databases, SSH, or `/Applications`.

The complete adversarial matrix is implemented once before the first frozen
implementation review. Later closure work adds only regressions for accepted
findings; it does not repeatedly redesign the matrix.

## 8. Implementation phases and gates

### Phase A — contracts and metadata

- add the source observation schema and backward-compatible evidence extension;
- register `GATE-SOURCE`, exact suite dispositions, timeouts, command argv,
  exclusions, and fixed selection;
- update metadata validation and malicious contract tests;
- add `CHG-SOURCE-GATE`; update only test-system bug records whose historical
  false-green path this phase actually closes.

Gate: direct and module contract/quality tests, schema validation, metadata, and
targeted fresh review.

### Phase B — one-suite source execution

- extract/reuse the trusted supervisor primitive without changing RUE05A
  behavior;
- execute one fixed fake source suite through observation, normalized result,
  evidence, and seal;
- prove raw RC, counts, digests, timeout, output, descendants, and drift fail
  closed.

Gate: all existing run-evidence tests plus the new targeted source-executor
matrix.

### Phase C — exact multi-suite catalog and source seal

- exercise the exact 15-suite ordered selection only through fixed fake
  commands/private seams; this validates orchestration and is not a real
  complete source run;
- enforce observation/result/catalog bijection and aggregate precedence;
- add fixed CLI and compatibility `run_all.sh` forwarding;
- reclassify Acceptance/artifact and retire the old source gate without
  changing product behavior.

Gate: the complete adversarial matrix, targeted CLI E2E, metadata, impact-pr,
and diff checks.

### Phase D — frozen formal acceptance

- freeze one allowlisted target diff, candidate tree, candidate commit, and
  detached checkout identity using §5.1;
- testing/evidence reviewer performs the only complete source run, all schemas,
  quality and runner tests, metadata, impact-pr, real exit-code/evidence
  readback, and records exact RCs in the detached candidate checkout;
- code reviewer inspects state machine, TOCTOU, concurrency assumptions,
  candidate-preparation authority, process cleanup, and scope, running targeted
  tests only in the detached candidate checkout;
- the testing/evidence reviewer is the only actor that performs the real
  complete 15-suite source run;
- formal acceptance is pass-without-candidate-changing-findings: any reviewer
  request that requires a source, test, metadata, Spec, candidate-tree, or
  evidence-authority change is BLOCK and ends this Goal turn under §5.1;
- findings that require no candidate change may only clarify the review report;
  they cannot alter evidence or convert a non-PASS result;
- if both formal reviewers PASS, perform one fresh high-level dual acceptance
  over the unchanged candidate; neither fresh reviewer repeats the complete
  source run;
- root rechecks exact hashes/status and key smoke only;
- fresh Sol xhigh performs the important-subphase/final clean acceptance.

Before candidate construction, ordinary targeted review findings are batched
and closed according to review process v2. After candidate construction, no
candidate-changing closure is authorized. No reviewer BLOCK candidate may
advance a branch. A requested fix invalidates the candidate and its formal
review; because a BLOCK candidate checkout may not be deleted without new user
direction, formal BLOCK is a hard stop for this Goal turn.

## 9. Allowed modification set

Implementation may modify only:

- `docs/README.md`
- `docs/operations/quality-kernel.md`
- `docs/operations/quality-source-gate.md`
- `quality/schema/quality-kernel.v1.schema.json`
- `quality/schema/evidence-manifest.v1.schema.json`
- `quality/schema/source-observation.v1.schema.json`
- `quality/test-catalog.v1.json`
- `quality/release-gates.v1.json`
- `quality/requirements.v1.json`
- `quality/production-paths.v1.json`
- `quality/changes/v0.8.3/CHG-SOURCE-GATE.json`
- `quality/bugs/BUG-083-RC.json`
- `quality/bugs/BUG-083-RETRY.json`
- `quality/bugs/BUG-083-ORPHANS.json`
- `quality/bugs/BUG-083-RUST-COVERAGE.json`
- `test/run_all.sh`
- `test/quality/validate_quality_metadata.py`
- `test/quality/test_quality_kernel.py`
- `test/quality/test_run_evidence_attempt0_runner.py`
- `test/quality/run_evidence/attempt0_runner.py`
- `test/quality/run_evidence/manifest_contracts.py`
- new files below `test/quality/source_gate/`
- new source-gate fixtures below `test/quality/fixtures/source_gate/`
- new `test/quality/test_source_gate_*.py` files
- `desktop/skill-package/src/science.rs`, limited to `cfg(test)` timeout
  constants and the matching forced-timeout fixture; production-compiled bytes
  and behavior must not change
- `test/test_provider_mock_scenarios.py`, limited to synchronizing existing
  durability and phase-order assertions with completed request handling and
  the `hits.jsonl` fsync
- `test/test_skill_runtime_boundary.py`, limited to updating the existing
  source-order assertion to the production traced gateway verification call
- `desktop/src-tauri/src/commands/runtime.rs`, limited to clarifying the two
  existing ignored test reasons as Acceptance-boundary exclusions
- `desktop/skill-package/src/github.rs`, limited to clarifying the existing
  full-size mock-GitHub ignored test reason as an Acceptance-boundary exclusion

`atomic_store.py`, clean snapshot, RUE retry/aggregation/CLI, existing schemas
other than the evidence extension, product source, legacy layer scripts, audit
documents, AGENTS/rules/context, and other worktrees are read-only. A required
change outside this set is a Spec change and must be reported and reviewed
before editing.

The five exact exceptions above are the minimal v5 closure delta justified by
the sealed v4 formal run and explicitly approved by the user on 2026-07-27.
They do not authorize any Science feature, provider behavior, product runtime,
public command, retry, ABI, catalog-suite, or threat-model expansion. The v4
evidence established, respectively: a default skill-package test timeout
caused by a test-only two-second contraction of the production ten-second
  bound; provider-mock assertions racing the handler's state transition and
  durable append; and a boundary assertion naming the pre-trace gateway
  verification call. Their closure must retain the same 15-suite selection,
  approved ignored-ID sets, sequential no-retry execution, and fail-closed
  observation contract.

The user additionally authorized future evidence-backed scope amendments of
this same class without a separate approval round. Such an amendment is valid
only when a fresh reviewer or root-cause audit identifies a current frozen-Spec
blocker, the added paths and edits are the smallest closure for that blocker,
the amendment is recorded here and in the change record before editing, and
independent pre-freeze review confirms that it adds no product feature,
production behavior, public ABI/CLI, retry, release, credential, real-state, or
network authority. Any expansion that fails one of those predicates still
requires explicit user direction. Candidate construction, branch advancement,
push, tag, PR, release, and destructive worktree operations are not delegated
by this amendment authority.

## 10. Stop conditions

Stop and report before implementation or checkpoint if:

- branch, HEAD lineage, origin/main, clean starting state, or target worktree
  identity drifts;
- Spec review finds a current-scope false-green or unsafe ABI gap;
- implementation requires artifact, install, live, signing, notarization,
  release, network, credentials, real state, or product fixes;
- safe offline source execution cannot be represented without reading Cargo or
  other credentials;
- any required suite is omitted, nonauthoritative, or cannot produce a typed
  fail-closed result;
- any formal reviewer returns BLOCK;
- the frozen snapshot changes during formal review;
- candidate construction cannot prove the exact allowlisted target-byte,
  tree/blob, single-parent, detached, and clean-checkout identities;
- candidate preparation or final branch/index compare-and-swap encounters an
  uncertain result;
- any final gate is non-PASS.

Only after every phase and final clean acceptance passes may the target branch
advance to the already accepted candidate commit, creating the one scope-exact
local checkpoint, followed by a new local handoff. Then stop; do not push, tag,
open a PR, release, delete/prune the detached checkout, clean worktrees, or begin
another goal.
