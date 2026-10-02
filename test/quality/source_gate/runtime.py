"""Public source-gate orchestration over frozen, dependency-bound inputs."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import pwd
import stat
import sys
import unicodedata
import ctypes
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The public source CLI is isolated.  Bind its reviewed dependency set before
# importing the schema consumers below.  Unit tests run non-isolated and use
# their already-bound test environment.
_ISOLATED_DEPENDENCIES: tuple[str, list[dict[str, Any]]] | None = None
if sys.flags.isolated == 1:
    from test.quality.run_evidence import cli as _bootstrap_cli

    _ISOLATED_DEPENDENCIES = _bootstrap_cli._dependency_bootstrap()

from test.quality.run_evidence.atomic_store import (
    RunLayout,
    RunStoreError,
    create_run_layout,
)
from test.quality.run_evidence.attempt0_runner import (
    copy_snapshot_bound_file,
    supervise_raw_command,
)
from test.quality.run_evidence.clean_commit_snapshot import (
    capture_clean_commit_snapshot,
)
from test.quality.run_evidence.contracts import ContractViolation
from test.quality.run_evidence.manifest_contracts import canonical_json_bytes
from test.quality.source_gate.aggregation import (
    complete_source_run,
    prepare_source_run,
    publish_source_pair,
)
from test.quality.source_gate.executor import execute_source_plans
from test.quality.source_gate.contracts import validate_source_catalog
from test.quality.source_gate.planning import (
    SourceSuitePlan,
    build_source_plans,
)


_INVOCATION_PREFIX = (
    "/usr/bin/python3",
    "-I",
    "test/quality/source_gate/cli.py",
    "run",
    "--output-root",
)
_DIGEST_KEYS = frozenset({
    "schema_bundle",
    "catalog",
    "gates",
    "runner",
    "fixtures",
    "build_recipes",
    "sanitized_environment",
    "tools",
})
_CARGO_CONFIG = (
    b"[source.crates-io]\n"
    b"replace-with = 'rsproxy-sparse'\n\n"
    b"[source.rsproxy-sparse]\n"
    b'registry = "sparse+https://rsproxy.cn/index/"\n\n'
    b"[net]\n"
    b"offline = true\n"
)
_DEPENDENCY_MAX_ENTRIES = 100_000
_DEPENDENCY_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_DEPENDENCY_MAX_FILE_BYTES = 128 * 1024 * 1024
_DEPENDENCY_MAX_PATH_BYTES = 4096
_DEPENDENCY_MAX_COMPONENTS = 64
_DEPENDENCY_DIRECTORY_MODE = 0o755
_DEPENDENCY_FILE_MODES = frozenset({0o640, 0o644, 0o755})
_SOURCE_OBSERVATION_LIMIT_BYTES = 4 * 1024 * 1024
_DARWIN_UNIX_PATH_MAX_BYTES = 103
_SOURCE_TMP_DESCENDANT_BUDGET_BYTES = 64
_PROC_PIDPATH_CAPACITY = 4096
_REVIEWED_PYTHON_ENTRY_PATH = (
    "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/"
    "Python3.framework/Versions/3.9/bin/python3.9"
)
_REVIEWED_PYTHON_PROCESS_IMAGE_PATH = (
    "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/"
    "Python3.framework/Versions/3.9/Resources/Python.app/Contents/"
    "MacOS/Python"
)
_SOURCE_METADATA_PATHS = {
    "catalog": "quality/test-catalog.v1.json",
    "gates": "quality/release-gates.v1.json",
    "kernel": "quality/schema/quality-kernel.v1.schema.json",
    "inventory": (
        "test/quality/fixtures/source_gate/expected_test_ids.v1.json"
    ),
}
_SELECTED_CARGO_LOCK_PATHS = (
    "desktop/src-tauri/Cargo.lock",
    "desktop/gateway/Cargo.lock",
    "desktop/skill-package/Cargo.lock",
)


class SourceRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourceRuntimeInputs:
    catalog: Mapping[str, Any]
    gates: Mapping[str, Any]
    inventory_raw: bytes
    head_sha: str
    merge_base_sha: str
    tools: Mapping[str, str]
    tool_identity_sha256: str
    input_digests: Mapping[str, str]
    rustup_home: str
    started_at: str
    completed_at: str
    platform: Mapping[str, str]
    python_dependency_root: str | None = None
    cargo_registry_root: str | None = None
    cargo_dependency_roots: Mapping[str, str] | None = None


@dataclass(frozen=True)
class SourceRuntimeDependencies:
    preflight: Callable[[], SourceRuntimeInputs]
    capture_snapshot: Callable[
        [RunLayout, SourceRuntimeInputs], Mapping[str, Any]
    ]
    run_one: Callable[
        [RunLayout, SourceSuitePlan, Mapping[str, Any]], Any
    ]
    recheck: Callable[
        [str, int | None, SourceSuitePlan | None], bool
    ]
    input_digests: Callable[
        [
            Mapping[str, Any],
            tuple[SourceSuitePlan, ...],
            SourceRuntimeInputs,
        ],
        Mapping[str, str],
    ] | None = None
    close: Callable[[], None] | None = None
    now: Callable[[], str] | None = None
    prepare_cargo_view: Callable[
        [SourceRuntimeInputs, str], None
    ] | None = None
    bind_gateway_target: Callable[[str, int], None] | None = None


def _assert_root_binding(
    root: str,
    root_fd: int,
    *,
    expected_nlink: int,
) -> None:
    public_fd: int | None = None
    try:
        held = os.fstat(root_fd)
        named = os.stat(root, follow_symlinks=False)
        public_fd = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        public = os.fstat(public_fd)
    except OSError as exc:
        raise SourceRuntimeError("output root binding lost") from exc
    finally:
        if public_fd is not None:
            try:
                os.close(public_fd)
            except OSError:
                pass
    identity = (held.st_dev, held.st_ino)
    if (
        identity != (named.st_dev, named.st_ino)
        or identity != (public.st_dev, public.st_ino)
        or not all(stat.S_ISDIR(item.st_mode) for item in (held, named, public))
        or any(item.st_uid != os.geteuid() for item in (held, named, public))
        or any(
            stat.S_IMODE(item.st_mode) != 0o700
            for item in (held, named, public)
        )
        or any(item.st_nlink != expected_nlink for item in (held, named, public))
    ):
        raise SourceRuntimeError("output root binding lost")


def _source_tmp_path(
    output_root: str,
    platform_record: Mapping[str, str],
) -> str:
    path = os.path.join(output_root, "state", "t")
    if (
        platform_record.get("os") == "darwin"
        and len(os.fsencode(path)) + _SOURCE_TMP_DESCENDANT_BUDGET_BYTES
        > _DARWIN_UNIX_PATH_MAX_BYTES
    ):
        raise SourceRuntimeError("source temp socket capacity")
    return path


def _assert_source_tmp_binding(
    path: str,
    held_fd: int,
    *,
    require_empty: bool = False,
) -> None:
    public_fd: int | None = None
    try:
        held = os.fstat(held_fd)
        named = os.stat(path, follow_symlinks=False)
        public_fd = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        public = os.fstat(public_fd)
        nonempty = require_empty and bool(os.listdir(held_fd))
    except OSError as exc:
        raise SourceRuntimeError("source temp binding lost") from exc
    finally:
        if public_fd is not None:
            try:
                os.close(public_fd)
            except OSError:
                pass
    identity = (held.st_dev, held.st_ino)
    if (
        identity != (named.st_dev, named.st_ino)
        or identity != (public.st_dev, public.st_ino)
        or not all(stat.S_ISDIR(item.st_mode) for item in (held, named, public))
        or any(item.st_uid != os.geteuid() for item in (held, named, public))
        or any(
            stat.S_IMODE(item.st_mode) != 0o700
            for item in (held, named, public)
        )
        or nonempty
    ):
        raise SourceRuntimeError("source temp binding lost")


def _assert_state_root_binding(root_fd: int, state_fd: int) -> None:
    try:
        held = os.fstat(state_fd)
        named = os.stat("state", dir_fd=root_fd, follow_symlinks=False)
    except OSError as exc:
        raise SourceRuntimeError("source state binding lost") from exc
    if (
        (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
        or not stat.S_ISDIR(held.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or held.st_uid != os.geteuid()
        or named.st_uid != os.geteuid()
        or stat.S_IMODE(held.st_mode) != 0o700
        or stat.S_IMODE(named.st_mode) != 0o700
    ):
        raise SourceRuntimeError("source state binding lost")


def _validate_inputs(value: Any) -> SourceRuntimeInputs:
    if not isinstance(value, SourceRuntimeInputs):
        raise SourceRuntimeError("source preflight contract")
    if (
        len(value.head_sha) != 40
        or len(value.merge_base_sha) != 40
        or not all(
            char in "0123456789abcdef"
            for char in value.head_sha + value.merge_base_sha
        )
        or len(value.tool_identity_sha256) != 64
        or set(value.input_digests) != _DIGEST_KEYS
        or any(
            not isinstance(item, str)
            or len(item) != 64
            or any(char not in "0123456789abcdef" for char in item)
            for item in value.input_digests.values()
        )
        or set(value.platform) != {"os", "arch", "toolchain"}
        or not all(
            isinstance(item, str) and item
            for item in value.platform.values()
        )
        or any(
            item is not None
            and (
                not isinstance(item, str)
                or not item.startswith("/")
                or item == "/"
                or item.endswith("/")
                or "//" in item
            )
            for item in (
                value.python_dependency_root,
                value.cargo_registry_root,
            )
        )
        or (
            value.cargo_dependency_roots is not None
            and (
                not isinstance(value.cargo_dependency_roots, Mapping)
                or not value.cargo_dependency_roots
                or any(
                    not isinstance(key, str)
                    or not isinstance(item, str)
                    for key, item in value.cargo_dependency_roots.items()
                )
            )
        )
    ):
        raise SourceRuntimeError("source preflight contract")
    return value


def _require_recheck(
    dependencies: SourceRuntimeDependencies,
    stage: str,
    index: int | None = None,
    plan: SourceSuitePlan | None = None,
) -> bool:
    if dependencies.recheck(stage, index, plan) is not True:
        raise ContractViolation("ADAPTER_MALFORMED", "source input drift")
    return True


def _source_observation_size_bound(plan: SourceSuitePlan) -> int:
    """Return a conservative serialized bound for the trusted source adapter."""
    expected = list(plan.expected_test_ids)
    derived_tool = None
    if plan.driver_config is not None:
        derived_tool = {
            "path": os.path.join(
                str(plan.driver_config["target_dir"]),
                "debug",
                "csswitch-gateway",
            ),
            "mode": "0755",
            "size": 128 * 1024 * 1024,
            "sha256": "f" * 64,
        }
    value = {
        "schema": "source-observation.v1",
        "run_id": "f" * 32,
        "suite_id": plan.suite["id"],
        "entrypoint_id": plan.suite["entrypoint_id"],
        "attempt_index": 0,
        "command_argv_sha256": "f" * 64,
        "environment_sha256": "f" * 64,
        "tool_identity_sha256": "f" * 64,
        "raw_process": {"state": "EXITED", "process_exit": 255},
        "adapter_exit": 13,
        "executed": len(expected),
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "ignored": 0,
        "todo": len(expected),
        "not_run": 0,
        "discovered_test_ids": expected,
        "executed_test_ids": expected,
        "failed_test_ids": [],
        "skipped_test_ids": [],
        "ignored_test_ids": [],
        "todo_test_ids": expected,
        "not_run_test_ids": [],
        "stdout": {
            "bytes": 64 * 1024 * 1024,
            "sha256": "f" * 64,
            "truncated": True,
        },
        "stderr": {
            "bytes": 64 * 1024 * 1024,
            "sha256": "f" * 64,
            "truncated": True,
        },
        "derived_tool": derived_tool,
        "outcome_hint": "BLOCKED",
        "classification_hint": "REAL_MACHINE",
        "reason_code": "X" * 64,
    }
    return len(canonical_json_bytes(value))


def _source_failure_reason(
    error: BaseException,
    *,
    partial_results: bool,
) -> str:
    if isinstance(error, ContractViolation) and "drift" in str(error).lower():
        return "INPUT_DRIFT"
    if isinstance(error, RunStoreError) and error.code in {
        "PARTIAL_RESULTS",
        "DUPLICATE_RESULTS",
        "REPLAYED_RESULT",
        "RESULT_BINDING_MISMATCH",
    }:
        return error.code
    if partial_results:
        return "PARTIAL_RESULTS"
    return "INTERNAL_ERROR"


def _record_source_failure(
    layout: RunLayout,
    *,
    stage: str,
    error: BaseException,
    partial_results: bool,
    fallback_time: str,
    now: Callable[[], str] | None,
) -> None:
    """Best-effort terminalization that never replaces the primary failure."""
    try:
        try:
            created_at = fallback_time if now is None else now()
        except BaseException:
            created_at = fallback_time
        layout.record_first_failure({
            "schema": "run-failure.v1",
            "run_id": layout.run_id,
            "stage": stage,
            "reason_code": _source_failure_reason(
                error,
                partial_results=partial_results,
            ),
            "run_manifest": None,
            "created_at": created_at,
            "terminal": True,
        })
    except BaseException:
        pass


def execute_source_gate_with_dependencies(
    output_root: str,
    root_fd: int,
    dependencies: SourceRuntimeDependencies,
) -> tuple[int, Mapping[str, Any]]:
    """Execute one frozen source run through explicit dependency seams."""
    if (
        not isinstance(dependencies, SourceRuntimeDependencies)
        or not isinstance(output_root, str)
        or not output_root.startswith("/")
        or output_root == "/"
        or not isinstance(root_fd, int)
    ):
        raise SourceRuntimeError("source runtime arguments")

    # Preflight is deliberately complete before the output root is mutated.
    inputs = _validate_inputs(dependencies.preflight())
    run_tmp = _source_tmp_path(output_root, inputs.platform)
    _assert_root_binding(output_root, root_fd, expected_nlink=2)
    try:
        os.mkdir("state", 0o700, dir_fd=root_fd)
        os.mkdir("evidence", 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
    except OSError as exc:
        raise SourceRuntimeError("source run roots") from exc
    _assert_root_binding(output_root, root_fd, expected_nlink=4)

    layout: RunLayout | None = None
    gateway_target_fd: int | None = None
    state_root_fd: int | None = None
    run_tmp_fd: int | None = None
    seal: Mapping[str, Any] | None = None
    close_error: BaseException | None = None
    primary_error: BaseException | None = None
    try:
        layout = create_run_layout(
            os.path.join(output_root, "state"),
            os.path.join(output_root, "evidence"),
        )
        _assert_root_binding(output_root, root_fd, expected_nlink=4)
        snapshot = dependencies.capture_snapshot(layout, inputs)
        if (
            not isinstance(snapshot, Mapping)
            or snapshot.get("run_id") != layout.run_id
            or snapshot.get("head_sha") != inputs.head_sha
            or snapshot.get("snapshot_mode") != "clean-commit"
        ):
            raise SourceRuntimeError("source snapshot binding")
        _require_recheck(dependencies, "after-snapshot")

        run_home = os.path.join(layout.state_path, "source-home")
        cargo_home = os.path.join(layout.state_path, "cargo-home")
        for path in (run_home, cargo_home):
            os.mkdir(path, 0o700)
        try:
            state_root_fd = os.open(
                "state",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            _assert_state_root_binding(root_fd, state_root_fd)
            os.mkdir("t", 0o700, dir_fd=state_root_fd)
            run_tmp_fd = os.open(
                "t",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=state_root_fd,
            )
            _assert_source_tmp_binding(
                run_tmp,
                run_tmp_fd,
                require_empty=True,
            )
        except OSError as exc:
            raise SourceRuntimeError("source temp creation") from exc
        if inputs.cargo_dependency_roots is not None:
            if dependencies.prepare_cargo_view is None:
                _materialize_dependency_view(
                    inputs.cargo_dependency_roots,
                    cargo_home,
                )
            else:
                dependencies.prepare_cargo_view(inputs, cargo_home)
        elif inputs.cargo_registry_root is not None:
            os.symlink(
                inputs.cargo_registry_root,
                os.path.join(cargo_home, "registry"),
                target_is_directory=True,
            )
        if (
            inputs.cargo_dependency_roots is not None
            or inputs.cargo_registry_root is not None
        ):
            _write_cargo_config(cargo_home)
        gateway_target = os.path.join(
            layout.state_path,
            "gateway-target",
        )
        try:
            os.mkdir("gateway-target", 0o700, dir_fd=layout._state_fd)
            gateway_target_fd = os.open(
                "gateway-target",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                dir_fd=layout._state_fd,
            )
            gateway_item = os.fstat(gateway_target_fd)
            if (
                not stat.S_ISDIR(gateway_item.st_mode)
                or gateway_item.st_uid != os.geteuid()
                or stat.S_IMODE(gateway_item.st_mode) != 0o700
                or os.listdir(gateway_target_fd)
            ):
                raise SourceRuntimeError("private gateway target unsafe")
        except OSError as exc:
            raise SourceRuntimeError(
                "private gateway target unsafe",
            ) from exc
        if dependencies.bind_gateway_target is not None:
            dependencies.bind_gateway_target(
                gateway_target,
                gateway_target_fd,
            )
        plans = build_source_plans(
            inputs.catalog,
            inputs.gates,
            inputs.inventory_raw,
            tools=inputs.tools,
            tool_identity_sha256=inputs.tool_identity_sha256,
            run_home=run_home,
            run_tmp=run_tmp,
            offline_cargo_home=cargo_home,
            rustup_home=inputs.rustup_home,
            gateway_target=gateway_target,
            python_dependency_root=inputs.python_dependency_root,
        )
        if any(
            _source_observation_size_bound(plan)
            > _SOURCE_OBSERVATION_LIMIT_BYTES
            for plan in plans
        ):
            raise SourceRuntimeError("source observation capacity")
        def recheck_with_tmp(
            stage: str,
            index: int | None = None,
            plan: SourceSuitePlan | None = None,
        ) -> bool:
            if run_tmp_fd is None:
                raise SourceRuntimeError("source temp binding lost")
            _assert_source_tmp_binding(run_tmp, run_tmp_fd)
            return _require_recheck(dependencies, stage, index, plan)

        recheck_with_tmp("after-plan")

        binding = layout._finalized_snapshot_binding
        if binding is None:
            raise SourceRuntimeError("source snapshot binding")
        invocation = (*_INVOCATION_PREFIX, output_root)
        input_digests = (
            dict(inputs.input_digests)
            if dependencies.input_digests is None
            else dict(dependencies.input_digests(snapshot, plans, inputs))
        )
        if (
            set(input_digests) != _DIGEST_KEYS
            or any(
                not isinstance(item, str)
                or len(item) != 64
                or any(char not in "0123456789abcdef" for char in item)
                for item in input_digests.values()
            )
        ):
            raise SourceRuntimeError("source input digests")
        run_manifest = {
            "schema": "run-manifest.v1",
            "run_id": layout.run_id,
            "profile": "source",
            "head_sha": inputs.head_sha,
            "comparison_base": {
                "policy": "merge-base-origin-main",
                "sha": inputs.merge_base_sha,
            },
            "source_snapshot_manifest": {
                "path": binding.publication.path,
                "sha256": binding.publication.sha256,
            },
            "change_set": None,
            "invocation_argv": list(invocation),
            "expected_suites": [
                {
                    "suite_id": plan.suite["id"],
                    "entrypoint_id": plan.suite["entrypoint_id"],
                }
                for plan in plans
            ],
            "input_digests": input_digests,
            "platform": dict(inputs.platform),
            "started_at": inputs.started_at,
        }
        state = prepare_source_run(
            layout,
            run_manifest,
            plans=plans,
            invocation_argv=invocation,
        )
        try:
            execute_source_plans(
                plans,
                run_id=layout.run_id,
                run_one=lambda plan, config: dependencies.run_one(
                    layout, plan, config,
                ),
                recheck=lambda when, index, plan: recheck_with_tmp(
                    "suite-" + when, index, plan,
                ),
                on_pair=lambda observation, result: publish_source_pair(
                    state, observation, result,
                ),
            )
        except BaseException as exc:
            primary_error = exc
            _record_source_failure(
                layout,
                stage="EXECUTE",
                error=exc,
                partial_results=len(state.results) != len(state.plans),
                fallback_time=inputs.completed_at,
                now=dependencies.now,
            )
            raise
        try:
            recheck_with_tmp("before-evidence")
            seal = complete_source_run(
                state,
                completed_at=(
                    inputs.completed_at
                    if dependencies.now is None
                    else dependencies.now()
                ),
                pre_seal_recheck=lambda: recheck_with_tmp(
                    "before-seal",
                ),
            )
        except BaseException as exc:
            primary_error = exc
            _record_source_failure(
                layout,
                stage="AGGREGATE",
                error=exc,
                partial_results=len(state.results) != len(state.plans),
                fallback_time=inputs.completed_at,
                now=dependencies.now,
            )
            raise
    except BaseException as exc:
        if primary_error is None:
            primary_error = exc
        raise
    finally:
        if layout is not None:
            try:
                layout.close()
            except BaseException as exc:
                close_error = exc
        if dependencies.close is not None:
            try:
                dependencies.close()
            except BaseException as exc:
                if close_error is None:
                    close_error = exc
        for fd in (gateway_target_fd, run_tmp_fd, state_root_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as exc:
                    if close_error is None:
                        close_error = exc
        if (
            seal is None
            and primary_error is None
            and close_error is not None
        ):
            raise close_error

    return int(seal["runner_exit"]), {
        "schema": "source-gate-summary.v1",
        "run_id": seal["run_id"],
        "aggregate_decision": seal["aggregate_decision"],
        "runner_exit": seal["runner_exit"],
        "completion_seal": "completion-seal.json",
    }


def _strict_json(raw: bytes) -> Mapping[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SourceRuntimeError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError(item),
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SourceRuntimeError("source metadata JSON") from exc
    if not isinstance(value, Mapping):
        raise SourceRuntimeError("source metadata JSON")
    return value


def _read_production_inputs(
    read: Callable[[str], bytes],
) -> tuple[
    dict[str, bytes],
    dict[str, str],
    Mapping[str, Any],
    Mapping[str, Any],
]:
    """Read the closed source metadata/lock set through one private seam."""
    if not callable(read):
        raise SourceRuntimeError("source metadata input reader")
    raw_paths = {
        **_SOURCE_METADATA_PATHS,
        **{path: path for path in _SELECTED_CARGO_LOCK_PATHS},
    }
    try:
        raw = {key: read(path) for key, path in raw_paths.items()}
    except (OSError, KeyError) as exc:
        raise SourceRuntimeError("source metadata input missing") from exc
    if any(not isinstance(value, bytes) or not value for value in raw.values()):
        raise SourceRuntimeError("source metadata input missing")
    catalog = _strict_json(raw["catalog"])
    gates = _strict_json(raw["gates"])
    _strict_json(raw["kernel"])
    _strict_json(raw["inventory"])
    validate_source_catalog(catalog, gates)
    return raw, raw_paths, catalog, gates


def _bound_tool_record(fd: int, path: str) -> dict[str, Any]:
    try:
        before = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or before.st_nlink < 1
            or before.st_size <= 0
            or os.path.realpath(path) != path
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                named.st_dev,
                named.st_ino,
                named.st_mode,
                named.st_uid,
                named.st_nlink,
                named.st_size,
                named.st_mtime_ns,
                named.st_ctime_ns,
            )
        ):
            raise SourceRuntimeError("source tool unsafe")
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise SourceRuntimeError("source tool short read")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (
            os.read(fd, 1)
            or (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
        ):
            raise SourceRuntimeError("source tool drift")
        return {
            "path": path,
            "resolved_path": os.path.realpath(path),
            "mode": stat.S_IMODE(before.st_mode),
            "owner": before.st_uid,
            "nlink": before.st_nlink,
            "size": before.st_size,
            "sha256": digest.hexdigest(),
        }
    except OSError as exc:
        raise SourceRuntimeError("source tool unsafe") from exc


def _open_held_tool(path: str) -> tuple[int, dict[str, Any]]:
    fd: int | None = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        return fd, _bound_tool_record(fd, path)
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def _tool_record(path: str) -> dict[str, Any]:
    fd: int | None = None
    try:
        fd, record = _open_held_tool(path)
        return record
    finally:
        if fd is not None:
            os.close(fd)


def _proc_pidpath_raw(pid: int, capacity: int) -> tuple[int, bytes]:
    """Darwin libproc seam returning the kernel-reported Mach image bytes."""
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = library.proc_pidpath
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        function.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(capacity)
        count = int(function(pid, buffer, capacity))
        return count, bytes(buffer.raw[: max(0, count)])
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise SourceRuntimeError("process executable unavailable") from exc


def _current_process_image_path(
    query: Callable[[int, int], tuple[int, bytes]] | None = None,
) -> str:
    query = _proc_pidpath_raw if query is None else query
    try:
        count, raw = query(os.getpid(), _PROC_PIDPATH_CAPACITY)
    except SourceRuntimeError:
        raise
    except BaseException as exc:
        raise SourceRuntimeError("process executable unavailable") from exc
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or not isinstance(raw, bytes)
        or count <= 0
        or count >= _PROC_PIDPATH_CAPACITY - 1
        or len(raw) != count
        or b"\x00" in raw
    ):
        raise SourceRuntimeError("process executable unavailable")
    try:
        path = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SourceRuntimeError("process executable unavailable") from exc
    if (
        not path.startswith("/")
        or path == "/"
        or path.endswith("/")
        or "//" in path
        or os.path.realpath(path) != path
    ):
        raise SourceRuntimeError("process executable unsafe")
    return path


def _open_python_composite_authority(
    *,
    launcher_path: str = "/usr/bin/python3",
    image_path: str | None = None,
    entry_path: str | None = None,
    reviewed_entry_path: str = _REVIEWED_PYTHON_ENTRY_PATH,
    reviewed_image_path: str = _REVIEWED_PYTHON_PROCESS_IMAGE_PATH,
) -> tuple[dict[str, int], dict[str, Any]]:
    """Open independent held launcher and current-process image records."""
    if image_path is None:
        image_path = _current_process_image_path()
    if entry_path is None:
        entry_path = os.path.realpath(sys.executable)
    if (
        entry_path != reviewed_entry_path
        or image_path != reviewed_image_path
    ):
        raise SourceRuntimeError("process executable unreviewed")
    fds: dict[str, int] = {}
    try:
        launcher_fd, launcher = _open_held_tool(launcher_path)
        fds["launcher"] = launcher_fd
        process_fd, process_executable = _open_held_tool(image_path)
        fds["process_executable"] = process_fd
        return fds, {
            "launcher": launcher,
            "process_executable": process_executable,
        }
    except BaseException:
        for fd in fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _recheck_python_composite_authority(
    fds: Mapping[str, int],
    expected: Mapping[str, Any],
    *,
    launcher_path: str = "/usr/bin/python3",
    image_path: str | None = None,
    entry_path: str | None = None,
    reviewed_entry_path: str = _REVIEWED_PYTHON_ENTRY_PATH,
    reviewed_image_path: str = _REVIEWED_PYTHON_PROCESS_IMAGE_PATH,
) -> bool:
    if (
        set(fds) != {"launcher", "process_executable"}
        or set(expected) != {"launcher", "process_executable"}
    ):
        return False
    try:
        current_path = (
            _current_process_image_path()
            if image_path is None
            else image_path
        )
        current_entry = (
            os.path.realpath(sys.executable)
            if entry_path is None
            else entry_path
        )
        if (
            expected["launcher"].get("path") != launcher_path
            or expected["process_executable"].get("path") != current_path
            or current_entry != reviewed_entry_path
            or current_path != reviewed_image_path
        ):
            return False
        return (
            _bound_tool_record(
                fds["launcher"],
                launcher_path,
            )
            == expected["launcher"]
            and _bound_tool_record(
                fds["process_executable"],
                current_path,
            )
            == expected["process_executable"]
        )
    except (OSError, SourceRuntimeError, KeyError, TypeError):
        return False


def _parent_gateway_record(
    target_fd: int,
    target_path: str,
) -> dict[str, Any]:
    """Independently bind the derived gateway after the loopback suite."""
    debug_fd = binary_fd = None

    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    try:
        held_target = os.fstat(target_fd)
        named_target = os.stat(target_path, follow_symlinks=False)
        if (
            not stat.S_ISDIR(held_target.st_mode)
            or held_target.st_uid != os.geteuid()
            or stat.S_IMODE(held_target.st_mode) != 0o700
            or identity(held_target) != identity(named_target)
        ):
            raise SourceRuntimeError("derived gateway target drift")
        debug_fd = os.open(
            "debug",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=target_fd,
        )
        binary_fd = os.open(
            "csswitch-gateway",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=debug_fd,
        )
        before = os.fstat(binary_fd)
        named = os.stat(
            "csswitch-gateway",
            dir_fd=debug_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o755
            or not 0 < before.st_size <= 128 * 1024 * 1024
            or identity(before) != identity(named)
        ):
            raise SourceRuntimeError("derived gateway unsafe")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(binary_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise SourceRuntimeError("derived gateway short read")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(binary_fd)
        closing_named = os.stat(
            "csswitch-gateway",
            dir_fd=debug_fd,
            follow_symlinks=False,
        )
        closing_target = os.fstat(target_fd)
        closing_target_named = os.stat(
            target_path,
            follow_symlinks=False,
        )
        if (
            os.read(binary_fd, 1)
            or identity(after) != identity(before)
            or identity(closing_named) != identity(before)
            or identity(closing_target) != identity(held_target)
            or identity(closing_target_named) != identity(held_target)
        ):
            raise SourceRuntimeError("derived gateway drift")
        return {
            "path": os.path.join(
                target_path,
                "debug",
                "csswitch-gateway",
            ),
            "mode": "0755",
            "size": before.st_size,
            "sha256": digest.hexdigest(),
        }
    except OSError as exc:
        raise SourceRuntimeError("derived gateway unsafe") from exc
    finally:
        for fd in (binary_fd, debug_fd):
            if fd is not None:
                os.close(fd)


def _verify_parent_gateway_record(
    target_fd: int,
    target_path: str,
    derived: Any,
) -> dict[str, Any]:
    if (
        not isinstance(derived, Mapping)
        or set(derived) != {"path", "mode", "size", "sha256"}
    ):
        raise SourceRuntimeError("derived gateway parent mismatch")
    actual = _parent_gateway_record(target_fd, target_path)
    if dict(derived) != actual:
        raise SourceRuntimeError("derived gateway parent mismatch")
    return actual


def _directory_record(path: str) -> tuple[int, ...]:
    fd: int | None = None
    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        held = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        identity = (
            held.st_dev,
            held.st_ino,
            held.st_mode,
            held.st_uid,
            held.st_nlink,
            held.st_mtime_ns,
            held.st_ctime_ns,
        )
        if (
            not stat.S_ISDIR(held.st_mode)
            or held.st_uid != os.geteuid()
            or os.path.realpath(path) != path
            or identity
            != (
                named.st_dev,
                named.st_ino,
                named.st_mode,
                named.st_uid,
                named.st_nlink,
                named.st_mtime_ns,
                named.st_ctime_ns,
            )
        ):
            raise SourceRuntimeError("offline Rust view unsafe")
        return identity
    except OSError as exc:
        raise SourceRuntimeError("offline Rust view unsafe") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _offline_root_digest_records(
    value: Any,
) -> dict[str, list[int]]:
    if not isinstance(value, Mapping) or not value:
        raise SourceRuntimeError("offline Rust view identity")
    result: dict[str, list[int]] = {}
    for path, record in value.items():
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path == "/"
            or path.endswith("/")
            or "//" in path
            or not isinstance(record, tuple)
            or len(record) != 7
            or any(
                not isinstance(item, int) or isinstance(item, bool)
                for item in record
            )
            or record[0] < 0
            or record[1] <= 0
            or not stat.S_ISDIR(record[2])
            or record[3] != os.geteuid()
            or record[4] < 1
        ):
            raise SourceRuntimeError("offline Rust view identity")
        result[path] = list(record)
    return result


def _safe_dependency_component(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise SourceRuntimeError("offline dependency path unsafe")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise SourceRuntimeError("offline dependency path unsafe") from exc
    return value


def _dependency_inventory(
    roots: Mapping[str, str],
    *,
    fault_hook: Callable[[str, str], None] | None = None,
) -> tuple[Mapping[str, Any], str]:
    """Inventory exact offline dependency bytes through held directory FDs."""
    if (
        not isinstance(roots, Mapping)
        or not roots
        or any(
            not isinstance(logical, str)
            or not isinstance(path, str)
            or not logical
            or logical.startswith("/")
            or logical.endswith("/")
            or "//" in logical
            or any(
                _safe_dependency_component(component) != component
                for component in logical.split("/")
            )
            or not path.startswith("/")
            or path == "/"
            or path.endswith("/")
            or "//" in path
            or os.path.realpath(path) != path
            for logical, path in roots.items()
        )
        or len(set(roots.values())) != len(roots)
    ):
        raise SourceRuntimeError("offline dependency roots unsafe")
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    entry_count = 0
    owner = os.geteuid()

    def invoke(event: str, logical: str) -> None:
        if fault_hook is not None:
            fault_hook(event, logical)

    def identity(item: os.stat_result) -> tuple[int, ...]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    def count(logical: str, size: int = 0) -> None:
        nonlocal entry_count, total_bytes
        entry_count += 1
        total_bytes += size
        if (
            entry_count > _DEPENDENCY_MAX_ENTRIES
            or total_bytes > _DEPENDENCY_MAX_TOTAL_BYTES
            or len(logical.split("/")) > _DEPENDENCY_MAX_COMPONENTS
            or len(logical.encode("utf-8")) > _DEPENDENCY_MAX_PATH_BYTES
        ):
            raise SourceRuntimeError("offline dependency limits")

    def scan(parent_fd: int, logical: str) -> None:
        nonlocal entry_count, total_bytes
        before = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != owner
            or stat.S_IMODE(before.st_mode) != _DEPENDENCY_DIRECTORY_MODE
        ):
            raise SourceRuntimeError("offline dependency directory unsafe")
        count(logical)
        entries.append({
            "path": logical,
            "type": "directory",
            "mode": "0755",
        })
        invoke("before-list", logical)
        names = os.listdir(parent_fd)
        invoke("after-list", logical)
        if (
            not all(isinstance(name, str) for name in names)
            or len(names) != len(set(names))
        ):
            raise SourceRuntimeError("offline dependency directory unsafe")
        names = sorted(
            (_safe_dependency_component(name) for name in names),
            key=lambda item: item.encode("utf-8"),
        )
        for name in names:
            child_logical = logical + "/" + name
            count(child_logical)
            try:
                named_before = os.stat(
                    name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise SourceRuntimeError(
                    "offline dependency entry unsafe",
                ) from exc
            if named_before.st_uid != owner:
                raise SourceRuntimeError("offline dependency owner")
            if stat.S_ISDIR(named_before.st_mode):
                if (
                    stat.S_IMODE(named_before.st_mode)
                    != _DEPENDENCY_DIRECTORY_MODE
                ):
                    raise SourceRuntimeError(
                        "offline dependency directory unsafe",
                    )
                child_fd: int | None = None
                try:
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                        | os.O_CLOEXEC,
                        dir_fd=parent_fd,
                    )
                    opened = os.fstat(child_fd)
                    if identity(opened) != identity(named_before):
                        raise SourceRuntimeError(
                            "offline dependency directory drift",
                        )
                    # scan() counts its own directory; undo the generic child
                    # count performed before the entry type was known.
                    entry_count -= 1
                    scan(child_fd, child_logical)
                    after = os.fstat(child_fd)
                    named_after = os.stat(
                        name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                    if (
                        identity(after) != identity(opened)
                        or identity(named_after) != identity(opened)
                    ):
                        raise SourceRuntimeError(
                            "offline dependency directory drift",
                        )
                except OSError as exc:
                    raise SourceRuntimeError(
                        "offline dependency directory unsafe",
                    ) from exc
                finally:
                    if child_fd is not None:
                        os.close(child_fd)
                continue
            if not stat.S_ISREG(named_before.st_mode):
                raise SourceRuntimeError("offline dependency special entry")
            mode = stat.S_IMODE(named_before.st_mode)
            if (
                mode not in _DEPENDENCY_FILE_MODES
                or named_before.st_nlink != 1
                or named_before.st_size < 0
                or named_before.st_size > _DEPENDENCY_MAX_FILE_BYTES
            ):
                raise SourceRuntimeError("offline dependency file unsafe")
            total_bytes += named_before.st_size
            if total_bytes > _DEPENDENCY_MAX_TOTAL_BYTES:
                raise SourceRuntimeError("offline dependency limits")
            file_fd: int | None = None
            try:
                invoke("before-open", child_logical)
                file_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
                opened = os.fstat(file_fd)
                if identity(opened) != identity(named_before):
                    raise SourceRuntimeError(
                        "offline dependency file drift",
                    )
                invoke("before-read", child_logical)
                digest = hashlib.sha256()
                remaining = opened.st_size
                while remaining:
                    chunk = os.read(file_fd, min(1024 * 1024, remaining))
                    if not chunk:
                        raise SourceRuntimeError(
                            "offline dependency short read",
                        )
                    digest.update(chunk)
                    remaining -= len(chunk)
                if os.read(file_fd, 1):
                    raise SourceRuntimeError(
                        "offline dependency long read",
                    )
                invoke("after-read", child_logical)
                after = os.fstat(file_fd)
                named_after = os.stat(
                    name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if (
                    identity(after) != identity(opened)
                    or identity(named_after) != identity(opened)
                ):
                    raise SourceRuntimeError(
                        "offline dependency file drift",
                    )
                entries.append({
                    "path": child_logical,
                    "type": "file",
                    "mode": "{:04o}".format(mode),
                    "size": opened.st_size,
                    "sha256": digest.hexdigest(),
                })
            except OSError as exc:
                raise SourceRuntimeError(
                    "offline dependency file unsafe",
                ) from exc
            finally:
                if file_fd is not None:
                    os.close(file_fd)
        invoke("before-closing-list", logical)
        closing_names = sorted(
            (
                _safe_dependency_component(name)
                for name in os.listdir(parent_fd)
            ),
            key=lambda item: item.encode("utf-8"),
        )
        after = os.fstat(parent_fd)
        if closing_names != names or identity(after) != identity(before):
            raise SourceRuntimeError("offline dependency directory drift")

    for logical, path in sorted(
        roots.items(),
        key=lambda item: item[0].encode("utf-8"),
    ):
        root_fd: int | None = None
        try:
            root_fd = os.open(
                path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            scan(root_fd, logical)
        except OSError as exc:
            raise SourceRuntimeError(
                "offline dependency root unsafe",
            ) from exc
        finally:
            if root_fd is not None:
                os.close(root_fd)
    inventory = {
        "schema": "cargo-offline-dependency-inventory.v1",
        "limits": {
            "max_entries": _DEPENDENCY_MAX_ENTRIES,
            "max_total_bytes": _DEPENDENCY_MAX_TOTAL_BYTES,
            "max_file_bytes": _DEPENDENCY_MAX_FILE_BYTES,
            "max_path_bytes": _DEPENDENCY_MAX_PATH_BYTES,
            "max_components": _DEPENDENCY_MAX_COMPONENTS,
        },
        "entry_count": entry_count,
        "total_bytes": total_bytes,
        "entries": entries,
    }
    return inventory, _sha_json(inventory)


def _materialize_dependency_view(
    source_roots: Mapping[str, str],
    cargo_home: str,
) -> tuple[Mapping[str, str], Mapping[str, Any], str]:
    """Copy only inventoried dependency bytes into the private Cargo HOME."""
    expected, expected_digest = _dependency_inventory(source_roots)
    if (
        not isinstance(cargo_home, str)
        or not cargo_home.startswith("/")
        or cargo_home == "/"
        or os.path.realpath(cargo_home) != cargo_home
    ):
        raise SourceRuntimeError("offline dependency destination unsafe")
    root_fd: int | None = None
    source_fds: dict[str, int] = {}

    def ensure_destination(parts: list[str]) -> int:
        if root_fd is None:
            raise SourceRuntimeError("offline dependency destination unsafe")
        current = os.dup(root_fd)
        try:
            for component in parts:
                _safe_dependency_component(component)
                try:
                    os.mkdir(component, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    dir_fd=current,
                )
                item = os.fstat(child)
                if (
                    not stat.S_ISDIR(item.st_mode)
                    or item.st_uid != os.geteuid()
                ):
                    os.close(child)
                    raise SourceRuntimeError(
                        "offline dependency destination unsafe",
                    )
                os.fchmod(child, 0o755)
                os.close(current)
                current = child
            return current
        except BaseException:
            os.close(current)
            raise

    def source_file(logical: str) -> int:
        matches = [
            root for root in source_roots
            if logical == root or logical.startswith(root + "/")
        ]
        if len(matches) != 1 or logical == matches[0]:
            raise SourceRuntimeError("offline dependency source binding")
        root = matches[0]
        current = os.dup(source_fds[root])
        try:
            parts = logical[len(root) + 1:].split("/")
            for component in parts[:-1]:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    dir_fd=current,
                )
                os.close(current)
                current = child
            fd = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current,
            )
            os.close(current)
            return fd
        except BaseException:
            os.close(current)
            raise

    try:
        root_fd = os.open(
            cargo_home,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        for logical, path in source_roots.items():
            source_fds[logical] = os.open(
                path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        for entry in expected["entries"]:
            logical = entry["path"]
            parts = logical.split("/")
            if entry["type"] == "directory":
                destination = ensure_destination(parts)
                os.close(destination)
                continue
            source_fd = destination_fd = parent_fd = None
            try:
                source_fd = source_file(logical)
                source_item = os.fstat(source_fd)
                if (
                    stat.S_IMODE(source_item.st_mode)
                    != int(entry["mode"], 8)
                    or source_item.st_uid != os.geteuid()
                    or source_item.st_nlink != 1
                    or source_item.st_size != entry["size"]
                ):
                    raise SourceRuntimeError(
                        "offline dependency source binding",
                    )
                parent_fd = ensure_destination(parts[:-1])
                destination_fd = os.open(
                    parts[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent_fd,
                )
                digest = hashlib.sha256()
                remaining = source_item.st_size
                while remaining:
                    chunk = os.read(
                        source_fd,
                        min(1024 * 1024, remaining),
                    )
                    if not chunk:
                        raise SourceRuntimeError(
                            "offline dependency source binding",
                        )
                    digest.update(chunk)
                    offset = 0
                    while offset < len(chunk):
                        count = os.write(destination_fd, chunk[offset:])
                        if count <= 0:
                            raise SourceRuntimeError(
                                "offline dependency destination unsafe",
                            )
                        offset += count
                    remaining -= len(chunk)
                if (
                    os.read(source_fd, 1)
                    or digest.hexdigest() != entry["sha256"]
                ):
                    raise SourceRuntimeError(
                        "offline dependency source binding",
                    )
                os.fchmod(destination_fd, int(entry["mode"], 8))
                os.fsync(destination_fd)
                os.fsync(parent_fd)
            except OSError as exc:
                raise SourceRuntimeError(
                    "offline dependency materialization failed",
                ) from exc
            finally:
                for fd in (destination_fd, parent_fd, source_fd):
                    if fd is not None:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
        os.fsync(root_fd)
    except OSError as exc:
        raise SourceRuntimeError(
            "offline dependency materialization failed",
        ) from exc
    finally:
        for fd in source_fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        if root_fd is not None:
            os.close(root_fd)
    closing_source, closing_source_digest = _dependency_inventory(source_roots)
    destination_roots = {
        logical: os.path.join(cargo_home, logical)
        for logical in source_roots
    }
    copied, copied_digest = _dependency_inventory(destination_roots)
    if (
        closing_source != expected
        or closing_source_digest != expected_digest
        or copied != expected
        or copied_digest != expected_digest
    ):
        raise SourceRuntimeError("offline dependency materialization drift")
    return destination_roots, copied, copied_digest


def _materialize_bound_dependency_view(
    source_roots: Mapping[str, str],
    cargo_home: str,
    *,
    expected_inventory: Mapping[str, Any],
    expected_digest: str,
) -> tuple[Mapping[str, str], Mapping[str, Any], str]:
    roots, inventory, digest = _materialize_dependency_view(
        source_roots,
        cargo_home,
    )
    if inventory != expected_inventory or digest != expected_digest:
        raise SourceRuntimeError("offline dependency preflight drift")
    return roots, inventory, digest


def _write_cargo_config(cargo_home: str) -> None:
    config_fd: int | None = None
    cargo_fd: int | None = None
    try:
        cargo_fd = os.open(
            cargo_home,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        config_fd = os.open(
            "config.toml",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=cargo_fd,
        )
        offset = 0
        while offset < len(_CARGO_CONFIG):
            count = os.write(config_fd, _CARGO_CONFIG[offset:])
            if count <= 0:
                raise SourceRuntimeError("offline Rust view")
            offset += count
        os.fsync(config_fd)
        os.fsync(cargo_fd)
    except OSError as exc:
        raise SourceRuntimeError("offline Rust view") from exc
    finally:
        for fd in (config_fd, cargo_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _sha_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _production_dependencies(root_fd: int) -> SourceRuntimeDependencies:
    """Bind the sole isolated production path without executing a suite."""
    from test.quality.run_evidence import cli as rue_cli

    repo_root = Path(__file__).resolve().parents[3]
    state: dict[str, Any] = {}
    adapter_fd: int | None = None
    driver_fd: int | None = None

    def read(relative: str) -> bytes:
        raw, _ = rue_cli._read_regular(repo_root / relative)
        return raw

    def bind_tools(
        python_authority: Mapping[str, Any],
    ) -> tuple[dict[str, str], str, dict[str, Any]]:
        account_home = pwd.getpwuid(os.geteuid()).pw_dir
        rust_bin = os.path.join(
            account_home,
            ".rustup/toolchains/stable-aarch64-apple-darwin/bin",
        )
        tool_paths = {
            "PYTHON": "/usr/bin/python3",
            "BASH": "/bin/bash",
            "NODE": "/usr/local/bin/node",
            "CARGO": os.path.join(rust_bin, "cargo"),
            "RUSTC": os.path.join(rust_bin, "rustc"),
            "GIT": "/usr/bin/git",
        }
        records = {
            name: (
                dict(python_authority)
                if name == "PYTHON"
                else _tool_record(path)
            )
            for name, path in tool_paths.items()
        }
        return tool_paths, _sha_json(records), records

    def preflight() -> SourceRuntimeInputs:
        python_fds: dict[str, int] = {}
        try:
            dependency_root, python_dependency_inventory = (
                _ISOLATED_DEPENDENCIES
                if _ISOLATED_DEPENDENCIES is not None
                else rue_cli._dependency_bootstrap()
            )
            raw, raw_paths, catalog, gates = _read_production_inputs(read)
            lock_raw = {
                path: raw[path]
                for path in _SELECTED_CARGO_LOCK_PATHS
            }
            git = rue_cli._git_binding()
            python_fds, python_authority = (
                _open_python_composite_authority()
            )
            tools, tool_digest, tool_records = bind_tools(
                python_authority,
            )
            account_home = pwd.getpwuid(os.geteuid()).pw_dir
            if (
                not account_home.startswith("/")
                or account_home == "/"
                or os.path.realpath(account_home) != account_home
            ):
                raise SourceRuntimeError("account home unsafe")
            rustup_home = os.path.join(account_home, ".rustup")
            cargo_registry = os.path.join(account_home, ".cargo/registry")
            for path in (rustup_home, cargo_registry):
                item = os.stat(path, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(item.st_mode)
                    or item.st_uid != os.geteuid()
                    or os.path.realpath(path) != path
                ):
                    raise SourceRuntimeError("offline Rust view unsafe")
            dependency_roots = {
                "registry/index": os.path.join(cargo_registry, "index"),
                "registry/cache": os.path.join(cargo_registry, "cache"),
                "registry/src": os.path.join(cargo_registry, "src"),
            }
            if any(
                b'\nsource = "git+' in b"\n" + value
                for value in lock_raw.values()
            ):
                cargo_git = os.path.join(account_home, ".cargo/git")
                dependency_roots.update({
                    "git/db": os.path.join(cargo_git, "db"),
                    "git/checkouts": os.path.join(cargo_git, "checkouts"),
                })
            cargo_dependency_inventory, dependency_digest = (
                _dependency_inventory(dependency_roots)
            )
            tool_identity_digest = _sha_json({
                "binary_tools": tool_digest,
                "cargo_dependencies": dependency_digest,
            })
            state.update({
                "raw": raw,
                "raw_paths": raw_paths,
                "git": git,
                "tools": tools,
                "binary_tool_digest": tool_digest,
                "tool_identity_digest": tool_identity_digest,
                "tool_records": tool_records,
                "python_authority": python_authority,
                "python_authority_fds": python_fds,
                "dependency_root": dependency_root,
                "dependency_inventory": python_dependency_inventory,
                "cargo_dependency_inventory": cargo_dependency_inventory,
                "cargo_dependency_digest": dependency_digest,
                "cargo_dependency_roots": dependency_roots,
                "active_cargo_inventory": cargo_dependency_inventory,
                "active_cargo_digest": dependency_digest,
                "active_cargo_roots": dependency_roots,
                "offline_roots": {
                    path: _directory_record(path)
                    for path in (rustup_home, cargo_registry)
                },
            })
            zero = "0" * 64
            return SourceRuntimeInputs(
                catalog=catalog,
                gates=gates,
                inventory_raw=raw["inventory"],
                head_sha=git[0],
                merge_base_sha=git[2],
                tools=tools,
                tool_identity_sha256=tool_identity_digest,
                input_digests={key: zero for key in _DIGEST_KEYS},
                rustup_home=rustup_home,
                started_at=rue_cli._now(),
                completed_at=rue_cli._now(),
                platform={
                    "os": platform.system().lower(),
                    "arch": platform.machine(),
                    "toolchain": "source-gate.v1",
                },
                python_dependency_root=dependency_root,
                cargo_registry_root=cargo_registry,
                cargo_dependency_roots=dependency_roots,
            )
        except BaseException:
            for fd in python_fds.values():
                try:
                    os.close(fd)
                except OSError:
                    pass
            state.pop("python_authority_fds", None)
            raise

    def capture(
        layout: RunLayout,
        inputs: SourceRuntimeInputs,
    ) -> Mapping[str, Any]:
        captured = capture_clean_commit_snapshot(
            str(repo_root),
            inputs.head_sha,
            layout,
        )
        state["snapshot"] = captured.manifest
        return captured.manifest

    def recheck(
        stage: str,
        index: int | None,
        plan: SourceSuitePlan | None,
    ) -> bool:
        if rue_cli._git_binding() != state.get("git"):
            return False
        expected_raw = state.get("raw")
        raw_paths = state.get("raw_paths")
        if (
            not isinstance(expected_raw, Mapping)
            or not isinstance(raw_paths, Mapping)
        ):
            return False
        for key, relative in raw_paths.items():
            if read(relative) != expected_raw.get(key):
                return False
        python_authority = state.get("python_authority")
        python_authority_fds = state.get("python_authority_fds")
        if (
            not isinstance(python_authority, Mapping)
            or not isinstance(python_authority_fds, Mapping)
            or not _recheck_python_composite_authority(
                python_authority_fds,
                python_authority,
            )
        ):
            return False
        tools, digest, records = bind_tools(python_authority)
        dependency_root, dependency_inventory = rue_cli._dependency_bootstrap()
        offline_roots = state.get("offline_roots")
        if not isinstance(offline_roots, Mapping):
            return False
        for path, expected in offline_roots.items():
            try:
                actual = _directory_record(path)
            except SourceRuntimeError:
                return False
            if actual != tuple(expected):
                return False
        try:
            cargo_inventory, cargo_digest = _dependency_inventory(
                state["active_cargo_roots"],
            )
        except SourceRuntimeError:
            return False
        cargo_config_path = state.get("cargo_config_path")
        if cargo_config_path is not None:
            try:
                config_record = _tool_record(cargo_config_path)
            except SourceRuntimeError:
                return False
            if (
                config_record["mode"] != 0o600
                or config_record["owner"] != os.geteuid()
                or config_record["nlink"] != 1
                or config_record["size"] != len(_CARGO_CONFIG)
                or config_record["sha256"]
                != hashlib.sha256(_CARGO_CONFIG).hexdigest()
            ):
                return False
        accepted_gateway = state.get("accepted_gateway_record")
        if accepted_gateway is not None:
            try:
                _verify_parent_gateway_record(
                    state["gateway_target_fd"],
                    state["gateway_target_path"],
                    accepted_gateway,
                )
            except (KeyError, SourceRuntimeError, TypeError):
                return False
        return (
            tools == state.get("tools")
            and digest == state.get("binary_tool_digest")
            and records == state.get("tool_records")
            and dependency_root == state.get("dependency_root")
            and dependency_inventory == state.get("dependency_inventory")
            and cargo_digest == state.get("active_cargo_digest")
            and cargo_inventory == state.get("active_cargo_inventory")
        )

    def prepare_cargo_view(
        inputs: SourceRuntimeInputs,
        cargo_home: str,
    ) -> None:
        if inputs.cargo_dependency_roots != state.get(
            "cargo_dependency_roots",
        ):
            raise SourceRuntimeError("offline dependency source binding")
        roots, inventory, digest = _materialize_bound_dependency_view(
            state["cargo_dependency_roots"],
            cargo_home,
            expected_inventory=state["cargo_dependency_inventory"],
            expected_digest=state["cargo_dependency_digest"],
        )
        state["active_cargo_roots"] = roots
        state["active_cargo_inventory"] = inventory
        state["active_cargo_digest"] = digest
        state["cargo_config_path"] = os.path.join(
            cargo_home,
            "config.toml",
        )

    def bind_gateway_target(path: str, fd: int) -> None:
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or not isinstance(fd, int)
            or fd < 3
            or "gateway_target_path" in state
        ):
            raise SourceRuntimeError("private gateway target binding")
        held = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISDIR(held.st_mode)
            or held.st_uid != os.geteuid()
            or stat.S_IMODE(held.st_mode) != 0o700
            or (held.st_dev, held.st_ino)
            != (named.st_dev, named.st_ino)
            or os.listdir(fd)
        ):
            raise SourceRuntimeError("private gateway target binding")
        state["gateway_target_path"] = path
        state["gateway_target_fd"] = fd

    def input_digests(
        snapshot: Mapping[str, Any],
        plans: tuple[SourceSuitePlan, ...],
        inputs: SourceRuntimeInputs,
    ) -> Mapping[str, str]:
        entries = snapshot.get("entries")
        if not isinstance(entries, list):
            raise SourceRuntimeError("snapshot inventory")
        by_path = {
            item.get("path"): item
            for item in entries
            if isinstance(item, Mapping) and isinstance(item.get("path"), str)
        }

        def selected(paths) -> list[Mapping[str, Any]]:
            values = []
            expanded = set()
            for path in paths:
                if path.endswith("/"):
                    expanded.update(
                        candidate
                        for candidate in by_path
                        if candidate.startswith(path)
                    )
                else:
                    expanded.add(path)
            for path in sorted(expanded):
                item = by_path.get(path)
                if not isinstance(item, Mapping) or item.get("type") != "file":
                    raise SourceRuntimeError("snapshot inventory")
                values.append(dict(item))
            return values

        suites = [plan.suite for plan in plans]
        schemas = [
            path for path in by_path
            if path.startswith("quality/schema/")
        ]
        source_paths = [
            path for suite in suites for path in suite["source_paths"]
        ]
        fixture_paths = [
            path for suite in suites for path in suite["fixture_paths"]
        ]
        build_paths = [
            path for suite in suites for path in suite["build_recipe_paths"]
        ]
        environment = [
            {
                "suite_id": plan.suite["id"],
                "environment": dict(plan.environment),
            }
            for plan in plans
        ]
        return {
            "schema_bundle": _sha_json(selected(schemas)),
            "catalog": hashlib.sha256(state["raw"]["catalog"]).hexdigest(),
            "gates": hashlib.sha256(state["raw"]["gates"]).hexdigest(),
            "runner": _sha_json(selected(source_paths)),
            "fixtures": _sha_json(selected(fixture_paths)),
            "build_recipes": _sha_json(selected(build_paths)),
            "sanitized_environment": _sha_json(environment),
            "tools": _sha_json({
                "binaries": state["tool_records"],
                "dependencies": state["dependency_inventory"],
                "cargo_config_sha256": hashlib.sha256(
                    _CARGO_CONFIG,
                ).hexdigest(),
                "cargo_dependency_inventory": state[
                    "cargo_dependency_digest"
                ],
                "cargo_dependency_entry_count": state[
                    "cargo_dependency_inventory"
                ]["entry_count"],
                "cargo_dependency_total_bytes": state[
                    "cargo_dependency_inventory"
                ]["total_bytes"],
                "offline_roots": _offline_root_digest_records(
                    state["offline_roots"],
                ),
                "git": {
                    "head_sha": state["git"][0],
                    "origin_main_sha": state["git"][1],
                    "merge_base_sha": state["git"][2],
                },
            }),
        }

    def run_one(
        layout: RunLayout,
        plan: SourceSuitePlan,
        config: Mapping[str, Any],
    ):
        nonlocal adapter_fd, driver_fd
        snapshot = state.get("snapshot")
        if not isinstance(snapshot, Mapping):
            raise SourceRuntimeError("snapshot adapter binding")
        if adapter_fd is None:
            adapter_fd = copy_snapshot_bound_file(
                repo_root=str(repo_root),
                layout=layout,
                snapshot=snapshot,
                logical_path="test/quality/source_gate/adapter.py",
                cache_leaf="source-adapter.py",
            )
        loopback = plan.suite["id"] == "SUITE-PY-LOOPBACK"
        if loopback and driver_fd is None:
            driver_fd = copy_snapshot_bound_file(
                repo_root=str(repo_root),
                layout=layout,
                snapshot=snapshot,
                logical_path=(
                    "test/quality/source_gate/gateway_driver.py"
                ),
                cache_leaf="source-gateway-driver.py",
            )
        dependency_root = state["dependency_root"]
        bootstrap = (
            "import os,sys;"
            "sys.path.append(" + repr(dependency_root) + ");"
            "os.lseek(198,0,0);"
            "p='/dev/fd/198';"
            "exec(compile(open(p,'rb').read(),p,'exec'))"
        )
        raw_config = canonical_json_bytes(dict(config))
        frame = len(raw_config).to_bytes(4, "big") + raw_config
        authority = tuple(
            fd for fd in (
                root_fd,
                layout._state_fd,
                layout._snapshot_fd,
                layout._attempts_fd,
                layout._cache_fd,
                layout._tmp_fd,
                layout._evidence_fd,
                layout._results_fd,
            )
            if fd is not None and fd != adapter_fd
        )
        supervised = supervise_raw_command(
            argv=(
                "/usr/bin/python3",
                "-I",
                "-c",
                bootstrap,
                "--config-fd",
                "197",
                "--observation-fd",
                "199",
            ),
            environment={
                "HOME": plan.environment["HOME"],
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "TMPDIR": plan.environment["TMPDIR"],
            },
            timeout_seconds=plan.suite["timeout_seconds"] + 5,
            output_limit_bytes=64 * 1024 * 1024,
            observation_limit_bytes=_SOURCE_OBSERVATION_LIMIT_BYTES,
            authority_fds=authority,
            framed_config=frame,
            inherited_fds=(
                ((adapter_fd, 198), (driver_fd, 196))
                if loopback and driver_fd is not None
                else ((adapter_fd, 198),)
            ),
        )
        if loopback:
            target_fd = state.get("gateway_target_fd")
            target_path = state.get("gateway_target_path")
            observation = supervised.observation
            if (
                not isinstance(target_fd, int)
                or not isinstance(target_path, str)
                or not isinstance(observation, Mapping)
            ):
                raise SourceRuntimeError(
                    "derived gateway parent mismatch",
                )
            accepted = _verify_parent_gateway_record(
                target_fd,
                target_path,
                observation.get("derived_tool"),
            )
            state["accepted_gateway_record"] = accepted
        return supervised

    def close() -> None:
        nonlocal adapter_fd, driver_fd
        if adapter_fd is not None:
            os.close(adapter_fd)
            adapter_fd = None
        if driver_fd is not None:
            os.close(driver_fd)
            driver_fd = None
        python_fds = state.pop("python_authority_fds", {})
        if isinstance(python_fds, Mapping):
            for fd in python_fds.values():
                try:
                    os.close(fd)
                except OSError:
                    pass

    return SourceRuntimeDependencies(
        preflight=preflight,
        capture_snapshot=capture,
        run_one=run_one,
        recheck=recheck,
        input_digests=input_digests,
        close=close,
        now=rue_cli._now,
        prepare_cargo_view=prepare_cargo_view,
        bind_gateway_target=bind_gateway_target,
    )


def execute_source_gate(
    output_root: str,
    root_fd: int,
) -> tuple[int, Mapping[str, Any]]:
    return execute_source_gate_with_dependencies(
        output_root,
        root_fd,
        _production_dependencies(root_fd),
    )
