#!/usr/bin/python3
"""Fixed one-suite NODE-RUN-EVIDENCE command.

This is deliberately not a general test launcher.  Its public argument surface,
catalog selection, fixture, environment, retry policy, and aggregation target
are all fixed.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import platform
import pwd
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CLI_RELATIVE = "test/quality/run_evidence/cli.py"
_PYTHON = "/usr/bin/python3"
_SUITE_ID = "SUITE-RUE05A"
_ENTRYPOINT_ID = "ENTRY-RUE05A-ATTEMPT0"
_OUTPUT_TOKEN = "{ABS_EMPTY_0700_DIR}"
_COMMAND_TEMPLATE = [
    _PYTHON,
    "-I",
    _CLI_RELATIVE,
    "run",
    "--output-root",
    _OUTPUT_TOKEN,
]
_EXPECTED_RULE = {
    "name": "run-evidence-fixed-one-suite",
    "purpose": (
        "Execute only the catalog-bound SUITE-RUE05A focused source-unit "
        "NODE-RUN-EVIDENCE command."
    ),
    "suite_ids": [_SUITE_ID],
    "executor_implemented": True,
}
_EXPECTED_SUITE = {
    "id": _SUITE_ID,
    "name": "fixed one-suite NODE-RUN-EVIDENCE CLI",
    "kind": "python",
    "category": "runner",
    "entrypoint": (
        "/usr/bin/python3 -I test/quality/run_evidence/cli.py run "
        "--output-root {ABS_EMPTY_0700_DIR}"
    ),
    "entrypoint_id": _ENTRYPOINT_ID,
    "command_argv": _COMMAND_TEMPLATE,
    "cwd_mode": "repo-root",
    "profiles": ["focused"],
    "adapter_protocol": "adapter-result.v1",
    "timeout_seconds": 10,
    "readiness_timeout_seconds": 2,
    "retry_policy": "readiness-timeout-once",
    "fixture_paths": [
        "test/quality/fixtures/run_evidence/attempt0_fixture.py",
    ],
    "build_recipe_paths": [],
    "environment_allowlist": [],
    "source_paths": [
        "quality/schema/adapter-result.v1.schema.json",
        "quality/schema/test-result.v1.schema.json",
        "quality/schema/run-manifest.v1.schema.json",
        "quality/schema/source-snapshot-manifest.v1.schema.json",
        "quality/schema/evidence-manifest.v1.schema.json",
        "quality/schema/completion-seal.v1.schema.json",
        "test/quality/run_evidence/atomic_store.py",
        "test/quality/run_evidence/clean_commit_snapshot.py",
        "test/quality/run_evidence/contracts.py",
        "test/quality/run_evidence/manifest_contracts.py",
        "test/quality/run_evidence/attempt0_runner.py",
        "test/quality/run_evidence/retry_runner.py",
        "test/quality/run_evidence/aggregation_runner.py",
        _CLI_RELATIVE,
    ],
    "evidence_layer": "source-test",
    "owner": "quality-kernel",
    "status": "implemented",
    "reason": None,
    "expiry": None,
    "replacement_id": None,
    "requirement_ids": ["REQ-083-SCHEMA", "REQ-083-FOCUSED"],
    "bug_ids": [],
    "gate_ids": [],
    "expected_status": "PASS",
    "historical_case_ids": [],
    "selection_rule": {
        "mode": "focused",
        "include_paths": [
            "quality/",
            "test/quality/run_evidence/",
            "test/quality/test_run_evidence_cli.py",
        ],
        "exclude_statuses": [
            "legacy",
            "manual",
            "quarantine",
            "retired",
            "not-yet-automatable",
        ],
    },
}
_DISTRIBUTIONS = {
    "jsonschema": (
        "4.25.1",
        "jsonschema-4.25.1.dist-info",
        "00adda22c7e8876c9f9144a35d7217d0ac3e18dec5f4c9163ce563038f54bf1c",
    ),
    "attrs": (
        "26.1.0",
        "attrs-26.1.0.dist-info",
        "44ffe016f8ee38bcf9a63f7e2b293c444bb3d2e0ff94287c84a9216a936be14f",
    ),
    "referencing": (
        "0.36.2",
        "referencing-0.36.2.dist-info",
        "0dc8202d8c351d0f8c272ab0f43e623f3a8426d177739b84cfd81d415cb2c288",
    ),
    "jsonschema_specifications": (
        "2025.9.1",
        "jsonschema_specifications-2025.9.1.dist-info",
        "798a9eec35fba88a0efbe59dac80ba5c6a02d6d9859c2d67ce0357d8f6c26925",
    ),
    "rpds_py": (
        "0.27.1",
        "rpds_py-0.27.1.dist-info",
        "e89f4ba46a2bb19fe5b52cee72ef8049e953d8e1828f84483a41f1feb2b6079d",
    ),
    "typing_extensions": (
        "4.14.1",
        "typing_extensions-4.14.1.dist-info",
        "9c3c254bc029c11fa3c2eb521843d4b6bc86c5ad638e1fde791cbf602af399f7",
    ),
}
_MODULES = {
    "jsonschema": "jsonschema",
    "attrs": "attrs",
    "referencing": "referencing",
    "jsonschema_specifications": "jsonschema_specifications",
    "rpds_py": "rpds",
    "typing_extensions": "typing_extensions",
}
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_MAX_FILE = 64 * 1024 * 1024


class _PreflightError(RuntimeError):
    pass


class _ContractError(RuntimeError):
    pass


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _read_regular(
    path: Path,
    *,
    limit: int = _MAX_FILE,
    require_owner: bool = True,
    require_single_link: bool = True,
) -> tuple[bytes, os.stat_result]:
    text = str(path)
    if not path.is_absolute() or os.path.realpath(text) != text:
        raise _PreflightError("unsafe path")
    fd: int | None = None
    try:
        fd = os.open(text, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(fd)
        named = os.stat(text, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or (require_owner and before.st_uid != os.geteuid())
            or (require_single_link and before.st_nlink != 1)
            or before.st_size < 0
            or before.st_size > limit
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
            raise _PreflightError("unsafe file")
        parts: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise _PreflightError("short read")
            parts.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise _PreflightError("long read")
        raw = b"".join(parts)
        after = os.fstat(fd)
        named_after = os.stat(text, follow_symlinks=False)
        if (
            (
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
            or (
                named_after.st_dev,
                named_after.st_ino,
                named_after.st_mode,
                named_after.st_uid,
                named_after.st_nlink,
                named_after.st_size,
                named_after.st_mtime_ns,
                named_after.st_ctime_ns,
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
            raise _PreflightError("file drift")
        return raw, before
    except OSError as exc:
        raise _PreflightError("file read failed") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _dependency_bootstrap() -> tuple[str, list[dict[str, Any]]]:
    try:
        account = pwd.getpwuid(os.geteuid())
        site_root = os.path.join(
            account.pw_dir,
            "Library",
            "Python",
            "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "lib",
            "python",
            "site-packages",
        )
        if os.path.realpath(site_root) != site_root:
            raise _PreflightError("dependency root is not exact")
        root_item = os.stat(site_root, follow_symlinks=False)
        if not stat.S_ISDIR(root_item.st_mode) or root_item.st_uid != os.geteuid():
            raise _PreflightError("dependency root is unsafe")
        inventories: list[dict[str, Any]] = []
        for distribution, (version, dist_leaf, record_sha) in _DISTRIBUTIONS.items():
            dist = Path(site_root) / dist_leaf
            metadata_raw, _ = _read_regular(dist / "METADATA", limit=1024 * 1024)
            metadata = metadata_raw.decode("utf-8", "strict")
            if "\nVersion: {}\n".format(version) not in "\n" + metadata:
                raise _PreflightError("dependency version drift")
            record_raw, _ = _read_regular(dist / "RECORD", limit=4 * 1024 * 1024)
            if _sha(record_raw) != record_sha:
                raise _PreflightError("dependency RECORD drift")
            rows: list[dict[str, Any]] = []
            for row in csv.reader(io.StringIO(record_raw.decode("utf-8", "strict"))):
                if len(row) != 3 or not row[0] or "\x00" in row[0]:
                    raise _PreflightError("dependency RECORD malformed")
                logical, declared_hash, declared_size = row
                relative = PurePosixPath(logical)
                outside_cache = ".." in relative.parts
                if outside_cache:
                    if not declared_hash and not declared_size:
                        rows.append(
                            {"path": logical, "sha256": None, "size": None},
                        )
                        continue
                    target = (Path(site_root) / logical).resolve()
                    if not str(target).startswith(account.pw_dir + os.sep):
                        raise _PreflightError("external dependency payload")
                else:
                    target = Path(site_root) / logical
                if relative.is_absolute() or "." in relative.parts:
                    raise _PreflightError("dependency RECORD path")
                payload, item = _read_regular(target)
                if declared_hash:
                    algorithm, separator, encoded = declared_hash.partition("=")
                    if algorithm != "sha256" or separator != "=":
                        raise _PreflightError("dependency RECORD hash")
                    expected = base64.urlsafe_b64encode(
                        hashlib.sha256(payload).digest(),
                    ).rstrip(b"=").decode("ascii")
                    if encoded != expected:
                        raise _PreflightError("dependency payload drift")
                elif logical != dist_leaf + "/RECORD":
                    raise _PreflightError("unhashed dependency payload")
                if declared_size and declared_size != str(item.st_size):
                    raise _PreflightError("dependency size drift")
                rows.append(
                    {
                        "path": logical,
                        "sha256": _sha(payload),
                        "size": item.st_size,
                    },
                )
            inventories.append(
                {
                    "distribution": distribution,
                    "version": version,
                    "record_sha256": record_sha,
                    "files": rows,
                },
            )
        if site_root not in sys.path:
            sys.path.append(site_root)
        for distribution, module_name in _MODULES.items():
            module = __import__(module_name)
            origin = getattr(module, "__file__", None)
            if (
                not isinstance(origin, str)
                or not os.path.realpath(origin).startswith(site_root + os.sep)
            ):
                raise _PreflightError(
                    "dependency origin drift: " + distribution,
                )
        return site_root, inventories
    except _PreflightError:
        raise
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise _PreflightError("dependency bootstrap failed") from exc


try:
    if sys.flags.isolated != 1:
        raise SystemExit(2)
    _dependency_bootstrap()
except _PreflightError:
    raise SystemExit(2)

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from jsonschema import Draft202012Validator
from test.quality.run_evidence.aggregation_runner import (
    _prepare_catalog_bound_run,
    complete_fixed_run,
)
from test.quality.run_evidence.atomic_store import (
    RunLayout,
    RunStoreError,
    create_run_layout,
)
from test.quality.run_evidence.attempt0_runner import run_attempt0
from test.quality.run_evidence.clean_commit_snapshot import (
    SnapshotError,
    capture_clean_commit_snapshot,
)
from test.quality.run_evidence.retry_runner import retry_attempt1


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _parse(argv: Sequence[str]) -> str:
    if len(argv) != 3 or argv[0] != "run" or argv[1] != "--output-root":
        raise ValueError("usage")
    output = argv[2]
    if not output or output == _OUTPUT_TOKEN:
        raise ValueError("usage")
    return output


def _validate_output_root(value: str) -> tuple[str, int]:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value == "/"
        or value.endswith("/")
        or "//" in value
        or os.path.normpath(value) != value
        or os.path.realpath(value) != value
        or value == str(_REPO_ROOT)
        or value.startswith(str(_REPO_ROOT) + os.sep)
    ):
        raise _PreflightError("output root must be a canonical external path")
    fd: int | None = None
    try:
        fd = os.open(
            value,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        item = os.fstat(fd)
        named = os.stat(value, follow_symlinks=False)
        if (
            not stat.S_ISDIR(item.st_mode)
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) != 0o700
            or item.st_nlink != 2
            or (item.st_dev, item.st_ino) != (named.st_dev, named.st_ino)
            or os.listdir(fd)
        ):
            raise _PreflightError("output root must be empty private directory")
        return value, fd
    except OSError as exc:
        raise _PreflightError("output root is unsafe") from exc
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def _assert_output_root_binding(
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
        raise _ContractError("output root binding lost") from exc
    finally:
        if public_fd is not None:
            try:
                os.close(public_fd)
            except OSError:
                pass
    identity = (held.st_dev, held.st_ino)
    if (
        not all(stat.S_ISDIR(item.st_mode) for item in (held, named, public))
        or any(item.st_uid != os.geteuid() for item in (held, named, public))
        or any(stat.S_IMODE(item.st_mode) != 0o700 for item in (held, named, public))
        or any(item.st_nlink != expected_nlink for item in (held, named, public))
        or identity != (named.st_dev, named.st_ino)
        or identity != (public.st_dev, public.st_ino)
    ):
        raise _ContractError("output root binding lost")


def _load_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _PreflightError("invalid JSON") from exc


def _catalog_preflight() -> tuple[dict[str, Any], bytes, bytes, bytes]:
    kernel_raw, _ = _read_regular(
        _REPO_ROOT / "quality/schema/quality-kernel.v1.schema.json",
    )
    catalog_raw, _ = _read_regular(
        _REPO_ROOT / "quality/test-catalog.v1.json",
    )
    gates_raw, _ = _read_regular(
        _REPO_ROOT / "quality/release-gates.v1.json",
    )
    kernel = _load_json(kernel_raw)
    catalog = _load_json(catalog_raw)
    gates = _load_json(gates_raw)
    if not isinstance(catalog, dict) or not isinstance(gates, dict):
        raise _PreflightError("catalog or gates document invalid")
    try:
        Draft202012Validator.check_schema(kernel)
        catalog_schema = {
            "$schema": kernel["$schema"],
            "$defs": kernel["$defs"],
            **kernel["$defs"]["TestSuiteCatalogV1"],
        }
        Draft202012Validator(catalog_schema).validate(catalog)
    except Exception as exc:
        raise _PreflightError("catalog schema invalid") from exc
    suites = [
        item
        for item in catalog.get("suites", [])
        if isinstance(item, dict) and item.get("id") == _SUITE_ID
    ]
    rules = [
        item
        for item in catalog.get("selection_rules", [])
        if isinstance(item, dict)
        and (
            item.get("name") == _EXPECTED_RULE["name"]
            or _SUITE_ID in item.get("suite_ids", [])
        )
    ]
    if (
        len(suites) != 1
        or suites[0] != _EXPECTED_SUITE
        or len(rules) != 1
        or rules[0] != _EXPECTED_RULE
        or any(_SUITE_ID in gate.get("required_suite_ids", []) for gate in gates.get("gates", []) if isinstance(gate, dict))
    ):
        raise _PreflightError("fixed catalog selection drift")
    return suites[0], catalog_raw, gates_raw, kernel_raw


def _git(argv: Sequence[str]) -> str:
    env = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }
    try:
        result = subprocess.run(
            [
                "/usr/bin/git",
                "--no-replace-objects",
                "-C",
                str(_REPO_ROOT),
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.excludesFile=/dev/null",
                *argv,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _PreflightError("git preflight failed") from exc
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        raise _PreflightError("git preflight failed")
    try:
        return result.stdout.decode("ascii", "strict").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise _PreflightError("git output invalid") from exc


def _git_binding() -> tuple[str, str, str]:
    head = _git(["rev-parse", "--verify", "HEAD^{commit}"])
    origin = _git(
        ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
    )
    merge_base = _git(
        ["merge-base", "HEAD^{commit}", "refs/remotes/origin/main^{commit}"],
    )
    if not all(_SHA40.fullmatch(value) for value in (head, origin, merge_base)):
        raise _PreflightError("git identity invalid")
    if _git(["status", "--porcelain=v1", "--untracked-files=all"]):
        raise _PreflightError("worktree is not clean")
    return head, origin, merge_base


def _entry_inventory(
    snapshot: Mapping[str, Any],
    paths: Sequence[str],
    *,
    prefix: str | None = None,
) -> list[dict[str, Any]]:
    entries = snapshot.get("entries")
    if not isinstance(entries, list):
        raise _ContractError("snapshot entries missing")
    by_path = {
        item.get("path"): item
        for item in entries
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    selected = (
        sorted(path for path in by_path if path.startswith(prefix))
        if prefix is not None
        else list(paths)
    )
    result = []
    for path in selected:
        item = by_path.get(path)
        if (
            not isinstance(item, dict)
            or item.get("type") != "file"
            or set(item)
            != {"path", "type", "mode", "size", "sha256"}
        ):
            raise _ContractError("snapshot inventory incomplete")
        result.append(dict(item))
    return result


def _tool_digest(
    git_binding: tuple[str, str, str],
) -> str:
    dependency_root, dependency_inventories = _dependency_bootstrap()
    python_raw, python_item = _read_regular(
        Path(_PYTHON),
        limit=32 * 1024 * 1024,
        require_owner=False,
        require_single_link=False,
    )
    resolved_executable = os.path.realpath(sys.executable)
    executable_raw, executable_item = _read_regular(
        Path(resolved_executable),
        limit=32 * 1024 * 1024,
        require_owner=False,
    )
    git_raw, git_item = _read_regular(
        Path("/usr/bin/git"),
        limit=32 * 1024 * 1024,
        require_owner=False,
        require_single_link=False,
    )
    tools = {
        "python_command": {
            "path": _PYTHON,
            "mode": stat.S_IMODE(python_item.st_mode),
            "nlink": python_item.st_nlink,
            "size": python_item.st_size,
            "sha256": _sha(python_raw),
        },
        "sys_executable": {
            "path": sys.executable,
            "resolved_path": resolved_executable,
            "mode": stat.S_IMODE(executable_item.st_mode),
            "nlink": executable_item.st_nlink,
            "size": executable_item.st_size,
            "sha256": _sha(executable_raw),
        },
        "dependency_root": dependency_root,
        "distributions": dependency_inventories,
        "git": {
            "path": "/usr/bin/git",
            "mode": stat.S_IMODE(git_item.st_mode),
            "nlink": git_item.st_nlink,
            "size": git_item.st_size,
            "sha256": _sha(git_raw),
        },
        "git_binding": {
            "head_sha": git_binding[0],
            "origin_main_sha": git_binding[1],
            "merge_base_sha": git_binding[2],
        },
    }
    return _sha(_canonical(tools))


def _input_digests(
    snapshot: Mapping[str, Any],
    catalog_raw: bytes,
    gates_raw: bytes,
    layout: RunLayout,
    git_binding: tuple[str, str, str],
) -> dict[str, str]:
    schema_inventory = _entry_inventory(
        snapshot,
        (),
        prefix="quality/schema/",
    )
    runner_inventory = _entry_inventory(
        snapshot,
        (
            "test/quality/run_evidence/atomic_store.py",
            "test/quality/run_evidence/clean_commit_snapshot.py",
            "test/quality/run_evidence/contracts.py",
            "test/quality/run_evidence/manifest_contracts.py",
            "test/quality/run_evidence/attempt0_runner.py",
            "test/quality/run_evidence/retry_runner.py",
            "test/quality/run_evidence/aggregation_runner.py",
            _CLI_RELATIVE,
        ),
    )
    fixture_inventory = _entry_inventory(
        snapshot,
        ("test/quality/fixtures/run_evidence/attempt0_fixture.py",),
    )
    environment = {
        "HOME": layout.state_path,
        "PATH": os.defpath,
        "PYTHONNOUSERSITE": "1",
        "RUE05A_ENTRYPOINT": _ENTRYPOINT_ID,
    }
    return {
        "schema_bundle": _sha(_canonical(schema_inventory)),
        "catalog": _sha(catalog_raw),
        "gates": _sha(gates_raw),
        "runner": _sha(_canonical(runner_inventory)),
        "fixtures": _sha(_canonical(fixture_inventory)),
        "build_recipes": _sha(_canonical([])),
        "sanitized_environment": _sha(_canonical(environment)),
        "tools": _tool_digest(git_binding),
    }


def _recheck(
    expected_git: tuple[str, str, str],
    expected_catalog: bytes,
    expected_gates: bytes,
    expected_kernel: bytes,
    expected_tools: str | None,
) -> None:
    if _git_binding() != expected_git:
        raise _ContractError("git drift")
    for relative, expected in (
        ("quality/test-catalog.v1.json", expected_catalog),
        ("quality/release-gates.v1.json", expected_gates),
        ("quality/schema/quality-kernel.v1.schema.json", expected_kernel),
    ):
        current, _ = _read_regular(_REPO_ROOT / relative)
        if current != expected:
            raise _ContractError("input drift")
    if expected_tools is None:
        _dependency_bootstrap()
    elif _tool_digest(expected_git) != expected_tools:
        raise _ContractError("tool drift")


def _record_failure(layout: RunLayout, reason: str) -> None:
    code = "INPUT_DRIFT" if "drift" in reason.lower() else "INTERNAL_ERROR"
    try:
        layout.record_first_failure(
            {
                "schema": "run-failure.v1",
                "run_id": layout.run_id,
                "stage": "INTERNAL",
                "reason_code": code,
                "run_manifest": None,
                "created_at": _now(),
                "terminal": True,
            },
        )
    except BaseException:
        pass


def _execute(output_root: str) -> tuple[int, dict[str, Any] | None]:
    root, root_fd = _validate_output_root(output_root)
    layout: RunLayout | None = None
    output_mutated = False
    try:
        suite, catalog_raw, gates_raw, kernel_raw = _catalog_preflight()
        git_binding = _git_binding()
        os.mkdir("state", 0o700, dir_fd=root_fd)
        output_mutated = True
        os.mkdir("evidence", 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        _assert_output_root_binding(root, root_fd, expected_nlink=4)
        layout = create_run_layout(
            os.path.join(root, "state"),
            os.path.join(root, "evidence"),
        )
        _assert_output_root_binding(root, root_fd, expected_nlink=4)
        capture = capture_clean_commit_snapshot(
            str(_REPO_ROOT),
            git_binding[0],
            layout,
        )
        _recheck(
            git_binding,
            catalog_raw,
            gates_raw,
            kernel_raw,
            None,
        )
        digests = _input_digests(
            capture.manifest,
            catalog_raw,
            gates_raw,
            layout,
            git_binding,
        )
        argv = [*_COMMAND_TEMPLATE[:-1], root]
        run_manifest = {
            "schema": "run-manifest.v1",
            "run_id": layout.run_id,
            "profile": "focused",
            "head_sha": git_binding[0],
            "comparison_base": {
                "policy": "merge-base-origin-main",
                "sha": git_binding[2],
            },
            "source_snapshot_manifest": {
                "path": capture.publication.path,
                "sha256": capture.publication.sha256,
            },
            "change_set": None,
            "invocation_argv": argv,
            "expected_suites": [
                {
                    "suite_id": _SUITE_ID,
                    "entrypoint_id": _ENTRYPOINT_ID,
                },
            ],
            "input_digests": digests,
            "platform": {
                "os": platform.system().lower(),
                "arch": platform.machine(),
                "toolchain": "{} {}".format(
                    platform.python_implementation(),
                    platform.python_version(),
                ),
            },
            "started_at": _now(),
        }
        _recheck(
            git_binding,
            catalog_raw,
            gates_raw,
            kernel_raw,
            digests["tools"],
        )
        _prepare_catalog_bound_run(
            layout,
            run_manifest,
            catalog_command_argv=suite["command_argv"],
            output_root=root,
        )
        _recheck(
            git_binding,
            catalog_raw,
            gates_raw,
            kernel_raw,
            digests["tools"],
        )
        attempt0 = run_attempt0(repo_root=str(_REPO_ROOT), layout=layout)
        if (
            attempt0.disposition,
            attempt0.reason_code,
            attempt0.attempt_record.process_exit,
        ) == ("READINESS", "READINESS_TIMEOUT", 13):
            retry_attempt1(repo_root=str(_REPO_ROOT), layout=layout)
        _recheck(
            git_binding,
            catalog_raw,
            gates_raw,
            kernel_raw,
            digests["tools"],
        )
        seal = complete_fixed_run(layout, _now())
        _assert_output_root_binding(root, root_fd, expected_nlink=4)
        line = {
            "claim": "NODE-RUN-EVIDENCE",
            "decision": seal["aggregate_decision"],
            "evidence_path": layout.evidence_path,
            "run_id": layout.run_id,
            "runner_exit": seal["runner_exit"],
            "scope": "fixed-one-suite-focused-source-unit",
        }
        return int(seal["runner_exit"]), line
    except _PreflightError:
        if not output_mutated:
            raise
        if layout is not None:
            _record_failure(layout, "input drift")
        return 12, None
    except SnapshotError as exc:
        if exc.secondary_code == "INTERNAL_INTERRUPT":
            raise KeyboardInterrupt()
        if layout is not None:
            _record_failure(layout, str(exc))
        return 12, None
    except (RunStoreError, _ContractError) as exc:
        if layout is not None:
            _record_failure(layout, str(exc))
        return 12, None
    finally:
        if layout is not None:
            try:
                layout.close()
            except RunStoreError:
                pass
        try:
            os.close(root_fd)
        except OSError:
            pass


def main() -> int:
    try:
        output_root = _parse(sys.argv[1:])
    except ValueError:
        return 64
    try:
        rc, line = _execute(output_root)
    except _PreflightError:
        return 2
    except KeyboardInterrupt:
        return 130
    except BaseException:
        return 12
    if line is not None:
        sys.stdout.buffer.write(_canonical(line))
        sys.stdout.buffer.flush()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
