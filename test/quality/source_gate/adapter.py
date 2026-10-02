"""Snapshot-bound internal adapter for one catalog-selected source suite.

This module is not a public command surface.  The source executor supplies one
canonical configuration through FD 197 and one observation/ACK socket through
FD 199.  The raw test child receives neither descriptor.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
from collections.abc import Mapping, Sequence
from typing import Any


_REPO_ROOT = os.path.realpath(os.getcwd())
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from test.quality.run_evidence.attempt0_runner import (  # noqa: E402
    Attempt0RunnerError,
    TrustedCommandResult,
    supervise_raw_command,
)
from test.quality.run_evidence.manifest_contracts import (  # noqa: E402
    canonical_json_bytes,
    load_canonical_json,
    validate_source_observation,
)
from test.quality.source_gate.parsers import parse_framework  # noqa: E402


_CONFIG_FD = 197
_BOUND_DRIVER_FD = 196
_DRIVER_CHILD_FD = 195
_BOUND_ADAPTER_FD = 198
_OBSERVATION_FD = 199
_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_IGNORED_BOUNDARIES = frozenset((
    "real-machine", "installed", "public-network", "provider", "acceptance",
))


class SourceAdapterError(RuntimeError):
    pass


def _sorted(values: Sequence[str]) -> list[str]:
    return sorted(values, key=lambda item: item.encode("utf-8"))


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_config(fd: int) -> Mapping[str, Any]:
    header = os.read(fd, 4)
    if len(header) != 4:
        raise SourceAdapterError("CONFIG_MALFORMED")
    size = int.from_bytes(header, "big")
    if not 0 < size <= _MAX_CONFIG_BYTES:
        raise SourceAdapterError("CONFIG_MALFORMED")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            raise SourceAdapterError("CONFIG_MALFORMED")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise SourceAdapterError("CONFIG_MALFORMED")
    raw = b"".join(chunks)
    value = load_canonical_json(raw)
    if not isinstance(value, Mapping) or canonical_json_bytes(value) != raw:
        raise SourceAdapterError("CONFIG_MALFORMED")
    required = {
        "schema", "run_id", "suite_id", "entrypoint_id", "kind", "argv",
        "environment", "timeout_seconds", "output_limit_bytes",
        "expected_test_ids", "approved_skipped_test_ids",
        "approved_ignored_test_ids", "approved_ignored_tests",
        "command_argv_sha256",
        "environment_sha256", "tool_identity_sha256",
        "driver_config",
    }
    if set(value) != required or value.get("schema") != "source-adapter-config.v1":
        raise SourceAdapterError("CONFIG_MALFORMED")
    if (
        not isinstance(value.get("argv"), list)
        or not value["argv"]
        or not all(isinstance(item, str) and item for item in value["argv"])
        or not isinstance(value.get("environment"), Mapping)
        or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in value["environment"].items()
        )
        or value.get("kind") not in {"meta", "python", "inventory", "rust", "frontend", "shell"}
    ):
        raise SourceAdapterError("CONFIG_MALFORMED")
    driver_config = value.get("driver_config")
    if value.get("suite_id") == "SUITE-PY-LOOPBACK":
        if (
            not isinstance(driver_config, Mapping)
            or set(driver_config) != {
                "schema",
                "target_dir",
                "cargo_path",
                "python_path",
                "environment",
            }
            or driver_config.get("schema")
            != "gateway-driver-config.v1"
            or driver_config.get("environment")
            != value.get("environment")
        ):
            raise SourceAdapterError("CONFIG_MALFORMED")
    elif driver_config is not None:
        raise SourceAdapterError("CONFIG_MALFORMED")
    for key in (
        "expected_test_ids", "approved_skipped_test_ids",
        "approved_ignored_test_ids",
    ):
        items = value.get(key)
        if (
            not isinstance(items, list)
            or not all(isinstance(item, str) and item for item in items)
            or items != _sorted(items)
            or len(items) != len(set(items))
        ):
            raise SourceAdapterError("CONFIG_MALFORMED")
    ignored_tests = value.get("approved_ignored_tests")
    if (
        not isinstance(ignored_tests, Mapping)
        or list(ignored_tests) != value["approved_ignored_test_ids"]
    ):
        raise SourceAdapterError("CONFIG_MALFORMED")
    for item in ignored_tests.values():
        if (
            not isinstance(item, Mapping)
            or set(item) != {"boundary", "reason"}
            or item.get("boundary") not in _IGNORED_BOUNDARIES
            or not isinstance(item.get("reason"), str)
            or not item["reason"]
            or len(item["reason"]) > 512
            or any(ord(char) < 32 or ord(char) == 127 for char in item["reason"])
        ):
            raise SourceAdapterError("CONFIG_MALFORMED")
    return value


def build_observation(
    config: Mapping[str, Any],
    raw: TrustedCommandResult,
) -> dict[str, Any]:
    expected = list(config["expected_test_ids"])
    try:
        stdout_text = raw.stdout.decode("utf-8", "strict")
        stderr_text = raw.stderr.decode("utf-8", "strict")
        text = stdout_text + "\n" + stderr_text
        decoding_failed = False
    except UnicodeDecodeError:
        text = ""
        decoding_failed = True

    kind = config["kind"]
    if kind == "meta":
        # A meta command is one catalog-reviewed component.  Its process status
        # is the observation; stdout markers never determine success.
        discovered = list(expected) if len(expected) == 1 else []
        executed = list(expected) if len(expected) == 1 else []
        states = {"passed": [], "failed": [], "skipped": [], "ignored": [], "todo": [], "not_run": []}
        state = raw.raw_process.get("state")
        if executed:
            states["passed" if state == "EXITED" and raw.raw_process.get("process_exit") == 0 else "failed"] = list(executed)
        parse_failed = len(expected) != 1
    else:
        discovered, executed, states, parse_failed = parse_framework(
            kind,
            text,
            expected,
            {
                test_id: value["reason"]
                for test_id, value in config["approved_ignored_tests"].items()
            },
        )

    discovered = _sorted(discovered)
    executed = _sorted(executed)
    for values in states.values():
        values.sort(key=lambda item: item.encode("utf-8"))
    missing = _sorted(list(set(expected) - set(executed)))
    declared_not_run = _sorted(states["not_run"])
    not_run = declared_not_run if declared_not_run else missing
    identity_failed = (
        parse_failed
        or decoding_failed
        or discovered != expected
        or (executed != expected and declared_not_run != missing)
        or len(executed) != len(set(executed))
    )
    observed_skipped = states["skipped"]
    observed_ignored = states["ignored"]
    unapproved_state = (
        observed_skipped != list(config["approved_skipped_test_ids"])
        or observed_ignored != list(config["approved_ignored_test_ids"])
        or bool(states["todo"])
        or bool(declared_not_run)
    )
    process_state = raw.raw_process.get("state")
    process_exit = raw.raw_process.get("process_exit")
    if process_state == "HARD_TIMEOUT":
        adapter_exit, outcome, classification, reason = (
            13, "BLOCKED", "INFRA", "PROCESS_TIMEOUT",
        )
    elif process_state != "EXITED":
        adapter_exit, outcome, classification, reason = (
            12, "FAIL", "INFRA", str(process_state),
        )
    elif identity_failed or raw.stdout_truncated or raw.stderr_truncated:
        adapter_exit, outcome, classification, reason = (
            12, "FAIL", "INFRA", "TEST_IDENTITY_MISMATCH",
        )
    elif unapproved_state:
        adapter_exit, outcome, classification, reason = (
            11, "BLOCKED", "ENVIRONMENT", "UNAPPROVED_TEST_STATE",
        )
    elif process_exit != 0:
        adapter_exit, outcome, classification, reason = (
            (10 if states["failed"] else 12),
            "FAIL",
            ("NONE" if states["failed"] else "INFRA"),
            ("ASSERTION_FAILED" if states["failed"] else "EXIT_STATUS_MISMATCH"),
        )
    elif states["failed"]:
        adapter_exit, outcome, classification, reason = (
            10, "FAIL", "NONE", "ASSERTION_FAILED",
        )
    else:
        adapter_exit, outcome, classification, reason = 0, "PASS", "NONE", "NONE"

    derived_tool = None
    if config["suite_id"] == "SUITE-PY-LOOPBACK":
        derived_tool = raw.observation
        derived_path = (
            derived_tool.get("path")
            if isinstance(derived_tool, Mapping)
            else None
        )
        derived_size = (
            derived_tool.get("size")
            if isinstance(derived_tool, Mapping)
            else None
        )
        derived_sha = (
            derived_tool.get("sha256")
            if isinstance(derived_tool, Mapping)
            else None
        )
        if (
            not isinstance(derived_tool, Mapping)
            or set(derived_tool)
            != {"path", "mode", "size", "sha256"}
            or not isinstance(derived_path, str)
            or not derived_path.startswith("/")
            or derived_path == "/"
            or derived_path.endswith("/")
            or "//" in derived_path
            or any(
                part in {"", ".", ".."}
                for part in derived_path.split("/")[1:]
            )
            or derived_tool.get("mode") != "0755"
            or not isinstance(derived_size, int)
            or isinstance(derived_size, bool)
            or not 0 < derived_size <= 128 * 1024 * 1024
            or not isinstance(derived_sha, str)
            or len(derived_sha) != 64
            or any(
                char not in "0123456789abcdef"
                for char in derived_sha
            )
            or raw.observation_error is not None
            or raw.observation_acked is not True
        ):
            raise SourceAdapterError("DERIVED_TOOL_MALFORMED")
        derived_tool = dict(derived_tool)
    elif raw.observation is not None:
        raise SourceAdapterError("DERIVED_TOOL_UNEXPECTED")

    observation = {
        "schema": "source-observation.v1",
        "run_id": config["run_id"],
        "suite_id": config["suite_id"],
        "entrypoint_id": config["entrypoint_id"],
        "attempt_index": 0,
        "command_argv_sha256": config["command_argv_sha256"],
        "environment_sha256": config["environment_sha256"],
        "tool_identity_sha256": config["tool_identity_sha256"],
        "raw_process": dict(raw.raw_process),
        "adapter_exit": adapter_exit,
        "executed": len(executed),
        "passed": len(states["passed"]),
        "failed": len(states["failed"]),
        "skipped": len(states["skipped"]),
        "ignored": len(states["ignored"]),
        "todo": len(states["todo"]),
        "not_run": len(not_run),
        "discovered_test_ids": discovered,
        "executed_test_ids": executed,
        "failed_test_ids": states["failed"],
        "skipped_test_ids": states["skipped"],
        "ignored_test_ids": states["ignored"],
        "todo_test_ids": states["todo"],
        "not_run_test_ids": not_run,
        "stdout": {
            "bytes": len(raw.stdout),
            "sha256": _sha(raw.stdout),
            "truncated": raw.stdout_truncated,
        },
        "stderr": {
            "bytes": len(raw.stderr),
            "sha256": _sha(raw.stderr),
            "truncated": raw.stderr_truncated,
        },
        "derived_tool": derived_tool,
        "outcome_hint": outcome,
        "classification_hint": classification,
        "reason_code": reason,
    }
    validate_source_observation(observation)
    return observation


def _send_observation(fd: int, observation: Mapping[str, Any]) -> None:
    raw = canonical_json_bytes(observation)
    frame = len(raw).to_bytes(4, "big") + raw
    sock = socket.socket(fileno=fd)
    try:
        view = memoryview(frame)
        while view:
            sent = sock.send(view)
            if sent <= 0:
                raise SourceAdapterError("OBSERVATION_SEND_FAILED")
            view = view[sent:]
        ack = bytearray()
        while len(ack) < 4:
            chunk = sock.recv(4 - len(ack))
            if not chunk:
                raise SourceAdapterError("ACK_MISSING")
            ack.extend(chunk)
        if bytes(ack) != b"ACK!":
            raise SourceAdapterError("ACK_MALFORMED")
    finally:
        sock.close()


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args != [
        "--config-fd", str(_CONFIG_FD),
        "--observation-fd", str(_OBSERVATION_FD),
    ]:
        return 12
    try:
        config = _read_config(_CONFIG_FD)
        os.close(_CONFIG_FD)
        loopback = config["suite_id"] == "SUITE-PY-LOOPBACK"
        raw_config = (
            canonical_json_bytes(dict(config["driver_config"]))
            if loopback
            else None
        )
        frame = (
            len(raw_config).to_bytes(4, "big") + raw_config
            if raw_config is not None
            else None
        )
        raw = supervise_raw_command(
            argv=tuple(config["argv"]),
            environment=config["environment"],
            timeout_seconds=config["timeout_seconds"],
            output_limit_bytes=config["output_limit_bytes"],
            # Loopback's inner DUP2 atomically replaces the inherited outer
            # observation FD 199 with its derived-record socket.  Every other
            # raw child has no such replacement and must close both outer
            # authority descriptors before exec.
            authority_fds=(
                (_BOUND_ADAPTER_FD,)
                if loopback
                else (_BOUND_ADAPTER_FD, _OBSERVATION_FD)
            ),
            framed_config=frame,
            inherited_fds=(
                ((_BOUND_DRIVER_FD, _DRIVER_CHILD_FD),)
                if loopback
                else ()
            ),
        )
        observation = build_observation(config, raw)
        _send_observation(_OBSERVATION_FD, observation)
        return int(observation["adapter_exit"])
    except (Attempt0RunnerError, OSError, SourceAdapterError, TypeError, ValueError):
        return 12


if __name__ == "__main__":
    raise SystemExit(main())
