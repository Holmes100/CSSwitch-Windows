"""Snapshot-bound current-source gateway builder for the loopback suite.

This internal driver is executed as the one raw command owned by the existing
trusted supervisor.  Its build and unittest children remain in that inherited
process group; this module deliberately owns no timeout, signal, process-group,
session, retry, or kill policy.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any


_CONFIG_FD = 197
_DERIVED_FD = 199
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_GATEWAY_BYTES = 128 * 1024 * 1024
_MANIFEST = "desktop/gateway/Cargo.toml"
_TEST_MODULES = (
    "test.test_gateway_rust",
    "test.test_provider_mock_scenarios",
    "test.test_installed_provider_matrix",
)
_BASE_ENVIRONMENT_KEYS = frozenset({
    "CARGO_HOME",
    "CARGO_NET_OFFLINE",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONNOUSERSITE",
    "RUSTC",
    "RUSTUP_HOME",
    "TMPDIR",
})


class GatewayDriverError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _safe_absolute(path: Any) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path == "/"
        or path.endswith("/")
        or "//" in path
        or os.path.realpath(path) != path
        or any(part in {"", ".", ".."} for part in path.split("/")[1:])
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
    ):
        raise GatewayDriverError("CONFIG_MALFORMED")
    return path


def _read_config(fd: int) -> Mapping[str, Any]:
    header = os.read(fd, 4)
    if len(header) != 4:
        raise GatewayDriverError("CONFIG_MALFORMED")
    size = int.from_bytes(header, "big")
    if not 0 < size <= _MAX_CONFIG_BYTES:
        raise GatewayDriverError("CONFIG_MALFORMED")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            raise GatewayDriverError("CONFIG_MALFORMED")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise GatewayDriverError("CONFIG_MALFORMED")
    raw = b"".join(chunks)
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=lambda pairs: _closed_pairs(pairs),
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError(item),
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise GatewayDriverError("CONFIG_MALFORMED") from exc
    if not isinstance(value, Mapping) or _canonical(value) != raw:
        raise GatewayDriverError("CONFIG_MALFORMED")
    required = {
        "schema",
        "target_dir",
        "cargo_path",
        "python_path",
        "environment",
    }
    environment = value.get("environment")
    if (
        set(value) != required
        or value.get("schema") != "gateway-driver-config.v1"
        or not isinstance(environment, Mapping)
        or set(environment) not in {
            _BASE_ENVIRONMENT_KEYS,
            _BASE_ENVIRONMENT_KEYS | {"PYTHONPATH"},
        }
        or any(
            not isinstance(key, str)
            or not isinstance(item, str)
            or not item
            for key, item in environment.items()
        )
        or environment.get("CARGO_NET_OFFLINE") != "true"
    ):
        raise GatewayDriverError("CONFIG_MALFORMED")
    for key in ("target_dir", "cargo_path", "python_path"):
        _safe_absolute(value.get(key))
    return value


def _closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def _identity(item: os.stat_result) -> tuple[int, ...]:
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


def _open_empty_target(path: str) -> int:
    fd: int | None = None
    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        held = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISDIR(held.st_mode)
            or held.st_uid != os.geteuid()
            or stat.S_IMODE(held.st_mode) != 0o700
            or _identity(held) != _identity(named)
            or os.listdir(fd)
        ):
            raise GatewayDriverError("PRIVATE_TARGET_UNSAFE")
        return fd
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        raise GatewayDriverError("PRIVATE_TARGET_UNSAFE") from exc
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def _gateway_record(target_fd: int, target_path: str) -> dict[str, Any]:
    debug_fd = binary_fd = None
    try:
        target_before = os.fstat(target_fd)
        target_named = os.stat(target_path, follow_symlinks=False)
        if (
            not stat.S_ISDIR(target_before.st_mode)
            or target_before.st_uid != os.geteuid()
            or stat.S_IMODE(target_before.st_mode) != 0o700
            or _identity(target_before) != _identity(target_named)
        ):
            raise GatewayDriverError("PRIVATE_TARGET_DRIFT")
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
            or not 0 < before.st_size <= _MAX_GATEWAY_BYTES
            or _identity(before) != _identity(named)
        ):
            raise GatewayDriverError("DERIVED_TOOL_UNSAFE")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(binary_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise GatewayDriverError("DERIVED_TOOL_DRIFT")
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
            or _identity(after) != _identity(before)
            or _identity(closing_named) != _identity(before)
            or _identity(closing_target) != _identity(target_before)
            or _identity(closing_target_named) != _identity(target_before)
        ):
            raise GatewayDriverError("DERIVED_TOOL_DRIFT")
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
        raise GatewayDriverError("DERIVED_TOOL_UNSAFE") from exc
    finally:
        for fd in (binary_fd, debug_fd):
            if fd is not None:
                os.close(fd)


def _run_child(argv: Sequence[str], environment: Mapping[str, str]) -> int:
    completed = subprocess.run(
        list(argv),
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        check=False,
        start_new_session=False,
    )
    return int(completed.returncode)


def _send_derived(fd: int, record: Mapping[str, Any]) -> None:
    raw = _canonical(record)
    frame = len(raw).to_bytes(4, "big") + raw
    sock = socket.socket(fileno=fd)
    try:
        view = memoryview(frame)
        while view:
            sent = sock.send(view)
            if sent <= 0:
                raise GatewayDriverError("DERIVED_SEND_FAILED")
            view = view[sent:]
        ack = bytearray()
        while len(ack) < 4:
            chunk = sock.recv(4 - len(ack))
            if not chunk:
                raise GatewayDriverError("DERIVED_ACK_MISSING")
            ack.extend(chunk)
        if bytes(ack) != b"ACK!":
            raise GatewayDriverError("DERIVED_ACK_MALFORMED")
    finally:
        sock.close()


def run_driver(
    config: Mapping[str, Any],
    *,
    run_child: Callable[[Sequence[str], Mapping[str, str]], int] = _run_child,
    emit: Callable[[Mapping[str, Any]], None],
) -> int:
    target_path = _safe_absolute(config["target_dir"])
    target_fd = _open_empty_target(target_path)
    try:
        build_argv = (
            config["cargo_path"],
            "build",
            "--offline",
            "--locked",
            "--manifest-path",
            _MANIFEST,
            "--bin",
            "csswitch-gateway",
            "--target-dir",
            target_path,
        )
        build_rc = run_child(build_argv, config["environment"])
        if not isinstance(build_rc, int) or isinstance(build_rc, bool):
            raise GatewayDriverError("BUILD_STATUS_UNSAFE")
        if build_rc != 0:
            return 12
        record = _gateway_record(target_fd, target_path)
        emit(record)
        test_environment = dict(config["environment"])
        test_environment["CSSWITCH_GATEWAY_BIN"] = record["path"]
        test_argv = (
            config["python_path"],
            "-m",
            "unittest",
            *_TEST_MODULES,
            "-v",
        )
        test_rc = run_child(test_argv, test_environment)
        if (
            not isinstance(test_rc, int)
            or isinstance(test_rc, bool)
            or not 0 <= test_rc <= 255
        ):
            raise GatewayDriverError("TEST_STATUS_UNSAFE")
        return test_rc
    finally:
        os.close(target_fd)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args != [
        "--config-fd",
        str(_CONFIG_FD),
        "--derived-fd",
        str(_DERIVED_FD),
    ]:
        return 12
    try:
        config = _read_config(_CONFIG_FD)
        os.close(_CONFIG_FD)
        return run_driver(
            config,
            emit=lambda record: _send_derived(_DERIVED_FD, record),
        )
    except (
        GatewayDriverError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ):
        return 12


if __name__ == "__main__":
    raise SystemExit(main())
