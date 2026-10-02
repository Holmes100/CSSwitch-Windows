"""The deliberately small RUE-05A/RUE-06 fixed attempt executor.

This module owns one fixture, one child, one adapter channel and one private
attempt record at a time.  Policy and retry scheduling remain outside it.
"""
from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import select
import signal
import socket
import stat
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .atomic_store import RunLayout, RunStoreError
from .contracts import AttemptDecisionV1, adjudicate_adapter_attempt, adjudicate_parent_event
from .manifest_contracts import canonical_json_bytes, load_canonical_json


_FIXTURE_RELATIVE = ("test", "quality", "fixtures", "run_evidence", "attempt0_fixture.py")
_FIXTURE_LOGICAL = "/".join(_FIXTURE_RELATIVE)
_SUITE_ID = "SUITE-RUE05A"
_ENTRYPOINT_ID = "ENTRY-RUE05A-ATTEMPT0"
_CHILD_CONFIG_FD = 197
_CHILD_CACHE_FD = 198
_CHILD_ADAPTER_FD = 199
_CACHE_BOOTSTRAP = "import os;os.lseek(198,0,0);p='/dev/fd/198';exec(compile(open(p,'rb').read(),p,'exec'))"
_MAX_FIXTURE_BYTES = 1024 * 1024
_MAX_ADAPTER_BYTES = 64 * 1024
_MAX_TRUSTED_OBSERVATION_BYTES = 4 * 1024 * 1024
_MAX_OUTPUT_BYTES = 64 * 1024
_MAX_RAW_TIMEOUT_SECONDS = 3605
_TIMEOUT_SECONDS = 2.0
_TERM_GRACE_SECONDS = 0.20
_TERMINAL_DRAIN_SECONDS = 0.25


class Attempt0RunnerError(RuntimeError):
    """A typed local executor failure; no result schema is invented for it."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class TrustedCommandResult:
    """Private raw-command result produced by the trusted supervisor."""

    raw_process: Mapping[str, Any]
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    observation: Mapping[str, Any] | None = None
    observation_error: str | None = None
    observation_acked: bool = False


def _identity(item: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (item.st_dev, item.st_ino, item.st_uid, stat.S_IMODE(item.st_mode), item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def _read_exact(fd: int, size: int) -> bytes:
    parts: list[bytes] = []
    remaining = size
    os.lseek(fd, 0, os.SEEK_SET)
    while remaining:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            raise Attempt0RunnerError("FD_DRIFT")
        parts.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise Attempt0RunnerError("FD_DRIFT")
    return b"".join(parts)


def _open_repo_root(repo_root: str | os.PathLike[str]) -> int:
    text = os.fspath(repo_root)
    if not isinstance(text, str) or not text.startswith("/") or text == "/" or "//" in text:
        raise Attempt0RunnerError("REPOSITORY_UNSAFE")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in text[1:].split("/"):
            if not component or component in {".", ".."}:
                raise Attempt0RunnerError("REPOSITORY_UNSAFE")
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        item = os.fstat(fd)
        if not stat.S_ISDIR(item.st_mode):
            raise Attempt0RunnerError("REPOSITORY_UNSAFE")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _snapshot_fixture_digest(manifest: Mapping[str, Any]) -> tuple[str, int, str]:
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise Attempt0RunnerError("SNAPSHOT_BINDING_MISMATCH")
    found = [entry for entry in entries if isinstance(entry, Mapping) and entry.get("path") == _FIXTURE_LOGICAL]
    if len(found) != 1 or found[0].get("type") != "file" or found[0].get("mode") not in {"100644", "100755"}:
        raise Attempt0RunnerError("SNAPSHOT_BINDING_MISMATCH")
    digest = found[0].get("sha256")
    size, mode = found[0].get("size"), found[0].get("mode")
    if not isinstance(digest, str) or len(digest) != 64 or not isinstance(size, int) or isinstance(size, bool):
        raise Attempt0RunnerError("SNAPSHOT_BINDING_MISMATCH")
    return digest, size, mode


def _copy_bound_fixture(
    repo_root: str | os.PathLike[str], layout: RunLayout, expected_digest: str,
    expected_size: int, expected_mode: str, attempt_index: int,
) -> int:
    """Copy source bytes through held descriptors and return a held cache FD."""
    root_fd = source_fd = cache_fd = verify_fd = result_fd = None
    try:
        root_fd = _open_repo_root(repo_root)
        parent = root_fd
        for leaf in _FIXTURE_RELATIVE[:-1]:
            child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            if parent != root_fd:
                os.close(parent)
            parent = child
        source_fd = os.open(_FIXTURE_RELATIVE[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        named_before = os.stat(_FIXTURE_RELATIVE[-1], dir_fd=parent, follow_symlinks=False)
        first = os.fstat(source_fd)
        expected_permissions = {"100644": 0o644, "100755": 0o755}[expected_mode]
        if (
            not stat.S_ISREG(first.st_mode) or first.st_nlink != 1
            or _identity(first) != _identity(named_before)
            or first.st_size != expected_size or first.st_size > _MAX_FIXTURE_BYTES
            or stat.S_IMODE(first.st_mode) != expected_permissions
        ):
            raise Attempt0RunnerError("TOOL_IDENTITY_CHANGED")
        raw = _read_exact(source_fd, first.st_size)
        named_after = os.stat(_FIXTURE_RELATIVE[-1], dir_fd=parent, follow_symlinks=False)
        after = os.fstat(source_fd)
        if (
            _identity(first) != _identity(after) or _identity(after) != _identity(named_after)
            or after.st_size != expected_size or hashlib.sha256(raw).hexdigest() != expected_digest
        ):
            raise Attempt0RunnerError("TOOL_IDENTITY_CHANGED")
        try:
            cache_leaf = f"attempt{attempt_index}-fixture.py"
            cache_fd = os.open(cache_leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=layout._cache_fd_required())
        except FileExistsError:
            raise Attempt0RunnerError("CACHE_REPLAY")
        offset = 0
        while offset < len(raw):
            count = os.write(cache_fd, raw[offset:])
            if count <= 0:
                raise Attempt0RunnerError("FD_DRIFT")
            offset += count
        os.fsync(cache_fd)
        written = os.fstat(cache_fd)
        if not stat.S_ISREG(written.st_mode) or written.st_nlink != 1 or written.st_size != expected_size:
            raise Attempt0RunnerError("FD_DRIFT")
        written_identity = _identity(written)
        verify_fd = os.open(cache_leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=layout._cache_fd_required())
        cache_named = os.stat(cache_leaf, dir_fd=layout._cache_fd_required(), follow_symlinks=False)
        verified = os.fstat(verify_fd)
        if (
            not stat.S_ISREG(verified.st_mode)
            or stat.S_IMODE(verified.st_mode) != 0o600
            or verified.st_uid != os.geteuid()
            or verified.st_nlink != 1
            or verified.st_size != expected_size
            or expected_size > _MAX_FIXTURE_BYTES
            or _identity(verified) != written_identity
            or _identity(verified) != _identity(cache_named)
        ):
            raise Attempt0RunnerError("TOOL_IDENTITY_CHANGED")
        reread = _read_exact(verify_fd, expected_size)
        verified_after = os.fstat(verify_fd)
        cache_named_after = os.stat(
            cache_leaf,
            dir_fd=layout._cache_fd_required(),
            follow_symlinks=False,
        )
        if (
            _identity(verified_after) != written_identity
            or _identity(cache_named_after) != written_identity
            or hashlib.sha256(reread).hexdigest() != expected_digest
        ):
            raise Attempt0RunnerError("TOOL_IDENTITY_CHANGED")
        os.close(cache_fd); cache_fd = None
        result_fd, verify_fd = verify_fd, None
        return result_fd
    except OSError as exc:
        raise Attempt0RunnerError("TOOL_IDENTITY_CHANGED") from exc
    finally:
        for fd in (verify_fd, cache_fd, source_fd):
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
        # ``parent`` may equal root, but close only once.
        if 'parent' in locals() and parent != root_fd:
            try: os.close(parent)
            except OSError: pass
        if root_fd is not None:
            try: os.close(root_fd)
            except OSError: pass


def copy_snapshot_bound_file(
    *,
    repo_root: str | os.PathLike[str],
    layout: RunLayout,
    snapshot: Mapping[str, Any],
    logical_path: str,
    cache_leaf: str,
    max_bytes: int = _MAX_FIXTURE_BYTES,
) -> int:
    """Copy one snapshot-manifest file to a held private cache descriptor."""
    if (
        not isinstance(snapshot, Mapping)
        or not isinstance(logical_path, str)
        or not logical_path
        or logical_path.startswith("/")
        or any(part in {"", ".", ".."} for part in logical_path.split("/"))
        or not isinstance(cache_leaf, str)
        or not cache_leaf
        or "/" in cache_leaf
        or not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or not 1 <= max_bytes <= 64 * 1024 * 1024
    ):
        raise Attempt0RunnerError("SNAPSHOT_BINDING_MISMATCH")
    with layout._lock:
        layout._open()
        rebound_snapshot = layout._read_bound_finalized_snapshot()
    if rebound_snapshot != snapshot:
        raise Attempt0RunnerError("SNAPSHOT_BINDING_MISMATCH")
    entries = snapshot.get("entries")
    found = [
        entry for entry in entries
        if isinstance(entry, Mapping) and entry.get("path") == logical_path
    ] if isinstance(entries, list) else []
    if (
        len(found) != 1
        or found[0].get("type") != "file"
        or found[0].get("mode") not in {"100644", "100755"}
        or not isinstance(found[0].get("size"), int)
        or isinstance(found[0].get("size"), bool)
        or not 0 <= found[0]["size"] <= max_bytes
        or not isinstance(found[0].get("sha256"), str)
        or len(found[0]["sha256"]) != 64
    ):
        raise Attempt0RunnerError("SNAPSHOT_BINDING_MISMATCH")
    expected = found[0]
    root_fd = parent_fd = source_fd = cache_write = cache_read = None
    try:
        root_fd = _open_repo_root(repo_root)
        parent_fd = root_fd
        parts = logical_path.split("/")
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
            if parent_fd != root_fd:
                os.close(parent_fd)
            parent_fd = next_fd
        source_fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        before = os.fstat(source_fd)
        named_before = os.stat(
            parts[-1], dir_fd=parent_fd, follow_symlinks=False,
        )
        expected_mode = {"100644": 0o644, "100755": 0o755}[
            expected["mode"]
        ]
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_size != expected["size"]
            or _identity(before) != _identity(named_before)
        ):
            raise Attempt0RunnerError("TOOL_IDENTITY_CHANGED")
        raw = _read_exact(source_fd, before.st_size)
        after = os.fstat(source_fd)
        named_after = os.stat(
            parts[-1], dir_fd=parent_fd, follow_symlinks=False,
        )
        if (
            _identity(after) != _identity(before)
            or _identity(named_after) != _identity(before)
            or hashlib.sha256(raw).hexdigest() != expected["sha256"]
        ):
            raise Attempt0RunnerError("TOOL_IDENTITY_CHANGED")
        cache_write = os.open(
            cache_leaf,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=layout._cache_fd_required(),
        )
        offset = 0
        while offset < len(raw):
            count = os.write(cache_write, raw[offset:])
            if count <= 0:
                raise Attempt0RunnerError("FD_DRIFT")
            offset += count
        os.fsync(cache_write)
        written = os.fstat(cache_write)
        if (
            not stat.S_ISREG(written.st_mode)
            or written.st_uid != os.geteuid()
            or written.st_nlink != 1
            or stat.S_IMODE(written.st_mode) != 0o600
            or written.st_size != len(raw)
        ):
            raise Attempt0RunnerError("FD_DRIFT")
        written_identity = _identity(written)
        os.close(cache_write)
        cache_write = None
        cache_read = os.open(
            cache_leaf,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=layout._cache_fd_required(),
        )
        named_cache = os.stat(
            cache_leaf,
            dir_fd=layout._cache_fd_required(),
            follow_symlinks=False,
        )
        cached = os.fstat(cache_read)
        reread = _read_exact(cache_read, len(raw))
        cached_after = os.fstat(cache_read)
        named_cache_after = os.stat(
            cache_leaf,
            dir_fd=layout._cache_fd_required(),
            follow_symlinks=False,
        )
        if (
            _identity(cached) != written_identity
            or _identity(named_cache) != written_identity
            or _identity(cached_after) != written_identity
            or _identity(named_cache_after) != written_identity
            or hashlib.sha256(reread).hexdigest() != expected["sha256"]
        ):
            raise Attempt0RunnerError("TOOL_IDENTITY_CHANGED")
        os.lseek(cache_read, 0, os.SEEK_SET)
        result, cache_read = cache_read, None
        return result
    except Attempt0RunnerError:
        raise
    except OSError as exc:
        raise Attempt0RunnerError("TOOL_IDENTITY_CHANGED") from exc
    finally:
        for fd in (cache_read, cache_write, source_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if parent_fd is not None and parent_fd != root_fd:
            try:
                os.close(parent_fd)
            except OSError:
                pass
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError:
                pass


def _moved_child_fd(fd: int) -> int:
    return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 200)


def _wait_once(pid: int, slot: list[int], done: threading.Event) -> None:
    try:
        while True:
            try:
                _, status = os.waitpid(pid, 0)
                break
            except InterruptedError:
                continue
        slot.append(status)  # The wait slot is written before NOTE_EXIT is observable.
    finally:
        done.set()


def _send_ack(peer: socket.socket, remaining: memoryview) -> int:
    return peer.send(remaining)


def _abort_authority_transport(kqueue: Any, peer: socket.socket) -> None:
    """Reject one invalid authority frame without waiting for child timeout."""
    fd = peer.fileno()
    for filter_value in (
        select.KQ_FILTER_READ,
        select.KQ_FILTER_WRITE,
    ):
        _delete_kevent(kqueue, fd, filter_value)
    try:
        peer.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    peer.close()


def _write_framed_config(fd: int, chunk: memoryview) -> int:
    """Private nonblocking config-transport seam.

    Chunks are capped at PIPE_BUF by the caller.  A successful pipe write of
    that size is therefore atomic; a short write is authority loss rather than
    a second, weaker recovery protocol.
    """
    return os.write(fd, chunk)


def _bounded_failure_drain(fds: tuple[int | None, ...]) -> None:
    """Drain already-nonblocking child output after a post-spawn failure."""
    pending = {fd for fd in fds if fd is not None}
    deadline = time.monotonic() + _TERMINAL_DRAIN_SECONDS
    while pending and time.monotonic() < deadline:
        progressed = False
        for fd in tuple(pending):
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                pending.discard(fd)
                continue
            progressed = True
            if not chunk:
                pending.discard(fd)
        if pending and not progressed:
            time.sleep(0.005)


def _spawn_actions(
    held_cache_fd: int, adapter_fd: int, output_fd: int,
    child_cache: int, child_adapter: int, child_output: int,
) -> list[tuple[int, ...]]:
    actions: list[tuple[int, ...]] = [
        (os.POSIX_SPAWN_DUP2, child_cache, _CHILD_CACHE_FD),
        (os.POSIX_SPAWN_DUP2, child_adapter, _CHILD_ADAPTER_FD),
        (os.POSIX_SPAWN_DUP2, child_output, 1),
        (os.POSIX_SPAWN_DUP2, child_output, 2),
    ]
    for original in (held_cache_fd, adapter_fd, output_fd, child_cache, child_adapter, child_output):
        if original not in {_CHILD_CACHE_FD, _CHILD_ADAPTER_FD, 1, 2}:
            actions.append((os.POSIX_SPAWN_CLOSE, original))
    return actions


def _close_fds(values: list[int | None]) -> None:
    for fd in values:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _signal_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        pass
    except OSError as error:
        if error.errno != errno.ESRCH:
            raise Attempt0RunnerError("PROCESS_GROUP_CLEANUP_FAILED") from error


def _process_group_gone(pid: int, *, leader_reaped: bool) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    except OSError as error:
        if error.errno == errno.ESRCH:
            return True
        if error.errno == errno.EPERM:
            # Darwin may report EPERM for the now-empty pgid after the sole
            # leader has been reaped.  Before reap it remains unconfirmed.
            return leader_reaped
        raise Attempt0RunnerError("PROCESS_GROUP_CLEANUP_FAILED") from error
    return False


def _cleanup_spawned_group(
    pid: int,
    slot: list[int],
    reaped: threading.Event,
    reaper: threading.Thread | None,
    reaper_started: bool,
) -> None:
    """Terminate one spawned process group and reap its leader exactly once.

    A populated wait slot proves only that the leader was reaped.  Descendants
    may still own the PGID and may ignore TERM, so every exception path must
    independently prove that the whole group is gone.
    """
    cleanup_failed = False
    try:
        _signal_group(pid, signal.SIGTERM)
    except Attempt0RunnerError as error:
        if getattr(error.__cause__, "errno", None) != errno.EPERM:
            cleanup_failed = True

    group_gone = False
    for _ in range(max(1, int(_TERM_GRACE_SECONDS / 0.005))):
        try:
            group_gone = _process_group_gone(
                pid, leader_reaped=bool(slot),
            )
        except Attempt0RunnerError:
            cleanup_failed = True
            break
        if group_gone:
            break
        time.sleep(0.005)

    if not group_gone:
        try:
            _signal_group(pid, signal.SIGKILL)
        except Attempt0RunnerError as error:
            if getattr(error.__cause__, "errno", None) != errno.EPERM:
                cleanup_failed = True

    if reaper_started:
        if not reaped.wait(2.0):
            cleanup_failed = True
        if reaper is not None:
            reaper.join(0.05)
            if reaper.is_alive():
                cleanup_failed = True
    elif not slot:
        try:
            while True:
                try:
                    _, status_value = os.waitpid(pid, 0)
                    break
                except InterruptedError:
                    continue
            slot.append(status_value)
            reaped.set()
        except OSError:
            cleanup_failed = True

    if not slot:
        cleanup_failed = True
    group_gone = False
    for _ in range(max(1, int(_TERMINAL_DRAIN_SECONDS / 0.005))):
        try:
            group_gone = _process_group_gone(
                pid, leader_reaped=bool(slot),
            )
        except Attempt0RunnerError:
            cleanup_failed = True
            break
        if group_gone:
            break
        time.sleep(0.005)
    if not group_gone:
        cleanup_failed = True
    if cleanup_failed:
        raise Attempt0RunnerError("PROCESS_GROUP_CLEANUP_FAILED")


def _delete_kevent(kqueue: Any, ident: int, filter_value: int) -> None:
    try:
        kqueue.control([select.kevent(ident, filter=filter_value, flags=select.KQ_EV_DELETE)], 0, 0)
    except OSError as error:
        if error.errno not in {errno.ENOENT, errno.EBADF}:
            raise


def _exit_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return -255


def _infra(reason: str, rc: int, run_id: str, attempt_index: int) -> AttemptDecisionV1:
    # Existing RUE-01 decision type and reason vocabulary; no runner schema.
    from .contracts import AttemptRecord
    return AttemptDecisionV1(
        run_id, _SUITE_ID, _ENTRYPOINT_ID, attempt_index,
        AttemptRecord(attempt_index, rc), "INFRA", reason,
    )


def _run_attempt(
    *, repo_root: str | os.PathLike[str], layout: RunLayout,
    attempt_index: int, scenario: str = "normal",
) -> AttemptDecisionV1:
    if attempt_index == 0:
        manifest = layout.begin_attempt0()
        publish = layout.publish_attempt0_decision
    elif attempt_index == 1:
        manifest = layout.begin_attempt1()
        publish = layout.publish_attempt1_decision
    else:
        raise Attempt0RunnerError("ATTEMPT_INDEX_UNSAFE")
    digest, fixture_size, fixture_mode = _snapshot_fixture_digest(manifest)
    try:
        held_cache_fd = _copy_bound_fixture(
            repo_root, layout, digest, fixture_size, fixture_mode, attempt_index,
        )
    except Attempt0RunnerError as error:
        if error.code == "TOOL_IDENTITY_CHANGED":
            decision = adjudicate_parent_event(
                "TOOL_IDENTITY_CHANGED", None, layout.run_id,
                _SUITE_ID, _ENTRYPOINT_ID, attempt_index,
            )
            publish(decision)
            return decision
        raise
    parent_sock: socket.socket | None = None
    child_sock: socket.socket | None = None
    out_read = out_write = child_cache = child_adapter = child_output = None
    pid: int | None = None
    kqueue = None
    reaper: threading.Thread | None = None
    reaped = threading.Event()
    slot: list[int] = []
    reaper_started = False
    child_reaped = False
    start: float | None = None
    try:
        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        out_read, out_write = os.pipe()
        parent_sock.setblocking(False)
        os.set_blocking(out_read, False)
        # /dev/fd inherits the open-file description offset; execution must
        # start from the verified bytes rather than the preceding hash read.
        os.lseek(held_cache_fd, 0, os.SEEK_SET)
        child_cache = _moved_child_fd(held_cache_fd)
        child_adapter = _moved_child_fd(child_sock.fileno())
        child_output = _moved_child_fd(out_write)
        env = {
            "HOME": layout.state_path, "PATH": os.defpath, "PYTHONNOUSERSITE": "1",
            "RUE05A_ENTRYPOINT": _ENTRYPOINT_ID,
        }
        if scenario != "normal": env["RUE05A_PRIVATE_SCENARIO"] = scenario
        actions = _spawn_actions(held_cache_fd, child_sock.fileno(), out_write, child_cache, child_adapter, child_output)
        argv = [
            sys.executable, "-I", "-S", "-c", _CACHE_BOOTSTRAP,
            "--adapter-fd", str(_CHILD_ADAPTER_FD), "--attempt-index",
            str(attempt_index), layout.run_id, _SUITE_ID, _ENTRYPOINT_ID,
        ]
        pid = os.posix_spawn(sys.executable, argv, env, file_actions=actions, setpgroup=0)
    except OSError:
        _close_fds([child_cache, child_adapter, child_output, held_cache_fd, out_read, out_write])
        if parent_sock is not None: parent_sock.close()
        if child_sock is not None: child_sock.close()
        decision = adjudicate_parent_event(
            "SPAWN_EXEC_FAILED", None, layout.run_id,
            _SUITE_ID, _ENTRYPOINT_ID, attempt_index,
        )
        publish(decision)
        return decision
    try:
        _close_fds([
            child_cache, child_adapter, child_output, held_cache_fd, out_write,
        ])
        held_cache_fd = out_write = None
        child_sock.close()
        child_sock = None
        buf = bytearray()
        adapter: Any = None
        adapter_error: str | None = None
        adapter_eof = output_eof = False
        ack_offset = 0
        output = 0
        output_limit = timed_out = False
        term_at: float | None = None
        cutoff_at: float | None = None
        group_term_at: float | None = None
        group_kill_sent = False
        start = time.monotonic()
    except BaseException:
        if parent_sock is not None:
            try:
                parent_sock.close()
            except OSError:
                pass
            parent_sock = None
        if child_sock is not None:
            try:
                child_sock.close()
            except OSError:
                pass
            child_sock = None
        _cleanup_spawned_group(pid, slot, reaped, reaper, reaper_started)
        _bounded_failure_drain((out_read,))
        _close_fds([
            child_cache, child_adapter, child_output, held_cache_fd,
            out_read, out_write,
        ])
        raise
    decision: AttemptDecisionV1 | None = None
    try:
        kqueue = select.kqueue()
        kqueue.control([
            select.kevent(pid, filter=select.KQ_FILTER_PROC, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT, fflags=select.KQ_NOTE_EXIT),
            select.kevent(parent_sock.fileno(), filter=select.KQ_FILTER_READ, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE),
            select.kevent(out_read, filter=select.KQ_FILTER_READ, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE),
        ], 0, 0)
        # Register kernel exit readiness before the sole reaper can consume it.
        reaper = threading.Thread(target=_wait_once, args=(pid, slot, reaped), daemon=True)
        reaper.start()
        reaper_started = True
        while True:
            now = time.monotonic()
            if cutoff_at is None and now - start >= _TIMEOUT_SECONDS and term_at is None:
                timed_out = True
                _signal_group(pid, signal.SIGTERM)
                term_at = now
            if term_at is not None and cutoff_at is None and now - term_at >= _TERM_GRACE_SECONDS:
                _signal_group(pid, signal.SIGKILL)
            group_gone = cutoff_at is not None and _process_group_gone(pid, leader_reaped=bool(slot))
            if cutoff_at is not None:
                since_cutoff = now - cutoff_at
                if (
                    not group_gone and group_term_at is None and since_cutoff >= 0.06
                    and (bool(slot) or not (adapter_eof and output_eof))
                ):
                    _signal_group(pid, signal.SIGTERM)
                    group_term_at = now
                if not group_gone and group_term_at is not None and now - group_term_at >= 0.10 and not group_kill_sent:
                    _signal_group(pid, signal.SIGKILL)
                    group_kill_sent = True
                if since_cutoff >= _TERMINAL_DRAIN_SECONDS:
                    if not group_gone:
                        raise Attempt0RunnerError("PROCESS_GROUP_CLEANUP_FAILED")
                    if not (adapter_eof and output_eof):
                        raise Attempt0RunnerError("TERMINAL_DRAIN_INCOMPLETE")
            if cutoff_at is not None and adapter_eof and output_eof and group_gone:
                break
            deadline = start + _TIMEOUT_SECONDS if cutoff_at is None else cutoff_at + _TERMINAL_DRAIN_SECONDS
            events = kqueue.control(None, 8, max(0.0, min(0.05, deadline - now)))
            # Kernel NOTE_EXIT is the cutoff.  It wins over every other event
            # returned in the same batch, independent of reaper scheduling.
            if any(event.filter == select.KQ_FILTER_PROC and event.fflags & select.KQ_NOTE_EXIT for event in events):
                cutoff_at = cutoff_at or time.monotonic()
            for event in events:
                if event.filter == select.KQ_FILTER_PROC:
                    continue
                if event.filter == select.KQ_FILTER_READ and event.ident == parent_sock.fileno():
                    try:
                        chunk = parent_sock.recv(65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        adapter_eof = True
                        _delete_kevent(kqueue, parent_sock.fileno(), select.KQ_FILTER_READ)
                        continue
                    if cutoff_at is not None:
                        adapter_error = "ADAPTER_LATE"
                        continue
                    if adapter is not None or adapter_error is not None:
                        adapter_error = "ADAPTER_MALFORMED"
                        continue
                    buf.extend(chunk)
                    if len(buf) < 4:
                        continue
                    length = int.from_bytes(buf[:4], "big")
                    if length == 0 or length > _MAX_ADAPTER_BYTES:
                        adapter_error = "ADAPTER_MALFORMED"
                        continue
                    if len(buf) < 4 + length:
                        continue
                    if len(buf) != 4 + length:
                        adapter_error = "ADAPTER_MALFORMED"
                        continue
                    raw = bytes(buf[4:])
                    try:
                        adapter = load_canonical_json(raw)
                        if canonical_json_bytes(adapter) != raw:
                            raise ValueError()
                    except Exception:
                        adapter_error = "ADAPTER_MALFORMED"
                        adapter = None
                        continue
                    kqueue.control([select.kevent(parent_sock.fileno(), filter=select.KQ_FILTER_WRITE, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE)], 0, 0)
                elif event.filter == select.KQ_FILTER_WRITE and event.ident == parent_sock.fileno():
                    if cutoff_at is not None or adapter is None or ack_offset == 4:
                        continue
                    try:
                        count = _send_ack(parent_sock, memoryview(b"ACK!")[ack_offset:])
                    except BlockingIOError:
                        continue
                    except OSError:
                        adapter_error = "ADAPTER_MALFORMED"
                        _delete_kevent(kqueue, parent_sock.fileno(), select.KQ_FILTER_WRITE)
                        continue
                    if count <= 0:
                        raise Attempt0RunnerError("ACK_FAILED")
                    ack_offset += count
                    if ack_offset == 4:
                        _delete_kevent(kqueue, parent_sock.fileno(), select.KQ_FILTER_WRITE)
                elif event.filter == select.KQ_FILTER_READ and event.ident == out_read:
                    try:
                        chunk = os.read(out_read, 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        output_eof = True
                        _delete_kevent(kqueue, out_read, select.KQ_FILTER_READ)
                    else:
                        output += len(chunk)
                        if output > _MAX_OUTPUT_BYTES and not output_limit:
                            output_limit = True
                            if term_at is None:
                                _signal_group(pid, signal.SIGTERM)
                                term_at = time.monotonic()
        if not adapter_eof or not output_eof:
            raise Attempt0RunnerError("TERMINAL_DRAIN_INCOMPLETE")
        if not _process_group_gone(pid, leader_reaped=bool(slot)):
            raise Attempt0RunnerError("PROCESS_GROUP_CLEANUP_FAILED")
        if buf and adapter is None and adapter_error is None:
            adapter_error = "ADAPTER_MALFORMED"
        if adapter is not None and ack_offset != 4 and adapter_error is None:
            adapter_error = "ADAPTER_MALFORMED"
        reaper.join(1.0)
        if not slot:
            raise Attempt0RunnerError("REAP_FAILED")
        child_reaped = True
        rc = _exit_code(slot[0])
        if output_limit:
            decision = adjudicate_parent_event("OUTPUT_LIMIT", rc, layout.run_id, _SUITE_ID, _ENTRYPOINT_ID, attempt_index)
        elif timed_out:
            decision = adjudicate_parent_event("HARD_TIMEOUT", rc, layout.run_id, _SUITE_ID, _ENTRYPOINT_ID, attempt_index)
        elif adapter_error == "ADAPTER_LATE":
            decision = _infra("ADAPTER_LATE", rc, layout.run_id, attempt_index)
        elif adapter_error is not None:
            decision = adjudicate_adapter_attempt({}, rc, layout.run_id, _SUITE_ID, _ENTRYPOINT_ID, attempt_index)
        elif adapter is None:
            decision = adjudicate_adapter_attempt(None, rc, layout.run_id, _SUITE_ID, _ENTRYPOINT_ID, attempt_index)
        else:
            decision = adjudicate_adapter_attempt(adapter, rc, layout.run_id, _SUITE_ID, _ENTRYPOINT_ID, attempt_index)
    except BaseException:
        if parent_sock is not None:
            try:
                parent_sock.close()
            except OSError:
                pass
            parent_sock = None
        _cleanup_spawned_group(pid, slot, reaped, reaper, reaper_started)
        _bounded_failure_drain((out_read,))
        raise
    finally:
        if kqueue is not None:
            kqueue.close()
        if parent_sock is not None:
            parent_sock.close()
        _close_fds([out_read])
    publish(decision)
    return decision


def _run_attempt0(*, repo_root: str | os.PathLike[str], layout: RunLayout, scenario: str = "normal") -> AttemptDecisionV1:
    return _run_attempt(
        repo_root=repo_root, layout=layout, attempt_index=0, scenario=scenario,
    )


def supervise_raw_command(
    *,
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
    authority_fds: tuple[int, ...] = (),
    framed_config: bytes | None = None,
    inherited_fds: tuple[tuple[int, int], ...] = (),
    observation_limit_bytes: int = _MAX_ADAPTER_BYTES,
) -> TrustedCommandResult:
    """Run one fixed raw command with the RUE kqueue/reap/cleanup mechanics.

    This is a private extraction for the source adapter.  It deliberately has
    no shell, cwd, retry, scenario, policy, or environment inheritance surface.
    The caller must already be in the snapshot-bound repository cwd.
    """
    if (
        not isinstance(argv, tuple)
        or not argv
        or any(not isinstance(item, str) or not item for item in argv)
        or not argv[0].startswith("/")
        or not isinstance(environment, Mapping)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment.items())
        or not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0.05 <= timeout_seconds <= _MAX_RAW_TIMEOUT_SECONDS
        or not isinstance(output_limit_bytes, int)
        or isinstance(output_limit_bytes, bool)
        or not 1024 <= output_limit_bytes <= 64 * 1024 * 1024
        or not isinstance(observation_limit_bytes, int)
        or isinstance(observation_limit_bytes, bool)
        or not 1024 <= observation_limit_bytes
        <= _MAX_TRUSTED_OBSERVATION_BYTES
        or any(not isinstance(fd, int) or fd < 3 for fd in authority_fds)
        or len(set(authority_fds)) != len(authority_fds)
        or any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or not all(isinstance(fd, int) and fd >= 3 for fd in pair)
            or pair[1] in {_CHILD_CONFIG_FD, _CHILD_ADAPTER_FD}
            for pair in inherited_fds
        )
        or len({pair[1] for pair in inherited_fds}) != len(inherited_fds)
        or (
            framed_config is not None
            and (
                not isinstance(framed_config, bytes)
                or not 4 < len(framed_config) <= 4 * 1024 * 1024 + 4
                or int.from_bytes(framed_config[:4], "big")
                != len(framed_config) - 4
            )
        )
    ):
        raise Attempt0RunnerError("RAW_COMMAND_UNSAFE")
    out_read = out_write = err_read = err_write = stdin_fd = None
    child_out = child_err = child_stdin = None
    config_read = config_write = child_config = child_observation = None
    child_inherited: list[int] = []
    parent_sock: socket.socket | None = None
    child_sock: socket.socket | None = None
    pid: int | None = None
    kqueue = None
    reaper: threading.Thread | None = None
    reaped = threading.Event()
    slot: list[int] = []
    reaper_started = False
    child_reaped = False
    try:
        out_read, out_write = os.pipe()
        err_read, err_write = os.pipe()
        stdin_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.set_blocking(out_read, False)
        os.set_blocking(err_read, False)
        child_out = _moved_child_fd(out_write)
        child_err = _moved_child_fd(err_write)
        child_stdin = _moved_child_fd(stdin_fd)
        actions: list[tuple[int, ...]] = [
            (os.POSIX_SPAWN_DUP2, child_stdin, 0),
            (os.POSIX_SPAWN_DUP2, child_out, 1),
            (os.POSIX_SPAWN_DUP2, child_err, 2),
        ]
        if framed_config is not None:
            config_read, config_write = os.pipe()
            os.set_blocking(config_write, False)
            parent_sock, child_sock = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_STREAM,
            )
            parent_sock.setblocking(False)
            child_config = _moved_child_fd(config_read)
            child_observation = _moved_child_fd(child_sock.fileno())
            actions.extend([
                (os.POSIX_SPAWN_DUP2, child_config, _CHILD_CONFIG_FD),
                (
                    os.POSIX_SPAWN_DUP2,
                    child_observation,
                    _CHILD_ADAPTER_FD,
                ),
            ])
        for source_fd, destination_fd in inherited_fds:
            moved = _moved_child_fd(source_fd)
            child_inherited.append(moved)
            actions.append((os.POSIX_SPAWN_DUP2, moved, destination_fd))
        close_candidates = (
            out_read, out_write, err_read, err_write, stdin_fd,
            child_out, child_err, child_stdin,
            config_read, config_write,
            child_sock.fileno() if child_sock is not None else None,
            child_config, child_observation,
            *(source for source, _ in inherited_fds),
            *child_inherited,
            *authority_fds,
        )
        for fd in close_candidates:
            if fd is not None and fd not in {
                0, 1, 2, child_out, child_err, child_stdin,
                child_config, child_observation,
                *child_inherited,
            }:
                actions.append((os.POSIX_SPAWN_CLOSE, fd))
        for fd in (
            child_out, child_err, child_stdin,
            child_config, child_observation,
            *child_inherited,
        ):
            if fd is None:
                continue
            if fd not in {0, 1, 2}:
                actions.append((os.POSIX_SPAWN_CLOSE, fd))
        pid = os.posix_spawn(
            argv[0], list(argv), dict(environment),
            file_actions=actions, setpgroup=0,
        )
        # The sole timeout/process-group/reap authority begins at the first
        # successful return from spawn.  No potentially blocking transport
        # operation is permitted before this timestamp.
        start = time.monotonic()
    except BaseException as exc:
        if pid is not None:
            _close_fds([
                out_write, err_write, stdin_fd,
                child_out, child_err, child_stdin, config_read, config_write,
                child_config, child_observation, *child_inherited,
            ])
            for peer in (parent_sock, child_sock):
                if peer is not None:
                    try:
                        peer.close()
                    except OSError:
                        pass
            _cleanup_spawned_group(
                pid, slot, reaped, reaper, reaper_started,
            )
            _bounded_failure_drain((out_read, err_read))
            _close_fds([out_read, err_read])
            if isinstance(exc, OSError):
                raise Attempt0RunnerError("SUPERVISOR_SETUP_FAILED") from exc
            raise
        _close_fds([
            out_read, out_write, err_read, err_write, stdin_fd,
            child_out, child_err, child_stdin, config_read, config_write,
            child_config, child_observation, *child_inherited,
        ])
        if parent_sock is not None:
            parent_sock.close()
        if child_sock is not None:
            child_sock.close()
        if not isinstance(exc, OSError):
            raise
        return TrustedCommandResult(
            {"state": "PRE_EXEC_FAILED"}, b"", b"", False, False,
        )
    try:
        _close_fds([
            out_write, err_write, stdin_fd, child_out, child_err, child_stdin,
            config_read, child_config, child_observation,
            *child_inherited,
        ])
        out_write = err_write = stdin_fd = child_out = child_err = child_stdin = None
        config_read = child_config = child_observation = None
        if child_sock is not None:
            child_sock.close()
            child_sock = None
        stdout = bytearray()
        stderr = bytearray()
        out_eof = err_eof = False
        out_truncated = err_truncated = False
        output_limited = timed_out = False
        term_at: float | None = None
        cutoff_at: float | None = None
        group_term_at: float | None = None
        group_kill_sent = False
        if start is None:
            raise Attempt0RunnerError("SUPERVISOR_SETUP_FAILED")
        raw_process: Mapping[str, Any] | None = None
        observation_buffer = bytearray()
        observation: Mapping[str, Any] | None = None
        observation_error: str | None = None
        observation_eof = framed_config is None
        ack_offset = 0
        config_offset = 0
        config_complete = framed_config is None
    except BaseException:
        _close_fds([config_write])
        config_write = None
        if parent_sock is not None:
            try:
                parent_sock.close()
            except OSError:
                pass
            parent_sock = None
        if child_sock is not None:
            try:
                child_sock.close()
            except OSError:
                pass
            child_sock = None
        _cleanup_spawned_group(pid, slot, reaped, reaper, reaper_started)
        _bounded_failure_drain((out_read, err_read))
        _close_fds([
            out_read, out_write, err_read, err_write, stdin_fd,
            child_out, child_err, child_stdin, config_read,
            child_config, child_observation, *child_inherited,
        ])
        raise
    try:
        try:
            kqueue = select.kqueue()
        except OSError as exc:
            raise Attempt0RunnerError("SUPERVISOR_SETUP_FAILED") from exc
        registrations = [
            select.kevent(
                pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
                fflags=select.KQ_NOTE_EXIT,
            ),
            select.kevent(out_read, filter=select.KQ_FILTER_READ, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE),
            select.kevent(err_read, filter=select.KQ_FILTER_READ, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE),
        ]
        if parent_sock is not None:
            registrations.append(
                select.kevent(
                    parent_sock.fileno(),
                    filter=select.KQ_FILTER_READ,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE,
                ),
            )
        if config_write is not None:
            registrations.append(
                select.kevent(
                    config_write,
                    filter=select.KQ_FILTER_WRITE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE,
                ),
            )
        try:
            kqueue.control(registrations, 0, 0)
        except OSError as exc:
            raise Attempt0RunnerError("SUPERVISOR_SETUP_FAILED") from exc
        reaper = threading.Thread(
            target=_wait_once, args=(pid, slot, reaped), daemon=True,
        )
        reaper.start()
        reaper_started = True
        while True:
            now = time.monotonic()
            if (
                config_write is not None
                and framed_config is not None
                and cutoff_at is None
            ):
                # A writable pipe can remain writable without producing a
                # distinct later notification after nested spawn activity.
                # Make bounded nonblocking progress inside this same
                # kqueue/timeout/group/reap loop; EAGAIN leaves the registered
                # write filter authoritative for the next iteration.
                remaining = memoryview(framed_config)[config_offset:]
                chunk = remaining[: min(len(remaining), 4096)]
                try:
                    count = _write_framed_config(config_write, chunk)
                except BlockingIOError:
                    count = None
                except OSError as exc:
                    raise Attempt0RunnerError(
                        "CONFIG_WRITE_FAILED",
                    ) from exc
                if count is not None:
                    if count != len(chunk):
                        raise Attempt0RunnerError("CONFIG_WRITE_FAILED")
                    config_offset += count
                    if config_offset == len(framed_config):
                        _delete_kevent(
                            kqueue,
                            config_write,
                            select.KQ_FILTER_WRITE,
                        )
                        _close_fds([config_write])
                        config_write = None
                        config_complete = True
            if cutoff_at is None and now - start >= timeout_seconds and term_at is None:
                timed_out = True
                _signal_group(pid, signal.SIGTERM)
                term_at = now
            if term_at is not None and cutoff_at is None and now - term_at >= _TERM_GRACE_SECONDS:
                _signal_group(pid, signal.SIGKILL)
            group_gone = cutoff_at is not None and _process_group_gone(
                pid, leader_reaped=bool(slot),
            )
            if cutoff_at is not None:
                since_cutoff = now - cutoff_at
                if (
                    not group_gone and group_term_at is None
                    and since_cutoff >= 0.06
                    and (
                        bool(slot)
                        or not (out_eof and err_eof and observation_eof)
                    )
                ):
                    _signal_group(pid, signal.SIGTERM)
                    group_term_at = now
                if (
                    not group_gone and group_term_at is not None
                    and now - group_term_at >= 0.10 and not group_kill_sent
                ):
                    _signal_group(pid, signal.SIGKILL)
                    group_kill_sent = True
                if since_cutoff >= _TERMINAL_DRAIN_SECONDS:
                    if not group_gone:
                        raise Attempt0RunnerError("PROCESS_GROUP_CLEANUP_FAILED")
                    if not (out_eof and err_eof and observation_eof):
                        raise Attempt0RunnerError("TERMINAL_DRAIN_INCOMPLETE")
            if (
                cutoff_at is not None
                and out_eof and err_eof and observation_eof and group_gone
            ):
                break
            deadline = (
                start + timeout_seconds
                if cutoff_at is None
                else cutoff_at + _TERMINAL_DRAIN_SECONDS
            )
            events = kqueue.control(
                None, 8, max(0.0, min(0.05, deadline - now)),
            )
            if any(
                event.filter == select.KQ_FILTER_PROC
                and event.fflags & select.KQ_NOTE_EXIT
                for event in events
            ):
                cutoff_at = cutoff_at or time.monotonic()
            for event in events:
                if event.filter == select.KQ_FILTER_PROC:
                    continue
                if (
                    config_write is not None
                    and event.ident == config_write
                    and event.filter == select.KQ_FILTER_WRITE
                ):
                    if cutoff_at is not None:
                        _delete_kevent(
                            kqueue,
                            config_write,
                            select.KQ_FILTER_WRITE,
                        )
                        _close_fds([config_write])
                        config_write = None
                        continue
                    if framed_config is None:
                        raise Attempt0RunnerError("CONFIG_WRITE_FAILED")
                    remaining = memoryview(framed_config)[config_offset:]
                    # PIPE_BUF writes are all-or-nothing for a pipe.  This
                    # makes a short result an explicit transport failure while
                    # still allowing a multi-megabyte frame to progress inside
                    # the one supervised event loop.
                    chunk = remaining[: min(len(remaining), 4096)]
                    try:
                        count = _write_framed_config(config_write, chunk)
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        raise Attempt0RunnerError(
                            "CONFIG_WRITE_FAILED",
                        ) from exc
                    if count != len(chunk):
                        raise Attempt0RunnerError("CONFIG_WRITE_FAILED")
                    config_offset += count
                    if config_offset == len(framed_config):
                        _delete_kevent(
                            kqueue,
                            config_write,
                            select.KQ_FILTER_WRITE,
                        )
                        _close_fds([config_write])
                        config_write = None
                        config_complete = True
                    continue
                if (
                    parent_sock is not None
                    and event.ident == parent_sock.fileno()
                    and event.filter == select.KQ_FILTER_WRITE
                ):
                    if cutoff_at is not None or observation is None:
                        continue
                    try:
                        count = _send_ack(
                            parent_sock,
                            memoryview(b"ACK!")[ack_offset:],
                        )
                    except BlockingIOError:
                        continue
                    except OSError:
                        observation_error = "ADAPTER_MALFORMED"
                        _delete_kevent(
                            kqueue,
                            parent_sock.fileno(),
                            select.KQ_FILTER_WRITE,
                        )
                        continue
                    if count <= 0:
                        raise Attempt0RunnerError("ACK_FAILED")
                    ack_offset += count
                    if ack_offset == 4:
                        _delete_kevent(
                            kqueue,
                            parent_sock.fileno(),
                            select.KQ_FILTER_WRITE,
                        )
                    continue
                if event.filter != select.KQ_FILTER_READ:
                    continue
                if (
                    parent_sock is not None
                    and event.ident == parent_sock.fileno()
                ):
                    try:
                        chunk = parent_sock.recv(65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        observation_eof = True
                        _delete_kevent(
                            kqueue,
                            parent_sock.fileno(),
                            select.KQ_FILTER_READ,
                        )
                        continue
                    if cutoff_at is not None:
                        observation_error = "ADAPTER_LATE"
                        continue
                    if observation is not None or observation_error is not None:
                        observation_error = "ADAPTER_MALFORMED"
                        observation_eof = True
                        _abort_authority_transport(kqueue, parent_sock)
                        parent_sock = None
                        continue
                    observation_buffer.extend(chunk)
                    if len(observation_buffer) < 4:
                        continue
                    length = int.from_bytes(
                        observation_buffer[:4], "big",
                    )
                    if length == 0 or length > observation_limit_bytes:
                        observation_error = "ADAPTER_MALFORMED"
                        observation_eof = True
                        _abort_authority_transport(kqueue, parent_sock)
                        parent_sock = None
                        continue
                    if len(observation_buffer) < 4 + length:
                        continue
                    if len(observation_buffer) != 4 + length:
                        observation_error = "ADAPTER_MALFORMED"
                        observation_eof = True
                        _abort_authority_transport(kqueue, parent_sock)
                        parent_sock = None
                        continue
                    raw_observation = bytes(observation_buffer[4:])
                    try:
                        candidate = load_canonical_json(raw_observation)
                        if (
                            not isinstance(candidate, Mapping)
                            or canonical_json_bytes(candidate)
                            != raw_observation
                        ):
                            raise ValueError()
                        observation = candidate
                    except Exception:
                        observation_error = "ADAPTER_MALFORMED"
                        observation = None
                        observation_eof = True
                        _abort_authority_transport(kqueue, parent_sock)
                        parent_sock = None
                        continue
                    # Complete the common ACK path in the same supervised read
                    # event.  A partial send or EAGAIN remains under the
                    # existing nonblocking write filter; no child can wait on
                    # a future write notification that the kernel may coalesce.
                    try:
                        count = _send_ack(
                            parent_sock,
                            memoryview(b"ACK!")[ack_offset:],
                        )
                    except BlockingIOError:
                        count = None
                    except OSError:
                        observation_error = "ADAPTER_MALFORMED"
                        observation_eof = True
                        _abort_authority_transport(kqueue, parent_sock)
                        parent_sock = None
                        continue
                    if count is not None:
                        if count <= 0:
                            raise Attempt0RunnerError("ACK_FAILED")
                        ack_offset += count
                    if ack_offset != 4:
                        kqueue.control([
                            select.kevent(
                                parent_sock.fileno(),
                                filter=select.KQ_FILTER_WRITE,
                                flags=(
                                    select.KQ_EV_ADD
                                    | select.KQ_EV_ENABLE
                                ),
                            ),
                        ], 0, 0)
                    continue
                fd = int(event.ident)
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    if fd == out_read:
                        out_eof = True
                    elif fd == err_read:
                        err_eof = True
                    _delete_kevent(kqueue, fd, select.KQ_FILTER_READ)
                    continue
                target = stdout if fd == out_read else stderr
                available = max(0, output_limit_bytes - len(stdout) - len(stderr))
                if available:
                    target.extend(chunk[:available])
                if len(chunk) > available:
                    if fd == out_read:
                        out_truncated = True
                    else:
                        err_truncated = True
                    output_limited = True
                    if term_at is None:
                        _signal_group(pid, signal.SIGTERM)
                        term_at = time.monotonic()
        if not out_eof or not err_eof or not observation_eof:
            raise Attempt0RunnerError("TERMINAL_DRAIN_INCOMPLETE")
        if not _process_group_gone(pid, leader_reaped=bool(slot)):
            raise Attempt0RunnerError("PROCESS_GROUP_CLEANUP_FAILED")
        reaper.join(1.0)
        if not slot:
            raise Attempt0RunnerError("REAP_FAILED")
        child_reaped = True
        rc = _exit_code(slot[0])
        if observation_buffer and observation is None and observation_error is None:
            observation_error = "ADAPTER_MALFORMED"
        if (
            framed_config is not None
            and not config_complete
            and observation_error is None
        ):
            observation_error = "ADAPTER_MALFORMED"
        if (
            framed_config is not None
            and observation is not None
            and ack_offset != 4
            and observation_error is None
        ):
            observation_error = "ADAPTER_MALFORMED"
        if framed_config is not None and observation is None and observation_error is None:
            observation_error = "ADAPTER_MISSING"
        if output_limited:
            raw_process = {"state": "OUTPUT_LIMIT"}
        elif timed_out:
            raw_process = {"state": "HARD_TIMEOUT"}
        elif rc < 0:
            raw_process = {"state": "SIGNALED", "process_signal": -rc}
        else:
            raw_process = {"state": "EXITED", "process_exit": rc}
    except BaseException:
        _close_fds([config_write])
        config_write = None
        if parent_sock is not None:
            try:
                parent_sock.close()
            except OSError:
                pass
            parent_sock = None
        _cleanup_spawned_group(pid, slot, reaped, reaper, reaper_started)
        _bounded_failure_drain((out_read, err_read))
        raise
    finally:
        if kqueue is not None:
            kqueue.close()
        if parent_sock is not None:
            parent_sock.close()
        _close_fds([out_read, err_read, config_write])
    if raw_process is None:
        raise Attempt0RunnerError("REAP_FAILED")
    return TrustedCommandResult(
        raw_process, bytes(stdout), bytes(stderr),
        out_truncated, err_truncated,
        observation, observation_error, ack_offset == 4,
    )


def run_attempt0(*, repo_root: str | os.PathLike[str], layout: RunLayout) -> AttemptDecisionV1:
    """Run the one fixed RUE-05A normal attempt; no caller-controlled fixture or argv."""
    return _run_attempt0(repo_root=repo_root, layout=layout)
