"""RUE-03 store plus narrow RUE-04/05/06/fixed-aggregation primitives.

This module has no Git subprocess, retry execution, aggregation policy, or CLI
logic.  It only owns layout-local publication claims and exact readbacks.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import os
import secrets
import stat
import threading
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .manifest_contracts import canonical_json_bytes, load_canonical_json, validate_source_snapshot, validate_terminal_set
from .contracts import AttemptDecisionV1

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_RENAME_FLAGS = 0x4 | 0x10 | 0x20
_MAX_RECORD_BYTES = 1024 * 1024
_MAX_FAILURE_BYTES = 64 * 1024
_ATTEMPT0_SUITE_ID = "SUITE-RUE05A"
_ATTEMPT0_ENTRYPOINT_ID = "ENTRY-RUE05A-ATTEMPT0"
_FAILURE_STAGES = frozenset(("RUN_ROOT", "SNAPSHOT", "CHANGE_SET", "PLAN", "EXECUTE", "AGGREGATE", "SEAL", "INTERRUPT", "INTERNAL"))
# mkdir(2) is subject to the process-global umask.  Serialise the short
# critical section so a new private directory has the requested mode before
# its descriptor is opened; permissions are never adjusted through its name.
_UMASK_LOCK = threading.RLock()
_AREAS = {
    "snapshot": frozenset(("source-snapshot-manifest.json",)),
    "attempts": None,
    "evidence": frozenset(("run-manifest.json", "evidence-manifest.json")),
    "results": None,
    "root": frozenset(("run-manifest.json", "evidence-manifest.json")),
}


@dataclass(frozen=True)
class TempOwnerIdentityV1:
    dev: int
    ino: int
    uid: int
    file_type: str
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class TempResidualV1:
    temp_leaf: str
    owner_identity: TempOwnerIdentityV1 | None
    expected_sha256: str
    state: str


class RunStoreError(RuntimeError):
    """Typed storage failure.  Its fields deliberately never contain absolute paths."""

    def __init__(
        self,
        code: str,
        *,
        stage: str = "STORE",
        run_id: str | None = None,
        published_may_exist: bool = False,
        failure_recorded: bool = False,
        secondary_code: str | None = None,
        residual: TempResidualV1 | None = None,
        final_leaf: str | None = None,
        final_identity_state: str = "UNKNOWN",
        published: bool | None = None,
    ) -> None:
        if published is not None:
            published_may_exist = published
        self.code = code
        self.stage = stage
        self.run_id = run_id
        self.published_may_exist = published_may_exist
        # Kept as a compatibility alias while all new callers use the explicit field.
        self.published = published_may_exist
        self.failure_recorded = failure_recorded
        self.secondary_code = secondary_code
        self.residual = residual
        self.final_leaf = final_leaf
        self.final_identity_state = final_identity_state
        super().__init__(code)


@dataclass(frozen=True)
class PublishedJson:
    area: str
    leaf: str
    path: str
    sha256: str
    size: int
    identity: TempOwnerIdentityV1


@dataclass(frozen=True)
class FirstFailureResult:
    status: str
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class SnapshotCaptureLease:
    """An unforgeable, layout-local capability for one snapshot capture."""

    run_id: str
    _nonce: bytes


@dataclass(frozen=True)
class SnapshotPublicationTicket:
    """A published snapshot which has not yet crossed the success boundary."""

    run_id: str
    expected_head_sha: str
    publication: PublishedJson
    identity: TempOwnerIdentityV1
    _nonce: bytes


@dataclass(frozen=True)
class FinalizedSnapshotBinding:
    """The exact RUE-04 publication consumed by the one attempt-0 claim.

    This is deliberately held only by a ``RunLayout``.  It is not an
    authority registry and cannot be reconstructed from a path string.
    """

    run_id: str
    head_sha: str
    publication: PublishedJson
    identity: TempOwnerIdentityV1


def _error(code: str, **kwargs: Any) -> RunStoreError:
    return RunStoreError(code, **kwargs)


def _secondary(error: RunStoreError, code: str) -> RunStoreError:
    return _error(
        error.code, stage=error.stage, run_id=error.run_id,
        published_may_exist=error.published_may_exist,
        failure_recorded=error.failure_recorded,
        secondary_code=error.secondary_code or code,
        residual=error.residual, final_leaf=error.final_leaf,
        final_identity_state=error.final_identity_state,
    )


def _owned_close(
    fd: int | None,
    primary: RunStoreError | None = None,
    *,
    run_id: str | None = None,
    published: bool = False,
    final_leaf: str | None = None,
    final_identity_state: str = "UNKNOWN",
) -> RunStoreError | None:
    """Close exactly once; never retry an owned descriptor after an error."""
    if fd is None:
        return primary
    try:
        os.close(fd)
    except OSError:
        if primary is None:
            return _error("CLOSE_FAILED", stage="CLOSE", run_id=run_id, published_may_exist=published, final_leaf=final_leaf, final_identity_state=final_identity_state)
        result = _secondary(primary, "CLOSE_FAILED")
        if published and not result.published_may_exist:
            result = _error(
                result.code, stage=result.stage, run_id=result.run_id or run_id,
                published_may_exist=True, failure_recorded=result.failure_recorded,
                secondary_code=result.secondary_code, residual=result.residual,
                final_leaf=result.final_leaf or final_leaf,
                final_identity_state=result.final_identity_state,
            )
        return result
    return primary


def _close_many(
    fds: list[int | None], primary: RunStoreError | None = None, *, run_id: str | None = None, published: bool = False
) -> RunStoreError | None:
    for fd in fds:
        primary = _owned_close(fd, primary, run_id=run_id, published=published)
    return primary


def _close_checked(fd: int | None, primary: RunStoreError | None, *, run_id: str, published: bool, final_leaf: str) -> None:
    result = _owned_close(fd, primary, run_id=run_id, published=published, final_leaf=final_leaf)
    if result is not None:
        raise result


def _again(call: Any, *args: Any, **kwargs: Any) -> Any:
    while True:
        try:
            return call(*args, **kwargs)
        except InterruptedError:
            continue


def _mode(item: os.stat_result) -> int:
    return stat.S_IMODE(item.st_mode)


def _same(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _owner(item: os.stat_result) -> TempOwnerIdentityV1:
    return TempOwnerIdentityV1(
        item.st_dev,
        item.st_ino,
        item.st_uid,
        "regular" if stat.S_ISREG(item.st_mode) else "other",
        _mode(item),
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _owner_matches(item: os.stat_result, owner: TempOwnerIdentityV1, *, exact: bool = True) -> bool:
    candidate = _owner(item)
    if not exact:
        return candidate.dev == owner.dev and candidate.ino == owner.ino
    return candidate == owner


def _stable(left: os.stat_result, right: os.stat_result) -> bool:
    """Full stable identity: inode equality alone is not enough for evidence."""
    return _owner(left) == _owner(right)


def _leaf(value: str) -> bool:
    if not isinstance(value, str) or not value or "/" in value or value in {".", ".."}:
        return False
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
    return (
        bool(encoded)
        and value == unicodedata.normalize("NFC", value)
        and "\x00" not in value
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _absolute_components(value: str | os.PathLike[str]) -> tuple[str, tuple[str, ...]]:
    text = os.fspath(value)
    if not isinstance(text, str) or not text.startswith("/") or text in {"", "/"} or text.endswith("/") or "//" in text:
        raise _error("RUN_ROOT_UNSAFE", stage="ROOT")
    try:
        text.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise _error("RUN_ROOT_UNSAFE", stage="ROOT")
    parts = tuple(text[1:].split("/"))
    if text != unicodedata.normalize("NFC", text) or any(not _leaf(part) for part in parts):
        raise _error("RUN_ROOT_UNSAFE", stage="ROOT")
    return text, parts


def _open_absolute_root(value: str | os.PathLike[str]) -> tuple[int, tuple[tuple[int, int], ...]]:
    _, parts = _absolute_components(value)
    try:
        fd = _again(os.open, "/", _DIR_FLAGS)
    except OSError:
        raise _error("RUN_ROOT_UNSAFE", stage="ROOT")
    lineage: list[tuple[int, int]] = []
    try:
        for leaf in parts:
            try:
                next_fd = _again(os.open, leaf, _DIR_FLAGS, dir_fd=fd)
            except OSError:
                raise _error("RUN_ROOT_UNSAFE", stage="ROOT")
            old_fd, fd = fd, next_fd  # register the new owner before adjudicating old close.
            close_error = _owned_close(old_fd, run_id=None)
            if close_error is not None:
                close_error = _owned_close(fd, close_error)  # close new once; keep old-close primary.
                fd = None
                raise close_error  # type: ignore[misc]
            item = os.fstat(fd)
            if not stat.S_ISDIR(item.st_mode):
                raise _error("RUN_ROOT_UNSAFE", stage="ROOT")
            lineage.append((item.st_dev, item.st_ino))
        item = os.fstat(fd)
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid() or (_mode(item) & 0o022):
            raise _error("RUN_ROOT_UNSAFE", stage="ROOT")
        return fd, tuple(lineage)
    except RunStoreError as error:
        raise _owned_close(fd, error)  # type: ignore[misc]
    except OSError:
        error = _error("RUN_ROOT_UNSAFE", stage="ROOT")
        raise _owned_close(fd, error)  # type: ignore[misc]


def _fsync(fd: int, code: str = "PUBLISH_IO_FAILED") -> None:
    try:
        _again(os.fsync, fd)
    except OSError:
        raise _error(code, stage="FSYNC")


def _safe_dir_stat(item: os.stat_result, *, private: bool) -> os.stat_result:
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid() or (_mode(item) & 0o022):
        raise _error("RUN_ROOT_UNSAFE", stage="ROOT")
    if private and _mode(item) != 0o700:
        raise _error("RUN_ROOT_UNSAFE", stage="ROOT")
    return item


def _safe_dir(fd: int, *, private: bool) -> os.stat_result:
    try:
        return _safe_dir_stat(os.fstat(fd), private=private)
    except RunStoreError:
        raise
    except OSError:
        raise _error("FD_DRIFT", stage="BIND")


def _mkdir_open(parent_fd: int, leaf: str, *, reuse: bool) -> int:
    created: os.stat_result | None = None
    try:
        # A caller's umask must not turn a private run directory into an
        # unreadable one.  The name is not chmod'ed: after mkdir we bind it to
        # a descriptor before applying fchmod to the descriptor itself.
        with _UMASK_LOCK:
            previous_umask = os.umask(0)
            try:
                _again(os.mkdir, leaf, 0o700, dir_fd=parent_fd)
            finally:
                os.umask(previous_umask)
        created = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        _safe_dir_stat(created, private=True)
    except FileExistsError:
        if not reuse:
            raise _error("RUN_ID_COLLISION", stage="LAYOUT")
    except RunStoreError:
        raise
    except OSError:
        raise _error("RUN_ROOT_UNSAFE", stage="LAYOUT")
    try:
        fd = _again(os.open, leaf, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError:
        raise _error("RUN_ROOT_UNSAFE", stage="LAYOUT")
    try:
        opened = os.fstat(fd)
        # Do not fchmod a descriptor unless it is provably the directory this
        # invocation created.  A name swap between mkdir and open is foreign
        # state and must remain byte-for-byte and mode-for-mode untouched.
        if created is not None:
            if not _same(created, opened):
                raise _error("PATH_DRIFT", stage="LAYOUT")
            _again(os.fchmod, fd, 0o700)
        _safe_dir(fd, private=True)
        held = os.fstat(fd)
        named = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        _safe_dir_stat(named, private=True)
        if not _same(named, held):
            raise _error("PATH_DRIFT", stage="LAYOUT")
        if created is not None:
            _fsync(parent_fd, "RUN_ROOT_UNSAFE")
        return fd
    except RunStoreError as error:
        raise _owned_close(fd, error)  # type: ignore[misc]
    except OSError:
        raise _owned_close(fd, _error("RUN_ROOT_UNSAFE", stage="LAYOUT"))  # type: ignore[misc]


def _named_fd(parent_fd: int, leaf: str, held_fd: int, *, private_parent: bool = False) -> None:
    """Verify a live public name still resolves to exactly the held descriptor."""
    try:
        probe = _again(os.open, leaf, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError:
        raise _error("PATH_DRIFT", stage="BIND")
    primary: RunStoreError | None = None
    try:
        if private_parent:
            _safe_dir(parent_fd, private=True)
        public = _safe_dir(probe, private=True)
        held = _safe_dir(held_fd, private=True)
        if not _same(public, held):
            raise _error("PATH_DRIFT", stage="BIND")
    except RunStoreError as error:
        primary = error
    except OSError:
        primary = _error("FD_DRIFT", stage="BIND")
    primary = _owned_close(probe, primary)
    if primary is not None:
        raise primary


def _verify_layout_binding(
    state_root_fd: int,
    evidence_root_fd: int,
    state_runs_fd: int,
    evidence_runs_fd: int,
    layout: "RunLayout",
) -> None:
    """Bind every public root/runs/run/area name before returning or publishing."""
    _named_fd(state_root_fd, "runs", state_runs_fd)
    _named_fd(evidence_root_fd, "runs", evidence_runs_fd)
    _named_fd(state_runs_fd, layout.run_id, layout._state_fd_required(), private_parent=True)
    _named_fd(evidence_runs_fd, layout.run_id, layout._evidence_fd_required(), private_parent=True)
    _named_fd(layout._state_fd_required(), "snapshot", layout._snapshot_fd_required(), private_parent=True)
    _named_fd(layout._state_fd_required(), "attempts", layout._attempts_fd_required(), private_parent=True)
    _named_fd(layout._state_fd_required(), "cache", layout._cache_fd_required(), private_parent=True)
    _named_fd(layout._state_fd_required(), "tmp", layout._tmp_fd_required(), private_parent=True)
    _named_fd(layout._evidence_fd_required(), "results", layout._results_fd_required(), private_parent=True)


def _verify_creation_public_binding(
    state_root_path: str,
    evidence_root_path: str,
    state_root_fd: int,
    evidence_root_fd: int,
    state_runs_fd: int,
    evidence_runs_fd: int,
    layout: "RunLayout",
) -> None:
    """Re-open caller paths before bootstrap FDs are released; reject root swaps."""
    fresh_state = fresh_evidence = None
    primary: RunStoreError | None = None
    try:
        fresh_state, _ = _open_absolute_root(state_root_path)
        fresh_evidence, _ = _open_absolute_root(evidence_root_path)
        if not _same(os.fstat(fresh_state), os.fstat(state_root_fd)) or not _same(os.fstat(fresh_evidence), os.fstat(evidence_root_fd)):
            raise _error("PATH_DRIFT", stage="BIND", run_id=layout.run_id)
        _verify_layout_binding(fresh_state, fresh_evidence, state_runs_fd, evidence_runs_fd, layout)
    except RunStoreError as error:
        primary = error
    except OSError:
        primary = _error("PATH_DRIFT", stage="BIND", run_id=layout.run_id)
    primary = _close_many([fresh_state, fresh_evidence], primary, run_id=layout.run_id)
    if primary is not None:
        raise primary


def _read_exact(fd: int, size: int, *, code: str) -> bytes:
    try:
        _again(os.lseek, fd, 0, os.SEEK_SET)
    except OSError:
        raise _error(code, stage="READ")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = _again(os.read, fd, min(remaining, 65536))
        except OSError:
            raise _error(code, stage="READ")
        if not chunk:
            raise _error(code, stage="READ")
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        if _again(os.read, fd, 1):
            raise _error(code, stage="READ")
    except RunStoreError:
        raise
    except OSError:
        raise _error(code, stage="READ")
    return b"".join(chunks)


def _write_all(fd: int, raw: bytes) -> None:
    if len(raw) > _MAX_RECORD_BYTES:
        raise _error("PUBLISH_RECORD_TOO_LARGE", stage="WRITE")
    offset = 0
    while offset < len(raw):
        try:
            count = _again(os.write, fd, raw[offset:])
        except OSError:
            raise _error("PUBLISH_IO_FAILED", stage="WRITE")
        if count <= 0:
            raise _error("PUBLISH_IO_FAILED", stage="WRITE")
        offset += count


def _rename_exclusive(parent_fd: int, temp_leaf: str, final_leaf: str) -> None:
    if not _leaf(temp_leaf) or not _leaf(final_leaf):
        raise _error("CONTRACT_FAILURE", stage="RENAME")
    try:
        function = ctypes.CDLL(None, use_errno=True).renameatx_np
    except (AttributeError, OSError):
        raise _error("PUBLISH_ATOMIC_UNSUPPORTED", stage="RENAME")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(parent_fd, temp_leaf.encode("utf-8"), parent_fd, final_leaf.encode("utf-8"), _RENAME_FLAGS)
    if result == 0:
        return
    number = ctypes.get_errno()
    codes = {
        errno.EEXIST: "PUBLISH_EXISTS",
        45: "PUBLISH_ATOMIC_UNSUPPORTED",
        102: "PUBLISH_ATOMIC_UNSUPPORTED",
        errno.EINVAL: "CONTRACT_FAILURE",
        107: "RESOLUTION_REJECTED",
        errno.ENOENT: "PATH_DRIFT",
        62: "PATH_DRIFT",
        errno.EBADF: "FD_DRIFT",
    }
    raise _error(codes.get(number, "CONTRACT_FAILURE" if number == 0 else "RENAME_FAILED"), stage="RENAME")


def _publication_name(
    area: str,
    leaf: str,
    *,
    failure: bool,
    dedicated_attempt: bool = False,
    dedicated_terminal: bool = False,
) -> None:
    if area not in _AREAS or not _leaf(leaf):
        raise _error("PUBLISH_AREA_INVALID", stage="PUBLISH")
    if leaf == "completion-seal.json":
        if not dedicated_terminal or area != "root" or failure:
            raise _error("PUBLISH_AREA_INVALID", stage="PUBLISH")
        return
    if failure:
        if area != "evidence" or leaf != "run-failure.json":
            raise _error("PUBLISH_AREA_INVALID", stage="PUBLISH")
        return
    fixed = _AREAS[area]
    if leaf == "run-failure.json" or (fixed is not None and leaf not in fixed):
        raise _error("PUBLISH_AREA_INVALID", stage="PUBLISH")
    if area == "results" and not (leaf.startswith("SUITE-") and leaf.endswith(".json")):
        raise _error("PUBLISH_AREA_INVALID", stage="PUBLISH")
    if area == "attempts":
        if not dedicated_attempt or leaf not in {"attempt-0.json", "attempt-1.json"}:
            raise _error("PUBLISH_AREA_INVALID", stage="PUBLISH")


@dataclass
class RunLayout:
    run_id: str
    state_path: str
    evidence_path: str
    _state_fd: int | None
    _snapshot_fd: int | None
    _attempts_fd: int | None
    _cache_fd: int | None
    _tmp_fd: int | None
    _evidence_fd: int | None
    _results_fd: int | None
    _closed: bool = False
    _closing: bool = False
    _close_error: RunStoreError | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _state_root_path: str = field(default="", repr=False)
    _evidence_root_path: str = field(default="", repr=False)
    _snapshot_nonce: bytes | None = field(default=None, repr=False)
    _snapshot_lease: SnapshotCaptureLease | None = field(default=None, repr=False)
    _snapshot_ticket: SnapshotPublicationTicket | None = field(default=None, repr=False)
    _snapshot_state: str = field(default="OPEN", repr=False)
    _finalized_snapshot_binding: FinalizedSnapshotBinding | None = field(default=None, repr=False)
    _attempt0_started: bool = field(default=False, repr=False)
    _attempt0_publication_started: bool = field(default=False, repr=False)
    _attempt0_publication: PublishedJson | None = field(default=None, repr=False)
    _attempt1_started: bool = field(default=False, repr=False)
    _attempt1_publication_started: bool = field(default=False, repr=False)
    _attempt1_publication: PublishedJson | None = field(default=None, repr=False)
    _fixed_prepare_started: bool = field(default=False, repr=False)
    _fixed_run_publication: PublishedJson | None = field(default=None, repr=False)
    _fixed_completion_started: bool = field(default=False, repr=False)
    _fixed_result_publication: PublishedJson | None = field(default=None, repr=False)
    _fixed_evidence_publication: PublishedJson | None = field(default=None, repr=False)
    _fixed_seal_publication: PublishedJson | None = field(default=None, repr=False)

    def _state_fd_required(self) -> int:
        if self._state_fd is None:
            raise _error("LAYOUT_CLOSED", stage="LAYOUT", run_id=self.run_id)
        return self._state_fd

    def _snapshot_fd_required(self) -> int:
        if self._snapshot_fd is None:
            raise _error("LAYOUT_CLOSED", stage="LAYOUT", run_id=self.run_id)
        return self._snapshot_fd

    def _attempts_fd_required(self) -> int:
        if self._attempts_fd is None:
            raise _error("LAYOUT_CLOSED", stage="LAYOUT", run_id=self.run_id)
        return self._attempts_fd

    def _cache_fd_required(self) -> int:
        if self._cache_fd is None:
            raise _error("LAYOUT_CLOSED", stage="LAYOUT", run_id=self.run_id)
        return self._cache_fd

    def _tmp_fd_required(self) -> int:
        if self._tmp_fd is None:
            raise _error("LAYOUT_CLOSED", stage="LAYOUT", run_id=self.run_id)
        return self._tmp_fd

    def _evidence_fd_required(self) -> int:
        if self._evidence_fd is None:
            raise _error("LAYOUT_CLOSED", stage="LAYOUT", run_id=self.run_id)
        return self._evidence_fd

    def _results_fd_required(self) -> int:
        if self._results_fd is None:
            raise _error("LAYOUT_CLOSED", stage="LAYOUT", run_id=self.run_id)
        return self._results_fd

    def _open(self) -> None:
        if self._closing or self._closed or any(
            fd is None for fd in (self._state_fd, self._snapshot_fd, self._attempts_fd, self._cache_fd, self._tmp_fd, self._evidence_fd, self._results_fd)
        ):
            raise _error("LAYOUT_CLOSED", stage="LAYOUT", run_id=self.run_id)

    def _evidence_open(self) -> None:
        if self._closing or self._closed or self._evidence_fd is None:
            raise _error("LAYOUT_CLOSED", stage="LAYOUT", run_id=self.run_id)

    def _fd(self, area: str) -> int:
        self._open()
        table = {
            "snapshot": self._snapshot_fd_required,
            "attempts": self._attempts_fd_required,
            "evidence": self._evidence_fd_required,
            "root": self._evidence_fd_required,
            "results": self._results_fd_required,
        }
        if area not in table:
            raise _error("PUBLISH_AREA_INVALID", stage="PUBLISH", run_id=self.run_id)
        return table[area]()

    def publish_json(self, area: str, leaf: str, value: Any) -> PublishedJson:
        with self._lock:
            if area == "snapshot":
                raise _error("SNAPSHOT_SPECIAL_PUBLISH_REQUIRED", stage="SNAPSHOT", run_id=self.run_id)
            if area == "attempts":
                # Attempt records are evidence decisions, never generic JSON.
                raise _error("PUBLISH_AREA_INVALID", stage="PUBLISH", run_id=self.run_id)
            if area in {"root", "evidence", "results"}:
                # Run, result, evidence, and seal leaves are authority-bearing.
                # Only the fixed aggregation path may publish them.
                raise _error("PUBLISH_AREA_INVALID", stage="PUBLISH", run_id=self.run_id)
            return _publish(self, area, leaf, canonical_json_bytes(value), failure=False)

    def _read_bound_publication(
        self,
        publication: PublishedJson | None,
        *,
        expected_area: str,
        expected_leaf: str,
        code: str,
        max_size: int = _MAX_RECORD_BYTES,
    ) -> Mapping[str, Any]:
        """Read canonical JSON from one exact layout-owned publication.

        Size and full publication identity are trusted from the successful
        no-clobber publication before the descriptor is read.  Both the held
        descriptor and its public name must retain that exact identity across
        read and parse passes.
        """
        self._open()
        if (
            publication is None
            or publication.area != expected_area
            or publication.leaf != expected_leaf
            or not 0 < publication.size <= max_size
        ):
            raise _error(code, stage="AGGREGATE", run_id=self.run_id)
        try:
            _verify_live_layout(self)
            parent = self._fd(expected_area)
            fd = _again(os.open, publication.leaf, _READ_FLAGS, dir_fd=parent)
        except RunStoreError as rename_error:
            raise
        except OSError:
            raise _error(code, stage="AGGREGATE", run_id=self.run_id)
        primary: RunStoreError | None = None
        decoded: Mapping[str, Any] | None = None
        try:
            before = os.fstat(fd)
            named_before = os.stat(
                publication.leaf, dir_fd=parent, follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or _mode(before) != 0o600
                or before.st_nlink != 1
                or before.st_size != publication.size
                or not _owner_matches(before, publication.identity)
                or not _stable(before, named_before)
            ):
                raise _error(code, stage="AGGREGATE", run_id=self.run_id)
            raw = _read_exact(fd, publication.size, code=code)
            after_read = os.fstat(fd)
            named_after_read = os.stat(
                publication.leaf, dir_fd=parent, follow_symlinks=False,
            )
            if (
                not _owner_matches(after_read, publication.identity)
                or not _stable(before, after_read)
                or not _stable(after_read, named_after_read)
                or hashlib.sha256(raw).hexdigest() != publication.sha256
            ):
                raise _error(code, stage="AGGREGATE", run_id=self.run_id)
            value = load_canonical_json(raw)
            if not isinstance(value, Mapping) or canonical_json_bytes(value) != raw:
                raise _error(code, stage="AGGREGATE", run_id=self.run_id)
            after_parse = os.fstat(fd)
            named_after_parse = os.stat(
                publication.leaf, dir_fd=parent, follow_symlinks=False,
            )
            if (
                not _owner_matches(after_parse, publication.identity)
                or not _stable(after_read, after_parse)
                or not _stable(after_parse, named_after_parse)
            ):
                raise _error(code, stage="AGGREGATE", run_id=self.run_id)
            decoded = value
        except RunStoreError as error:
            primary = error
        except Exception:
            primary = _error(code, stage="AGGREGATE", run_id=self.run_id)
        primary = _owned_close(
            fd, primary, run_id=self.run_id, final_leaf=publication.leaf,
        )
        if primary is not None:
            raise primary
        return decoded  # type: ignore[return-value]

    def _read_bound_finalized_snapshot(self) -> Mapping[str, Any]:
        """Re-read the exact finalized snapshot through its held layout binding."""
        self._open()
        binding = self._finalized_snapshot_binding
        if self._snapshot_state != "FINALIZED" or binding is None:
            raise _error("SNAPSHOT_UNAVAILABLE", stage="EXECUTE", run_id=self.run_id)
        try:
            _verify_live_layout(self)
            fd = _again(os.open, binding.publication.leaf, _READ_FLAGS, dir_fd=self._snapshot_fd_required())
        except RunStoreError:
            raise
        except OSError:
            raise _error("SNAPSHOT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
        primary: RunStoreError | None = None
        manifest: Mapping[str, Any] | None = None
        try:
            before = os.fstat(fd)
            named = os.stat(binding.publication.leaf, dir_fd=self._snapshot_fd_required(), follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode) or _mode(before) != 0o600
                or before.st_nlink != 1
                or before.st_size != binding.publication.size
                or not _owner_matches(before, binding.identity)
                or not _stable(before, named)
            ):
                raise _error("SNAPSHOT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
            raw = _read_exact(
                fd, binding.publication.size,
                code="SNAPSHOT_BINDING_MISMATCH",
            )
            after = os.fstat(fd)
            named_after = os.stat(
                binding.publication.leaf,
                dir_fd=self._snapshot_fd_required(),
                follow_symlinks=False,
            )
            if (
                not _stable(before, after) or not _stable(after, named_after)
                or not _owner_matches(after, binding.identity) or after.st_size != binding.publication.size
                or hashlib.sha256(raw).hexdigest() != binding.publication.sha256
            ):
                raise _error("SNAPSHOT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
            decoded = load_canonical_json(raw)
            if not isinstance(decoded, Mapping):
                raise _error("SNAPSHOT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
            validate_source_snapshot(decoded)
            if (
                decoded.get("schema") != "source-snapshot-manifest.v1"
                or decoded.get("run_id") != self.run_id
                or decoded.get("head_sha") != binding.head_sha
                or decoded.get("snapshot_mode") != "clean-commit"
                or canonical_json_bytes(decoded) != raw
            ):
                raise _error("SNAPSHOT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
            manifest = decoded
        except RunStoreError as error:
            primary = error
        except Exception:
            primary = _error("SNAPSHOT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
        primary = _owned_close(fd, primary, run_id=self.run_id, final_leaf=binding.publication.leaf)
        if primary is not None:
            raise primary
        return manifest  # type: ignore[return-value]

    def begin_attempt0(self) -> Mapping[str, Any]:
        """Claim the single attempt-0 slot after re-reading RUE-04 evidence.

        The claim is made while the layout lifetime lock is held.  A final
        snapshot name is not trusted merely because it was once linearized:
        the exact named regular file, identity, bytes, canonical form and
        semantic binding are checked again immediately before the one-way
        local started bit is set.
        """
        with self._lock:
            self._open()
            self._snapshot_terminal_absent()
            if self._fixed_completion_started:
                raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
            if self._attempt0_started:
                raise _error("ATTEMPT_DUPLICATE", stage="EXECUTE", run_id=self.run_id)
            try:
                os.stat("attempt-0.json", dir_fd=self._attempts_fd_required(), follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
            else:
                raise _error("ATTEMPT_DUPLICATE", stage="EXECUTE", run_id=self.run_id)
            manifest = self._read_bound_finalized_snapshot()
            self._attempt0_started = True
            return manifest

    def publish_attempt0_decision(self, decision: AttemptDecisionV1) -> PublishedJson:
        """Publish the only attempt-0 decision through the narrow evidence path."""
        with self._lock:
            self._open()
            self._snapshot_terminal_absent()
            if self._fixed_completion_started:
                raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
            if not self._attempt0_started:
                raise _error("ATTEMPT_NOT_STARTED", stage="EXECUTE", run_id=self.run_id)
            if self._attempt0_publication_started:
                raise _error("ATTEMPT_DUPLICATE", stage="EXECUTE", run_id=self.run_id)
            if (
                not isinstance(decision, AttemptDecisionV1)
                or decision.run_id != self.run_id
                or decision.attempt_index != 0
                or decision.suite_id != _ATTEMPT0_SUITE_ID
                or decision.entrypoint_id != _ATTEMPT0_ENTRYPOINT_ID
            ):
                raise _error("ATTEMPT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
            self._read_bound_finalized_snapshot()
            value = {
                "run_id": decision.run_id,
                "suite_id": decision.suite_id,
                "entrypoint_id": decision.entrypoint_id,
                "attempt_index": decision.attempt_index,
                "process_exit": decision.attempt_record.process_exit,
                "disposition": decision.disposition,
                "reason_code": decision.reason_code,
            }
            # This is a one-way in-memory claim.  Once publication is called,
            # success, failure and uncertainty all consume attempt-0 forever.
            self._attempt0_publication_started = True
            publication = _publish(self, "attempts", "attempt-0.json", canonical_json_bytes(value), failure=False, dedicated_attempt=True)
            self._attempt0_publication = publication
            return publication

    def _read_bound_attempt(self, attempt_index: int) -> AttemptDecisionV1:
        """Read one exact publication owned by this live layout."""
        if attempt_index == 0:
            publication = self._attempt0_publication
        elif attempt_index == 1:
            publication = self._attempt1_publication
        else:
            raise _error("ATTEMPT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
        if publication is None:
            raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
        self._read_bound_finalized_snapshot()
        try:
            _verify_live_layout(self)
            fd = _again(os.open, publication.leaf, _READ_FLAGS, dir_fd=self._attempts_fd_required())
        except RunStoreError:
            raise
        except OSError:
            raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
        primary: RunStoreError | None = None
        decision: AttemptDecisionV1 | None = None
        try:
            before = os.fstat(fd)
            named = os.stat(publication.leaf, dir_fd=self._attempts_fd_required(), follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode) or _mode(before) != 0o600
                or before.st_nlink != 1 or before.st_size != publication.size
                or not _owner_matches(before, publication.identity)
                or not _stable(before, named)
            ):
                raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
            raw = _read_exact(fd, publication.size, code="ATTEMPT_STATE_UNSAFE")
            after = os.fstat(fd)
            named_after = os.stat(
                publication.leaf,
                dir_fd=self._attempts_fd_required(),
                follow_symlinks=False,
            )
            if (
                not _stable(before, after) or not _stable(after, named_after)
                or not _owner_matches(after, publication.identity)
                or after.st_size != publication.size
                or hashlib.sha256(raw).hexdigest() != publication.sha256
            ):
                raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
            value = load_canonical_json(raw)
            if not isinstance(value, Mapping) or canonical_json_bytes(value) != raw or set(value) != {
                "run_id", "suite_id", "entrypoint_id", "attempt_index",
                "process_exit", "disposition", "reason_code",
            }:
                raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
            from .contracts import AttemptRecord
            decision = AttemptDecisionV1(
                value["run_id"], value["suite_id"], value["entrypoint_id"],
                value["attempt_index"], AttemptRecord(value["attempt_index"], value["process_exit"]),
                value["disposition"], value["reason_code"],
            )
            if (
                decision.run_id != self.run_id
                or decision.suite_id != _ATTEMPT0_SUITE_ID
                or decision.entrypoint_id != _ATTEMPT0_ENTRYPOINT_ID
                or decision.attempt_index != attempt_index
            ):
                raise _error("ATTEMPT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
        except RunStoreError as error:
            primary = error
        except Exception:
            primary = _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
        primary = _owned_close(fd, primary, run_id=self.run_id, final_leaf=publication.leaf)
        if primary is not None:
            raise primary
        return decision  # type: ignore[return-value]

    def begin_attempt1(self) -> Mapping[str, Any]:
        """Claim attempt-1 only from the exact persisted readiness attempt-0."""
        with self._lock:
            self._open()
            self._snapshot_terminal_absent()
            if self._fixed_completion_started:
                raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
            if self._attempt1_started:
                raise _error("ATTEMPT_DUPLICATE", stage="EXECUTE", run_id=self.run_id)
            try:
                os.stat("attempt-1.json", dir_fd=self._attempts_fd_required(), follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
            else:
                raise _error("ATTEMPT_DUPLICATE", stage="EXECUTE", run_id=self.run_id)
            manifest = self._read_bound_finalized_snapshot()
            attempt0 = self._read_bound_attempt(0)
            if (
                attempt0.disposition != "READINESS"
                or attempt0.reason_code != "READINESS_TIMEOUT"
                or attempt0.attempt_record.process_exit != 13
            ):
                raise _error("ATTEMPT_NOT_ELIGIBLE", stage="EXECUTE", run_id=self.run_id)
            self._attempt1_started = True
            return manifest

    def publish_attempt1_decision(self, decision: AttemptDecisionV1) -> PublishedJson:
        """Publish the one eligible attempt-1 decision; uncertainty is terminal."""
        with self._lock:
            self._open()
            self._snapshot_terminal_absent()
            if self._fixed_completion_started:
                raise _error("ATTEMPT_STATE_UNSAFE", stage="EXECUTE", run_id=self.run_id)
            if not self._attempt1_started:
                raise _error("ATTEMPT_NOT_STARTED", stage="EXECUTE", run_id=self.run_id)
            if self._attempt1_publication_started:
                raise _error("ATTEMPT_DUPLICATE", stage="EXECUTE", run_id=self.run_id)
            if (
                not isinstance(decision, AttemptDecisionV1)
                or decision.run_id != self.run_id
                or decision.attempt_index != 1
                or decision.suite_id != _ATTEMPT0_SUITE_ID
                or decision.entrypoint_id != _ATTEMPT0_ENTRYPOINT_ID
            ):
                raise _error("ATTEMPT_BINDING_MISMATCH", stage="EXECUTE", run_id=self.run_id)
            self._read_bound_attempt(0)
            value = {
                "run_id": decision.run_id,
                "suite_id": decision.suite_id,
                "entrypoint_id": decision.entrypoint_id,
                "attempt_index": decision.attempt_index,
                "process_exit": decision.attempt_record.process_exit,
                "disposition": decision.disposition,
                "reason_code": decision.reason_code,
            }
            self._attempt1_publication_started = True
            publication = _publish(self, "attempts", "attempt-1.json", canonical_json_bytes(value), failure=False, dedicated_attempt=True)
            self._attempt1_publication = publication
            return publication

    def read_retry_decisions(self) -> tuple[AttemptDecisionV1, AttemptDecisionV1]:
        """Return both exact persisted records for final retry adjudication."""
        with self._lock:
            self._open()
            self._snapshot_terminal_absent()
            initial = self._read_bound_attempt(0), self._read_bound_attempt(1)
            closing = self._read_bound_attempt(0), self._read_bound_attempt(1)
            if closing != initial:
                raise _error(
                    "ATTEMPT_STATE_UNSAFE",
                    stage="EXECUTE",
                    run_id=self.run_id,
                )
            return initial

    def snapshot_capture_lease(self):
        """Return a context manager spanning capture through terminal handling.

        The lease is intentionally layout-local: a copied dataclass has no
        authority because its nonce must be the active object identity.
        """
        layout = self

        class _LeaseContext:
            lease: SnapshotCaptureLease | None = None

            def __enter__(self) -> SnapshotCaptureLease:
                with layout._lock:
                    layout._open()
                    if layout._snapshot_state in {"CAPTURING", "PUBLISHED_PENDING"}:
                        raise _error("ACTIVE_OPERATION", stage="SNAPSHOT", run_id=layout.run_id)
                    if layout._snapshot_state != "OPEN":
                        raise _error("SNAPSHOT_UNAVAILABLE", stage="SNAPSHOT", run_id=layout.run_id, published_may_exist=True)
                    if layout._snapshot_nonce is not None:
                        raise _error("ACTIVE_OPERATION", stage="SNAPSHOT", run_id=layout.run_id)
                    nonce = secrets.token_bytes(32)
                    layout._snapshot_nonce = nonce
                    self.lease = SnapshotCaptureLease(layout.run_id, nonce)
                    layout._snapshot_lease = self.lease
                    layout._snapshot_state = "CAPTURING"
                    return self.lease

            def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
                with layout._lock:
                    if self.lease is not None and layout._snapshot_nonce == self.lease._nonce:
                        layout._snapshot_nonce = None
                        layout._snapshot_lease = None
                        if layout._snapshot_state == "CAPTURING":
                            layout._snapshot_state = "OPEN"
                return False

        return _LeaseContext()

    def _require_snapshot_lease(self, lease: SnapshotCaptureLease) -> None:
        if (
            not isinstance(lease, SnapshotCaptureLease)
            or lease.run_id != self.run_id
            or self._snapshot_nonce is None
            or lease is not self._snapshot_lease
            or not secrets.compare_digest(lease._nonce, self._snapshot_nonce)
        ):
            raise _error("LEASE_INVALID", stage="SNAPSHOT", run_id=self.run_id)

    def _snapshot_terminal_absent(self) -> None:
        parent = self._evidence_fd_required()
        for leaf in ("run-failure.json", "completion-seal.json"):
            try:
                item = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                raise _error("TERMINAL_STATE_UNSAFE", stage="SNAPSHOT", run_id=self.run_id)
            if not stat.S_ISREG(item.st_mode):
                raise _error("TERMINAL_STATE_UNSAFE", stage="SNAPSHOT", run_id=self.run_id)
            raise _error("TERMINAL_CONFLICT", stage="SNAPSHOT", run_id=self.run_id)

    def publish_snapshot_manifest(
        self, manifest: Mapping[str, Any], *, expected_head_sha: str, lease: SnapshotCaptureLease
    ) -> SnapshotPublicationTicket:
        """Publish a validated clean-commit manifest but do not report success yet."""
        with self._lock:
            self._open(); self._require_snapshot_lease(lease)
            if self._snapshot_state != "CAPTURING" or self._snapshot_ticket is not None:
                raise _error("FINALIZED", stage="SNAPSHOT", run_id=self.run_id, published_may_exist=True)
            if not isinstance(expected_head_sha, str) or len(expected_head_sha) != 40:
                raise _error("SNAPSHOT_BINDING_MISMATCH", stage="SNAPSHOT", run_id=self.run_id)
            if not isinstance(manifest, Mapping) or (
                manifest.get("run_id") != self.run_id
                or manifest.get("head_sha") != expected_head_sha
                or manifest.get("snapshot_mode") != "clean-commit"
            ):
                raise _error("SNAPSHOT_BINDING_MISMATCH", stage="SNAPSHOT", run_id=self.run_id)
            try:
                validate_source_snapshot(manifest)
                raw = canonical_json_bytes(manifest)
            except Exception:
                raise _error("SNAPSHOT_VALIDATION_FAILED", stage="SNAPSHOT", run_id=self.run_id)
            if len(raw) > _MAX_RECORD_BYTES:
                raise _error("SNAPSHOT_VALIDATION_FAILED", stage="SNAPSHOT", run_id=self.run_id)
            self._snapshot_terminal_absent()
            publication = _publish(self, "snapshot", "source-snapshot-manifest.json", raw, failure=False)
            try:
                item = os.stat("source-snapshot-manifest.json", dir_fd=self._snapshot_fd_required(), follow_symlinks=False)
                if (
                    not stat.S_ISREG(item.st_mode) or _mode(item) != 0o600 or item.st_nlink != 1
                    or not _owner_matches(item, publication.identity)
                ):
                    raise OSError()
            except OSError:
                raise _error("PUBLISH_VERIFY_FAILED", stage="SNAPSHOT", run_id=self.run_id, published_may_exist=True)
            ticket = SnapshotPublicationTicket(
                self.run_id, expected_head_sha, publication,
                publication.identity, lease._nonce,
            )
            self._snapshot_ticket = ticket
            self._snapshot_state = "PUBLISHED_PENDING"
            return ticket

    def linearize_snapshot_success(self, ticket: SnapshotPublicationTicket, *, lease: SnapshotCaptureLease) -> PublishedJson:
        """Atomically verify and finalize a post-checked snapshot publication."""
        with self._lock:
            self._open(); self._require_snapshot_lease(lease)
            if (
                self._snapshot_state != "PUBLISHED_PENDING"
                or ticket is not self._snapshot_ticket
                or not isinstance(ticket, SnapshotPublicationTicket)
                or ticket._nonce != lease._nonce
            ):
                raise _error("TICKET_INVALID", stage="SNAPSHOT", run_id=self.run_id, published_may_exist=True)
            try:
                _verify_live_layout(self)
            except RunStoreError as error:
                raise _error(error.code, stage=error.stage, run_id=self.run_id, published_may_exist=True, secondary_code=error.secondary_code)
            try:
                fd = _again(os.open, ticket.publication.leaf, _READ_FLAGS, dir_fd=self._snapshot_fd_required())
            except OSError:
                raise _error("PUBLISH_VERIFY_FAILED", stage="SNAPSHOT", run_id=self.run_id, published_may_exist=True)
            primary: RunStoreError | None = None
            try:
                before = os.fstat(fd)
                named = os.stat(ticket.publication.leaf, dir_fd=self._snapshot_fd_required(), follow_symlinks=False)
                if (
                    not stat.S_ISREG(before.st_mode) or _mode(before) != 0o600
                    or before.st_nlink != 1
                    or before.st_size != ticket.publication.size
                    or not _owner_matches(before, ticket.identity)
                    or not _stable(before, named)
                ):
                    raise _error(
                        "PUBLISH_VERIFY_FAILED",
                        stage="SNAPSHOT",
                        run_id=self.run_id,
                        published_may_exist=True,
                    )
                raw = _read_exact(
                    fd, ticket.publication.size,
                    code="PUBLISH_VERIFY_FAILED",
                )
                after = os.fstat(fd)
                named_after = os.stat(
                    ticket.publication.leaf,
                    dir_fd=self._snapshot_fd_required(),
                    follow_symlinks=False,
                )
                if (
                    not _stable(before, after)
                    or not _stable(after, named_after)
                    or not _owner_matches(after, ticket.identity)
                    or _mode(after) != 0o600 or after.st_nlink != 1 or after.st_size != ticket.publication.size
                    or hashlib.sha256(raw).hexdigest() != ticket.publication.sha256 or canonical_json_bytes(load_canonical_json(raw)) != raw
                ):
                    raise _error("PUBLISH_VERIFY_FAILED", stage="SNAPSHOT", run_id=self.run_id, published_may_exist=True)
                self._snapshot_terminal_absent()
            except RunStoreError as error:
                primary = _error(error.code, stage=error.stage, run_id=self.run_id, published_may_exist=True)
            except Exception:
                primary = _error("PUBLISH_VERIFY_FAILED", stage="SNAPSHOT", run_id=self.run_id, published_may_exist=True)
            primary = _owned_close(fd, primary, run_id=self.run_id, published=True, final_leaf=ticket.publication.leaf)
            if primary is not None:
                raise primary
            self._snapshot_state = "FINALIZED"
            self._finalized_snapshot_binding = FinalizedSnapshotBinding(
                self.run_id, ticket.expected_head_sha, ticket.publication, ticket.identity
            )
            self._snapshot_ticket = None
            return ticket.publication

    def record_first_failure(self, failure: Any, *, _snapshot_lease: SnapshotCaptureLease | None = None) -> FirstFailureResult:
        with self._lock:
            self._evidence_open()
            if not isinstance(failure, dict):
                raise _error("FAILURE_INVALID", stage="FAILURE", run_id=self.run_id)
            stage = failure.get("stage")
            if not isinstance(stage, str) or stage not in _FAILURE_STAGES:
                raise _error("FAILURE_INVALID", stage="FAILURE", run_id=self.run_id)
            owner = (
                isinstance(_snapshot_lease, SnapshotCaptureLease)
                and _snapshot_lease.run_id == self.run_id
                and _snapshot_lease is self._snapshot_lease
                and self._snapshot_nonce is not None
                and secrets.compare_digest(_snapshot_lease._nonce, self._snapshot_nonce)
            )
            post_snapshot = _FAILURE_STAGES - {"RUN_ROOT", "SNAPSHOT"}
            active_snapshot = self._snapshot_state in {"CAPTURING", "PUBLISHED_PENDING"}
            if active_snapshot and stage != "SNAPSHOT":
                raise _error("STAGE_ORDER_UNSAFE", stage="FAILURE", run_id=self.run_id)
            if active_snapshot and not owner:
                # Only the capture owner may terminalize its SNAPSHOT stage.
                raise _error("ACTIVE_OPERATION", stage="FAILURE", run_id=self.run_id)
            if self._snapshot_state == "OPEN" and stage != "RUN_ROOT":
                raise _error("STAGE_ORDER_UNSAFE", stage="FAILURE", run_id=self.run_id)
            if self._snapshot_state == "PUBLISHED_FAILED":
                raise _error("STAGE_ORDER_UNSAFE", stage="FAILURE", run_id=self.run_id)
            if self._snapshot_state == "FINALIZED" and stage not in post_snapshot:
                raise _error("STAGE_FINALIZED", stage="FAILURE", run_id=self.run_id)
            pending_owner = self._snapshot_state == "PUBLISHED_PENDING" and owner
            try:
                _verify_evidence_binding(self)
                if failure.get("run_id") != self.run_id or failure.get("run_manifest") is not None:
                    raise _error("FAILURE_INVALID", stage="FAILURE", run_id=self.run_id)
                try:
                    validate_terminal_set(None, failure)
                    raw = canonical_json_bytes(failure)
                except Exception:
                    raise _error("FAILURE_INVALID", stage="FAILURE", run_id=self.run_id)
                parent = self._evidence_fd_required()
                try:
                    os.stat("completion-seal.json", dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError:
                    raise _error("TERMINAL_CONFLICT", stage="FAILURE", run_id=self.run_id)
                else:
                    raise _error("TERMINAL_CONFLICT", stage="FAILURE", run_id=self.run_id)
                try:
                    preflight_fd = _again(os.open, "run-failure.json", _READ_FLAGS, dir_fd=parent)
                except FileNotFoundError:
                    preflight_fd = None
                except OSError:
                    raise _error("FAILURE_EXISTING_UNSAFE", stage="FAILURE", run_id=self.run_id)
                if preflight_fd is not None:
                    result = self._existing_failure(parent, preflight_fd)
                    _verify_evidence_binding(self)
                else:
                    value = _publish(self, "evidence", "run-failure.json", raw, failure=True)
                    result = FirstFailureResult("RECORDED", value.path, value.sha256, value.size)
            except BaseException:
                if pending_owner:
                    self._snapshot_state = "PUBLISHED_FAILED"
                    self._snapshot_ticket = None
                raise
            if active_snapshot and owner:
                self._snapshot_state = "TERMINAL"
                self._snapshot_ticket = None
            return result

    def _existing_failure(self, parent_fd: int, preflight_fd: int | None = None) -> FirstFailureResult:
        """Read an existing terminal record only while its name stays FD-bound."""
        try:
            named_before = os.stat("run-failure.json", dir_fd=parent_fd, follow_symlinks=False)
            fd = preflight_fd if preflight_fd is not None else _again(os.open, "run-failure.json", _READ_FLAGS, dir_fd=parent_fd)
        except OSError:
            error = _error("FAILURE_EXISTING_UNSAFE", stage="FAILURE", run_id=self.run_id)
            raise _owned_close(preflight_fd, error, run_id=self.run_id)  # type: ignore[misc]
        primary: RunStoreError | None = None
        raw = b""
        first: os.stat_result | None = None
        try:
            first = os.fstat(fd)
            if (
                not stat.S_ISREG(first.st_mode)
                or first.st_uid != os.geteuid()
                or _mode(first) != 0o600
                or first.st_nlink != 1
                or first.st_size > _MAX_FAILURE_BYTES
                or not _stable(named_before, first)
            ):
                raise _error("FAILURE_EXISTING_UNSAFE", stage="FAILURE", run_id=self.run_id)
            raw = _read_exact(fd, first.st_size, code="FAILURE_EXISTING_UNSAFE")
            post_read = os.fstat(fd)
            named_post_read = os.stat("run-failure.json", dir_fd=parent_fd, follow_symlinks=False)
            if not _stable(first, post_read) or not _stable(post_read, named_post_read):
                primary = _error("FAILURE_EXISTING_UNSAFE", stage="FAILURE", run_id=self.run_id)
            if primary is None:
                decoded = load_canonical_json(raw)
                validate_terminal_set(None, decoded)
                if decoded.get("run_id") != self.run_id or decoded.get("run_manifest") is not None:
                    primary = _error("FAILURE_EXISTING_UNSAFE", stage="FAILURE", run_id=self.run_id)
            if primary is None:
                post_parse = os.fstat(fd)
                named_post_parse = os.stat("run-failure.json", dir_fd=parent_fd, follow_symlinks=False)
                if not _stable(first, post_parse) or not _stable(post_parse, named_post_parse):
                    primary = _error("FAILURE_EXISTING_UNSAFE", stage="FAILURE", run_id=self.run_id)
        except RunStoreError as exc:
            primary = exc
        except OSError:
            primary = _error("FAILURE_EXISTING_UNSAFE", stage="FAILURE", run_id=self.run_id)
        except Exception:
            primary = _error("FAILURE_EXISTING_UNSAFE", stage="FAILURE", run_id=self.run_id)
        primary = _owned_close(fd, primary, run_id=self.run_id)
        if primary is not None:
            raise primary
        return FirstFailureResult("ALREADY_RECORDED", "run-failure.json", hashlib.sha256(raw).hexdigest(), len(raw))

    def close(self) -> None:
        with self._lock:
            if self._snapshot_nonce is not None:
                raise _error("ACTIVE_OPERATION", stage="LAYOUT", run_id=self.run_id)
            if self._closed:
                if self._close_error is not None:
                    raise self._close_error
                return
            self._closing = True
            fds: list[int] = []
            for field_name in ("_tmp_fd", "_cache_fd", "_attempts_fd", "_snapshot_fd", "_state_fd", "_results_fd", "_evidence_fd"):
                value = getattr(self, field_name)
                setattr(self, field_name, None)
                if value is not None:
                    fds.append(value)
            close_error = _close_many(fds, run_id=self.run_id)
            self._closed = True
            self._closing = False
            if close_error is not None:
                self._close_error = close_error
                raise self._close_error

    def __enter__(self) -> "RunLayout":
        with self._lock:
            self._open()
            return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if exc_type is not None:
            try:
                self.close()
            except RunStoreError:
                pass
            return False
        self.close()
        return False


def _verify_live_layout(layout: RunLayout) -> None:
    """Re-walk public roots after bootstrap descriptors have been closed."""
    state_root_fd = evidence_root_fd = state_runs_fd = evidence_runs_fd = None
    primary: RunStoreError | None = None
    try:
        state_root_fd, _ = _open_absolute_root(layout._state_root_path)
        evidence_root_fd, _ = _open_absolute_root(layout._evidence_root_path)
        state_runs_fd = _again(os.open, "runs", _DIR_FLAGS, dir_fd=state_root_fd)
        evidence_runs_fd = _again(os.open, "runs", _DIR_FLAGS, dir_fd=evidence_root_fd)
        _named_fd(state_runs_fd, layout.run_id, layout._state_fd_required(), private_parent=True)
        _named_fd(evidence_runs_fd, layout.run_id, layout._evidence_fd_required(), private_parent=True)
        _named_fd(layout._state_fd_required(), "snapshot", layout._snapshot_fd_required(), private_parent=True)
        _named_fd(layout._state_fd_required(), "attempts", layout._attempts_fd_required(), private_parent=True)
        _named_fd(layout._state_fd_required(), "cache", layout._cache_fd_required(), private_parent=True)
        _named_fd(layout._state_fd_required(), "tmp", layout._tmp_fd_required(), private_parent=True)
        _named_fd(layout._evidence_fd_required(), "results", layout._results_fd_required(), private_parent=True)
    except RunStoreError as error:
        primary = error
    except OSError:
        primary = _error("PATH_DRIFT", stage="BIND", run_id=layout.run_id)
    primary = _close_many([state_runs_fd, evidence_runs_fd, state_root_fd, evidence_root_fd], primary, run_id=layout.run_id)
    if primary is not None:
        raise primary


def _verify_evidence_binding(layout: RunLayout) -> None:
    """Bind a failure record to the current evidence-root/runs/run public path."""
    root_fd = runs_fd = None
    primary: RunStoreError | None = None
    try:
        root_fd, _ = _open_absolute_root(layout._evidence_root_path)
        runs_fd = _again(os.open, "runs", _DIR_FLAGS, dir_fd=root_fd)
        _named_fd(runs_fd, layout.run_id, layout._evidence_fd_required(), private_parent=True)
    except RunStoreError as error:
        primary = error
    except OSError:
        primary = _error("PATH_DRIFT", stage="BIND", run_id=layout.run_id)
    primary = _close_many([runs_fd, root_fd], primary, run_id=layout.run_id)
    if primary is not None:
        raise primary


def _failure_record(run_id: str) -> dict[str, Any]:
    return {
        "schema": "run-failure.v1",
        "run_id": run_id,
        "stage": "RUN_ROOT",
        "reason_code": "RUN_ROOT_UNSAFE",
        "run_manifest": None,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "terminal": True,
    }


def _root_failure(layout: RunLayout, primary: RunStoreError) -> RunStoreError:
    try:
        layout.record_first_failure(_failure_record(layout.run_id))
        recorded, secondary = True, None
    except RunStoreError as secondary_error:
        recorded, secondary = False, secondary_error.code
    try:
        layout.close()
    except RunStoreError as close_error:
        secondary = secondary or close_error.code
    return _error(
        primary.code,
        stage=primary.stage,
        run_id=layout.run_id,
        published_may_exist=primary.published_may_exist,
        failure_recorded=recorded,
        secondary_code=secondary,
        residual=primary.residual,
        final_leaf=primary.final_leaf,
        final_identity_state=primary.final_identity_state,
    )


def create_run_layout(state_root: str | os.PathLike[str], evidence_parent: str | os.PathLike[str]) -> RunLayout:
    """Create private state/evidence trees and hold their seven run descriptors."""
    run_id = secrets.token_bytes(16).hex()
    state_root_fd = evidence_root_fd = state_runs_fd = evidence_runs_fd = None
    state_run_fd = evidence_run_fd = snapshot_fd = attempts_fd = cache_fd = tmp_fd = results_fd = None
    locked = False
    layout: RunLayout | None = None
    try:
        state_root_fd, state_lineage = _open_absolute_root(state_root)
        evidence_root_fd, evidence_lineage = _open_absolute_root(evidence_parent)
        if state_lineage == evidence_lineage[: len(state_lineage)] or evidence_lineage == state_lineage[: len(evidence_lineage)]:
            raise _error("RUN_ROOT_UNSAFE", stage="ROOT", run_id=run_id)
        state_runs_fd = _mkdir_open(state_root_fd, "runs", reuse=True)
        evidence_runs_fd = _mkdir_open(evidence_root_fd, "runs", reuse=True)
        evidence_run_fd = _mkdir_open(evidence_runs_fd, run_id, reuse=False)
        try:
            _again(fcntl.flock, evidence_run_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise _error("RUN_LOCKED", stage="LAYOUT", run_id=run_id)
        locked = True
        results_fd = _mkdir_open(evidence_run_fd, "results", reuse=False)
        state_run_fd = _mkdir_open(state_runs_fd, run_id, reuse=False)
        snapshot_fd = _mkdir_open(state_run_fd, "snapshot", reuse=False)
        attempts_fd = _mkdir_open(state_run_fd, "attempts", reuse=False)
        cache_fd = _mkdir_open(state_run_fd, "cache", reuse=False)
        tmp_fd = _mkdir_open(state_run_fd, "tmp", reuse=False)
        layout = RunLayout(
            run_id,
            os.path.join(os.fspath(state_root), "runs", run_id),
            os.path.join(os.fspath(evidence_parent), "runs", run_id),
            state_run_fd,
            snapshot_fd,
            attempts_fd,
            cache_fd,
            tmp_fd,
            evidence_run_fd,
            results_fd,
            _state_root_path=os.fspath(state_root),
            _evidence_root_path=os.fspath(evidence_parent),
        )
        state_run_fd = snapshot_fd = attempts_fd = cache_fd = tmp_fd = evidence_run_fd = results_fd = None
        _verify_layout_binding(state_root_fd, evidence_root_fd, state_runs_fd, evidence_runs_fd, layout)
        _verify_creation_public_binding(
            os.fspath(state_root), os.fspath(evidence_parent), state_root_fd, evidence_root_fd, state_runs_fd, evidence_runs_fd, layout
        )
        bootstrap_fds = [state_root_fd, evidence_root_fd, state_runs_fd, evidence_runs_fd]
        state_root_fd = evidence_root_fd = state_runs_fd = evidence_runs_fd = None
        close_error = _close_many(bootstrap_fds, run_id=run_id)
        if close_error is not None:
            raise close_error
        return layout
    except BaseException as raw:
        primary = raw if isinstance(raw, RunStoreError) else _error("RUN_ROOT_UNSAFE", stage="LAYOUT", run_id=run_id)
        if layout is not None:
            error = _root_failure(layout, primary)
            error = _close_many([state_root_fd, evidence_root_fd, state_runs_fd, evidence_runs_fd], error, run_id=run_id)
            raise error from raw  # type: ignore[misc]
        if locked and evidence_run_fd is not None:
            provisional = RunLayout(
                run_id, "", os.path.join(os.fspath(evidence_parent), "runs", run_id),
                None, None, None, None, None, evidence_run_fd, None,
                _evidence_root_path=os.fspath(evidence_parent),
            )
            evidence_run_fd = None
            error = _root_failure(provisional, primary)
            error = _close_many([state_root_fd, evidence_root_fd, state_runs_fd, evidence_runs_fd, state_run_fd, snapshot_fd, attempts_fd, cache_fd, tmp_fd, results_fd], error, run_id=run_id)
            raise error from raw  # type: ignore[misc]
        primary = _close_many([state_root_fd, evidence_root_fd, state_runs_fd, evidence_runs_fd, state_run_fd, evidence_run_fd, snapshot_fd, attempts_fd, cache_fd, tmp_fd, results_fd], primary, run_id=run_id)
        raise _error(
            primary.code,  # type: ignore[union-attr]
            stage=primary.stage,
            run_id=run_id,
            published_may_exist=primary.published_may_exist,
            secondary_code=primary.secondary_code,
            residual=primary.residual,
            final_leaf=primary.final_leaf,
            final_identity_state=primary.final_identity_state,
        ) from raw


def _residual(temp_leaf: str, owner: TempOwnerIdentityV1 | None, digest: str, parent_fd: int, *, rename_succeeded: bool) -> TempResidualV1:
    if rename_succeeded:
        return TempResidualV1(temp_leaf, owner, digest, "ABSENT")
    if owner is None:
        return TempResidualV1(temp_leaf, None, digest, "UNKNOWN")
    try:
        named = os.stat(temp_leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return TempResidualV1(temp_leaf, owner, digest, "ABSENT")
    except OSError:
        return TempResidualV1(temp_leaf, owner, digest, "UNKNOWN")
    return TempResidualV1(temp_leaf, owner, digest, "PRESENT_BOUND" if _owner_matches(named, owner, exact=False) else "PRESENT_REBOUND")


def _publish(
    layout: RunLayout,
    area: str,
    leaf: str,
    raw: bytes,
    *,
    failure: bool,
    dedicated_attempt: bool = False,
    dedicated_terminal: bool = False,
) -> PublishedJson:
    if failure:
        layout._evidence_open()
        _verify_evidence_binding(layout)
    else:
        layout._open()
        _verify_live_layout(layout)
    _publication_name(
        area,
        leaf,
        failure=failure,
        dedicated_attempt=dedicated_attempt,
        dedicated_terminal=dedicated_terminal,
    )
    parent_fd = layout._evidence_fd_required() if failure else layout._fd(area)
    digest = hashlib.sha256(raw).hexdigest()
    temp_leaf = ".tmp-" + secrets.token_bytes(16).hex()
    # Binding the run tree is not enough: permissions on the actual parent can
    # change between that walk and O_EXCL creation.  Refuse before creating any
    # temporary name, rather than leaving a residual in a now-unsafe directory.
    try:
        _safe_dir(parent_fd, private=True)
    except RunStoreError:
        raise _error("PATH_DRIFT", stage="TEMP", run_id=layout.run_id, final_leaf=leaf)
    fd: int | None = None
    owner: TempOwnerIdentityV1 | None = None
    rename_succeeded = False
    primary: RunStoreError | None = None
    result: PublishedJson | None = None
    final_safe_identity: TempOwnerIdentityV1 | None = None
    try:
        try:
            fd = _again(os.open, temp_leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            # It might be foreign: do not stat/read/rename/unlink it.
            raise _error("PUBLISH_TEMP_COLLISION", stage="TEMP", run_id=layout.run_id, final_leaf=leaf)
        except OSError:
            raise _error("PUBLISH_IO_FAILED", stage="TEMP", run_id=layout.run_id, final_leaf=leaf)
        try:
            first = os.fstat(fd)
        except OSError:
            raise _error("FD_DRIFT", stage="TEMP", run_id=layout.run_id, final_leaf=leaf)
        owner = _owner(first)
        if not stat.S_ISREG(first.st_mode) or first.st_uid != os.geteuid() or first.st_nlink != 1:
            raise _error("PUBLISH_TEMP_UNSAFE", stage="TEMP", run_id=layout.run_id, final_leaf=leaf)
        try:
            _again(os.fchmod, fd, 0o600)
            second = os.fstat(fd)
        except OSError:
            raise _error("PUBLISH_IO_FAILED", stage="TEMP", run_id=layout.run_id, final_leaf=leaf)
        if not _owner_matches(second, owner, exact=False) or _mode(second) != 0o600 or second.st_nlink != 1:
            raise _error("FD_DRIFT", stage="TEMP", run_id=layout.run_id, final_leaf=leaf)
        owner = _owner(second)
        _write_all(fd, raw)
        _fsync(fd)
        written = os.fstat(fd)
        if not _owner_matches(written, owner, exact=False) or written.st_nlink != 1 or written.st_size != len(raw):
            raise _error("FD_DRIFT", stage="WRITE", run_id=layout.run_id, final_leaf=leaf)
        if hashlib.sha256(_read_exact(fd, len(raw), code="FD_DRIFT")).hexdigest() != digest:
            raise _error("FD_DRIFT", stage="WRITE", run_id=layout.run_id, final_leaf=leaf)
        owner = _owner(written)
        try:
            named = os.stat(temp_leaf, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            raise _error("PATH_DRIFT", stage="RENAME", run_id=layout.run_id, final_leaf=leaf)
        if not _owner_matches(
            named, owner, exact=dedicated_terminal,
        ):
            raise _error("PATH_DRIFT", stage="RENAME", run_id=layout.run_id, final_leaf=leaf)
        if dedicated_terminal:
            # A completion seal becomes authoritative at the exclusive rename.
            # Complete every fallible durability/binding check while it still
            # has a non-authoritative temporary name.  After rename succeeds,
            # no later fsync/readback/close failure may turn a visible,
            # schema-valid terminal seal into caller-visible uncertainty.
            try:
                if canonical_json_bytes(load_canonical_json(raw)) != raw:
                    raise _error(
                        "CONTRACT_FAILURE",
                        stage="SEAL",
                        run_id=layout.run_id,
                        final_leaf=leaf,
                    )
            except RunStoreError:
                raise
            except Exception:
                raise _error(
                    "CONTRACT_FAILURE",
                    stage="SEAL",
                    run_id=layout.run_id,
                    final_leaf=leaf,
                )
            _verify_live_layout(layout)
            _fsync(parent_fd)
            held = os.fstat(fd)
            named_held = os.stat(
                temp_leaf, dir_fd=parent_fd, follow_symlinks=False,
            )
            final_read = _read_exact(
                fd, len(raw), code="PUBLISH_VERIFY_FAILED",
            )
            post_read = os.fstat(fd)
            named_post_read = os.stat(
                temp_leaf, dir_fd=parent_fd, follow_symlinks=False,
            )
            if (
                not _owner_matches(held, owner)
                or not _owner_matches(named_held, owner)
                or hashlib.sha256(final_read).hexdigest() != digest
                or not _owner_matches(post_read, owner)
                or not _owner_matches(named_post_read, owner)
            ):
                raise _error(
                    "PUBLISH_VERIFY_FAILED",
                    stage="SEAL",
                    run_id=layout.run_id,
                    final_leaf=leaf,
                )
        _rename_exclusive(parent_fd, temp_leaf, leaf)
        rename_succeeded = True
        if dedicated_terminal:
            # rename(2) preserves the already frozen inode.  No post-rename
            # read, fsync, close, or layout check is allowed to reverse this
            # terminal success.
            result = PublishedJson(
                area, leaf, leaf, digest, len(raw), owner,
            )
            try:
                os.close(fd)
            except OSError:
                pass
            fd = None
            return result
        if failure:
            _verify_evidence_binding(layout)
        _fsync(parent_fd)
        try:
            final_fd = _again(os.open, leaf, _READ_FLAGS, dir_fd=parent_fd)
        except OSError:
            raise _error("PATH_DRIFT", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf)
        final_primary: RunStoreError | None = None
        try:
            final = os.fstat(final_fd)
            if (
                not stat.S_ISREG(final.st_mode)
                or final.st_uid != os.geteuid()
                or _mode(final) != 0o600
                or final.st_nlink != 1
                or final.st_size != len(raw)
                or not _owner_matches(final, owner, exact=False)
            ):
                raise _error("PUBLISH_VERIFY_FAILED", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf, final_identity_state="MISMATCH")
            named_final = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if not _same(named_final, final):
                raise _error("PATH_DRIFT", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf, final_identity_state="REBOUND")
            if hashlib.sha256(_read_exact(final_fd, len(raw), code="PUBLISH_VERIFY_FAILED")).hexdigest() != digest:
                raise _error("PUBLISH_VERIFY_FAILED", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf, final_identity_state="MISMATCH")
            final_post_read = os.fstat(final_fd)
            named_post_read = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if not _stable(final, final_post_read) or not _stable(final_post_read, named_post_read):
                raise _error("PATH_DRIFT", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf, final_identity_state="REBOUND")
            final_safe_identity = _owner(final_post_read)
            _fsync(final_fd)
        except RunStoreError as error:
            final_primary = error
        except OSError:
            final_primary = _error("PUBLISH_IO_FAILED", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf)
        _close_checked(final_fd, final_primary, run_id=layout.run_id, published=True, final_leaf=leaf)
        _fsync(parent_fd)
        # The final name and all public run layout names must still bind held FDs.
        post_primary: RunStoreError | None = None
        try:
            post_fd = _again(os.open, leaf, _READ_FLAGS, dir_fd=parent_fd)
        except OSError:
            raise _error("PATH_DRIFT", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf, final_identity_state="REBOUND")
        try:
            post = os.fstat(post_fd)
            named_final = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (
                final_safe_identity is None
                or not stat.S_ISREG(post.st_mode)
                or post.st_uid != os.geteuid()
                or _mode(post) != 0o600
                or post.st_nlink != 1
                or post.st_size != len(raw)
                or not _owner_matches(post, final_safe_identity)
                or not _stable(post, named_final)
            ):
                raise _error("PATH_DRIFT", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf, final_identity_state="REBOUND")
            if hashlib.sha256(_read_exact(post_fd, len(raw), code="PUBLISH_VERIFY_FAILED")).hexdigest() != digest:
                raise _error("PUBLISH_VERIFY_FAILED", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf, final_identity_state="MISMATCH")
            post_after_read = os.fstat(post_fd)
            named_after_read = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not _owner_matches(post_after_read, final_safe_identity)
                or not _stable(post, post_after_read)
                or not _stable(post_after_read, named_after_read)
            ):
                raise _error("PATH_DRIFT", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf, final_identity_state="REBOUND")
            owner = final_safe_identity
        except RunStoreError as error:
            post_primary = error
        except OSError:
            post_primary = _error("PUBLISH_IO_FAILED", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf)
        _close_checked(post_fd, post_primary, run_id=layout.run_id, published=True, final_leaf=leaf)
        if failure:
            _verify_evidence_binding(layout)
        else:
            _verify_live_layout(layout)
        if owner is None:
            raise _error("PUBLISH_VERIFY_FAILED", stage="VERIFY", run_id=layout.run_id, published_may_exist=True, final_leaf=leaf)
        result = PublishedJson(
            area, leaf,
            ("results/" if area == "results" else "snapshot/" if area == "snapshot" else "attempts/" if area == "attempts" else "") + leaf,
            digest, len(raw), owner,
        )
    except RunStoreError as exc:
        if rename_succeeded and not exc.published_may_exist:
            exc = _error(
                exc.code,
                stage=exc.stage,
                run_id=layout.run_id,
                published_may_exist=True,
                failure_recorded=exc.failure_recorded,
                secondary_code=exc.secondary_code,
                residual=_residual(temp_leaf, owner, digest, parent_fd, rename_succeeded=True),
                final_leaf=leaf,
                final_identity_state=exc.final_identity_state,
            )
        elif exc.residual is None:
            exc = _error(
                exc.code,
                stage=exc.stage,
                run_id=layout.run_id,
                published_may_exist=exc.published_may_exist,
                failure_recorded=exc.failure_recorded,
                secondary_code=exc.secondary_code,
                residual=None if exc.code == "PUBLISH_TEMP_COLLISION" else _residual(temp_leaf, owner, digest, parent_fd, rename_succeeded=False),
                final_leaf=exc.final_leaf or leaf,
                final_identity_state=exc.final_identity_state,
            )
        primary = exc
    except OSError:
        primary = _error(
            "PUBLISH_IO_FAILED",
            stage="PUBLISH",
            run_id=layout.run_id,
            published_may_exist=rename_succeeded,
            residual=_residual(temp_leaf, owner, digest, parent_fd, rename_succeeded=rename_succeeded),
            final_leaf=leaf,
        )
    primary = _owned_close(fd, primary, run_id=layout.run_id, published=rename_succeeded, final_leaf=leaf)
    if primary is not None:
        raise primary
    if result is None:
        raise _error("PUBLISH_IO_FAILED", stage="PUBLISH", run_id=layout.run_id, final_leaf=leaf)
    return result


def publish_json(layout: RunLayout, area: str, leaf: str, value: Any) -> PublishedJson:
    return layout.publish_json(area, leaf, value)


def record_first_failure(layout: RunLayout, failure: Any) -> FirstFailureResult:
    return layout.record_first_failure(failure)
