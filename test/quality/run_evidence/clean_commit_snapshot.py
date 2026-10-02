"""RUE-04: capture a clean tracked tree from verified raw Git objects only."""
from __future__ import annotations

import errno
import hashlib
import os
import re
import select
import signal
import stat
import subprocess
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .atomic_store import PublishedJson, RunLayout, RunStoreError, SnapshotCaptureLease
from .manifest_contracts import canonical_json_bytes, validate_source_snapshot

GIT_EXECUTABLE = "/usr/bin/git"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_CLOCK = time.monotonic                 # private seams for deterministic tests
_DEFAULT_TIMEOUT = 120.0
_MAX_COMMIT = 16 * 1024 * 1024
_MAX_TREE_BYTES = 64 * 1024 * 1024
_MAX_TREES = 50_001
_MAX_OBJECTS = 100_002
_MAX_TREE_EXPANSIONS = 50_001
_MAX_ENTRY = 64 * 1024 * 1024
_MAX_ENTRIES = 50_000
_MAX_TOTAL = 1024 * 1024 * 1024
_MAX_OUTPUT = 64 * 1024 * 1024
_MAX_UNTRACKED_BYTES = 16 * 1024 * 1024
_MAX_UNTRACKED_PATHS = 50_000
_MAX_UNTRACKED_PATH_BYTES = 4096
_MAX_MANIFEST_BYTES = 1024 * 1024
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_META_READ = _READ | os.O_NONBLOCK
_ERROR_CODES = frozenset({"SNAPSHOT_ARGUMENT_INVALID", "SNAPSHOT_REPOSITORY_UNSAFE", "SNAPSHOT_ACTIVE_OPERATION",
    "SNAPSHOT_ALREADY_FINALIZED", "SNAPSHOT_HEAD_MISMATCH", "SNAPSHOT_DIRTY", "SNAPSHOT_INDEX_FLAGS_UNSAFE",
    "SNAPSHOT_BINDING_MISMATCH", "SNAPSHOT_GIT_FAILED", "SNAPSHOT_TIMEOUT", "SNAPSHOT_TREE_MALFORMED",
    "SNAPSHOT_PATH_UNSAFE", "SNAPSHOT_ENTRY_UNSUPPORTED", "SNAPSHOT_OBJECT_MISMATCH",
    "SNAPSHOT_SYMLINK_UNREPRESENTABLE", "SNAPSHOT_LIMIT_EXCEEDED", "SNAPSHOT_VALIDATION_FAILED", "SNAPSHOT_PUBLISH_FAILED"})


@dataclass(frozen=True)
class SnapshotCapture:
    manifest: Mapping[str, Any]
    publication: PublishedJson


class SnapshotError(RuntimeError):
    def __init__(self, code: str, *, stage: str = "SNAPSHOT", run_id: str | None = None,
                 published_may_exist: bool = False, failure_recorded: bool = False,
                 secondary_code: str | None = None) -> None:
        self.code, self.stage, self.run_id = code, stage, run_id
        self.published_may_exist, self.failure_recorded = published_may_exist, failure_recorded
        self.secondary_code = secondary_code
        super().__init__(code)


class _Failure(Exception):
    def __init__(self, code: str, secondary: str | None = None) -> None:
        self.code, self.secondary = code, secondary


@dataclass(frozen=True)
class _Identity:
    dev: int; ino: int; uid: int; mode: int; nlink: int; size: int; mtime_ns: int; ctime_ns: int


def _identity(item: os.stat_result) -> _Identity:
    return _Identity(item.st_dev, item.st_ino, item.st_uid, item.st_mode, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _remaining(deadline: float) -> float:
    value = deadline - _CLOCK()
    if value <= 0:
        raise _Failure("SNAPSHOT_TIMEOUT")
    return value


def _leaf(value: str) -> bool:
    return bool(value) and value not in {".", ".."} and "/" not in value and "\x00" not in value


def _safe_logical(value: str) -> bool:
    try: value.encode("utf-8", "strict")
    except UnicodeEncodeError: return False
    return bool(value) and len(value) <= 240 and value == unicodedata.normalize("NFC", value) and not value.startswith("/") and all(_leaf(part) for part in value.split("/")) and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _object_id(kind: bytes, raw: bytes) -> str:
    return hashlib.sha1(kind + b" " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def _clean_env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in {"LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"}}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_OPTIONAL_LOCKS": "0",
                "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0",
                "GIT_PAGER": "cat", "GIT_EDITOR": "true"})
    return env


def _close_many(fds: list[int | None], primary: _Failure | None = None) -> _Failure | None:
    """Close every owned FD exactly once without replacing an existing primary."""
    for fd in fds:
        if fd is None: continue
        try: os.close(fd)
        except BaseException:
            if primary is None: primary = _Failure("SNAPSHOT_REPOSITORY_UNSAFE", "CLOSE_FAILED")
            elif primary.secondary is None: primary.secondary = "CLOSE_FAILED"
    return primary


def _close(fd: int | None) -> None:
    error = _close_many([fd])
    if error is not None: raise error


def _validate_repo_argument(path: object) -> str:
    try: value = os.fspath(path)
    except (TypeError, ValueError): raise _Failure("SNAPSHOT_ARGUMENT_INVALID")
    if not isinstance(value, str) or not os.path.isabs(value) or value == "/" or value != unicodedata.normalize("NFC", value):
        raise _Failure("SNAPSHOT_ARGUMENT_INVALID")
    parts = value.split("/")[1:]
    if not parts or any(not _leaf(part) for part in parts): raise _Failure("SNAPSHOT_ARGUMENT_INVALID")
    return value


def _safe_absolute_dir(path: str | os.PathLike[str], deadline: float) -> tuple[str, int, _Identity]:
    _remaining(deadline)
    value = os.fspath(path)
    if not isinstance(value, str) or not os.path.isabs(value) or value == "/" or value != unicodedata.normalize("NFC", value):
        raise _Failure("SNAPSHOT_ARGUMENT_INVALID")
    parts = value.split("/")[1:]
    if not parts or any(not _leaf(part) for part in parts): raise _Failure("SNAPSHOT_ARGUMENT_INVALID")
    fd: int | None = None
    try:
        fd = os.open("/", _DIR)
        for part in parts:
            _remaining(deadline)
            next_fd = os.open(part, _DIR, dir_fd=fd)
            close_error = _close_many([fd]); fd = next_fd
            if close_error is not None: raise close_error
        item = os.fstat(fd)
        if not stat.S_ISDIR(item.st_mode): raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        _remaining(deadline); return value, fd, _identity(item)
    except _Failure as error:
        primary = _close_many([fd], error); raise primary  # type: ignore[misc]
    except OSError:
        primary = _close_many([fd], _Failure("SNAPSHOT_REPOSITORY_UNSAFE")); raise primary  # type: ignore[misc]


def _read_fd(fd: int, size: int, code: str, deadline: float | None = None) -> bytes:
    out: list[bytes] = []; left = size
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while left:
            if deadline is not None: _remaining(deadline)
            item = os.read(fd, min(left, 65536))
            if not item: raise _Failure(code)
            out.append(item); left -= len(item)
        if deadline is not None: _remaining(deadline)
        if os.read(fd, 1): raise _Failure(code)
    except OSError: raise _Failure(code)
    return b"".join(out)


def _safe_file(parent: int, leaf: str, deadline: float, *, optional: bool, limit: int = 1024 * 1024) -> tuple[bytes | None, _Identity | None]:
    _remaining(deadline)
    try: named_before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        if optional: return None, None
        raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    except OSError: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    if not stat.S_ISREG(named_before.st_mode):
        raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    try: fd = os.open(leaf, _META_READ, dir_fd=parent)
    except FileNotFoundError:
        raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    except OSError: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o022 or before.st_nlink != 1 or before.st_size > limit:
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        named = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if _identity(named_before) != _identity(before) or _identity(named) != _identity(before):
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        raw = _read_fd(fd, before.st_size, "SNAPSHOT_REPOSITORY_UNSAFE", deadline); _remaining(deadline)
        after = os.fstat(fd); named_after = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if _identity(before) != _identity(after) or _identity(after) != _identity(named_after): raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        result = (raw, _identity(after))
    except _Failure as error:
        primary = _close_many([fd], error); raise primary  # type: ignore[misc]
    except BaseException:
        primary = _close_many([fd], _Failure("SNAPSHOT_REPOSITORY_UNSAFE")); raise primary  # type: ignore[misc]
    close_error = _close_many([fd])
    if close_error is not None: raise close_error
    _remaining(deadline); return result


def _git_executable(deadline: float) -> _Identity:
    _remaining(deadline)
    fd: int | None = None; primary: _Failure | None = None
    try:
        named = os.lstat(GIT_EXECUTABLE); fd = os.open(GIT_EXECUTABLE, _READ); held = os.fstat(fd)
    except OSError:
        primary = _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    primary = _close_many([fd], primary)
    if primary is not None:
        raise primary
    if not stat.S_ISREG(named.st_mode) or stat.S_ISLNK(named.st_mode) or _identity(named) != _identity(held) or named.st_uid != 0 or stat.S_IMODE(named.st_mode) & 0o022 or not named.st_mode & 0o111:
        raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    _remaining(deadline); return _identity(held)


@dataclass
class _Binding:
    repo: str; root_fd: int; root_identity: _Identity; git_dir: str; git_fd: int; git_identity: _Identity
    common_dir: str; common_fd: int; common_identity: _Identity; git_exec: _Identity
    control: _Identity; commondir: _Identity | None; objects_fd: int; objects_identity: _Identity
    objects_info_identity: _Identity; alternates: tuple[tuple[str, _Identity | None], ...]
    config: tuple[tuple[str, _Identity | None], ...]; index: _Identity | None
    common_info_identity: _Identity | None; exclude: _Identity | None

    def base(self) -> list[str]:
        return [GIT_EXECUTABLE, "--no-replace-objects", f"--git-dir={self.git_dir}", f"--work-tree={self.repo}", "-c", "core.fsmonitor=false", "-c", f"core.excludesFile={os.devnull}"]

    def verify(self, deadline: float) -> None:
        _remaining(deadline)
        if _identity(os.fstat(self.root_fd)) != self.root_identity or _identity(os.fstat(self.git_fd)) != self.git_identity or _identity(os.fstat(self.common_fd)) != self.common_identity or _git_executable(deadline) != self.git_exec:
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        try:
            if _identity(os.stat(".git", dir_fd=self.root_fd, follow_symlinks=False)) != self.control: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        except OSError: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        for path, expected in ((self.repo, self.root_identity), (self.git_dir, self.git_identity), (self.common_dir, self.common_identity)):
            reopened = None; reopen_primary = None
            try:
                _, reopened, current = _safe_absolute_dir(path, deadline)
                if current != expected: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            except _Failure as error: reopen_primary = error
            reopen_primary = _close_many([reopened], reopen_primary)
            if reopen_primary is not None: raise reopen_primary
        _, current_commondir = _safe_file(self.git_fd, "commondir", deadline, optional=True, limit=4096)
        if current_commondir != self.commondir: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        try:
            if _identity(os.fstat(self.objects_fd)) != self.objects_identity or _identity(os.stat("objects", dir_fd=self.common_fd, follow_symlinks=False)) != self.objects_identity:
                raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            object_info_fd = os.open("info", _DIR, dir_fd=self.objects_fd); info_primary = None
            try:
                if _identity(os.fstat(object_info_fd)) != self.objects_info_identity or _identity(os.stat("info", dir_fd=self.objects_fd, follow_symlinks=False)) != self.objects_info_identity:
                    raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
                for leaf, expected in self.alternates:
                    raw, current = _safe_file(object_info_fd, leaf, deadline, optional=True, limit=4096)
                    if current != expected or raw not in (None, b""): raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            except _Failure as error: info_primary = error
            info_primary = _close_many([object_info_fd], info_primary)
            if info_primary is not None: raise info_primary
        except OSError: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        for leaf, expected in self.config:
            _, current = _safe_file(self.common_fd if leaf == "config" else self.git_fd, leaf, deadline, optional=True)
            if current != expected: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        current_index_raw, current_index = _safe_file(self.git_fd, "index", deadline, optional=True, limit=64 * 1024 * 1024)
        if current_index != self.index: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        _audit_index(current_index_raw, deadline)
        info_fd: int | None = None; common_info_primary: _Failure | None = None
        try:
            info_fd = os.open("info", _DIR, dir_fd=self.common_fd)
            if self.common_info_identity is None or _identity(os.fstat(info_fd)) != self.common_info_identity or _identity(os.stat("info", dir_fd=self.common_fd, follow_symlinks=False)) != self.common_info_identity:
                raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            _, current_exclude = _safe_file(info_fd, "exclude", deadline, optional=True)
        except FileNotFoundError:
            current_exclude = None
            if self.common_info_identity is not None: common_info_primary = _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        except _Failure as error: common_info_primary = error
        except OSError: common_info_primary = _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        common_info_primary = _close_many([info_fd], common_info_primary)
        if common_info_primary is not None: raise common_info_primary
        if current_exclude != self.exclude: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        _remaining(deadline)

    def close(self, primary: _Failure | None = None) -> _Failure | None:
        return _close_many([self.objects_fd, self.common_fd, self.git_fd, self.root_fd], primary)


def _open_child_dir(parent: int, leaf: str, deadline: float) -> int:
    _remaining(deadline)
    try:
        result = os.open(leaf, _DIR, dir_fd=parent); _remaining(deadline); return result
    except OSError: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")


def _resolve_gitdir(repo: str, root_fd: int, deadline: float) -> tuple[str, int]:
    _remaining(deadline)
    try: item = os.stat(".git", dir_fd=root_fd, follow_symlinks=False)
    except OSError: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    if stat.S_ISDIR(item.st_mode):
        path = os.path.join(repo, ".git")
    elif stat.S_ISREG(item.st_mode):
        raw, _ = _safe_file(root_fd, ".git", deadline, optional=False, limit=4096)
        try: text = raw.decode("utf-8", "strict") if raw is not None else ""
        except UnicodeDecodeError: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        if not text.startswith("gitdir: ") or not text.endswith("\n") or "\n" in text[:-1]: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        target = text[8:-1]
        if not target or "\x00" in target: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        path = target if os.path.isabs(target) else os.path.normpath(os.path.join(repo, target))
    else: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    _, fd, _ = _safe_absolute_dir(path, deadline)
    _remaining(deadline); return path, fd


def _config_lines(text: str, deadline: float) -> list[str]:
    """Return bounded Git-config logical lines with comments removed."""
    result: list[str] = []; pending = ""; quoted = False
    for physical in text.splitlines():
        _remaining(deadline)
        body: list[str] = []; escaped = False
        for char in physical:
            if escaped:
                body.append(char); escaped = False; continue
            if char == "\\":
                body.append(char); escaped = True; continue
            if char == '"':
                body.append(char); quoted = not quoted; continue
            if char in "#;" and not quoted:
                break
            body.append(char)
        current = "".join(body).rstrip()
        slash_count = len(current) - len(current.rstrip("\\"))
        continued = slash_count % 2 == 1
        if continued:
            current = current[:-1]
        pending += current
        if len(pending) > 65536:
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        if continued:
            continue
        if quoted:
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        if pending.strip():
            result.append(pending.strip())
        pending = ""; quoted = False
    if pending or quoted:
        raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    return result


def _audit_config(fd: int, leaf: str, deadline: float) -> _Identity | None:
    raw, identity = _safe_file(fd, leaf, deadline, optional=True)
    if raw is None: return None
    try: text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    section: str | None = None
    for line in _config_lines(text, deadline):
        if line.startswith("["):
            quoted = False; escaped = False; end = None
            for index, char in enumerate(line[1:], 1):
                if escaped: escaped = False; continue
                if char == "\\": escaped = True; continue
                if char == '"': quoted = not quoted; continue
                if char == "]" and not quoted:
                    end = index; break
            if end is None or line[end + 1:].strip():
                raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            header = line[1:end].strip()
            match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*)(?:\s+\"(?:[^\"\\\\]|\\\\.)*\")?", header)
            if match is None:
                raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            section = match.group(1).lower()
            if section in {"include", "includeif"}:
                raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            continue
        if section is None:
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        key = line.split("=", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key) is None:
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        if section == "core" and key.lower() == "worktree":
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    _remaining(deadline)
    return identity


def _audit_index(raw: bytes | None, deadline: float) -> None:
    """Validate the SHA-1 index envelope and reject split-index link data."""
    if raw is None:
        return
    _remaining(deadline)
    if len(raw) < 32 or raw[:4] != b"DIRC" or hashlib.sha1(raw[:-20]).digest() != raw[-20:]:
        raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    version = int.from_bytes(raw[4:8], "big"); count = int.from_bytes(raw[8:12], "big")
    if version not in {2, 3, 4}:
        raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    offset = 12; end = len(raw) - 20
    for _ in range(count):
        _remaining(deadline); entry_start = offset
        if offset + 62 > end:
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        flags = int.from_bytes(raw[offset + 60:offset + 62], "big"); offset += 62
        if flags & 0x4000:
            if version < 3 or offset + 2 > end:
                raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            offset += 2
        if version == 4:
            while True:
                if offset >= end:
                    raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
                value = raw[offset]; offset += 1
                if not value & 0x80:
                    break
            nul = raw.find(b"\0", offset, end)
            if nul < 0:
                raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            offset = nul + 1
        else:
            name_length = flags & 0x0FFF
            if name_length < 0x0FFF:
                nul = offset + name_length
                if nul >= end or raw[nul] != 0:
                    raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            else:
                nul = raw.find(b"\0", offset, end)
                if nul < 0:
                    raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            entry_length = nul + 1 - entry_start
            offset = entry_start + ((entry_length + 7) & ~7)
            if offset > end:
                raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    while offset < end:
        _remaining(deadline)
        if offset + 8 > end:
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        signature = raw[offset:offset + 4]
        size = int.from_bytes(raw[offset + 4:offset + 8], "big"); offset += 8
        if size > end - offset:
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        if signature == b"link":
            raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
        offset += size
    if offset != end:
        raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    _remaining(deadline)


def _bootstrap(repo_root: str | os.PathLike[str], deadline: float) -> _Binding:
    _remaining(deadline); repo, root_fd, root_id = _safe_absolute_dir(repo_root, deadline)
    git_fd = common_fd = objects_fd = None
    try:
        control = _identity(os.stat(".git", dir_fd=root_fd, follow_symlinks=False))
        git_dir, git_fd = _resolve_gitdir(repo, root_fd, deadline); git_id = _identity(os.fstat(git_fd))
        raw, commondir_id = _safe_file(git_fd, "commondir", deadline, optional=True, limit=4096)
        if raw is None: common_dir, common_fd = git_dir, os.dup(git_fd)
        else:
            try: value = raw.decode("utf-8", "strict").rstrip("\n")
            except UnicodeDecodeError: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            if not value or "\n" in value or "\x00" in value: raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
            common_dir = value if os.path.isabs(value) else os.path.normpath(os.path.join(git_dir, value))
            _, common_fd, _ = _safe_absolute_dir(common_dir, deadline)
        common_id = _identity(os.fstat(common_fd))
        config = (("config", _audit_config(common_fd, "config", deadline)), ("config.worktree", _audit_config(git_fd, "config.worktree", deadline)))
        objects_fd = _open_child_dir(common_fd, "objects", deadline); objects_id = _identity(os.fstat(objects_fd))
        info_fd = None; info_primary = None
        try:
            info_fd = _open_child_dir(objects_fd, "info", deadline); objects_info_id = _identity(os.fstat(info_fd)); alternate_records = []
            for leaf in ("alternates", "http-alternates"):
                alternate_raw, alternate_id = _safe_file(info_fd, leaf, deadline, optional=True, limit=4096)
                if alternate_raw not in (None, b""): raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
                alternate_records.append((leaf, alternate_id))
        except _Failure as error: info_primary = error
        info_primary = _close_many([info_fd], info_primary)
        if info_primary is not None: raise info_primary
        index_raw, index = _safe_file(git_fd, "index", deadline, optional=True, limit=64 * 1024 * 1024)
        _audit_index(index_raw, deadline)
        info_fd = None; common_info_primary = None
        try:
            info_fd = _open_child_dir(common_fd, "info", deadline); common_info_id = _identity(os.fstat(info_fd)); _, exclude = _safe_file(info_fd, "exclude", deadline, optional=True)
        except _Failure as error:
            # Missing info directory is acceptable; special/unsafe is not.
            try: os.stat("info", dir_fd=common_fd, follow_symlinks=False)
            except FileNotFoundError: common_info_id = None; exclude = None
            else: common_info_primary = error
        common_info_primary = _close_many([info_fd], common_info_primary)
        if common_info_primary is not None: raise common_info_primary
        _remaining(deadline)
        return _Binding(repo, root_fd, root_id, git_dir, git_fd, git_id, common_dir, common_fd, common_id, _git_executable(deadline), control, commondir_id, objects_fd, objects_id, objects_info_id, tuple(alternate_records), config, index, common_info_id, exclude)
    except BaseException as raw:
        primary = raw if isinstance(raw, _Failure) else _Failure("SNAPSHOT_REPOSITORY_UNSAFE", "INTERNAL_BOOTSTRAP_ERROR")
        primary = _close_many([objects_fd, common_fd, git_fd, root_fd], primary)
        raise primary  # type: ignore[misc]


def _terminate(proc: subprocess.Popen[bytes]) -> str | None:
    failed = False; cleanup_deadline = _CLOCK() + 2.0

    def signal_group(sig: int) -> bool | None:
        """True=signalled, False=absent, None=present but not controllable."""
        nonlocal failed
        try:
            os.killpg(proc.pid, sig)
            return True
        except OSError as error:
            if error.errno == errno.ESRCH:
                return False
            failed = True
            return None
        except BaseException:
            failed = True
            return None

    def group_exists() -> bool | None:
        nonlocal failed
        try:
            os.killpg(proc.pid, 0)
            return True
        except OSError as error:
            if error.errno == errno.ESRCH:
                return False
            failed = True
            return None
        except BaseException:
            failed = True
            return None

    def bounded_wait() -> bool:
        while True:
            remaining = max(0.0, cleanup_deadline - _CLOCK())
            try:
                proc.wait(timeout=remaining)
                return True
            except InterruptedError:
                if _CLOCK() >= cleanup_deadline:
                    return False
            except subprocess.TimeoutExpired:
                return False

    # Once the owned leader has been reaped its numeric PID can be reused as a
    # foreign process-group ID.  Never signal that ambiguous ID.
    if getattr(proc, "returncode", None) is not None:
        try:
            proc.wait(timeout=0)
        except BaseException:
            return "PROCESS_REAP_FAILED"
        return "BATCH_CLEANUP_FAILED"

    term = signal_group(signal.SIGTERM)
    if term is True:
        # Give cooperative members a short share of the fixed cleanup budget.
        # Do not wait()/poll() the leader here: keeping it unreaped prevents
        # its PID/process-group ID from being reused before group resolution.
        term_deadline = min(cleanup_deadline, _CLOCK() + 0.05)
        while _CLOCK() < term_deadline:
            state = group_exists()
            if state is False:
                break
            time.sleep(min(0.005, max(0.0, term_deadline - _CLOCK())))

    state = group_exists()
    terminal_signal = state is False
    if state is not False:
        killed = signal_group(signal.SIGKILL)
        terminal_signal = killed is not None

    reaped = False
    try:
        reaped = bounded_wait()
    except BaseException:
        failed = True
    if not reaped:
        if not terminal_signal:
            return "BATCH_CLEANUP_FAILED"
        try:
            # SIGKILL (or ESRCH for an already absent group) is terminal.
            proc.wait()
            reaped = True
        except BaseException:
            return "PROCESS_REAP_FAILED"
    else:
        try:
            # Idempotent final owned-leader reap check.
            proc.wait()
        except BaseException:
            return "PROCESS_REAP_FAILED"
    return "BATCH_CLEANUP_FAILED" if failed else None


def _command(binding: _Binding, argv: list[str], deadline: float, *, limit: int = _MAX_OUTPUT) -> bytes:
    binding.verify(deadline)
    proc: subprocess.Popen[bytes] | None = None; result: bytes | None = None
    primary: _Failure | None = None; unexpected: BaseException | None = None
    try:
        proc = subprocess.Popen(binding.base() + argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_clean_env(), shell=False, start_new_session=True)
        if proc.stdout is None: raise _Failure("SNAPSHOT_GIT_FAILED")
        out = bytearray(); fd = proc.stdout.fileno()
        while True:
            ready, _, _ = select.select([fd], [], [], _remaining(deadline))
            if not ready: raise _Failure("SNAPSHOT_TIMEOUT")
            piece = os.read(fd, min(65536, limit + 1 - len(out)))
            if not piece: break
            out.extend(piece)
            if len(out) > limit: raise _Failure("SNAPSHOT_GIT_FAILED")
        try: status = proc.wait(timeout=_remaining(deadline))
        except subprocess.TimeoutExpired: raise _Failure("SNAPSHOT_TIMEOUT")
        if status != 0: raise _Failure("SNAPSHOT_GIT_FAILED")
        binding.verify(deadline); result = bytes(out)
    except _Failure as error:
        primary = error
    except OSError:
        primary = _Failure("SNAPSHOT_GIT_FAILED")
    except BaseException as error:
        unexpected = error
    cleanup = None
    if proc is not None:
        try:
            if primary is not None or unexpected is not None or result is None:
                cleanup = _terminate(proc)
        except BaseException:
            cleanup = "BATCH_CLEANUP_FAILED"
        try:
            if proc.stdout is not None and not proc.stdout.closed:
                proc.stdout.close()
        except BaseException:
            cleanup = cleanup or "BATCH_CLEANUP_FAILED"
    if primary is not None:
        if primary.secondary is None: primary.secondary = cleanup
        raise primary
    if unexpected is not None:
        raise unexpected
    if cleanup is not None:
        raise _Failure("SNAPSHOT_GIT_FAILED", cleanup)
    if result is None:
        raise _Failure("SNAPSHOT_GIT_FAILED")
    return result


class _Batch:
    def __init__(self, binding: _Binding, deadline: float) -> None:
        self.binding, self.deadline = binding, deadline; self.proc: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> "_Batch":
        self.binding.verify(self.deadline)
        try:
            self.proc = subprocess.Popen(self.binding.base() + ["cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_clean_env(), shell=False, start_new_session=True)
        except OSError: raise _Failure("SNAPSHOT_GIT_FAILED")
        return self

    def _read(self, amount: int) -> bytes:
        if self.proc is None or self.proc.stdout is None: raise _Failure("SNAPSHOT_GIT_FAILED")
        fd = self.proc.stdout.fileno(); chunks: list[bytes] = []; left = amount
        while left:
            ready, _, _ = select.select([fd], [], [], _remaining(self.deadline))
            if not ready: raise _Failure("SNAPSHOT_TIMEOUT")
            item = os.read(fd, left)
            if not item: raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
            chunks.append(item); left -= len(item)
        return b"".join(chunks)

    def _line(self) -> bytes:
        out = bytearray()
        while len(out) <= 128:
            piece = self._read(1); out += piece
            if piece == b"\n": return bytes(out[:-1])
        raise _Failure("SNAPSHOT_OBJECT_MISMATCH")

    def get(self, oid: str, *, max_size: int = _MAX_ENTRY) -> tuple[str, bytes]:
        if self.proc is None or self.proc.stdin is None or not _SHA.fullmatch(oid): raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
        if not isinstance(max_size, int) or isinstance(max_size, bool) or max_size < 0 or max_size > _MAX_ENTRY:
            raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
        request = (oid + "\n").encode("ascii"); offset = 0
        try:
            while offset < len(request):
                _remaining(self.deadline); written = os.write(self.proc.stdin.fileno(), request[offset:])
                if written <= 0: raise _Failure("SNAPSHOT_GIT_FAILED")
                offset += written
        except OSError: raise _Failure("SNAPSHOT_GIT_FAILED")
        header = self._line().split(b" ")
        if len(header) != 3 or len(header[2]) > 20 or re.fullmatch(rb"(?:0|[1-9][0-9]*)", header[2]) is None:
            raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
        try: actual, kind = header[0].decode("ascii"), header[1].decode("ascii")
        except UnicodeDecodeError: raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
        if actual != oid or not _SHA.fullmatch(actual) or kind not in {"commit", "tree", "blob"}:
            raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
        size = int(header[2])
        if size > max_size:
            raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
        raw = self._read(size)
        if self._read(1) != b"\n" or _object_id(kind.encode("ascii"), raw) != oid: raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
        return kind, raw

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if self.proc is None: return False
        cleanup = None; close_failed = False

        # A body error owns the primary.  Closing stdin may let the leader exit
        # zero while a descendant remains in its process group, so do not take
        # the normal EOF/wait path (which would reap and free the PGID).  Keep
        # the leader unreaped, resolve the whole group, then preserve `exc`.
        if exc is not None:
            if self.proc.stdin is not None and not self.proc.stdin.closed:
                try:
                    self.proc.stdin.close()
                except BaseException:
                    close_failed = True
            try:
                cleanup = _terminate(self.proc)
            except BaseException:
                cleanup = "BATCH_CLEANUP_FAILED"
            for stream in (self.proc.stdin, self.proc.stdout):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except BaseException:
                        close_failed = True
            if isinstance(exc, _Failure) and exc.secondary is None:
                exc.secondary = cleanup or ("BATCH_CLEANUP_FAILED" if close_failed else None)
            return False

        failure: _Failure | None = None
        try:
            if self.proc.stdin is not None: self.proc.stdin.close()
            if self.proc.stdout is not None:
                ready, _, _ = select.select([self.proc.stdout.fileno()], [], [], _remaining(self.deadline))
                if not ready: raise _Failure("SNAPSHOT_TIMEOUT")
                if os.read(self.proc.stdout.fileno(), 1): raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
            if self.proc.wait(timeout=_remaining(self.deadline)) != 0: raise _Failure("SNAPSHOT_GIT_FAILED")
        except _Failure as error:
            failure = error; cleanup = _terminate(self.proc)
        except BaseException:
            failure = _Failure("SNAPSHOT_GIT_FAILED"); cleanup = _terminate(self.proc)
        for stream in (self.proc.stdin, self.proc.stdout):
            if stream is not None and not stream.closed:
                try: stream.close()
                except BaseException: close_failed = True
        if failure is not None:
            if failure.secondary is None:
                failure.secondary = cleanup or ("BATCH_CLEANUP_FAILED" if close_failed else None)
            raise failure
        elif close_failed:
            raise _Failure("SNAPSHOT_GIT_FAILED", "BATCH_CLEANUP_FAILED")
        return False


def _verify_git(binding: _Binding, deadline: float) -> None:
    raw = _command(binding, ["rev-parse", "--show-toplevel", "--absolute-git-dir", "--git-common-dir", "--show-object-format"], deadline, limit=8192).splitlines()
    try: top, git_dir, common, fmt = [value.decode("utf-8", "strict") for value in raw]
    except (UnicodeDecodeError, ValueError): raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")
    common = common if os.path.isabs(common) else os.path.normpath(os.path.join(binding.repo, common))
    if top != binding.repo or git_dir != binding.git_dir or common != binding.common_dir or fmt != "sha1": raise _Failure("SNAPSHOT_REPOSITORY_UNSAFE")


def _tree_entries(raw: bytes, deadline: float) -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []; names: set[bytes] = set(); pos = 0
    while pos < len(raw):
        _remaining(deadline)
        space, nul = raw.find(b" ", pos), raw.find(b"\0", pos)
        if space <= pos or nul <= space or nul + 21 > len(raw): raise _Failure("SNAPSHOT_TREE_MALFORMED")
        mode_b, name_b, oid_b = raw[pos:space], raw[space + 1:nul], raw[nul + 1:nul + 21]; pos = nul + 21
        try: mode, name = mode_b.decode("ascii"), name_b.decode("utf-8", "strict")
        except UnicodeDecodeError: raise _Failure("SNAPSHOT_PATH_UNSAFE")
        if mode not in {"40000", "100644", "100755", "120000"}: raise _Failure("SNAPSHOT_ENTRY_UNSUPPORTED")
        if name_b in names or not _leaf(name) or name != unicodedata.normalize("NFC", name): raise _Failure("SNAPSHOT_PATH_UNSAFE")
        names.add(name_b); result.append((mode, name, oid_b.hex()))
        _remaining(deadline)
    return result


def _objects(binding: _Binding, expected: str, run_id: str, deadline: float) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []; trees: dict[str, list[tuple[str, str, str]]] = {}; blobs: dict[str, bytes] = {}; requests = 0; tree_bytes = 0; total_bytes = 0; logical_tree_expansions = 0
    with _Batch(binding, deadline) as batch:
        def fetch(oid: str, max_size: int = _MAX_ENTRY) -> tuple[str, bytes]:
            nonlocal requests
            _remaining(deadline)
            if requests >= _MAX_OBJECTS: raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
            requests += 1; result = batch.get(oid, max_size=max_size); _remaining(deadline)
            return result
        kind, commit = fetch(expected, _MAX_COMMIT)
        if kind != "commit" or len(commit) > _MAX_COMMIT: raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
        if b"\n\n" not in commit: raise _Failure("SNAPSHOT_TREE_MALFORMED")
        header = commit.split(b"\n\n", 1)[0]; found = [line[5:] for line in header.split(b"\n") if line.startswith(b"tree ")]
        if len(found) != 1 or not _SHA.fullmatch(found[0].decode("ascii", "ignore")): raise _Failure("SNAPSHOT_TREE_MALFORMED")
        def walk(oid: str, prefix: str, ancestry: set[str]) -> None:
            nonlocal requests, tree_bytes, total_bytes, logical_tree_expansions
            _remaining(deadline)
            if logical_tree_expansions >= _MAX_TREE_EXPANSIONS: raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
            logical_tree_expansions += 1
            if oid in ancestry: raise _Failure("SNAPSHOT_TREE_MALFORMED")
            if oid not in trees:
                kind2, raw = fetch(oid); tree_bytes += len(raw)
                if kind2 != "tree": raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
                trees[oid] = _tree_entries(raw, deadline)
            if len(trees) > _MAX_TREES or tree_bytes > _MAX_TREE_BYTES or requests > _MAX_OBJECTS: raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
            for mode, name, child in trees[oid]:
                _remaining(deadline)
                path = name if not prefix else prefix + "/" + name
                if not _safe_logical(path): raise _Failure("SNAPSHOT_PATH_UNSAFE")
                if mode == "40000": walk(child, path, ancestry | {oid}); continue
                if child not in blobs:
                    kind3, raw = fetch(child)
                    if kind3 != "blob": raise _Failure("SNAPSHOT_OBJECT_MISMATCH")
                    blobs[child] = raw
                raw = blobs[child]
                if len(raw) > _MAX_ENTRY: raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
                if len(entries) >= _MAX_ENTRIES or total_bytes + len(raw) > _MAX_TOTAL: raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
                total_bytes += len(raw)
                item: dict[str, Any] = {"path": path, "type": "symlink" if mode == "120000" else "file", "mode": mode, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                if mode == "120000":
                    try: target = raw.decode("utf-8", "strict")
                    except UnicodeDecodeError: raise _Failure("SNAPSHOT_SYMLINK_UNREPRESENTABLE")
                    if not target or len(target) > 240 or target != unicodedata.normalize("NFC", target) or target.endswith("\n"): raise _Failure("SNAPSHOT_SYMLINK_UNREPRESENTABLE")
                    item["symlink_target"] = target
                entries.append(item)
        try: walk(found[0].decode("ascii"), "", set())
        except RecursionError: raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
    entries.sort(key=lambda item: item["path"].encode("utf-8"))
    if len(entries) > _MAX_ENTRIES or len({item["path"] for item in entries}) != len(entries): raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
    total = sum(item["size"] for item in entries)
    manifest = {"schema": "source-snapshot-manifest.v1", "run_id": run_id, "head_sha": expected, "snapshot_mode": "clean-commit", "entry_count": len(entries), "total_bytes": total, "entries": entries}
    try: validate_source_snapshot(manifest); canonical_json_bytes(manifest)
    except Exception: raise _Failure("SNAPSHOT_VALIDATION_FAILED")
    return manifest


def _validate_capture_manifest(value: Any, run_id: str, expected_head: str) -> Mapping[str, Any]:
    """Independently close the capture-to-store manifest boundary."""
    if not isinstance(value, Mapping):
        raise _Failure("SNAPSHOT_VALIDATION_FAILED")
    try:
        if (
            value.get("run_id") != run_id
            or value.get("head_sha") != expected_head
            or value.get("snapshot_mode") != "clean-commit"
        ):
            raise _Failure("SNAPSHOT_BINDING_MISMATCH")
    except _Failure:
        raise
    except BaseException:
        raise _Failure("SNAPSHOT_VALIDATION_FAILED")
    try:
        validate_source_snapshot(value)
        raw = canonical_json_bytes(value)
    except BaseException:
        raise _Failure("SNAPSHOT_VALIDATION_FAILED")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
    return value


def _tracked_bytes(root_fd: int, path: str, mode: str, deadline: float) -> tuple[bytes, dict[str, _Identity]]:
    current = root_fd; owned: list[int] = []; bindings: list[tuple[int, str, _Identity, int]] = []; primary: _Failure | None = None; result = None
    observed: dict[str, _Identity] = {}; parts = path.split("/")
    try:
        for index, part in enumerate(parts[:-1]):
            _remaining(deadline); parent = current
            named = os.stat(part, dir_fd=parent, follow_symlinks=False)
            current = os.open(part, _DIR, dir_fd=parent); opened = os.fstat(current)
            if _identity(named) != _identity(opened): raise _Failure("SNAPSHOT_DIRTY")
            identity = _identity(opened); observed["/".join(parts[:index + 1])] = identity
            owned.append(current); bindings.append((parent, part, identity, current))
        leaf = parts[-1]; before = os.stat(leaf, dir_fd=current, follow_symlinks=False)
        if before.st_size > _MAX_ENTRY: raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
        if mode == "120000":
            if not stat.S_ISLNK(before.st_mode): raise _Failure("SNAPSHOT_DIRTY")
            raw = os.readlink(leaf, dir_fd=current).encode("utf-8", "surrogateescape")
        else:
            if not stat.S_ISREG(before.st_mode) or ("100755" if stat.S_IMODE(before.st_mode) & 0o111 else "100644") != mode: raise _Failure("SNAPSHOT_DIRTY")
            # O_NONBLOCK ensures a lstat->FIFO/device replacement cannot turn
            # this checkout read into an operation beyond the absolute
            # deadline.  The following fstat/name checks still require the
            # exact regular inode observed above.
            fd = os.open(leaf, _META_READ, dir_fd=current)
            leaf_primary: _Failure | None = None
            try:
                opened = os.fstat(fd)
                if _identity(before) != _identity(opened): raise _Failure("SNAPSHOT_DIRTY")
                chunks: list[bytes] = []; left = before.st_size
                while left:
                    _remaining(deadline); piece = os.read(fd, min(left, 65536))
                    if not piece: raise _Failure("SNAPSHOT_DIRTY")
                    chunks.append(piece); left -= len(piece)
                _remaining(deadline)
                if os.read(fd, 1) or _identity(os.fstat(fd)) != _identity(before): raise _Failure("SNAPSHOT_DIRTY")
                raw = b"".join(chunks)
            except _Failure as error: leaf_primary = error
            except BaseException: leaf_primary = _Failure("SNAPSHOT_DIRTY", "INTERNAL_READ_ERROR")
            leaf_primary = _close_many([fd], leaf_primary)
            if leaf_primary is not None: raise leaf_primary
        after = os.stat(leaf, dir_fd=current, follow_symlinks=False)
        if _identity(before) != _identity(after): raise _Failure("SNAPSHOT_DIRTY")
        for parent, name, expected, held in bindings:
            if _identity(os.fstat(held)) != expected or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected:
                raise _Failure("SNAPSHOT_DIRTY")
        observed[path] = _identity(after); result = (raw, observed)
    except _Failure as error: primary = error
    except BaseException: primary = _Failure("SNAPSHOT_DIRTY", "INTERNAL_WALK_ERROR")
    primary = _close_many(list(reversed(owned)), primary)
    if primary is not None: raise primary
    if result is None: raise _Failure("SNAPSHOT_DIRTY")
    return result


def _verify_checkout_stable_set(root_fd: int, observed: Mapping[str, _Identity], deadline: float) -> None:
    """Rewalk every observed leaf and ancestor without following symlinks."""
    for path, expected_leaf in sorted(observed.items(), key=lambda item: item[0].encode("utf-8")):
        _remaining(deadline); parts = path.split("/"); current = root_fd
        owned: list[int] = []; primary: _Failure | None = None
        try:
            for index, part in enumerate(parts):
                _remaining(deadline)
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
                prefix = "/".join(parts[:index + 1]); expected = observed.get(prefix)
                if expected is None or _identity(named) != expected:
                    raise _Failure("SNAPSHOT_DIRTY")
                if index != len(parts) - 1:
                    next_fd = os.open(part, _DIR, dir_fd=current); owned.append(next_fd)
                    if _identity(os.fstat(next_fd)) != expected:
                        raise _Failure("SNAPSHOT_DIRTY")
                    current = next_fd
            if _identity(named) != expected_leaf:
                raise _Failure("SNAPSHOT_DIRTY")
        except _Failure as error:
            primary = error
        except BaseException:
            primary = _Failure("SNAPSHOT_DIRTY", "INTERNAL_STABLE_SET_ERROR")
        primary = _close_many(list(reversed(owned)), primary)
        if primary is not None:
            raise primary
    _remaining(deadline)


def _audit_untracked_without_excludes(
    binding: _Binding,
    tracked: Mapping[bytes, Mapping[str, Any]],
    deadline: float,
) -> Mapping[str, _Identity]:
    """Nofollow-walk the checkout before asking Git to read ignore controls."""
    binding.verify(deadline)
    observed: dict[str, _Identity] = {}
    count = 0; path_bytes = 0

    def walk(parent: int, prefix: str) -> None:
        nonlocal count, path_bytes
        try:
            iterator = os.scandir(parent)
        except OSError:
            raise _Failure("SNAPSHOT_DIRTY")
        try:
            with iterator:
                for entry in iterator:
                    _remaining(deadline)
                    name = entry.name
                    if not isinstance(name, str):
                        raise _Failure("SNAPSHOT_PATH_UNSAFE")
                    if not prefix and name == ".git":
                        continue
                    try:
                        encoded_name = name.encode("utf-8", "strict")
                    except UnicodeEncodeError:
                        raise _Failure("SNAPSHOT_PATH_UNSAFE")
                    if (
                        not _leaf(name)
                        or name != unicodedata.normalize("NFC", name)
                        or any(ord(char) < 32 or ord(char) == 127 for char in name)
                    ):
                        raise _Failure("SNAPSHOT_PATH_UNSAFE")
                    logical = f"{prefix}/{name}" if prefix else name
                    encoded = logical.encode("utf-8")
                    count += 1; path_bytes += len(encoded) + 1
                    if (
                        count > _MAX_UNTRACKED_PATHS
                        or len(encoded) > _MAX_UNTRACKED_PATH_BYTES
                        or path_bytes > _MAX_UNTRACKED_BYTES
                    ):
                        raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
                    try:
                        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    except OSError:
                        raise _Failure("SNAPSHOT_DIRTY")
                    identity = _identity(named)
                    if logical in observed:
                        raise _Failure("SNAPSHOT_PATH_UNSAFE")
                    observed[logical] = identity
                    # The preverified tracked map is the only authority that
                    # can permit an ignore control.  This rejects regular,
                    # symlink, FIFO, socket, device, and directory forms
                    # without opening or reading an untracked .gitignore.
                    if name.casefold() == ".gitignore" and encoded not in tracked:
                        raise _Failure("SNAPSHOT_DIRTY")
                    if stat.S_ISDIR(named.st_mode):
                        child: int | None = None; primary: _Failure | None = None
                        try:
                            child = os.open(name, _DIR, dir_fd=parent)
                            opened = os.fstat(child)
                            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                            if _identity(opened) != identity or _identity(current) != identity:
                                raise _Failure("SNAPSHOT_DIRTY")
                            walk(child, logical)
                        except _Failure as error:
                            primary = error
                        except OSError:
                            primary = _Failure("SNAPSHOT_DIRTY")
                        primary = _close_many([child], primary)
                        if primary is not None:
                            raise primary
        except _Failure:
            raise
        except BaseException:
            raise _Failure("SNAPSHOT_DIRTY", "INTERNAL_UNTRACKED_WALK_ERROR")

    walk(binding.root_fd, "")
    binding.verify(deadline)
    _remaining(deadline)
    return observed


def _clean(binding: _Binding, expected: str, manifest: Mapping[str, Any], deadline: float) -> None:
    binding.verify(deadline); _verify_git(binding, deadline)
    if _command(binding, ["rev-parse", "HEAD^{commit}"], deadline, limit=128).strip().decode("ascii", "ignore") != expected: raise _Failure("SNAPSHOT_HEAD_MISMATCH")
    expected_map = {item["path"].encode(): item for item in manifest["entries"]}
    staged = _command(binding, ["ls-files", "--cached", "--stage", "-z"], deadline)
    index: dict[bytes, tuple[str, str]] = {}
    if staged and not staged.endswith(b"\0"): raise _Failure("SNAPSHOT_DIRTY")
    for record in staged[:-1].split(b"\0") if staged else []:
        try: front, path = record.split(b"\t", 1); mode, oid, stage = front.split(b" ")
        except ValueError: raise _Failure("SNAPSHOT_DIRTY")
        if stage != b"0" or path in index or mode.decode("ascii", "ignore") not in {"100644", "100755", "120000"} or not _SHA.fullmatch(oid.decode("ascii", "ignore")): raise _Failure("SNAPSHOT_DIRTY")
        index[path] = (mode.decode(), oid.decode())
    if set(index) != set(expected_map) or any(index[path][0] != expected_map[path]["mode"] for path in index): raise _Failure("SNAPSHOT_DIRTY")
    flags = _command(binding, ["ls-files", "--cached", "-v", "-z"], deadline)
    seen: set[bytes] = set()
    if flags and not flags.endswith(b"\0"): raise _Failure("SNAPSHOT_INDEX_FLAGS_UNSAFE")
    for record in flags[:-1].split(b"\0") if flags else []:
        if len(record) < 3 or record[:1] != b"H" or record[1:2] != b" " or record[2:] in seen: raise _Failure("SNAPSHOT_INDEX_FLAGS_UNSAFE")
        seen.add(record[2:])
    if seen != set(index): raise _Failure("SNAPSHOT_INDEX_FLAGS_UNSAFE")
    ignore_observed: dict[str, _Identity] = {}
    for path_b, item in expected_map.items():
        try:
            path = path_b.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise _Failure("SNAPSHOT_PATH_UNSAFE")
        if path.split("/")[-1].casefold() != ".gitignore":
            continue
        raw, current = _tracked_bytes(binding.root_fd, path, item["mode"], deadline)
        if (
            len(raw) != item["size"]
            or hashlib.sha256(raw).hexdigest() != item["sha256"]
            or _object_id(b"blob", raw) != index[path_b][1]
        ):
            raise _Failure("SNAPSHOT_DIRTY")
        for logical, identity in current.items():
            if logical in ignore_observed and ignore_observed[logical] != identity:
                raise _Failure("SNAPSHOT_DIRTY")
            ignore_observed[logical] = identity
    untracked_observed = _audit_untracked_without_excludes(binding, expected_map, deadline)
    other = _command(binding, ["-c", f"core.excludesFile={os.devnull}", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "ls-files", "--others", "--exclude-standard", "--directory", "--no-empty-directory", "-z"], deadline)
    if other: raise _Failure("SNAPSHOT_DIRTY")
    _verify_checkout_stable_set(binding.root_fd, untracked_observed, deadline)
    _verify_checkout_stable_set(binding.root_fd, ignore_observed, deadline)
    checkout_total = 0; observed: dict[str, _Identity] = {}
    for path_b, item in expected_map.items():
        _remaining(deadline)
        try: path = path_b.decode("utf-8", "strict")
        except UnicodeDecodeError: raise _Failure("SNAPSHOT_PATH_UNSAFE")
        if checkout_total + item["size"] > _MAX_TOTAL: raise _Failure("SNAPSHOT_LIMIT_EXCEEDED")
        raw, current = _tracked_bytes(binding.root_fd, path, item["mode"], deadline); checkout_total += len(raw)
        for logical, identity in current.items():
            if logical in observed and observed[logical] != identity: raise _Failure("SNAPSHOT_DIRTY")
            observed[logical] = identity
        if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"] or _object_id(b"blob", raw) != index[path_b][1]: raise _Failure("SNAPSHOT_DIRTY")
    binding.verify(deadline); _verify_git(binding, deadline)
    if _command(binding, ["rev-parse", "HEAD^{commit}"], deadline, limit=128).strip().decode("ascii", "ignore") != expected:
        raise _Failure("SNAPSHOT_HEAD_MISMATCH")
    _verify_checkout_stable_set(binding.root_fd, observed, deadline)
    # The pre-exclude walk and verified ignore controls must remain stable
    # through the full tracked scan as well as through the excludes query.
    # In particular, a pure ignored directory is absent from `observed`.
    _verify_checkout_stable_set(binding.root_fd, untracked_observed, deadline)
    _verify_checkout_stable_set(binding.root_fd, ignore_observed, deadline)
    binding.verify(deadline)
    if _command(binding, ["rev-parse", "HEAD^{commit}"], deadline, limit=128).strip().decode("ascii", "ignore") != expected:
        raise _Failure("SNAPSHOT_HEAD_MISMATCH")


def _record(layout: RunLayout, lease: SnapshotCaptureLease, primary: SnapshotError) -> SnapshotError:
    try:
        result = layout.record_first_failure({"schema": "run-failure.v1", "run_id": layout.run_id, "stage": "SNAPSHOT", "reason_code": "SNAPSHOT_FAILED", "run_manifest": None, "created_at": _now(), "terminal": True}, _snapshot_lease=lease)
        recorded, secondary = result.status in {"RECORDED", "ALREADY_RECORDED"}, None
    except RunStoreError as error: recorded, secondary = False, error.code
    except BaseException: recorded, secondary = False, "INTERNAL_FAILURE_RECORD_ERROR"
    return SnapshotError(primary.code, run_id=primary.run_id, published_may_exist=primary.published_may_exist, failure_recorded=recorded, secondary_code=primary.secondary_code or secondary)


def _unexpected(raw: BaseException, run_id: str, published: bool) -> SnapshotError:
    if isinstance(raw, _Failure):
        code = raw.code if raw.code in _ERROR_CODES else "SNAPSHOT_VALIDATION_FAILED"
        return SnapshotError(code, run_id=run_id, published_may_exist=published, secondary_code=raw.secondary)
    category = "INTERNAL_INTERRUPT" if isinstance(raw, (KeyboardInterrupt, SystemExit)) else "INTERNAL_TYPE_ERROR" if isinstance(raw, TypeError) else "INTERNAL_RUNTIME_ERROR"
    return SnapshotError("SNAPSHOT_VALIDATION_FAILED", run_id=run_id, published_may_exist=published, secondary_code=category)


def capture_clean_commit_snapshot(repo_root: str | os.PathLike[str], expected_head_sha: str, layout: RunLayout) -> SnapshotCapture:
    if not isinstance(layout, RunLayout) or not isinstance(expected_head_sha, str) or not _SHA.fullmatch(expected_head_sha):
        raise SnapshotError("SNAPSHOT_ARGUMENT_INVALID", run_id=getattr(layout, "run_id", None))
    try:
        with layout.snapshot_capture_lease() as lease:
            binding: _Binding | None = None; published = False; primary: SnapshotError | None = None
            manifest: Mapping[str, Any] | None = None; ticket = None
            try:
                repo_value = _validate_repo_argument(repo_root)
                deadline = _CLOCK() + _DEFAULT_TIMEOUT; binding = _bootstrap(repo_value, deadline); _verify_git(binding, deadline)
                head = _command(binding, ["rev-parse", "HEAD^{commit}"], deadline, limit=128).strip().decode("ascii", "ignore")
                if head != expected_head_sha: raise _Failure("SNAPSHOT_HEAD_MISMATCH")
                manifest = _validate_capture_manifest(
                    _objects(binding, expected_head_sha, layout.run_id, deadline),
                    layout.run_id,
                    expected_head_sha,
                )
                _clean(binding, expected_head_sha, manifest, deadline)
                ticket = layout.publish_snapshot_manifest(manifest, expected_head_sha=expected_head_sha, lease=lease); published = True
            except RunStoreError as error:
                code = (
                    "SNAPSHOT_ACTIVE_OPERATION" if error.code == "ACTIVE_OPERATION"
                    else "SNAPSHOT_ALREADY_FINALIZED" if error.code in {"FINALIZED", "SNAPSHOT_UNAVAILABLE"}
                    else "SNAPSHOT_PUBLISH_FAILED"
                )
                primary = SnapshotError(code, run_id=layout.run_id, published_may_exist=error.published_may_exist, secondary_code=error.secondary_code)
            except BaseException as error:
                primary = _unexpected(error, layout.run_id, published)
            if binding is not None and (primary is not None or manifest is None or ticket is None):
                close_error = binding.close()
                if close_error is not None:
                    if primary is None:
                        primary = SnapshotError("SNAPSHOT_REPOSITORY_UNSAFE", run_id=layout.run_id, published_may_exist=published, secondary_code=close_error.secondary or close_error.code)
                    elif primary.secondary_code is None:
                        primary.secondary_code = close_error.secondary or close_error.code
                binding = None
            if primary is not None: raise _record(layout, lease, primary)
            if manifest is None or ticket is None:
                raise _record(layout, lease, SnapshotError("SNAPSHOT_PUBLISH_FAILED", run_id=layout.run_id, published_may_exist=published))

            try:
                _remaining(deadline)
                if binding is None:
                    raise _Failure("SNAPSHOT_VALIDATION_FAILED", "FINAL_CHECK_BINDING_MISSING")
                _clean(binding, expected_head_sha, manifest, deadline)
            except BaseException as error:
                primary = _unexpected(error, layout.run_id, True)
            if binding is not None:
                close_error = binding.close(); binding = None
                if close_error is not None:
                    if primary is None:
                        primary = SnapshotError("SNAPSHOT_REPOSITORY_UNSAFE", run_id=layout.run_id, published_may_exist=True, secondary_code=close_error.secondary or close_error.code)
                    elif primary.secondary_code is None:
                        primary.secondary_code = close_error.secondary or close_error.code
            if primary is not None:
                raise _record(layout, lease, primary)
            try:
                publication = layout.linearize_snapshot_success(ticket, lease=lease)
            except RunStoreError as error:
                raise _record(layout, lease, SnapshotError("SNAPSHOT_PUBLISH_FAILED", run_id=layout.run_id, published_may_exist=error.published_may_exist, secondary_code=error.secondary_code))
            except BaseException as error:
                raise _record(layout, lease, _unexpected(error, layout.run_id, True))
            return SnapshotCapture(manifest, publication)
    except RunStoreError as error:
        if error.code == "ACTIVE_OPERATION": raise SnapshotError("SNAPSHOT_ACTIVE_OPERATION", run_id=layout.run_id)
        if error.code in {"FINALIZED", "SNAPSHOT_UNAVAILABLE"}:
            raise SnapshotError("SNAPSHOT_ALREADY_FINALIZED", run_id=layout.run_id, published_may_exist=True)
        raise SnapshotError("SNAPSHOT_PUBLISH_FAILED", run_id=layout.run_id, published_may_exist=error.published_may_exist, secondary_code=error.secondary_code)
    except SnapshotError:
        raise
    except BaseException as error:
        raise _unexpected(error, layout.run_id, False)
