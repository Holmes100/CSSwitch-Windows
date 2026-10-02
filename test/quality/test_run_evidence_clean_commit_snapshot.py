"""Focused RUE-04 tests: exact Git objects, clean checkout, and terminal store."""
from __future__ import annotations

import hashlib
import multiprocessing
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from test.quality.run_evidence.atomic_store import create_run_layout
from test.quality.run_evidence import clean_commit_snapshot as snapshot
from test.quality.run_evidence.clean_commit_snapshot import SnapshotError, capture_clean_commit_snapshot
from test.quality.run_evidence.manifest_contracts import canonical_json_bytes


class CleanCommitSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        # RunLayout deliberately rejects the macOS /var -> /private/var symlink.
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"; self.repo.mkdir(mode=0o700)
        self.state = self.base / "state"; self.state.mkdir(mode=0o700)
        self.evidence = self.base / "evidence"; self.evidence.mkdir(mode=0o700)
        self.git("init", "-q")
        self.git("config", "user.email", "rue04@example.invalid")
        self.git("config", "user.name", "RUE-04")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def git(self, *argv: str) -> bytes:
        return subprocess.run(["/usr/bin/git", *argv], cwd=self.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout

    def committed_repo(self) -> str:
        (self.repo / "plain.txt").write_bytes(b"exact object bytes\n")
        executable = self.repo / "run.sh"; executable.write_bytes(b"#!/bin/sh\necho safe\n"); executable.chmod(0o755)
        os.symlink("missing-target", self.repo / "dangling")
        self.git("add", "."); self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD").decode().strip()

    def test_capture_uses_commit_objects_and_publishes_canonical_manifest(self) -> None:
        head = self.committed_repo()
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            result = capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(result.publication.path, "snapshot/source-snapshot-manifest.json")
            self.assertEqual(result.manifest["head_sha"], head)
            self.assertEqual([entry["path"] for entry in result.manifest["entries"]], ["dangling", "plain.txt", "run.sh"])
            symlink = result.manifest["entries"][0]
            self.assertEqual((symlink["type"], symlink["mode"], symlink["symlink_target"]), ("symlink", "120000", "missing-target"))
            self.assertEqual(symlink["sha256"], hashlib.sha256(b"missing-target").hexdigest())
            raw = (Path(layout.state_path) / result.publication.path).read_bytes()
            self.assertEqual(raw, canonical_json_bytes(result.manifest))
            self.assertEqual(result.publication.sha256, hashlib.sha256(raw).hexdigest())
            with self.assertRaises(SnapshotError) as replay:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual((replay.exception.code, replay.exception.failure_recorded), ("SNAPSHOT_ALREADY_FINALIZED", False))
        finally:
            layout.close()

    def test_dirty_checkout_is_rejected_and_terminal_failure_is_written(self) -> None:
        head = self.committed_repo()
        (self.repo / "plain.txt").write_bytes(b"changed\n")
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with self.assertRaises(SnapshotError) as raised:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(raised.exception.code, "SNAPSHOT_DIRTY")
            self.assertTrue(raised.exception.failure_recorded)
            self.assertTrue((Path(layout.evidence_path) / "run-failure.json").is_file())
        finally:
            layout.close()

    def test_untracked_hidden_flags_and_ignored_boundary(self) -> None:
        head = self.committed_repo()
        layout = create_run_layout(str(self.state), str(self.evidence))
        (self.repo / "foreign.tmp").write_bytes(b"not ignored")
        try:
            with self.assertRaises(SnapshotError) as untracked:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(untracked.exception.code, "SNAPSHOT_DIRTY")
        finally:
            layout.close()
        (self.repo / "foreign.tmp").unlink()
        self.git("update-index", "--assume-unchanged", "plain.txt")
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with self.assertRaises(SnapshotError) as flags:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(flags.exception.code, "SNAPSHOT_INDEX_FLAGS_UNSAFE")
        finally:
            layout.close()
        self.git("update-index", "--no-assume-unchanged", "plain.txt")
        (self.repo / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        self.git("add", ".gitignore"); self.git("commit", "-qm", "ignore fixture")
        (self.repo / "ignored").mkdir(); (self.repo / "ignored" / "build.out").write_bytes(b"cache")
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            result = capture_clean_commit_snapshot(self.repo, self.git("rev-parse", "HEAD").decode().strip(), layout)
            self.assertNotIn("ignored/build.out", {entry["path"] for entry in result.manifest["entries"]})
        finally:
            layout.close()

    def test_untracked_gitignore_cannot_hide_itself_or_payload(self) -> None:
        head = self.committed_repo()
        foreign = self.repo / "foreign"; foreign.mkdir()
        (foreign / ".gitignore").write_text("*\n", encoding="utf-8")
        (foreign / "payload.bin").write_bytes(b"must remain visible to the clean gate")
        # This is the regression counterexample: standard excludes alone
        # report no untracked paths because the untracked ignore hides both.
        self.assertEqual(
            self.git("ls-files", "--others", "--exclude-standard", "-z"),
            b"",
        )
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with self.assertRaises(SnapshotError) as raised:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(raised.exception.code, "SNAPSHOT_DIRTY")
            self.assertTrue(raised.exception.failure_recorded)
            self.assertFalse(raised.exception.published_may_exist)
        finally:
            layout.close()

    def test_nested_tracked_gitignore_allows_ignored_cache(self) -> None:
        self.committed_repo()
        nested = self.repo / "nested"; nested.mkdir()
        (nested / ".gitignore").write_text("cache/\n", encoding="utf-8")
        (nested / "tracked.txt").write_bytes(b"tracked boundary\n")
        self.git("add", "nested/.gitignore", "nested/tracked.txt")
        self.git("commit", "-qm", "tracked nested ignore")
        head = self.git("rev-parse", "HEAD").decode().strip()
        cache = nested / "cache"; cache.mkdir()
        (cache / "handoff.bin").write_bytes(b"legitimately ignored build output")
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            result = capture_clean_commit_snapshot(self.repo, head, layout)
            paths = {entry["path"] for entry in result.manifest["entries"]}
            self.assertIn("nested/.gitignore", paths)
            self.assertIn("nested/tracked.txt", paths)
            self.assertNotIn("nested/cache/handoff.bin", paths)
        finally:
            layout.close()

    def test_untracked_gitignore_symlink_and_fifo_are_rejected(self) -> None:
        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind):
                head = self.committed_repo()
                nested = self.repo / "nested"; nested.mkdir()
                control = nested / ".gitignore"
                if kind == "symlink":
                    os.symlink("../plain.txt", control)
                else:
                    os.mkfifo(control, mode=0o600)
                layout = create_run_layout(str(self.state), str(self.evidence))
                try:
                    with self.assertRaises(SnapshotError) as raised:
                        capture_clean_commit_snapshot(self.repo, head, layout)
                    self.assertEqual(raised.exception.code, "SNAPSHOT_DIRTY")
                finally:
                    layout.close()
                if kind != "fifo":
                    self.tearDown(); self.setUp()

    def test_case_alias_of_untracked_gitignore_is_fail_closed(self) -> None:
        head = self.committed_repo()
        nested = self.repo / "nested"; nested.mkdir()
        (nested / ".GITIGNORE").write_text("*\n", encoding="utf-8")
        (nested / "payload.bin").write_bytes(b"case-insensitive filesystems may read the alias")
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with self.assertRaises(SnapshotError) as raised:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(raised.exception.code, "SNAPSHOT_DIRTY")
        finally:
            layout.close()

    def test_untracked_walk_path_and_count_limits_fail_closed(self) -> None:
        head = self.committed_repo()
        (self.repo / "bad\nname").write_bytes(b"unsafe")
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with self.assertRaises(SnapshotError) as unsafe:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(unsafe.exception.code, "SNAPSHOT_PATH_UNSAFE")
        finally:
            layout.close()
        (self.repo / "bad\nname").unlink()
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with mock.patch.object(snapshot, "_MAX_UNTRACKED_PATHS", 1):
                with self.assertRaises(SnapshotError) as limited:
                    capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(limited.exception.code, "SNAPSHOT_LIMIT_EXCEEDED")
        finally:
            layout.close()

    def test_config_include_core_worktree_exclude_and_alternate_fail_before_capture(self) -> None:
        for section in (
            "[include]\npath = /private/tmp/foreign\n",
            "[core]\nworktree = /private/tmp/foreign\n",
            "# a harmless comment containing [ must not hide the next section\n[core]\nworktree = \"/private/tmp/foreign\" # reject\n",
            "[inclu\\\nde]\npath = \"/private/tmp/foreign;#literal\"\n",
            "[core]\nwork\\\ntree = /private/tmp/foreign\n",
        ):
            with self.subTest(section=section):
                head = self.committed_repo()
                with (self.repo / ".git" / "config").open("a", encoding="utf-8") as output:
                    output.write(section)
                layout = create_run_layout(str(self.state), str(self.evidence))
                try:
                    with self.assertRaises(SnapshotError) as raised:
                        capture_clean_commit_snapshot(self.repo, head, layout)
                    self.assertEqual((raised.exception.code, raised.exception.published_may_exist), ("SNAPSHOT_REPOSITORY_UNSAFE", False))
                finally:
                    layout.close()
                self.tearDown(); self.setUp()
        head = self.committed_repo()
        (self.repo / ".git" / "objects" / "info" / "alternates").write_text("/private/tmp/foreign\n", encoding="utf-8")
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with self.assertRaises(SnapshotError) as raised:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(raised.exception.code, "SNAPSHOT_REPOSITORY_UNSAFE")
        finally:
            layout.close()

    def test_batch_object_mismatch_active_lease_and_postpublish_failure(self) -> None:
        head = self.committed_repo()
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with mock.patch.object(snapshot._Batch, "get", return_value=("commit", b"tree " + b"0" * 40 + b"\n\n")):
                with self.assertRaises(SnapshotError) as malformed:
                    capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(malformed.exception.code, "SNAPSHOT_OBJECT_MISMATCH")
        finally:
            layout.close()

    def test_pending_capture_reports_active_operation(self) -> None:
        head = self.committed_repo(); layout = create_run_layout(str(self.state), str(self.evidence))
        manifest = {"schema": "source-snapshot-manifest.v1", "run_id": layout.run_id, "head_sha": head,
                    "snapshot_mode": "clean-commit", "entry_count": 0, "total_bytes": 0, "entries": []}
        try:
            with layout.snapshot_capture_lease() as lease:
                layout.publish_snapshot_manifest(manifest, expected_head_sha=head, lease=lease)
                with self.assertRaises(SnapshotError) as pending:
                    capture_clean_commit_snapshot(self.repo, head, layout)
                self.assertEqual((pending.exception.code, pending.exception.failure_recorded),
                                 ("SNAPSHOT_ACTIVE_OPERATION", False))
                layout.record_first_failure(
                    {"schema": "run-failure.v1", "run_id": layout.run_id, "stage": "SNAPSHOT",
                     "reason_code": "SNAPSHOT_FAILED", "run_manifest": None,
                     "created_at": "2026-07-24T00:00:00Z", "terminal": True},
                    _snapshot_lease=lease,
                )
        finally:
            layout.close()

    def test_timeout_cleanup_uses_process_group_term_then_kill(self) -> None:
        class Hung:
            pid = 4242
            def __init__(self): self.waits = 0; self.timeouts = []
            def poll(self): return None
            def wait(self, timeout=None):
                self.waits += 1; self.timeouts.append(timeout)
                if self.waits == 1: raise subprocess.TimeoutExpired("git", timeout)
                return 0
        proc = Hung(); sent = []
        with mock.patch.object(snapshot.os, "killpg", side_effect=lambda pid, sig: sent.append((pid, sig))):
            self.assertIsNone(snapshot._terminate(proc))
        self.assertEqual(sent[0], (4242, snapshot.signal.SIGTERM))
        self.assertEqual(sent[-1], (4242, snapshot.signal.SIGKILL))
        self.assertIn((4242, 0), sent)
        self.assertEqual(proc.waits, 2)
        self.assertIsNotNone(proc.timeouts[0])
        self.assertIsNone(proc.timeouts[1])
        class Exhausted:
            pid = 4343
            def __init__(self): self.timeouts = []
            def poll(self): return None
            def wait(self, timeout=None):
                self.timeouts.append(timeout)
                if timeout is not None: raise subprocess.TimeoutExpired("git", timeout)
                return 0
        exhausted = Exhausted()
        with mock.patch.object(snapshot.os, "killpg"):
            self.assertIsNone(snapshot._terminate(exhausted))
        self.assertEqual(len(exhausted.timeouts), 2)
        self.assertIsNone(exhausted.timeouts[-1])
        gone = Exhausted()
        with mock.patch.object(snapshot.os, "killpg", side_effect=ProcessLookupError(snapshot.errno.ESRCH, "gone")):
            self.assertIsNone(snapshot._terminate(gone))
        denied = Exhausted()
        with mock.patch.object(snapshot.os, "killpg", side_effect=PermissionError(snapshot.errno.EPERM, "denied")):
            self.assertEqual(snapshot._terminate(denied), "BATCH_CLEANUP_FAILED")
        self.assertEqual(denied.timeouts, [mock.ANY])
        head = self.committed_repo()
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with layout.snapshot_capture_lease():
                with self.assertRaises(SnapshotError) as active:
                    capture_clean_commit_snapshot(self.repo, head, layout)
                self.assertEqual((active.exception.code, active.exception.failure_recorded), ("SNAPSHOT_ACTIVE_OPERATION", False))
                with self.assertRaises(Exception): layout.close()
        finally:
            layout.close()

    def test_tracked_leaf_fifo_swap_after_lstat_never_blocks(self) -> None:
        head = self.committed_repo(); context = multiprocessing.get_context("fork")
        receive, send = context.Pipe(duplex=False)

        def child() -> None:
            layout = create_run_layout(str(self.state), str(self.evidence))
            real_open = snapshot.os.open; swapped = {"done": False}

            def swap_then_open(path, flags, *args, **kwargs):
                if path == "plain.txt" and not flags & os.O_DIRECTORY and not swapped["done"]:
                    target = self.repo / "plain.txt"
                    target.unlink(); os.mkfifo(target, mode=0o600)
                    swapped["done"] = True
                return real_open(path, flags, *args, **kwargs)

            try:
                with mock.patch.object(snapshot.os, "open", side_effect=swap_then_open):
                    capture_clean_commit_snapshot(self.repo, head, layout)
            except SnapshotError as error:
                send.send((error.code, swapped["done"]))
            except BaseException as error:
                send.send((type(error).__name__, swapped["done"]))
            else:
                send.send(("UNEXPECTED_SUCCESS", swapped["done"]))
            finally:
                try: layout.close()
                except BaseException: pass
                send.close()

        process = context.Process(target=child)
        process.start(); send.close(); timed_out = False
        try:
            process.join(5)
            if process.is_alive():
                timed_out = True
                process.terminate(); process.join(2)
            self.assertFalse(timed_out, "tracked leaf open blocked on lstat-to-FIFO replacement")
            self.assertEqual(process.exitcode, 0)
            self.assertTrue(receive.poll(1))
            self.assertEqual(receive.recv(), ("SNAPSHOT_DIRTY", True))
        finally:
            if process.is_alive():
                process.terminate(); process.join(2)
            receive.close()

    def test_cleanup_kills_term_ignoring_descendant_after_leader_exit(self) -> None:
        context = multiprocessing.get_context("fork")
        receive, send = context.Pipe(duplex=False)
        leader_program = (
            "import os,signal\n"
            "signal.signal(signal.SIGTERM,lambda *_: os._exit(0))\n"
            "child=os.fork()\n"
            "if child==0:\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            " os.write(1,(str(os.getpid())+'\\n').encode())\n"
            " while True: signal.pause()\n"
            "while True: signal.pause()\n"
        )

        def worker() -> None:
            proc = None; child_pid = None
            try:
                proc = subprocess.Popen(
                    [sys.executable, "-c", leader_program],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                send.send(("leader", proc.pid))
                if proc.stdout is None:
                    raise RuntimeError("missing child pid stream")
                child_pid = int(proc.stdout.readline().strip())
                if os.getpgid(child_pid) != proc.pid:
                    raise RuntimeError("descendant escaped fixture process group")
                send.send(("child", child_pid))
                cleanup = snapshot._terminate(proc)
                child_gone = False; deadline = snapshot._CLOCK() + 2.0
                while snapshot._CLOCK() < deadline:
                    try:
                        os.kill(child_pid, 0)
                    except ProcessLookupError:
                        child_gone = True; break
                    snapshot.time.sleep(0.01)
                send.send(("result", cleanup, proc.returncode, child_gone))
            except BaseException as error:
                send.send(("error", type(error).__name__))
            finally:
                if proc is not None and proc.returncode is None:
                    try: os.killpg(proc.pid, snapshot.signal.SIGKILL)
                    except OSError: pass
                    try: proc.wait(timeout=1)
                    except BaseException: pass
                if proc is not None and proc.stdout is not None:
                    try: proc.stdout.close()
                    except BaseException: pass
                if child_pid is not None:
                    try: os.kill(child_pid, snapshot.signal.SIGKILL)
                    except OSError: pass
                send.close()

        process = context.Process(target=worker)
        process.start(); send.close()
        leader_pid = child_pid = None; result = None; timed_out = False
        try:
            if receive.poll(3):
                first = receive.recv()
                if first[0] == "leader": leader_pid = first[1]
            if receive.poll(3):
                second = receive.recv()
                if second[0] == "child": child_pid = second[1]
            process.join(7)
            if process.is_alive():
                timed_out = True
                process.terminate(); process.join(2)
            if receive.poll(1):
                result = receive.recv()
        finally:
            if process.is_alive():
                process.terminate(); process.join(2)
            if timed_out and leader_pid is not None:
                try: os.killpg(leader_pid, snapshot.signal.SIGKILL)
                except OSError: pass
            if timed_out and child_pid is not None:
                try: os.kill(child_pid, snapshot.signal.SIGKILL)
                except OSError: pass
            receive.close()
        self.assertFalse(timed_out, "process-group cleanup exceeded the hard fixture timeout")
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(result, ("result", None, 0, True))

    def test_batch_body_error_cleans_group_before_zero_leader_reap(self) -> None:
        context = multiprocessing.get_context("fork")
        receive, send = context.Pipe(duplex=False)
        leader_program = (
            "import os,signal,sys\n"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "child=os.fork()\n"
            "if child==0:\n"
            " os.write(1,(str(os.getpid())+'\\n').encode())\n"
            " while True: signal.pause()\n"
            "for _ in sys.stdin.buffer: pass\n"
            "os.write(1,b'leader-exit\\n')\n"
            "os._exit(0)\n"
        )

        def worker() -> None:
            proc = None; child_pid = None
            try:
                proc = subprocess.Popen(
                    [sys.executable, "-c", leader_program],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                send.send(("leader", proc.pid))
                if proc.stdout is None:
                    raise RuntimeError("missing child pid stream")
                child_pid = int(proc.stdout.readline().strip())
                if os.getpgid(child_pid) != proc.pid:
                    raise RuntimeError("descendant escaped fixture process group")
                send.send(("child", child_pid))
                if proc.stdin is None:
                    raise RuntimeError("missing leader stdin")
                real_stdin = proc.stdin
                class CloseAfterLeaderExit:
                    @property
                    def closed(self): return real_stdin.closed
                    def close(self):
                        if real_stdin.closed: return
                        real_stdin.close()
                        if proc.stdout.readline() != b"leader-exit\n":
                            raise RuntimeError("leader did not exit from stdin EOF")
                proc.stdin = CloseAfterLeaderExit()
                batch = snapshot._Batch(object(), snapshot._CLOCK() + 10)
                batch.proc = proc
                primary = snapshot._Failure("SNAPSHOT_OBJECT_MISMATCH")
                observed = None
                try:
                    try:
                        raise primary
                    except snapshot._Failure as body:
                        if not batch.__exit__(type(body), body, body.__traceback__):
                            raise
                except snapshot._Failure as error:
                    observed = error
                child_gone = False; deadline = snapshot._CLOCK() + 2.0
                while snapshot._CLOCK() < deadline:
                    try:
                        os.kill(child_pid, 0)
                    except ProcessLookupError:
                        child_gone = True; break
                    snapshot.time.sleep(0.01)
                send.send((
                    "result",
                    None if observed is None else observed.code,
                    None if observed is None else observed.secondary,
                    observed is primary,
                    proc.returncode,
                    child_gone,
                ))
            except BaseException as error:
                send.send(("error", type(error).__name__))
            finally:
                if proc is not None and proc.returncode is None:
                    try: os.killpg(proc.pid, snapshot.signal.SIGKILL)
                    except OSError: pass
                    try: proc.wait(timeout=1)
                    except BaseException: pass
                for stream in (() if proc is None else (proc.stdin, proc.stdout)):
                    if stream is not None and not stream.closed:
                        try: stream.close()
                        except BaseException: pass
                if child_pid is not None:
                    try: os.kill(child_pid, snapshot.signal.SIGKILL)
                    except OSError: pass
                send.close()

        process = context.Process(target=worker)
        process.start(); send.close()
        leader_pid = child_pid = None; result = None; timed_out = False
        try:
            if receive.poll(3):
                first = receive.recv()
                if first[0] == "leader": leader_pid = first[1]
            if receive.poll(3):
                second = receive.recv()
                if second[0] == "child": child_pid = second[1]
            process.join(7)
            if process.is_alive():
                timed_out = True
                process.terminate(); process.join(2)
            if receive.poll(1):
                result = receive.recv()
        finally:
            if process.is_alive():
                process.terminate(); process.join(2)
            if timed_out and leader_pid is not None:
                try: os.killpg(leader_pid, snapshot.signal.SIGKILL)
                except OSError: pass
            if timed_out and child_pid is not None:
                try: os.kill(child_pid, snapshot.signal.SIGKILL)
                except OSError: pass
            receive.close()
        self.assertFalse(timed_out, "batch body-error cleanup exceeded the hard fixture timeout")
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(
            result,
            ("result", "SNAPSHOT_OBJECT_MISMATCH", None, True, 0, True),
        )

    def test_batch_body_primary_survives_stdin_close_failure(self) -> None:
        class BadInput:
            closed = False
            def __init__(self): self.closes = 0
            def close(self):
                self.closes += 1
                raise OSError("close")
        class Output:
            closed = False
            def close(self): self.closed = True
        class Proc:
            pid = 7171; returncode = None
            stdin = BadInput(); stdout = Output()
            def wait(self, timeout=None): raise AssertionError("normal wait path used")
        primary = snapshot._Failure("SNAPSHOT_OBJECT_MISMATCH")
        batch = snapshot._Batch(object(), snapshot._CLOCK() + 10); batch.proc = Proc()
        with mock.patch.object(snapshot, "_terminate", return_value=None) as terminate:
            self.assertFalse(batch.__exit__(snapshot._Failure, primary, None))
        terminate.assert_called_once_with(batch.proc)
        self.assertEqual(primary.code, "SNAPSHOT_OBJECT_MISMATCH")
        self.assertEqual(primary.secondary, "BATCH_CLEANUP_FAILED")
        self.assertEqual(batch.proc.stdin.closes, 2)
        self.assertTrue(batch.proc.stdout.closed)

    def test_malformed_commit_separator_and_immediate_limits_fail_closed(self) -> None:
        head = self.committed_repo()
        for patcher, code in (
            (mock.patch.object(snapshot._Batch, "get", return_value=("commit", b"tree " + b"0" * 40)), "SNAPSHOT_TREE_MALFORMED"),
            (mock.patch.object(snapshot, "_MAX_OBJECTS", 1), "SNAPSHOT_LIMIT_EXCEEDED"),
            (mock.patch.object(snapshot, "_MAX_ENTRIES", 2), "SNAPSHOT_LIMIT_EXCEEDED"),
            (mock.patch.object(snapshot, "_MAX_TOTAL", 1), "SNAPSHOT_LIMIT_EXCEEDED"),
        ):
            layout = create_run_layout(str(self.state), str(self.evidence))
            try:
                with patcher, self.assertRaises(SnapshotError) as raised:
                    capture_clean_commit_snapshot(self.repo, head, layout)
                self.assertEqual(raised.exception.code, code)
            finally:
                layout.close()

    def test_tree_dag_expands_each_logical_path_without_duplicate_requests(self) -> None:
        blob = b"shared"; blob_oid = snapshot._object_id(b"blob", blob)
        child = b"100644 x\0" + bytes.fromhex(blob_oid); child_oid = snapshot._object_id(b"tree", child)
        root = b"40000 a\0" + bytes.fromhex(child_oid) + b"40000 b\0" + bytes.fromhex(child_oid)
        root_oid = snapshot._object_id(b"tree", root)
        commit = b"tree " + root_oid.encode() + b"\n\nmsg\n"; commit_oid = snapshot._object_id(b"commit", commit)
        mapping = {commit_oid: ("commit", commit), root_oid: ("tree", root), child_oid: ("tree", child), blob_oid: ("blob", blob)}
        class FakeBatch:
            def __init__(self, binding, deadline): self.calls = []
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def get(self, oid, **kwargs): self.calls.append(oid); return mapping[oid]
        with mock.patch.object(snapshot, "_Batch", FakeBatch):
            manifest = snapshot._objects(object(), commit_oid, "a" * 32, snapshot._CLOCK() + 10)
        self.assertEqual([entry["path"] for entry in manifest["entries"]], ["a/x", "b/x"])
        self.assertEqual(manifest["total_bytes"], len(blob) * 2)

    def test_deep_binary_dag_hits_logical_expansion_limit(self) -> None:
        mapping = {}; child_raw = b""; child_oid = snapshot._object_id(b"tree", child_raw); mapping[child_oid] = ("tree", child_raw)
        for _ in range(15):
            raw = b"40000 a\0" + bytes.fromhex(child_oid) + b"40000 b\0" + bytes.fromhex(child_oid)
            child_oid = snapshot._object_id(b"tree", raw); mapping[child_oid] = ("tree", raw)
        commit = b"tree " + child_oid.encode() + b"\n\nmsg\n"; commit_oid = snapshot._object_id(b"commit", commit); mapping[commit_oid] = ("commit", commit)
        class FakeBatch:
            def __init__(self, binding, deadline): pass
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def get(self, oid, **kwargs): return mapping[oid]
        with mock.patch.object(snapshot, "_Batch", FakeBatch), self.assertRaises(snapshot._Failure) as raised:
            snapshot._objects(object(), commit_oid, "a" * 32, snapshot._CLOCK() + 10)
        self.assertEqual(raised.exception.code, "SNAPSHOT_LIMIT_EXCEEDED")

    def test_invalid_repo_and_unexpected_runtime_are_stable_typed_boundaries(self) -> None:
        layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with self.assertRaises(SnapshotError) as invalid:
                capture_clean_commit_snapshot(object(), "a" * 40, layout)
            self.assertEqual((invalid.exception.code, invalid.exception.failure_recorded), ("SNAPSHOT_ARGUMENT_INVALID", True))
        finally: layout.close()
        self.tearDown(); self.setUp(); layout = create_run_layout(str(self.state), str(self.evidence))
        class ExplodingPath:
            def __fspath__(self):
                raise RuntimeError("secret path must not leak")
        try:
            with self.assertRaises(SnapshotError) as pathlike:
                capture_clean_commit_snapshot(ExplodingPath(), "a" * 40, layout)
            self.assertEqual((pathlike.exception.code, pathlike.exception.failure_recorded, pathlike.exception.secondary_code),
                             ("SNAPSHOT_VALIDATION_FAILED", True, "INTERNAL_RUNTIME_ERROR"))
            self.assertNotIn("secret", str(pathlike.exception))
        finally: layout.close()
        head = self.committed_repo(); layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with mock.patch.object(snapshot, "_bootstrap", side_effect=RuntimeError("secret path must not leak")), self.assertRaises(SnapshotError) as internal:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual((internal.exception.code, internal.exception.failure_recorded, internal.exception.secondary_code), ("SNAPSHOT_VALIDATION_FAILED", True, "INTERNAL_RUNTIME_ERROR"))
            self.assertNotIn("secret", str(internal.exception))
        finally: layout.close()

    def test_close_many_preserves_primary_and_attempts_every_fd(self) -> None:
        primary = snapshot._Failure("SNAPSHOT_DIRTY"); calls = []
        with mock.patch.object(snapshot.os, "close", side_effect=lambda fd: (calls.append(fd), (_ for _ in ()).throw(OSError("close")))[1]):
            result = snapshot._close_many([11, 12, 13], primary)
        self.assertIs(result, primary); self.assertEqual(primary.code, "SNAPSHOT_DIRTY")
        self.assertEqual(primary.secondary, "CLOSE_FAILED"); self.assertEqual(calls, [11, 12, 13])

    def test_bootstrap_and_verify_obey_expired_deadline(self) -> None:
        self.committed_repo()
        with self.assertRaises(snapshot._Failure) as bootstrap:
            snapshot._bootstrap(self.repo, snapshot._CLOCK() - 1)
        self.assertEqual(bootstrap.exception.code, "SNAPSHOT_TIMEOUT")
        deadline = snapshot._CLOCK() + 10; binding = snapshot._bootstrap(self.repo, deadline)
        try:
            with self.assertRaises(snapshot._Failure) as verify:
                binding.verify(snapshot._CLOCK() - 1)
            self.assertEqual(verify.exception.code, "SNAPSHOT_TIMEOUT")
        finally: binding.close()

    def test_batch_extra_tail_fails_and_head_mismatch_never_requests_object(self) -> None:
        read_fd, write_fd = os.pipe(); os.write(write_fd, b"x"); os.close(write_fd)
        class Input:
            closed = False
            def close(self): self.closed = True
        class Proc:
            pid = 6161; stdin = Input(); stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return 0
            def wait(self, timeout=None): return 0
        batch = snapshot._Batch(object(), snapshot._CLOCK() + 10); batch.proc = Proc()
        with self.assertRaises(snapshot._Failure) as tail:
            batch.__exit__(None, None, None)
        self.assertEqual(tail.exception.code, "SNAPSHOT_OBJECT_MISMATCH")
        head = self.committed_repo(); layout = create_run_layout(str(self.state), str(self.evidence))
        try:
            with mock.patch.object(snapshot, "_objects") as objects, self.assertRaises(SnapshotError) as mismatch:
                capture_clean_commit_snapshot(self.repo, "0" * 40, layout)
            self.assertEqual((mismatch.exception.code, mismatch.exception.failure_recorded), ("SNAPSHOT_HEAD_MISMATCH", True)); objects.assert_not_called()
        finally: layout.close()

    def test_commit_header_limit_rejects_before_body_read(self) -> None:
        oid = "a" * 40
        class Input:
            def fileno(self): return 88
        class Proc:
            stdin = Input()
        batch = snapshot._Batch(object(), snapshot._CLOCK() + 10); batch.proc = Proc()
        with mock.patch.object(snapshot.os, "write", return_value=41), \
             mock.patch.object(batch, "_line", return_value=f"{oid} commit {snapshot._MAX_COMMIT + 1}".encode()), \
             mock.patch.object(batch, "_read") as read:
            with self.assertRaises(snapshot._Failure) as raised:
                batch.get(oid, max_size=snapshot._MAX_COMMIT)
        self.assertEqual(raised.exception.code, "SNAPSHOT_LIMIT_EXCEEDED")
        read.assert_not_called()

    def test_cat_file_size_token_is_canonical_ascii_decimal(self) -> None:
        oid = "a" * 40
        class Input:
            def fileno(self): return 88
        class Proc:
            stdin = Input()
        invalid = (b"+1", b"-0", b"01", b"1_0", b"", b"\xff", b"1" * 21)
        for token in invalid:
            with self.subTest(token=token):
                batch = snapshot._Batch(object(), snapshot._CLOCK() + 10); batch.proc = Proc()
                with mock.patch.object(snapshot.os, "write", return_value=41), \
                     mock.patch.object(batch, "_line", return_value=oid.encode() + b" commit " + token), \
                     mock.patch.object(batch, "_read") as read:
                    with self.assertRaises(snapshot._Failure) as raised:
                        batch.get(oid)
                self.assertEqual(raised.exception.code, "SNAPSHOT_OBJECT_MISMATCH")
                read.assert_not_called()
        empty_oid = snapshot._object_id(b"commit", b"")
        batch = snapshot._Batch(object(), snapshot._CLOCK() + 10); batch.proc = Proc()
        with mock.patch.object(snapshot.os, "write", return_value=41), \
             mock.patch.object(batch, "_line", return_value=f"{empty_oid} commit 0".encode()), \
             mock.patch.object(batch, "_read", side_effect=(b"", b"\n")) as read:
            self.assertEqual(batch.get(empty_oid, max_size=0), ("commit", b""))
        self.assertEqual(read.call_args_list, [mock.call(0), mock.call(1)])
        one_oid = snapshot._object_id(b"commit", b"x")
        batch = snapshot._Batch(object(), snapshot._CLOCK() + 10); batch.proc = Proc()
        with mock.patch.object(snapshot.os, "write", return_value=41), \
             mock.patch.object(batch, "_line", return_value=f"{one_oid} commit 1".encode()), \
             mock.patch.object(batch, "_read", side_effect=(b"x", b"\n")):
            self.assertEqual(batch.get(one_oid, max_size=1), ("commit", b"x"))

    def test_capture_revalidates_mocked_manifest_before_snapshot_store(self) -> None:
        head = self.committed_repo()
        def valid(run_id: str):
            return {"schema": "source-snapshot-manifest.v1", "run_id": run_id, "head_sha": head,
                    "snapshot_mode": "clean-commit", "entry_count": 0, "total_bytes": 0, "entries": []}
        binding_cases = []
        wrong_run = valid("b" * 32)
        wrong_head = valid("a" * 32); wrong_head["head_sha"] = "0" * 40
        wrong_mode = valid("a" * 32); wrong_mode["snapshot_mode"] = "focused-overlay"
        binding_cases.extend((("run_id", wrong_run), ("head", wrong_head), ("mode", wrong_mode)))
        for label, value in binding_cases:
            with self.subTest(case=label):
                layout = create_run_layout(str(self.state), str(self.evidence))
                value["run_id"] = value["run_id"] if label == "run_id" else layout.run_id
                try:
                    with mock.patch.object(snapshot, "_objects", return_value=value), \
                         mock.patch.object(layout, "publish_snapshot_manifest") as publish, \
                         mock.patch.object(snapshot, "_clean") as clean, \
                         self.assertRaises(SnapshotError) as raised:
                        capture_clean_commit_snapshot(self.repo, head, layout)
                    self.assertEqual(raised.exception.code, "SNAPSHOT_BINDING_MISMATCH")
                    self.assertTrue(raised.exception.failure_recorded)
                    self.assertFalse(raised.exception.published_may_exist)
                    publish.assert_not_called(); clean.assert_not_called()
                    self.assertEqual(list((Path(layout.state_path) / "snapshot").iterdir()), [])
                finally:
                    layout.close()

        layout = create_run_layout(str(self.state), str(self.evidence))
        schema_invalid = valid(layout.run_id); schema_invalid["schema"] = "invalid"
        try:
            with mock.patch.object(snapshot, "_objects", return_value=schema_invalid), \
                 mock.patch.object(layout, "publish_snapshot_manifest") as publish, \
                 mock.patch.object(snapshot, "_clean") as clean, \
                 self.assertRaises(SnapshotError) as raised:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(raised.exception.code, "SNAPSHOT_VALIDATION_FAILED")
            self.assertTrue(raised.exception.failure_recorded)
            publish.assert_not_called(); clean.assert_not_called()
        finally:
            layout.close()

        layout = create_run_layout(str(self.state), str(self.evidence)); canonical_invalid = valid(layout.run_id)
        try:
            with mock.patch.object(snapshot, "_objects", return_value=canonical_invalid), \
                 mock.patch.object(snapshot, "canonical_json_bytes", side_effect=ValueError("noncanonical")), \
                 mock.patch.object(layout, "publish_snapshot_manifest") as publish, \
                 mock.patch.object(snapshot, "_clean") as clean, \
                 self.assertRaises(SnapshotError) as raised:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(raised.exception.code, "SNAPSHOT_VALIDATION_FAILED")
            self.assertTrue(raised.exception.failure_recorded)
            publish.assert_not_called(); clean.assert_not_called()
        finally:
            layout.close()

        layout = create_run_layout(str(self.state), str(self.evidence)); oversized = valid(layout.run_id)
        oversized["entries"] = [
            {"path": f"{index:05d}-" + "x" * 190, "type": "file", "mode": "100644",
             "size": 0, "sha256": "0" * 64}
            for index in range(5000)
        ]
        oversized["entry_count"] = len(oversized["entries"])
        self.assertGreater(len(canonical_json_bytes(oversized)), snapshot._MAX_MANIFEST_BYTES)
        try:
            with mock.patch.object(snapshot, "_objects", return_value=oversized), \
                 mock.patch.object(layout, "publish_snapshot_manifest") as publish, \
                 mock.patch.object(snapshot, "_clean") as clean, \
                 self.assertRaises(SnapshotError) as raised:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(raised.exception.code, "SNAPSHOT_LIMIT_EXCEEDED")
            self.assertTrue(raised.exception.failure_recorded)
            self.assertFalse(raised.exception.published_may_exist)
            publish.assert_not_called(); clean.assert_not_called()
            self.assertEqual(list((Path(layout.state_path) / "snapshot").iterdir()), [])
        finally:
            layout.close()

    def test_skip_worktree_and_index_stage_mode_conflicts_are_dirty(self) -> None:
        mutations = []
        mutations.append(lambda: self.git("update-index", "--skip-worktree", "plain.txt"))
        mutations.append(lambda: ((self.repo / "added.txt").write_bytes(b"added"), self.git("add", "added.txt")))
        mutations.append(lambda: self.git("rm", "--cached", "-q", "plain.txt"))
        mutations.append(lambda: ((self.repo / "plain.txt").chmod(0o755), self.git("add", "plain.txt")))
        def unmerged():
            oid = self.git("hash-object", "plain.txt").decode().strip(); self.git("rm", "--cached", "-q", "plain.txt")
            raw = f"100644 {oid} 1\tplain.txt\n100644 {oid} 2\tplain.txt\n".encode()
            subprocess.run(["/usr/bin/git", "update-index", "--index-info"], cwd=self.repo, input=raw, check=True)
        mutations.append(unmerged)
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                head = self.committed_repo(); mutate(); layout = create_run_layout(str(self.state), str(self.evidence))
                try:
                    with self.assertRaises(SnapshotError) as raised:
                        capture_clean_commit_snapshot(self.repo, head, layout)
                    self.assertIn(raised.exception.code, {"SNAPSHOT_DIRTY", "SNAPSHOT_INDEX_FLAGS_UNSAFE"})
                    self.assertTrue(raised.exception.failure_recorded); self.assertFalse(raised.exception.published_may_exist)
                finally: layout.close()
                if index != len(mutations) - 1: self.tearDown(); self.setUp()

    def test_terminal_writer_wins_before_finalization(self) -> None:
        head = self.committed_repo(); layout = create_run_layout(str(self.state), str(self.evidence)); real = type(layout).linearize_snapshot_success
        def race(owner, ticket, *, lease):
            owner.record_first_failure({"schema": "run-failure.v1", "run_id": owner.run_id, "stage": "SNAPSHOT", "reason_code": "SNAPSHOT_FAILED", "run_manifest": None, "created_at": "2026-07-24T00:00:00Z", "terminal": True}, _snapshot_lease=lease)
            return real(owner, ticket, lease=lease)
        try:
            with mock.patch.object(type(layout), "linearize_snapshot_success", race), self.assertRaises(SnapshotError) as raised:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual((raised.exception.code, raised.exception.published_may_exist, raised.exception.failure_recorded), ("SNAPSHOT_PUBLISH_FAILED", True, True))
        finally: layout.close()

    def test_binding_detects_index_exclude_and_objects_public_name_drift(self) -> None:
        self.committed_repo(); deadline = snapshot._CLOCK() + 10; binding = snapshot._bootstrap(self.repo, deadline)
        try:
            index = self.repo / ".git" / "index"; raw = index.read_bytes(); index.write_bytes(raw + b"drift")
            with self.assertRaises(snapshot._Failure): binding.verify(deadline)
        finally:
            binding.close()
        self.tearDown(); self.setUp(); self.committed_repo(); deadline = snapshot._CLOCK() + 10; binding = snapshot._bootstrap(self.repo, deadline)
        try:
            exclude = self.repo / ".git" / "info" / "exclude"; exclude.write_bytes(exclude.read_bytes() + b"\n*.drift\n")
            with self.assertRaises(snapshot._Failure): binding.verify(deadline)
        finally:
            binding.close()
        self.tearDown(); self.setUp(); self.committed_repo(); deadline = snapshot._CLOCK() + 10; binding = snapshot._bootstrap(self.repo, deadline)
        try:
            objects = self.repo / ".git" / "objects"; detached = self.base / "objects-detached"
            os.rename(objects, detached); objects.mkdir()
            with self.assertRaises(snapshot._Failure): binding.verify(deadline)
        finally:
            binding.close()

    def test_binding_cleanup_precedes_linearization_and_no_cleanup_follows_success(self) -> None:
        head = self.committed_repo(); layout = create_run_layout(str(self.state), str(self.evidence)); order = []
        real_close = snapshot._Binding.close; real_linearize = type(layout).linearize_snapshot_success
        def observed_close(binding, primary=None):
            order.append("close")
            return real_close(binding, primary)
        def observed_linearize(owner, ticket, *, lease):
            order.append("linearize")
            return real_linearize(owner, ticket, lease=lease)
        try:
            with mock.patch.object(snapshot._Binding, "close", observed_close), mock.patch.object(type(layout), "linearize_snapshot_success", observed_linearize):
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual(order, ["close", "linearize"])
        finally:
            layout.close()

    def test_final_clean_rejects_midscan_early_leaf_and_head_drift(self) -> None:
        for drift in ("early-leaf", "head"):
            with self.subTest(drift=drift):
                head = self.committed_repo()
                tree = self.git("rev-parse", f"{head}^{{tree}}").decode().strip()
                other = subprocess.run(
                    ["/usr/bin/git", "commit-tree", tree, "-p", head], cwd=self.repo,
                    input=b"midscan head\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                ).stdout.decode().strip()
                head_ref = self.git("symbolic-ref", "HEAD").decode().strip()
                layout = create_run_layout(str(self.state), str(self.evidence))
                real_tracked = snapshot._tracked_bytes; calls = {"count": 0}
                def tracked_then_drift(*args, **kwargs):
                    result = real_tracked(*args, **kwargs); calls["count"] += 1
                    # Three tracked entries are scanned in each _clean.  Drift
                    # the early plain.txt only after the final scan read it.
                    if calls["count"] == 6:
                        if drift == "early-leaf":
                            (self.repo / "plain.txt").write_bytes(b"changed after early final read\n")
                        else:
                            (self.repo / ".git" / head_ref).write_text(other + "\n", encoding="ascii")
                    return result
                try:
                    with mock.patch.object(snapshot, "_tracked_bytes", side_effect=tracked_then_drift):
                        with self.assertRaises(SnapshotError) as raised:
                            capture_clean_commit_snapshot(self.repo, head, layout)
                    self.assertEqual(raised.exception.code, "SNAPSHOT_DIRTY" if drift == "early-leaf" else "SNAPSHOT_HEAD_MISMATCH")
                    self.assertTrue(raised.exception.published_may_exist)
                    self.assertTrue(raised.exception.failure_recorded)
                finally:
                    layout.close()
                    if drift == "early-leaf":
                        self.tearDown(); self.setUp()

    def test_final_clean_revalidates_ignored_only_directory_set(self) -> None:
        self.committed_repo()
        (self.repo / ".gitignore").write_text("ignored-only/\n", encoding="utf-8")
        self.git("add", ".gitignore"); self.git("commit", "-qm", "ignore isolated output")
        head = self.git("rev-parse", "HEAD").decode().strip()
        nested = self.repo / "ignored-only" / "nested"
        nested.mkdir(parents=True)
        layout = create_run_layout(str(self.state), str(self.evidence))
        real_audit = snapshot._audit_untracked_without_excludes
        real_tracked = snapshot._tracked_bytes
        state = {"audits": 0, "final_audited": False, "mutated": False}

        def audit_then_arm(*args, **kwargs):
            result = real_audit(*args, **kwargs)
            state["audits"] += 1
            if state["audits"] == 2:
                state["final_audited"] = True
            return result

        def tracked_then_mutate(*args, **kwargs):
            result = real_tracked(*args, **kwargs)
            if state["final_audited"] and not state["mutated"]:
                (nested / ".gitignore").write_text("*\n", encoding="utf-8")
                (nested / "payload.bin").write_bytes(b"appeared during final tracked scan")
                state["mutated"] = True
            return result

        try:
            with mock.patch.object(snapshot, "_audit_untracked_without_excludes", side_effect=audit_then_arm), \
                 mock.patch.object(snapshot, "_tracked_bytes", side_effect=tracked_then_mutate), \
                 self.assertRaises(SnapshotError) as raised:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertTrue(state["mutated"])
            self.assertEqual(raised.exception.code, "SNAPSHOT_DIRTY")
            self.assertTrue(raised.exception.published_may_exist)
            self.assertTrue(raised.exception.failure_recorded)
        finally:
            layout.close()

    def test_git_metadata_special_files_are_rejected_without_blocking(self) -> None:
        cases = (
            ".git/config",
            ".git/index",
            ".git/info/exclude",
            ".git/objects/info/alternates",
        )
        for index, relative in enumerate(cases):
            with self.subTest(path=relative):
                head = self.committed_repo(); target = self.repo / relative
                if target.exists() or target.is_symlink():
                    target.unlink()
                os.mkfifo(target, mode=0o600)
                layout = create_run_layout(str(self.state), str(self.evidence))
                try:
                    with self.assertRaises(SnapshotError) as raised:
                        capture_clean_commit_snapshot(self.repo, head, layout)
                    self.assertEqual(raised.exception.code, "SNAPSHOT_REPOSITORY_UNSAFE")
                    self.assertTrue(raised.exception.failure_recorded)
                finally:
                    layout.close()
                    if index != len(cases) - 1:
                        self.tearDown(); self.setUp()

    def test_existing_failure_fifo_capture_fails_within_process_deadline(self) -> None:
        head = self.committed_repo(); context = multiprocessing.get_context("fork")
        receive, send = context.Pipe(duplex=False)
        def child() -> None:
            layout = create_run_layout(str(self.state), str(self.evidence))
            os.mkfifo(Path(layout.evidence_path) / "run-failure.json", mode=0o600)
            try:
                capture_clean_commit_snapshot(self.repo, head, layout)
            except SnapshotError as error:
                send.send((error.code, error.failure_recorded, error.secondary_code))
            except BaseException as error:
                send.send((type(error).__name__, False, None))
            else:
                send.send(("UNEXPECTED_SUCCESS", False, None))
            finally:
                try: layout.close()
                except BaseException: pass
                send.close()
        process = context.Process(target=child)
        process.start(); send.close(); process.join(5)
        if process.is_alive():
            process.terminate(); process.join(2)
            self.fail("capture blocked on existing run-failure FIFO")
        self.assertEqual(process.exitcode, 0)
        self.assertTrue(receive.poll(1))
        code, recorded, secondary = receive.recv(); receive.close()
        self.assertEqual((code, recorded), ("SNAPSHOT_PUBLISH_FAILED", False))
        self.assertEqual(secondary, "FAILURE_EXISTING_UNSAFE")

    def test_split_index_is_rejected_before_and_after_backing_drift(self) -> None:
        head = self.committed_repo(); self.git("update-index", "--split-index")
        shared = sorted((self.repo / ".git").glob("sharedindex.*"))
        self.assertEqual(len(shared), 1)
        for drift in (False, True):
            with self.subTest(backing_drift=drift):
                if drift:
                    raw = shared[0].read_bytes()
                    shared[0].write_bytes(raw[:-1] + bytes((raw[-1] ^ 0xFF,)))
                layout = create_run_layout(str(self.state), str(self.evidence))
                try:
                    with self.assertRaises(SnapshotError) as raised:
                        capture_clean_commit_snapshot(self.repo, head, layout)
                    self.assertEqual(raised.exception.code, "SNAPSHOT_REPOSITORY_UNSAFE")
                    self.assertTrue(raised.exception.failure_recorded)
                    self.assertFalse(raised.exception.published_may_exist)
                    self.assertFalse((Path(layout.state_path) / "snapshot" / "source-snapshot-manifest.json").exists())
                finally:
                    layout.close()

    def test_final_reap_failure_is_secondary_and_does_not_replace_primary(self) -> None:
        class BadReap:
            pid = 5151
            def poll(self): return None
            def wait(self, timeout=None):
                if timeout is not None: raise subprocess.TimeoutExpired("git", timeout)
                raise OSError("reap")
        with mock.patch.object(snapshot.os, "killpg"):
            self.assertEqual(snapshot._terminate(BadReap()), "PROCESS_REAP_FAILED")
        head = self.committed_repo()
        layout = create_run_layout(str(self.state), str(self.evidence))
        real_clean = snapshot._clean; calls = {"count": 0}
        def fail_after_publish(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] == 2: raise snapshot._Failure("SNAPSHOT_DIRTY")
            return real_clean(*args, **kwargs)
        try:
            with mock.patch.object(snapshot, "_clean", side_effect=fail_after_publish):
                with self.assertRaises(SnapshotError) as published:
                    capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual((published.exception.code, published.exception.published_may_exist, published.exception.failure_recorded), ("SNAPSHOT_DIRTY", True, True))
            with self.assertRaises(SnapshotError) as replay:
                capture_clean_commit_snapshot(self.repo, head, layout)
            self.assertEqual((replay.exception.code, replay.exception.failure_recorded),
                             ("SNAPSHOT_ALREADY_FINALIZED", False))
        finally:
            layout.close()

    def test_final_linearization_check_rejects_head_and_early_file_drift(self) -> None:
        for drift in ("head", "file"):
            with self.subTest(drift=drift):
                head = self.committed_repo()
                tree = self.git("rev-parse", f"{head}^{{tree}}").decode().strip()
                other = subprocess.run(
                    ["/usr/bin/git", "commit-tree", tree, "-p", head],
                    cwd=self.repo, input=b"alternate head\n", stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=True,
                ).stdout.decode().strip()
                head_ref = self.git("symbolic-ref", "HEAD").decode().strip()
                layout = create_run_layout(str(self.state), str(self.evidence))
                real_publish = type(layout).publish_snapshot_manifest
                def publish_then_drift(owner, manifest, *, expected_head_sha, lease):
                    ticket = real_publish(owner, manifest, expected_head_sha=expected_head_sha, lease=lease)
                    if drift == "head":
                        (self.repo / ".git" / head_ref).write_text(other + "\n", encoding="ascii")
                    else:
                        (self.repo / "plain.txt").write_bytes(b"drift after pre-publication clean check\n")
                    return ticket
                try:
                    with mock.patch.object(type(layout), "publish_snapshot_manifest", publish_then_drift):
                        with self.assertRaises(SnapshotError) as raised:
                            capture_clean_commit_snapshot(self.repo, head, layout)
                    self.assertEqual(raised.exception.code, "SNAPSHOT_HEAD_MISMATCH" if drift == "head" else "SNAPSHOT_DIRTY")
                    self.assertTrue(raised.exception.published_may_exist)
                    self.assertTrue(raised.exception.failure_recorded)
                    self.assertEqual(layout._snapshot_state, "TERMINAL")
                finally:
                    layout.close()
                    if drift == "head":
                        self.tearDown(); self.setUp()

    def test_command_nonzero_exit_preserves_primary_when_stdout_close_fails(self) -> None:
        class Binding:
            def verify(self, deadline): return None
            def base(self): return ["/usr/bin/git"]
        class Stream:
            closed = False
            def fileno(self): return 91
            def close(self): raise OSError("close secret")
        class Proc:
            pid = 9191
            stdout = Stream()
            def poll(self): return 7
            def wait(self, timeout=None): return 7
        with mock.patch.object(snapshot.subprocess, "Popen", return_value=Proc()), \
             mock.patch.object(snapshot.select, "select", return_value=([91], [], [])), \
             mock.patch.object(snapshot.os, "read", return_value=b""):
            with self.assertRaises(snapshot._Failure) as raised:
                snapshot._command(Binding(), ["status"], snapshot._CLOCK() + 10)
        self.assertEqual(raised.exception.code, "SNAPSHOT_GIT_FAILED")
        self.assertEqual(raised.exception.secondary, "BATCH_CLEANUP_FAILED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
