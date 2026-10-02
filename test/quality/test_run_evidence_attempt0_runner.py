"""Focused RUE-05A adversarial tests; all process state is temporary."""
from __future__ import annotations

import hashlib
import contextlib
import errno
import json
import os
import signal
import shutil
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import test.quality.run_evidence.atomic_store as store
from test.quality.run_evidence.atomic_store import RunStoreError, create_run_layout
import test.quality.run_evidence.attempt0_runner as runner
from test.quality.run_evidence.attempt0_runner import _run_attempt0, run_attempt0
from test.quality.run_evidence.manifest_contracts import canonical_json_bytes


class Attempt0RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir()))
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"; self.state = self.base / "state"; self.evidence = self.base / "evidence"
        self.state.mkdir(mode=0o700); self.evidence.mkdir(mode=0o700)
        self.fixture = self.repo / "test/quality/fixtures/run_evidence/attempt0_fixture.py"
        self.fixture.parent.mkdir(parents=True)
        source = Path(__file__).parent / "fixtures/run_evidence/attempt0_fixture.py"
        shutil.copyfile(source, self.fixture)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _layout(self):
        layout = create_run_layout(str(self.state), str(self.evidence))
        self.addCleanup(lambda: self._close(layout))
        raw = self.fixture.read_bytes()
        manifest = {
            "schema": "source-snapshot-manifest.v1", "run_id": layout.run_id, "head_sha": "a" * 40,
            "snapshot_mode": "clean-commit", "entry_count": 1, "total_bytes": len(raw),
            "entries": [{"path": "test/quality/fixtures/run_evidence/attempt0_fixture.py", "type": "file", "mode": "100644", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}],
        }
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(manifest, expected_head_sha="a" * 40, lease=lease)
            layout.linearize_snapshot_success(ticket, lease=lease)
        return layout

    @staticmethod
    def _close(layout) -> None:
        try: layout.close()
        except RunStoreError: pass

    def test_01_happy_path_is_fixed_public_runner_and_private_record(self):
        layout = self._layout()
        decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual((decision.disposition, decision.reason_code, decision.attempt_record.process_exit), ("PASS", "NONE", 0))
        self.assertTrue((Path(layout.state_path) / "attempts/attempt-0.json").is_file())

    def test_02_stdout_marker_and_nonzero_rc_cannot_green(self):
        layout = self._layout()
        decision = _run_attempt0(repo_root=str(self.repo), layout=layout, scenario="fake-marker")
        self.assertEqual((decision.disposition, decision.reason_code, decision.attempt_record.process_exit), ("INFRA", "EXIT_STATUS_MISMATCH", 7))

    def test_03_missing_malformed_extra_timeout_and_output_limit_are_fail_closed(self):
        cases = {
            "missing": ("INFRA", "ADAPTER_MISSING"), "malformed": ("INFRA", "ADAPTER_MALFORMED"),
            "oversize": ("INFRA", "ADAPTER_MALFORMED"), "extra": ("INFRA", "ADAPTER_MALFORMED"),
            "partial-header": ("INFRA", "ADAPTER_MALFORMED"), "partial-payload": ("INFRA", "ADAPTER_MALFORMED"),
            "late": ("INFRA", "ADAPTER_LATE"), "timeout": ("HARD_TIMEOUT", "PROCESS_TIMEOUT"),
            "output-limit": ("INFRA", "OUTPUT_LIMIT"),
        }
        for scenario, expected in cases.items():
            with self.subTest(scenario=scenario):
                layout = self._layout()
                decision = _run_attempt0(repo_root=str(self.repo), layout=layout, scenario=scenario)
                self.assertEqual((decision.disposition, decision.reason_code), expected)
                self.assertIsNotNone(decision.attempt_record.process_exit)

    def test_04_source_replacement_before_copy_is_not_executed(self):
        layout = self._layout()
        self.fixture.write_text("raise SystemExit(0)\n")
        decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual((decision.disposition, decision.reason_code), ("INFRA", "TOOL_IDENTITY_CHANGED"))

        for replacement_mode in (0o600, 0o755):
            with self.subTest(replacement_mode=oct(replacement_mode)):
                os.chmod(self.fixture, 0o644)
                layout = self._layout()
                os.chmod(self.fixture, replacement_mode)
                decision = run_attempt0(repo_root=str(self.repo), layout=layout)
                self.assertEqual(
                    (decision.disposition, decision.reason_code),
                    ("INFRA", "TOOL_IDENTITY_CHANGED"),
                )

    def test_05_started_claim_and_publication_replay_cannot_green(self):
        layout = self._layout()
        run_attempt0(repo_root=str(self.repo), layout=layout)
        with self.assertRaises(RunStoreError) as started:
            run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual(started.exception.code, "ATTEMPT_DUPLICATE")

    def test_06_cache_name_replacement_after_held_fd_cannot_change_execution(self):
        layout = self._layout()
        real_move = runner._moved_child_fd
        swapped = {"done": False}

        def replace_cache(fd):
            if not swapped["done"]:
                swapped["done"] = True
                replacement = Path(layout.state_path) / "cache/replacement"
                replacement.write_text("raise SystemExit(99)\n")
                os.replace(replacement, Path(layout.state_path) / "cache/attempt0-fixture.py")
            return real_move(fd)

        with mock.patch.object(runner, "_moved_child_fd", side_effect=replace_cache):
            decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual((decision.disposition, decision.reason_code, decision.attempt_record.process_exit), ("PASS", "NONE", 0))

    def test_07_note_exit_cutoff_is_independent_of_delayed_reaper(self):
        layout = self._layout()
        real_wait = runner._wait_once
        calls = []

        def delayed(pid, slot, done):
            time.sleep(0.20)
            calls.append(pid)
            real_wait(pid, slot, done)

        with mock.patch.object(runner, "_wait_once", side_effect=delayed):
            decision = _run_attempt0(repo_root=str(self.repo), layout=layout, scenario="late")
        self.assertEqual((decision.disposition, decision.reason_code), ("INFRA", "ADAPTER_LATE"))
        self.assertEqual(len(calls), 1)

    def test_08_ack_short_writes_complete_and_zero_write_fails_without_publication(self):
        layout = self._layout()
        writes = []

        def one_byte(peer, remaining):
            writes.append(len(remaining))
            return peer.send(remaining[:1])

        with mock.patch.object(runner, "_send_ack", side_effect=one_byte):
            decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual((decision.disposition, decision.reason_code), ("PASS", "NONE"))
        self.assertGreaterEqual(len(writes), 4)

        layout = self._layout()
        with mock.patch.object(runner, "_send_ack", return_value=0):
            with self.assertRaises(runner.Attempt0RunnerError) as raised:
                run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual(raised.exception.code, "ACK_FAILED")
        self.assertFalse((Path(layout.state_path) / "attempts/attempt-0.json").exists())

    def test_09_descendant_holding_fds_is_killed_and_drained_before_pass(self):
        layout = self._layout()
        started = time.monotonic()
        decision = _run_attempt0(repo_root=str(self.repo), layout=layout, scenario="hold-after-frame")
        elapsed = time.monotonic() - started
        self.assertEqual((decision.disposition, decision.reason_code), ("PASS", "NONE"))
        self.assertGreaterEqual(elapsed, 0.05)
        self.assertLess(elapsed, 1.0)

        layout = self._layout()
        with self.assertRaises(runner.Attempt0RunnerError) as incomplete:
            _run_attempt0(repo_root=str(self.repo), layout=layout, scenario="terminal-drain-incomplete")
        self.assertEqual(incomplete.exception.code, "TERMINAL_DRAIN_INCOMPLETE")
        self.assertFalse((Path(layout.state_path) / "attempts/attempt-0.json").exists())
        time.sleep(0.25)  # The deliberately escaped test descendant exits at 0.45s.

        layout = self._layout(); pids = []; real_spawn = runner.os.posix_spawn
        def capture_spawn(*args, **kwargs):
            pid = real_spawn(*args, **kwargs); pids.append(pid); return pid
        with mock.patch.object(runner.os, "posix_spawn", side_effect=capture_spawn):
            decision = _run_attempt0(repo_root=str(self.repo), layout=layout, scenario="closed-fd-descendant")
        self.assertEqual((decision.disposition, decision.reason_code), ("PASS", "NONE"))
        with self.assertRaises(ProcessLookupError):
            os.killpg(pids[0], 0)

    def test_10_waitpid_once_reaps_child_and_fixed_fd_actions_do_not_close_destinations(self):
        layout = self._layout()
        real_spawn, real_waitpid = runner.os.posix_spawn, runner.os.waitpid
        pids, waits = [], []

        def capture_spawn(*args, **kwargs):
            pid = real_spawn(*args, **kwargs); pids.append(pid); return pid

        def capture_wait(pid, options):
            waits.append((pid, options)); return real_waitpid(pid, options)

        with mock.patch.object(runner.os, "posix_spawn", side_effect=capture_spawn), \
             mock.patch.object(runner.os, "waitpid", side_effect=capture_wait):
            self.assertEqual(run_attempt0(repo_root=str(self.repo), layout=layout).disposition, "PASS")
        self.assertEqual(waits, [(pids[0], 0)])
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)
        actions = runner._spawn_actions(198, 199, 198, 200, 201, 202)
        closed = {action[1] for action in actions if action[0] == os.POSIX_SPAWN_CLOSE}
        self.assertNotIn(198, closed); self.assertNotIn(199, closed)
        self.assertIn((os.POSIX_SPAWN_DUP2, 200, 198), actions)
        self.assertIn((os.POSIX_SPAWN_DUP2, 201, 199), actions)

    def test_11_spawn_and_event_loop_failures_close_fds_and_reap(self):
        layout = self._layout(); before = len(os.listdir("/dev/fd"))
        with mock.patch.object(runner.os, "pipe", side_effect=OSError("pipe")):
            decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual((decision.disposition, decision.reason_code), ("INFRA", "EXEC_FAILED"))
        self.assertLessEqual(len(os.listdir("/dev/fd")), before)

        layout = self._layout(); before = len(os.listdir("/dev/fd"))
        with mock.patch.object(runner.os, "posix_spawn", side_effect=OSError("spawn")):
            decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual((decision.disposition, decision.reason_code), ("INFRA", "EXEC_FAILED"))
        self.assertLessEqual(len(os.listdir("/dev/fd")), before)

        layout = self._layout(); before = len(os.listdir("/dev/fd")); pids = []
        real_spawn = runner.os.posix_spawn
        def capture_spawn(*args, **kwargs):
            pid = real_spawn(*args, **kwargs); pids.append(pid); return pid
        with mock.patch.object(runner.os, "posix_spawn", side_effect=capture_spawn), \
             mock.patch.object(runner, "_send_ack", side_effect=RuntimeError("unexpected")):
            with self.assertRaisesRegex(RuntimeError, "unexpected"):
                run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertLessEqual(len(os.listdir("/dev/fd")), before)
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)

        layout = self._layout(); before = len(os.listdir("/dev/fd")); real_read = runner._read_exact; calls = []
        def fail_verify(fd, size):
            calls.append(fd)
            if len(calls) == 2:
                raise runner.Attempt0RunnerError("FD_DRIFT")
            return real_read(fd, size)
        with mock.patch.object(runner, "_read_exact", side_effect=fail_verify):
            with self.assertRaises(runner.Attempt0RunnerError):
                run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertLessEqual(len(os.listdir("/dev/fd")), before)

    def test_12_uncertain_publication_raises_instead_of_returning_decision(self):
        layout = self._layout()
        uncertain = RunStoreError("PUBLISH_VERIFY_FAILED", published_may_exist=True)
        with mock.patch.object(store, "_publish", side_effect=uncertain):
            with self.assertRaises(RunStoreError) as raised:
                run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertTrue(raised.exception.published_may_exist)

    def test_13_pre_reaper_failures_use_one_synchronous_wait_and_close_fds(self):
        real_spawn, real_waitpid = runner.os.posix_spawn, runner.os.waitpid
        real_monotonic = runner.time.monotonic
        clock_calls = []

        def fail_first_clock():
            clock_calls.append(True)
            if len(clock_calls) == 1:
                raise OSError("post-spawn clock")
            return real_monotonic()

        class RegisterFailure:
            def __init__(self): self.inner = runner.select.kqueue()
            def control(self, *args, **kwargs): raise OSError("register")
            def close(self): self.inner.close()

        cases = (
            ("create", True, lambda stack: stack.enter_context(mock.patch.object(runner.select, "kqueue", side_effect=OSError("create")))),
            ("register", False, lambda stack: stack.enter_context(mock.patch.object(runner.select, "kqueue", return_value=RegisterFailure()))),
            ("thread-start", False, lambda stack: stack.enter_context(mock.patch.object(runner.threading.Thread, "start", side_effect=RuntimeError("start")))),
            ("post-spawn-clock", False, lambda stack: stack.enter_context(mock.patch.object(runner.time, "monotonic", side_effect=fail_first_clock))),
        )
        for label, inject_eintr, install in cases:
            with self.subTest(label=label):
                clock_calls.clear()
                layout = self._layout(); before = len(os.listdir("/dev/fd")); pids, attempts, successes = [], [], []
                def capture_spawn(*args, **kwargs):
                    pid = real_spawn(*args, **kwargs); pids.append(pid); return pid
                def capture_wait(pid, options):
                    attempts.append((pid, options))
                    if inject_eintr and len(attempts) == 1:
                        raise InterruptedError()
                    value = real_waitpid(pid, options)
                    successes.append(value)
                    return value
                # Use a local ExitStack so each failure injection ends before
                # the next subtest and cannot affect fixture setup.
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.object(runner.os, "posix_spawn", side_effect=capture_spawn))
                    stack.enter_context(mock.patch.object(runner.os, "waitpid", side_effect=capture_wait))
                    install(stack)
                    with self.assertRaises((OSError, RuntimeError)):
                        run_attempt0(repo_root=str(self.repo), layout=layout)
                self.assertEqual(attempts, [(pids[0], 0)] * (2 if inject_eintr else 1))
                self.assertEqual(len(successes), 1)
                self.assertLessEqual(len(os.listdir("/dev/fd")), before)
                with self.assertRaises(ProcessLookupError):
                    os.kill(pids[0], 0)

    def test_14_reaper_retries_eintr_and_started_reaper_cleanup_waits_for_completion(self):
        layout = self._layout()
        real_waitpid = runner.os.waitpid
        calls, successes = [], []

        def interrupted_once(pid, options):
            calls.append((pid, options))
            if len(calls) == 1:
                raise InterruptedError()
            value = real_waitpid(pid, options)
            successes.append(value)
            return value

        with mock.patch.object(runner.os, "waitpid", side_effect=interrupted_once):
            decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual(decision.disposition, "PASS")
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(successes), 1)

        layout = self._layout(); pids, waits = [], []
        real_spawn, real_waitpid, real_reaper = runner.os.posix_spawn, runner.os.waitpid, runner._wait_once
        def capture_spawn(*args, **kwargs):
            pid = real_spawn(*args, **kwargs); pids.append(pid); return pid
        def capture_wait(pid, options):
            value = real_waitpid(pid, options); waits.append(value); return value
        def delayed_reaper(pid, slot, done):
            time.sleep(1.20)
            real_reaper(pid, slot, done)
        started = time.monotonic()
        with mock.patch.object(runner.os, "posix_spawn", side_effect=capture_spawn), \
             mock.patch.object(runner.os, "waitpid", side_effect=capture_wait), \
             mock.patch.object(runner, "_wait_once", side_effect=delayed_reaper), \
             mock.patch.object(runner, "_send_ack", side_effect=RuntimeError("event-loop")):
            with self.assertRaisesRegex(RuntimeError, "event-loop"):
                run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertGreaterEqual(time.monotonic() - started, 1.15)
        self.assertEqual(len(waits), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)

    def test_15_unversioned_cwd_sitecustomize_cannot_preload_before_fixture(self):
        layout = self._layout()
        unversioned_cwd = self.base / "unversioned-cwd"
        unversioned_cwd.mkdir()
        sentinel = unversioned_cwd / "sitecustomize-loaded"
        (unversioned_cwd / "sitecustomize.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(sentinel)!r}).write_text('loaded')\n"
        )
        real_spawn = runner.os.posix_spawn
        spawned_argv = []

        def capture_spawn(path, argv, *args, **kwargs):
            spawned_argv.append(list(argv))
            return real_spawn(path, argv, *args, **kwargs)

        previous_cwd = os.getcwd()
        try:
            os.chdir(unversioned_cwd)
            with mock.patch.object(runner.os, "posix_spawn", side_effect=capture_spawn):
                decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        finally:
            os.chdir(previous_cwd)
        self.assertEqual(
            (decision.disposition, decision.reason_code, decision.attempt_record.process_exit),
            ("PASS", "NONE", 0),
        )
        self.assertEqual(spawned_argv[0][1:3], ["-I", "-S"])
        self.assertFalse(sentinel.exists())

    def test_16_cache_replacement_is_rejected_before_untrusted_size_read(self):
        for replacement_size in (
            len(self.fixture.read_bytes()),
            2 * 1024 * 1024,
        ):
            with self.subTest(replacement_size=replacement_size):
                layout = self._layout()
                manifest = layout.begin_attempt0()
                digest, expected_size, expected_mode = (
                    runner._snapshot_fixture_digest(manifest)
                )
                cache = Path(layout.state_path) / "cache"
                replacement = cache / "replacement"
                replacement.write_bytes(b"x" * replacement_size)
                os.chmod(replacement, 0o600)
                real_stat = runner.os.stat
                real_read = runner._read_exact
                swapped = {"done": False, "identity": None}

                def replace_before_cache_stat(path, *args, **kwargs):
                    if (
                        not swapped["done"]
                        and path == "attempt0-fixture.py"
                        and kwargs.get("dir_fd") == layout._cache_fd_required()
                    ):
                        swapped["done"] = True
                        os.replace(
                            replacement,
                            cache / "attempt0-fixture.py",
                        )
                        item = real_stat(cache / "attempt0-fixture.py")
                        swapped["identity"] = (item.st_dev, item.st_ino)
                    return real_stat(path, *args, **kwargs)

                def reject_replacement_read(fd, size):
                    item = os.fstat(fd)
                    if (item.st_dev, item.st_ino) == swapped["identity"]:
                        raise AssertionError("untrusted cache replacement was read")
                    return real_read(fd, size)

                with mock.patch.object(
                    runner.os, "stat", side_effect=replace_before_cache_stat,
                ), mock.patch.object(
                    runner, "_read_exact", side_effect=reject_replacement_read,
                ):
                    with self.assertRaises(runner.Attempt0RunnerError) as raised:
                        runner._copy_bound_fixture(
                            str(self.repo),
                            layout,
                            digest,
                            expected_size,
                            expected_mode,
                            0,
                        )
                self.assertEqual(raised.exception.code, "TOOL_IDENTITY_CHANGED")
                self.assertTrue(swapped["done"])
                self.assertFalse(
                    (
                        Path(layout.state_path)
                        / "attempts/attempt-0.json"
                    ).exists()
                )

    def test_17_cache_name_replay_before_verify_open_never_becomes_authority(self):
        source_raw = self.fixture.read_bytes()
        for replacement_raw in (
            source_raw,
            b"x" * len(source_raw),
            b"x" * (2 * 1024 * 1024),
        ):
            with self.subTest(replacement_size=len(replacement_raw)):
                layout = self._layout()
                manifest = layout.begin_attempt0()
                digest, expected_size, expected_mode = (
                    runner._snapshot_fixture_digest(manifest)
                )
                cache = Path(layout.state_path) / "cache"
                replacement = cache / "replacement"
                replacement.write_bytes(replacement_raw)
                os.chmod(replacement, 0o600)
                real_open = runner.os.open
                real_read = runner._read_exact
                swapped = {"done": False, "identity": None}

                def replace_before_verify_open(path, flags, *args, **kwargs):
                    if (
                        not swapped["done"]
                        and path == "attempt0-fixture.py"
                        and kwargs.get("dir_fd") == layout._cache_fd_required()
                        and flags & os.O_ACCMODE == os.O_RDONLY
                    ):
                        swapped["done"] = True
                        os.replace(
                            replacement,
                            cache / "attempt0-fixture.py",
                        )
                        item = os.stat(cache / "attempt0-fixture.py")
                        swapped["identity"] = (item.st_dev, item.st_ino)
                    return real_open(path, flags, *args, **kwargs)

                def reject_replacement_read(fd, size):
                    item = os.fstat(fd)
                    if (item.st_dev, item.st_ino) == swapped["identity"]:
                        raise AssertionError("replayed cache name was read")
                    return real_read(fd, size)

                with mock.patch.object(
                    runner.os,
                    "open",
                    side_effect=replace_before_verify_open,
                ), mock.patch.object(
                    runner,
                    "_read_exact",
                    side_effect=reject_replacement_read,
                ):
                    with self.assertRaises(runner.Attempt0RunnerError) as raised:
                        runner._copy_bound_fixture(
                            str(self.repo),
                            layout,
                            digest,
                            expected_size,
                            expected_mode,
                            0,
                        )
                self.assertEqual(raised.exception.code, "TOOL_IDENTITY_CHANGED")
                self.assertTrue(swapped["done"])
                self.assertFalse(
                    (
                        Path(layout.state_path)
                        / "attempts/attempt-0.json"
                    ).exists()
                )

    def test_18_raw_supervisor_preserves_real_exit_and_separate_output(self):
        result = runner.supervise_raw_command(
            argv=(
                os.path.realpath(os.sys.executable), "-I", "-S", "-c",
                "import sys;sys.stdout.write('out');sys.stderr.write('err');raise SystemExit(7)",
            ),
            environment={"PATH": os.defpath},
            timeout_seconds=1.0,
            output_limit_bytes=4096,
        )
        self.assertEqual(result.raw_process, {"state": "EXITED", "process_exit": 7})
        self.assertEqual((result.stdout, result.stderr), (b"out", b"err"))
        self.assertFalse(result.stdout_truncated)
        self.assertFalse(result.stderr_truncated)

    def test_19_raw_child_cannot_inherit_parent_authority_fd(self):
        read_fd, write_fd = os.pipe()
        authority_fd = runner._moved_child_fd(write_fd)
        os.close(write_fd)
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, authority_fd)
        result = runner.supervise_raw_command(
            argv=(
                os.path.realpath(os.sys.executable), "-I", "-S", "-c",
                (
                    "import errno,os,sys\n"
                    f"fd={authority_fd}\n"
                    "try: os.fstat(fd)\n"
                    "except OSError as exc: raise SystemExit(0 if exc.errno == errno.EBADF else 91)\n"
                    "raise SystemExit(92)\n"
                ),
            ),
            environment={"PATH": os.defpath},
            timeout_seconds=1.0,
            output_limit_bytes=4096,
            authority_fds=(authority_fd,),
        )
        self.assertEqual(result.raw_process, {"state": "EXITED", "process_exit": 0})
        self.assertTrue(stat.S_ISFIFO(os.fstat(authority_fd).st_mode))

    def test_20_raw_supervisor_normalizes_signal_and_output_limit(self):
        signaled = runner.supervise_raw_command(
            argv=(
                os.path.realpath(os.sys.executable), "-I", "-S", "-c",
                "import os,signal;os.kill(os.getpid(),signal.SIGTERM)",
            ),
            environment={"PATH": os.defpath},
            timeout_seconds=1.0,
            output_limit_bytes=4096,
        )
        self.assertEqual(
            signaled.raw_process,
            {"state": "SIGNALED", "process_signal": signal.SIGTERM},
        )

        limited = runner.supervise_raw_command(
            argv=(
                os.path.realpath(os.sys.executable), "-I", "-S", "-c",
                "import sys;sys.stdout.buffer.write(b'x'*8192);sys.stdout.flush()",
            ),
            environment={"PATH": os.defpath},
            timeout_seconds=1.0,
            output_limit_bytes=1024,
        )
        self.assertEqual(limited.raw_process, {"state": "OUTPUT_LIMIT"})
        self.assertEqual(len(limited.stdout) + len(limited.stderr), 1024)
        self.assertTrue(limited.stdout_truncated)

    def test_21_raw_timeout_kills_descendants_and_reaps_leader_once(self):
        real_spawn, real_waitpid = runner.os.posix_spawn, runner.os.waitpid
        pids, waits = [], []

        def capture_spawn(*args, **kwargs):
            pid = real_spawn(*args, **kwargs)
            pids.append(pid)
            return pid

        def capture_wait(pid, options):
            waits.append((pid, options))
            return real_waitpid(pid, options)

        program = (
            "import os,time\n"
            "if os.fork()==0:\n"
            " while True: time.sleep(1)\n"
            "while True: time.sleep(1)\n"
        )
        with mock.patch.object(
            runner.os, "posix_spawn", side_effect=capture_spawn,
        ), mock.patch.object(
            runner.os, "waitpid", side_effect=capture_wait,
        ):
            result = runner.supervise_raw_command(
                argv=(
                    os.path.realpath(os.sys.executable), "-I", "-S", "-c",
                    program,
                ),
                environment={"PATH": os.defpath},
                timeout_seconds=0.10,
                output_limit_bytes=4096,
            )
        self.assertEqual(result.raw_process, {"state": "HARD_TIMEOUT"})
        self.assertEqual(waits, [(pids[0], 0)])
        with self.assertRaises(ProcessLookupError):
            os.killpg(pids[0], 0)

    def test_22_framed_config_failures_share_timeout_group_and_reap_authority(self):
        real_spawn = runner.os.posix_spawn
        real_waitpid = runner.os.waitpid
        frame = (2).to_bytes(4, "big") + b"{}"
        child = (
            os.path.realpath(os.sys.executable), "-I", "-S", "-c",
            "import time\nwhile True: time.sleep(1)\n",
        )

        def exercise(label, injected, *, returns=False):
            pids: list[int] = []
            waits: list[tuple[int, int]] = []

            def capture_spawn(*args, **kwargs):
                pid = real_spawn(*args, **kwargs)
                pids.append(pid)
                return pid

            def capture_wait(pid, options):
                waits.append((pid, options))
                return real_waitpid(pid, options)

            with mock.patch.object(
                runner.os, "posix_spawn", side_effect=capture_spawn,
            ), mock.patch.object(
                runner.os, "waitpid", side_effect=capture_wait,
            ), mock.patch.object(
                runner, "_write_framed_config", side_effect=injected,
            ):
                if returns:
                    result = runner.supervise_raw_command(
                        argv=child,
                        environment={"PATH": os.defpath},
                        timeout_seconds=0.10,
                        output_limit_bytes=4096,
                        framed_config=frame,
                    )
                    self.assertEqual(
                        result.raw_process,
                        {"state": "HARD_TIMEOUT"},
                        label,
                    )
                    self.assertNotEqual(result.observation_error, None)
                else:
                    with self.assertRaises(
                        runner.Attempt0RunnerError,
                        msg=label,
                    ) as raised:
                        runner.supervise_raw_command(
                            argv=child,
                            environment={"PATH": os.defpath},
                            timeout_seconds=0.50,
                            output_limit_bytes=4096,
                            framed_config=frame,
                        )
                    self.assertEqual(
                        raised.exception.code,
                        "CONFIG_WRITE_FAILED",
                        label,
                    )
            self.assertEqual(waits, [(pids[0], 0)], label)
            with self.assertRaises(ProcessLookupError, msg=label):
                os.killpg(pids[0], 0)

        exercise(
            "blocked",
            lambda fd, chunk: (_ for _ in ()).throw(BlockingIOError()),
            returns=True,
        )
        exercise(
            "epipe",
            lambda fd, chunk: (_ for _ in ()).throw(
                BrokenPipeError(errno.EPIPE, "closed"),
            ),
        )
        exercise("short", lambda fd, chunk: max(0, len(chunk) - 1))
        exercise(
            "error",
            lambda fd, chunk: (_ for _ in ()).throw(
                OSError(errno.EIO, "write"),
            ),
        )

        class RegisterFailure:
            def __init__(self):
                self.inner = runner.select.kqueue()

            def control(self, *args, **kwargs):
                raise OSError(errno.EIO, "register")

            def close(self):
                self.inner.close()

        pids: list[int] = []
        waits: list[tuple[int, int]] = []

        def capture_spawn(*args, **kwargs):
            pid = real_spawn(*args, **kwargs)
            pids.append(pid)
            return pid

        def capture_wait(pid, options):
            waits.append((pid, options))
            return real_waitpid(pid, options)

        with mock.patch.object(
            runner.os, "posix_spawn", side_effect=capture_spawn,
        ), mock.patch.object(
            runner.os, "waitpid", side_effect=capture_wait,
        ), mock.patch.object(
            runner.select, "kqueue", return_value=RegisterFailure(),
        ):
            with self.assertRaises(runner.Attempt0RunnerError) as raised:
                runner.supervise_raw_command(
                    argv=child,
                    environment={"PATH": os.defpath},
                    timeout_seconds=0.50,
                    output_limit_bytes=4096,
                    framed_config=frame,
                )
        self.assertEqual(raised.exception.code, "SUPERVISOR_SETUP_FAILED")
        self.assertEqual(waits, [(pids[0], 0)])
        with self.assertRaises(ProcessLookupError):
            os.killpg(pids[0], 0)

        pids = []
        waits = []
        resistant_child = (
            "import os,signal,time\n"
            "ready_r,ready_w=os.pipe()\n"
            "if os.fork()==0:\n"
            " os.close(ready_r)\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            " os.write(ready_w,b'R')\n"
            " os.close(ready_w)\n"
            " while True: time.sleep(1)\n"
            "os.close(ready_w)\n"
            "assert os.read(ready_r,1)==b'R'\n"
            "os.close(ready_r)\n"
            "os._exit(0)\n"
        )

        def delayed_config_failure(fd, chunk):
            time.sleep(0.15)
            raise OSError(errno.EIO, "post-leader config failure")

        with mock.patch.object(
            runner.os, "posix_spawn", side_effect=capture_spawn,
        ), mock.patch.object(
            runner.os, "waitpid", side_effect=capture_wait,
        ), mock.patch.object(
            runner, "_write_framed_config",
            side_effect=delayed_config_failure,
        ):
            with self.assertRaises(runner.Attempt0RunnerError) as raised:
                runner.supervise_raw_command(
                    argv=(
                        os.path.realpath(os.sys.executable),
                        "-I", "-S", "-c", resistant_child,
                    ),
                    environment={"PATH": os.defpath},
                    timeout_seconds=1.0,
                    output_limit_bytes=4096,
                    framed_config=frame,
                )
        self.assertEqual(raised.exception.code, "CONFIG_WRITE_FAILED")
        self.assertEqual(waits, [(pids[0], 0)])
        with self.assertRaises(ProcessLookupError):
            os.killpg(pids[0], 0)

    def test_23_source_observation_limit_is_explicit_and_rejects_quickly(self):
        inventory = json.loads((
            Path(__file__).parent
            / "fixtures/source_gate/expected_test_ids.v1.json"
        ).read_text("utf-8"))
        record = inventory["suites"]["RUST-DESKTOP"]
        expected = record["discovered_test_ids"]
        skipped = record["approved_skipped_test_ids"]
        ignored = record["approved_ignored_test_ids"]
        value = {
            "schema": "source-observation.v1",
            "run_id": "f" * 32,
            "suite_id": "SUITE-RUST-DESKTOP",
            "entrypoint_id": "ENTRY-SOURCE-RUST-DESKTOP",
            "attempt_index": 0,
            "command_argv_sha256": "a" * 64,
            "environment_sha256": "b" * 64,
            "tool_identity_sha256": "c" * 64,
            "raw_process": {"state": "EXITED", "process_exit": 0},
            "adapter_exit": 0,
            "executed": len(expected),
            "passed": len(expected) - len(skipped) - len(ignored),
            "failed": 0,
            "skipped": len(skipped),
            "ignored": len(ignored),
            "todo": 0,
            "not_run": 0,
            "discovered_test_ids": expected,
            "executed_test_ids": expected,
            "failed_test_ids": [],
            "skipped_test_ids": skipped,
            "ignored_test_ids": ignored,
            "todo_test_ids": [],
            "not_run_test_ids": [],
            "stdout": {
                "bytes": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
                "truncated": False,
            },
            "stderr": {
                "bytes": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
                "truncated": False,
            },
            "derived_tool": None,
            "outcome_hint": "PASS",
            "classification_hint": "NONE",
            "reason_code": "NONE",
        }
        raw = canonical_json_bytes(value)
        frame = len(raw).to_bytes(4, "big") + raw
        self.assertEqual(len(expected), 443)
        self.assertGreater(len(raw), 64 * 1024)
        self.assertLess(len(raw), 4 * 1024 * 1024)
        program = (
            "import os,socket\n"
            "header=os.read(197,4)\n"
            "size=int.from_bytes(header,'big')\n"
            "parts=[]\n"
            "while size:\n"
            " chunk=os.read(197,min(65536,size))\n"
            " assert chunk\n"
            " parts.append(chunk)\n"
            " size-=len(chunk)\n"
            "assert os.read(197,1)==b''\n"
            "raw=b''.join(parts)\n"
            "peer=socket.socket(fileno=199)\n"
            "try:\n"
            " peer.sendall(len(raw).to_bytes(4,'big')+raw)\n"
            " ack=peer.recv(4)\n"
            "except OSError:\n"
            " raise SystemExit(12)\n"
            "finally:\n"
            " peer.close()\n"
            "raise SystemExit(0 if ack==b'ACK!' else 12)\n"
        )
        argv = (
            os.path.realpath(os.sys.executable), "-I", "-S", "-c", program,
        )
        started = time.monotonic()
        rejected = runner.supervise_raw_command(
            argv=argv,
            environment={"PATH": os.defpath},
            timeout_seconds=2.0,
            output_limit_bytes=4096,
            framed_config=frame,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(rejected.raw_process["state"], "EXITED")
        self.assertEqual(rejected.observation_error, "ADAPTER_MALFORMED")
        self.assertFalse(rejected.observation_acked)
        self.assertLess(elapsed, 1.0)

        accepted = runner.supervise_raw_command(
            argv=argv,
            environment={"PATH": os.defpath},
            timeout_seconds=2.0,
            output_limit_bytes=4096,
            framed_config=frame,
            observation_limit_bytes=4 * 1024 * 1024,
        )
        self.assertEqual(
            accepted.raw_process,
            {"state": "EXITED", "process_exit": 0},
        )
        self.assertEqual(accepted.observation, value)
        self.assertEqual(
            accepted.observation["discovered_test_ids"],
            expected,
        )
        self.assertEqual(
            accepted.observation["executed_test_ids"],
            expected,
        )
        self.assertTrue(accepted.observation_acked)

    def test_24_source_observation_and_outer_grace_limits_are_bounded(self):
        argv = ("/usr/bin/true",)
        result = runner.supervise_raw_command(
            argv=argv,
            environment={"PATH": os.defpath},
            timeout_seconds=3605,
            output_limit_bytes=4096,
            observation_limit_bytes=4 * 1024 * 1024,
        )
        self.assertEqual(
            result.raw_process,
            {"state": "EXITED", "process_exit": 0},
        )
        for kwargs in (
            {"timeout_seconds": 3605.01},
            {"observation_limit_bytes": 4 * 1024 * 1024 + 1},
            {"observation_limit_bytes": True},
        ):
            arguments = {
                "argv": argv,
                "environment": {"PATH": os.defpath},
                "timeout_seconds": 1.0,
                "output_limit_bytes": 4096,
                **kwargs,
            }
            with self.assertRaises(runner.Attempt0RunnerError) as raised:
                runner.supervise_raw_command(**arguments)
            self.assertEqual(raised.exception.code, "RAW_COMMAND_UNSAFE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
