"""Temporary-directory-only adversarial tests for the RUE-03 atomic store."""
from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import test.quality.run_evidence.atomic_store as store
from test.quality.run_evidence.atomic_store import (
    RunStoreError,
    TempOwnerIdentityV1,
    TempResidualV1,
    create_run_layout,
    publish_json,
    record_first_failure,
)
from test.quality.run_evidence.contracts import adjudicate_adapter_attempt, adjudicate_parent_event


class AtomicStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir()))
        self.base = Path(self.temp.name)
        self.state, self.evidence = self.base / "state", self.base / "evidence"
        self.state.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def layout(self):
        value = create_run_layout(str(self.state), str(self.evidence))
        self.addCleanup(self._quiet_close, value)
        return value

    @staticmethod
    def _store_publish(layout, area, leaf, value):
        """Exercise the internal store primitive without public authority."""
        with layout._lock:
            return store._publish(
                layout, area, leaf, store.canonical_json_bytes(value),
                failure=False,
            )

    @staticmethod
    def _quiet_close(layout) -> None:
        try:
            layout.close()
        except RunStoreError:
            pass

    @staticmethod
    def _failure(layout):
        return {
            "schema": "run-failure.v1", "run_id": layout.run_id,
            "stage": "RUN_ROOT", "reason_code": "RUN_ROOT_UNSAFE",
            "run_manifest": None, "created_at": "2026-07-24T00:00:00Z", "terminal": True,
        }

    def test_01_layout_is_private_and_lock_covers_lifetime(self):
        layout = self.layout()
        self.assertRegex(layout.run_id, r"^[0-9a-f]{32}$")
        paths = [Path(layout.state_path), Path(layout.evidence_path)]
        paths += [Path(layout.state_path) / item for item in ("snapshot", "attempts", "cache", "tmp")]
        paths += [Path(layout.evidence_path) / "results"]
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in paths))
        contender = os.open(layout.evidence_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, contender)
        with self.assertRaises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        layout.close()
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(contender, fcntl.LOCK_UN)

    def test_02_roots_reject_relative_symlink_overlap_and_unsafe_permissions(self):
        with self.assertRaises(RunStoreError):
            create_run_layout("relative", str(self.evidence))
        with self.assertRaises(RunStoreError):
            create_run_layout(str(self.state), str(self.state))
        nested = self.state / "nested"; nested.mkdir()
        with self.assertRaises(RunStoreError):
            create_run_layout(str(self.state), str(nested))
        link = self.base / "link"; link.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(RunStoreError):
            create_run_layout(str(link), str(self.evidence))
        os.chmod(self.state, 0o770)
        with self.assertRaises(RunStoreError):
            create_run_layout(str(self.state), str(self.evidence))

    def test_03_root_binding_failure_records_only_first_terminal_failure(self):
        with mock.patch.object(store, "_verify_layout_binding", side_effect=RunStoreError("PATH_DRIFT")):
            with self.assertRaises(RunStoreError) as raised:
                create_run_layout(str(self.state), str(self.evidence))
        self.assertTrue(raised.exception.failure_recorded)
        path = self.evidence / "runs" / raised.exception.run_id / "run-failure.json"
        self.assertTrue(path.is_file())

    def test_04_error_fields_do_not_expose_paths_or_foreign_bytes(self):
        error = RunStoreError("X", run_id="a" * 32, final_leaf="safe.json", residual=TempResidualV1(".tmp-a", None, "b" * 64, "UNKNOWN"))
        self.assertEqual(str(error), "X")
        self.assertEqual(error.final_leaf, "safe.json")
        self.assertNotIn("/", str(error))

    def test_05_leaf_rejects_non_nfc_control_nul_and_slash(self):
        for value in ("", "a/b", ".", "..", "\x00", "bad\n", "e\u0301.json"):
            with self.assertRaises(RunStoreError):
                self.layout().publish_json("root", value, {})

    def test_06_rename_abi_flags_and_eexist_mapping(self):
        calls = {}
        class Fake:
            def __call__(self, *args):
                calls["args"] = args
                return -1
        fake = Fake()
        library = type("Library", (), {"renameatx_np": fake})()
        with mock.patch.object(store.ctypes, "CDLL", return_value=library), \
             mock.patch.object(store.ctypes, "get_errno", return_value=errno.EEXIST):
            with self.assertRaises(RunStoreError) as raised:
                store._rename_exclusive(7, ".tmp-a", "run-manifest.json")
        self.assertEqual(raised.exception.code, "PUBLISH_EXISTS")
        self.assertEqual(calls["args"][-1], store._RENAME_FLAGS)
        self.assertEqual(fake.argtypes[-1], ctypes.c_uint)

    def test_07_rename_errno_contract_mapping(self):
        class Fake:
            def __call__(self, *args): return -1
        for number, code in ((45, "PUBLISH_ATOMIC_UNSUPPORTED"), (102, "PUBLISH_ATOMIC_UNSUPPORTED"),
                             (22, "CONTRACT_FAILURE"), (107, "RESOLUTION_REJECTED"),
                             (2, "PATH_DRIFT"), (62, "PATH_DRIFT"), (9, "FD_DRIFT"),
                             (0, "CONTRACT_FAILURE"), (999, "RENAME_FAILED")):
            with self.subTest(errno=number):
                fake = Fake(); library = type("Library", (), {"renameatx_np": fake})()
                with mock.patch.object(store.ctypes, "CDLL", return_value=library), \
                     mock.patch.object(store.ctypes, "get_errno", return_value=number):
                    with self.assertRaises(RunStoreError) as raised:
                        store._rename_exclusive(7, ".tmp-a", "run-manifest.json")
                self.assertEqual(raised.exception.code, code)

    def test_08_missing_rename_symbol_fails_closed_without_fallback(self):
        with mock.patch.object(store.ctypes, "CDLL", return_value=object()):
            with self.assertRaises(RunStoreError) as raised:
                store._rename_exclusive(7, ".tmp-a", "run-manifest.json")
        self.assertEqual(raised.exception.code, "PUBLISH_ATOMIC_UNSUPPORTED")

    def test_09_temp_collision_does_not_touch_foreign_file_or_use_link_unlink(self):
        layout = self.layout(); parent = Path(layout.evidence_path)
        foreign = parent / ".tmp-foreign"; foreign.write_bytes(b"foreign")
        real_open = os.open
        def collide(path, *args, **kwargs):
            if isinstance(path, str) and path.startswith(".tmp-"):
                raise FileExistsError(errno.EEXIST, "collision")
            return real_open(path, *args, **kwargs)
        with mock.patch.object(store.os, "open", side_effect=collide), \
             mock.patch.object(store.os, "unlink", side_effect=AssertionError("forbidden"), create=True), \
             mock.patch.object(store.os, "link", side_effect=AssertionError("forbidden"), create=True):
            with self.assertRaises(RunStoreError) as raised:
                self._store_publish(layout, "root", "run-manifest.json", {})
        self.assertEqual(raised.exception.code, "PUBLISH_TEMP_COLLISION")
        self.assertIsNone(raised.exception.residual)
        self.assertEqual(foreign.read_bytes(), b"foreign")

    def test_10_first_fstat_failure_has_unknown_residual(self):
        layout = self.layout(); real_fstat = os.fstat; calls = {"count": 0}
        def fail_first(fd):
            calls["count"] += 1
            # The parent is revalidated before O_EXCL; fail the first fstat of
            # the newly-created temp descriptor, not that parent check.
            if calls["count"] == 2: raise OSError(errno.EBADF, "bad")
            return real_fstat(fd)
        with mock.patch.object(store, "_verify_live_layout"), mock.patch.object(store.os, "fstat", side_effect=fail_first):
            with self.assertRaises(RunStoreError) as raised:
                self._store_publish(layout, "root", "run-manifest.json", {})
        self.assertEqual(raised.exception.residual.state, "UNKNOWN")
        self.assertIsNone(raised.exception.residual.owner_identity)

    def test_11_fchmod_failure_keeps_bound_temp(self):
        layout = self.layout()
        with mock.patch.object(store.os, "fchmod", side_effect=OSError(errno.EIO, "fail")):
            with self.assertRaises(RunStoreError) as raised:
                self._store_publish(layout, "root", "run-manifest.json", {})
        self.assertEqual(raised.exception.residual.state, "PRESENT_BOUND")
        self.assertIsInstance(raised.exception.residual.owner_identity, TempOwnerIdentityV1)

    def test_12_second_fstat_drift_is_rejected(self):
        layout = self.layout(); real_fstat = os.fstat; calls = {"count": 0}
        def drift(fd):
            calls["count"] += 1
            item = real_fstat(fd)
            if calls["count"] == 2:
                return os.stat_result((item.st_mode, item.st_ino + 1, item.st_dev, item.st_nlink, item.st_uid, item.st_gid, item.st_size, item.st_atime, item.st_mtime, item.st_ctime))
            return item
        with mock.patch.object(store, "_verify_live_layout"), mock.patch.object(store.os, "fstat", side_effect=drift):
            with self.assertRaises(RunStoreError) as raised:
                self._store_publish(layout, "root", "run-manifest.json", {})
        self.assertEqual(raised.exception.code, "FD_DRIFT")

    def test_13_short_write_and_file_fsync_leave_residual(self):
        layout = self.layout()
        with mock.patch.object(store.os, "write", return_value=0):
            with self.assertRaises(RunStoreError) as short:
                self._store_publish(layout, "root", "run-manifest.json", {"a": 1})
        self.assertEqual(short.exception.residual.state, "PRESENT_BOUND")
        with mock.patch.object(store, "_fsync", side_effect=RunStoreError("PUBLISH_IO_FAILED")):
            with self.assertRaises(RunStoreError) as synced:
                self._store_publish(layout, "root", "evidence-manifest.json", {"a": 1})
        self.assertEqual(synced.exception.residual.state, "PRESENT_BOUND")

    def test_14_pre_rename_name_drift_prevents_rename_call(self):
        layout = self.layout(); real_stat = os.stat; calls = {"count": 0}
        def missing(path, *args, **kwargs):
            if path.__class__ is str and path.startswith(".tmp-"):
                calls["count"] += 1
                if calls["count"] == 1: raise FileNotFoundError(errno.ENOENT, "gone")
            return real_stat(path, *args, **kwargs)
        with mock.patch.object(store.os, "stat", side_effect=missing), \
             mock.patch.object(store, "_rename_exclusive", side_effect=AssertionError("must not rename")):
            with self.assertRaises(RunStoreError) as raised:
                self._store_publish(layout, "root", "run-manifest.json", {"a": 1})
        self.assertEqual(raised.exception.code, "PATH_DRIFT")

    def test_15_eexist_keeps_temp_and_never_falls_back(self):
        layout = self.layout(); target = Path(layout.evidence_path) / "run-manifest.json"; target.write_bytes(b"foreign")
        with self.assertRaises(RunStoreError) as raised:
            self._store_publish(layout, "root", "run-manifest.json", {"a": 1})
        self.assertEqual(raised.exception.code, "PUBLISH_EXISTS")
        self.assertEqual(target.read_bytes(), b"foreign")
        self.assertEqual(raised.exception.residual.state, "PRESENT_BOUND")

    def test_16_success_has_exact_durability_order(self):
        layout = self.layout(); events = []; real_fsync = store._fsync
        def note(fd, code="PUBLISH_IO_FAILED"):
            events.append(fd); return real_fsync(fd, code)
        with mock.patch.object(store, "_fsync", side_effect=note):
            self._store_publish(layout, "root", "run-manifest.json", {"a": 1})
        self.assertGreaterEqual(len(events), 4)
        self.assertEqual(events[1], layout._evidence_fd)  # rename -> first parent fsync
        self.assertEqual(events[-1], layout._evidence_fd)  # final -> second parent fsync

    def test_17_final_replacement_after_rename_is_rejected(self):
        layout = self.layout(); parent = Path(layout.evidence_path); real_fsync = store._fsync; calls = {"parent": 0}
        def replace(fd, code="PUBLISH_IO_FAILED"):
            result = real_fsync(fd, code)
            if fd == layout._evidence_fd:
                calls["parent"] += 1
                if calls["parent"] == 2:
                    replacement = parent / "foreign-replacement"
                    replacement.write_bytes(b"foreign")
                    os.replace(replacement, parent / "run-manifest.json")
            return result
        with mock.patch.object(store, "_fsync", side_effect=replace):
            with self.assertRaises(RunStoreError) as raised:
                self._store_publish(layout, "root", "run-manifest.json", {"a": 1})
        self.assertTrue(raised.exception.published_may_exist)

    def test_18_existing_failure_reads_only_stably_bound_terminal_record(self):
        layout = self.layout(); first = record_first_failure(layout, self._failure(layout))
        self.assertEqual(first.status, "RECORDED")
        self.assertEqual(record_first_failure(layout, self._failure(layout)).status, "ALREADY_RECORDED")
        parent = Path(layout.evidence_path); original = store._read_exact
        def replace(fd, size, *, code):
            raw = original(fd, size, code=code)
            replacement = parent / "replacement"; replacement.write_bytes(raw)
            os.replace(replacement, parent / "run-failure.json")
            return raw
        with mock.patch.object(store, "_read_exact", side_effect=replace):
            with self.assertRaises(RunStoreError) as raised:
                record_first_failure(layout, self._failure(layout))
        self.assertEqual(raised.exception.code, "FAILURE_EXISTING_UNSAFE")

    def test_19_terminal_conflict_and_failure_publisher_use_same_path(self):
        layout = self.layout()
        (Path(layout.evidence_path) / "completion-seal.json").write_bytes(b"{}")
        with self.assertRaises(RunStoreError) as raised:
            record_first_failure(layout, self._failure(layout))
        self.assertEqual(raised.exception.code, "TERMINAL_CONFLICT")

    def test_20_rlock_close_vs_publish_double_close_and_context_primary(self):
        layout = self.layout(); entered = threading.Event(); release = threading.Event(); real_publish = store._publish
        def held(*args, **kwargs):
            entered.set(); release.wait(2); return real_publish(*args, **kwargs)
        result = []
        with mock.patch.object(store, "_publish", side_effect=held):
            worker = threading.Thread(target=lambda: result.append(self._store_publish(layout, "root", "run-manifest.json", {"a": 1})))
            worker.start(); self.assertTrue(entered.wait(1))
            closer = threading.Thread(target=layout.close); closer.start(); time.sleep(0.02); self.assertTrue(closer.is_alive())
            release.set(); worker.join(2); closer.join(2)
        self.assertEqual(len(result), 1)
        layout.close()
        context_layout = self.layout()
        with self.assertRaises(ValueError):
            with context_layout:
                raise ValueError("body-primary")

    def test_21_close_error_is_typed_and_does_not_mask_context_body(self):
        layout = self.layout(); real_close = os.close; calls = {"count": 0}
        def failing(fd):
            calls["count"] += 1
            if calls["count"] == 1: raise OSError(errno.EIO, "close")
            return real_close(fd)
        with mock.patch.object(store.os, "close", side_effect=failing):
            with self.assertRaises(RunStoreError) as raised:
                layout.close()
        self.assertEqual(raised.exception.code, "CLOSE_FAILED")
        layout2 = self.layout()
        with mock.patch.object(store.os, "close", side_effect=OSError(errno.EIO, "close")):
            with self.assertRaises(ValueError):
                with layout2:
                    raise ValueError("primary")

    def test_22_no_production_link_unlink_cleanup_and_catalog_is_legacy(self):
        source = Path(store.__file__).read_text()
        self.assertNotIn("os.unlink", source)
        self.assertNotIn("os.link", source)
        catalog = (Path(__file__).parents[2] / "quality/test-catalog.v1.json").read_text()
        self.assertIn('"adapter_protocol": "legacy"', catalog)
        self.assertIn('"profiles": []', catalog)

    def test_23_partial_layout_failure_uses_evidence_publisher_without_state_fds(self):
        original = store._mkdir_open; calls = {"count": 0}
        def fail_state(parent_fd, leaf, *, reuse):
            calls["count"] += 1
            if calls["count"] == 5:
                raise RunStoreError("RUN_ROOT_UNSAFE")
            return original(parent_fd, leaf, reuse=reuse)
        with mock.patch.object(store, "_mkdir_open", side_effect=fail_state):
            with self.assertRaises(RunStoreError) as raised:
                create_run_layout(str(self.state), str(self.evidence))
        self.assertTrue(raised.exception.failure_recorded)
        record = self.evidence / "runs" / raised.exception.run_id / "run-failure.json"
        self.assertTrue(record.is_file())

    def test_24_creation_reopens_original_absolute_roots_and_rejects_root_swap(self):
        old_state = self.base / "state-old"; original = store._verify_layout_binding
        def swap_after_relative_binding(*args):
            original(*args)
            os.rename(self.state, old_state)
            self.state.mkdir(mode=0o700)
        with mock.patch.object(store, "_verify_layout_binding", side_effect=swap_after_relative_binding):
            with self.assertRaises(RunStoreError) as raised:
                create_run_layout(str(self.state), str(self.evidence))
        self.assertEqual(raised.exception.code, "PATH_DRIFT")
        self.assertTrue(raised.exception.failure_recorded)
        self.assertTrue((self.evidence / "runs" / raised.exception.run_id / "run-failure.json").is_file())

    def test_25_evidence_binding_rejects_full_and_provisional_evidence_root_swaps(self):
        layout = self.layout(); old_evidence = self.base / "evidence-old"
        os.rename(self.evidence, old_evidence); self.evidence.mkdir(mode=0o700)
        with self.assertRaises(RunStoreError) as full:
            record_first_failure(layout, self._failure(layout))
        self.assertEqual(full.exception.code, "PATH_DRIFT")
        # A partial layout must not claim a terminal failure once its evidence path drifted.
        self.temp.cleanup(); self.setUp()
        old_evidence = self.base / "evidence-old"; original = store._mkdir_open; calls = {"count": 0}
        def fail_after_swap(parent_fd, leaf, *, reuse):
            calls["count"] += 1
            if calls["count"] == 5:
                os.rename(self.evidence, old_evidence); self.evidence.mkdir(mode=0o700)
                raise RunStoreError("RUN_ROOT_UNSAFE")
            return original(parent_fd, leaf, reuse=reuse)
        with mock.patch.object(store, "_mkdir_open", side_effect=fail_after_swap):
            with self.assertRaises(RunStoreError) as partial:
                create_run_layout(str(self.state), str(self.evidence))
        self.assertFalse(partial.exception.failure_recorded)

    def test_26_existing_failure_close_preserves_primary_or_reports_close(self):
        layout = self.layout(); record_first_failure(layout, self._failure(layout))
        with mock.patch.object(store.os, "close", side_effect=OSError(errno.EIO, "close")):
            with self.assertRaises(RunStoreError) as only_close:
                layout._existing_failure(layout._evidence_fd)
        self.assertEqual(only_close.exception.code, "CLOSE_FAILED")
        layout2 = self.layout(); record_first_failure(layout2, self._failure(layout2))
        with mock.patch.object(store, "_read_exact", side_effect=RunStoreError("FAILURE_EXISTING_UNSAFE")), \
             mock.patch.object(store.os, "close", side_effect=OSError(errno.EIO, "close")):
            with self.assertRaises(RunStoreError) as primary:
                layout2._existing_failure(layout2._evidence_fd)
        self.assertEqual((primary.exception.code, primary.exception.secondary_code), ("FAILURE_EXISTING_UNSAFE", "CLOSE_FAILED"))

    def test_27_root_walker_close_is_typed_once_and_never_leaks_raw_oserror(self):
        real_close = os.close; calls = []
        def close_then_error(fd):
            calls.append(fd); real_close(fd); raise OSError(errno.EIO, "close")
        with mock.patch.object(store.os, "close", side_effect=close_then_error):
            with self.assertRaises(RunStoreError) as raised:
                store._open_absolute_root(str(self.state))
        self.assertEqual((raised.exception.code, raised.exception.secondary_code), ("CLOSE_FAILED", "CLOSE_FAILED"))
        self.assertEqual(len(calls), 2)  # old descriptor and the immediately-owned next descriptor

    def test_28_binding_close_and_published_owned_close_are_never_success(self):
        layout = self.layout(); real_close = os.close
        def close_then_error(fd):
            real_close(fd); raise OSError(errno.EIO, "close")
        with mock.patch.object(store.os, "close", side_effect=close_then_error):
            with self.assertRaises(RunStoreError) as binding:
                store._verify_evidence_binding(layout)
        self.assertEqual(binding.exception.code, "CLOSE_FAILED")
        original = store._owned_close
        def published_close(fd, primary=None, **kwargs):
            if kwargs.get("published") and primary is None:
                original(fd, primary, **kwargs)
                return RunStoreError("CLOSE_FAILED", published_may_exist=True, final_leaf=kwargs.get("final_leaf"))
            return original(fd, primary, **kwargs)
        with mock.patch.object(store, "_owned_close", side_effect=published_close):
            with self.assertRaises(RunStoreError) as published:
                self._store_publish(layout, "root", "run-manifest.json", {"a": 1})
        self.assertEqual((published.exception.code, published.exception.published_may_exist), ("CLOSE_FAILED", True))

    def test_29_existing_failure_rejects_same_inode_same_size_inplace_rewrite_during_read(self):
        layout = self.layout(); record_first_failure(layout, self._failure(layout))
        path = Path(layout.evidence_path) / "run-failure.json"; before = (path.stat().st_ino, path.stat().st_size); original = store._read_exact
        def mutate(fd, size, *, code):
            raw = original(fd, size, code=code)
            changed = path.read_bytes().replace(b"2026-07-24", b"2026-07-25", 1)
            with path.open("r+b") as output:
                output.write(changed); output.flush(); os.fsync(output.fileno())
            return raw
        with mock.patch.object(store, "_read_exact", side_effect=mutate):
            with self.assertRaises(RunStoreError) as raised:
                layout._existing_failure(layout._evidence_fd)
        self.assertEqual(raised.exception.code, "FAILURE_EXISTING_UNSAFE")
        self.assertEqual((path.stat().st_ino, path.stat().st_size), before)

    def test_30_publish_rejects_same_inode_same_size_inplace_rewrite_after_final_read(self):
        layout = self.layout(); path = Path(layout.evidence_path) / "run-manifest.json"; original = store._read_exact; seen = {"verify": 0}
        def mutate(fd, size, *, code):
            raw = original(fd, size, code=code)
            if code == "PUBLISH_VERIFY_FAILED":
                seen["verify"] += 1
                if seen["verify"] == 2:
                    with path.open("r+b") as output:
                        output.write(b'{"a":2}'); output.flush(); os.fsync(output.fileno())
            return raw
        old_hash = hashlib.sha256(b'{"a":1}').hexdigest()
        with mock.patch.object(store, "_read_exact", side_effect=mutate):
            with self.assertRaises(RunStoreError) as raised:
                self._store_publish(layout, "root", "run-manifest.json", {"a": 1})
        self.assertTrue(raised.exception.published_may_exist)
        self.assertNotEqual(hashlib.sha256(path.read_bytes()).hexdigest(), old_hash)

    @staticmethod
    def _directory_manifest(path: Path):
        records = []
        for item in sorted(path.iterdir(), key=lambda candidate: candidate.name.encode("utf-8")):
            value = item.lstat(); kind = "file" if stat.S_ISREG(value.st_mode) else "dir" if stat.S_ISDIR(value.st_mode) else "other"
            digest = hashlib.sha256(item.read_bytes()).hexdigest() if kind == "file" else None
            records.append((item.name, kind, stat.S_IMODE(value.st_mode), value.st_size, digest, value.st_ino))
        return records

    def test_31_failure_preflight_existing_record_never_creates_temp_or_changes_manifest(self):
        layout = self.layout(); evidence = Path(layout.evidence_path)
        first = record_first_failure(layout, self._failure(layout)); before = self._directory_manifest(evidence)
        second = record_first_failure(layout, self._failure(layout)); third = record_first_failure(layout, self._failure(layout))
        self.assertEqual((first.status, second.status, third.status), ("RECORDED", "ALREADY_RECORDED", "ALREADY_RECORDED"))
        self.assertEqual(self._directory_manifest(evidence), before)
        self.assertFalse(any(name.startswith(".tmp-") for name, *_ in before))

    def test_32_late_rename_eexist_remains_explicit_failure_with_owned_temp(self):
        layout = self.layout(); evidence = Path(layout.evidence_path)
        with mock.patch.object(store, "_rename_exclusive", side_effect=RunStoreError("PUBLISH_EXISTS")):
            with self.assertRaises(RunStoreError) as raised:
                record_first_failure(layout, self._failure(layout))
        self.assertEqual(raised.exception.code, "PUBLISH_EXISTS")
        self.assertIsNotNone(raised.exception.residual)
        self.assertEqual(raised.exception.residual.state, "PRESENT_BOUND")
        self.assertTrue((evidence / raised.exception.residual.temp_leaf).is_file())
        self.assertFalse((evidence / "run-failure.json").exists())

    def test_33_existing_failure_root_rebind_is_rejected_before_preflight(self):
        layout = self.layout(); first = record_first_failure(layout, self._failure(layout))
        detached = self.base / "evidence-detached"; original_manifest = self._directory_manifest(Path(layout.evidence_path))
        os.rename(self.evidence, detached); self.evidence.mkdir(mode=0o700)
        with self.assertRaises(RunStoreError) as raised:
            record_first_failure(layout, self._failure(layout))
        self.assertEqual(raised.exception.code, "PATH_DRIFT")
        self.assertFalse((self.evidence / "runs").exists())
        self.assertEqual(self._directory_manifest(detached / "runs" / layout.run_id), original_manifest)
        self.assertTrue((detached / "runs" / layout.run_id / first.path).is_file())

    def test_34_failure_binding_rejects_real_evidence_directory_mode_drift_before_mutation(self):
        for suffix in ((), ("runs",), ("runs", "RUN")):
            with self.subTest(suffix=suffix):
                layout = self.layout(); parts = ("runs", layout.run_id) if suffix == ("runs", "RUN") else suffix
                target = Path(layout.evidence_path).parents[1] if not parts else Path(layout.evidence_path).parents[1].joinpath(*parts)
                if suffix == ():
                    target = self.evidence
                os.chmod(target, 0o777)
                try:
                    with self.assertRaises(RunStoreError):
                        record_first_failure(layout, self._failure(layout))
                    run_dir = Path(layout.evidence_path)
                    self.assertFalse((run_dir / "run-failure.json").exists())
                    self.assertFalse(any(item.name.startswith(".tmp-") for item in run_dir.iterdir()))
                finally:
                    os.chmod(target, 0o700)

    def test_35_ordinary_publish_rejects_state_and_area_mode_drift_before_mutation(self):
        for relative in ((), ("snapshot",), ("attempts",), ("cache",), ("tmp",)):
            with self.subTest(relative=relative):
                layout = self.layout(); target = Path(layout.state_path).joinpath(*relative)
                os.chmod(target, 0o777)
                try:
                    with self.assertRaises(RunStoreError):
                        self._store_publish(layout, "root", "run-manifest.json", {"a": 1})
                    evidence = Path(layout.evidence_path)
                    self.assertFalse((evidence / "run-manifest.json").exists())
                    self.assertFalse(any(item.name.startswith(".tmp-") for item in evidence.iterdir()))
                finally:
                    os.chmod(target, 0o700)

    def test_36_mkdir_open_binds_new_directory_before_fchmod_and_honors_umask(self):
        parent = self.base / "mkdir-parent"; parent.mkdir(mode=0o700)
        foreign = self.base / "foreign-directory"; foreign.mkdir(mode=0o755)
        (foreign / "keep").write_bytes(b"foreign-content")
        parent_fd = os.open(parent, store._DIR_FLAGS)
        self.addCleanup(os.close, parent_fd)
        real_open = os.open; swapped = {"done": False}

        def swap_before_open(path, *args, **kwargs):
            if path == "new-directory" and kwargs.get("dir_fd") == parent_fd and not swapped["done"]:
                swapped["done"] = True
                os.rename(parent / "new-directory", parent / "created-detached")
                os.rename(foreign, parent / "new-directory")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(store.os, "open", side_effect=swap_before_open):
            with self.assertRaises(RunStoreError) as raised:
                store._mkdir_open(parent_fd, "new-directory", reuse=False)
        self.assertEqual(raised.exception.code, "PATH_DRIFT")
        swapped_foreign = parent / "new-directory"
        self.assertEqual(stat.S_IMODE(swapped_foreign.stat().st_mode), 0o755)
        self.assertEqual((swapped_foreign / "keep").read_bytes(), b"foreign-content")
        self.assertTrue((parent / "created-detached").is_dir())

        previous_umask = os.umask(0o777)
        try:
            child_fd = store._mkdir_open(parent_fd, "umask-private", reuse=False)
        finally:
            os.umask(previous_umask)
        try:
            self.assertEqual(stat.S_IMODE(os.fstat(child_fd).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((parent / "umask-private").stat().st_mode), 0o700)
        finally:
            os.close(child_fd)

    def test_37_publish_rechecks_actual_private_parent_before_temp_open(self):
        cases = (
            ("failure", "evidence", "run-failure.json", lambda layout: record_first_failure(layout, self._failure(layout))),
            ("ordinary", "results", "SUITE-TEST.json", lambda layout: self._store_publish(layout, "results", "SUITE-TEST.json", {"a": 1})),
        )
        for kind, area, leaf, invoke in cases:
            with self.subTest(area=area):
                layout = self.layout()
                parent = Path(layout.evidence_path) if area == "evidence" else (
                    Path(layout.evidence_path) / "results" if area == "results" else Path(layout.state_path) / area
                )
                real_open = os.open; temp_opens = []

                def observe_temp_open(path, *args, **kwargs):
                    if isinstance(path, str) and path.startswith(".tmp-"):
                        temp_opens.append(path)
                    return real_open(path, *args, **kwargs)

                def mutate_after_binding(_layout):
                    os.chmod(parent, 0o755)

                verifier = "_verify_evidence_binding" if kind == "failure" else "_verify_live_layout"
                try:
                    with mock.patch.object(store, verifier, side_effect=mutate_after_binding), \
                         mock.patch.object(store.os, "open", side_effect=observe_temp_open):
                        with self.assertRaises(RunStoreError) as raised:
                            invoke(layout)
                    self.assertEqual(raised.exception.code, "PATH_DRIFT")
                    self.assertEqual(temp_opens, [])
                    self.assertFalse((parent / leaf).exists())
                    self.assertFalse(any(item.name.startswith(".tmp-") for item in parent.iterdir()))
                finally:
                    os.chmod(parent, 0o700)

    def test_38_snapshot_capture_lease_blocks_close_and_generic_snapshot_publish(self):
        layout = self.layout()
        with layout.snapshot_capture_lease() as lease:
            with self.assertRaises(RunStoreError) as active:
                layout.close()
            self.assertEqual(active.exception.code, "ACTIVE_OPERATION")
            with self.assertRaises(RunStoreError) as generic:
                layout.publish_json("snapshot", "source-snapshot-manifest.json", {"a": 1})
            self.assertEqual(generic.exception.code, "SNAPSHOT_SPECIAL_PUBLISH_REQUIRED")
            copied = store.SnapshotCaptureLease(lease.run_id, lease._nonce)
            with self.assertRaises(RunStoreError) as forged:
                layout._require_snapshot_lease(copied)
            self.assertEqual(forged.exception.code, "LEASE_INVALID")
            self.assertEqual(lease.run_id, layout.run_id)
        layout.close()

    @staticmethod
    def _snapshot_manifest(layout):
        return {"schema": "source-snapshot-manifest.v1", "run_id": layout.run_id, "head_sha": "a" * 40,
                "snapshot_mode": "clean-commit", "entry_count": 0, "total_bytes": 0, "entries": []}

    def test_39_pending_stage_order_ticket_forge_replay_and_consumption(self):
        layout = self.layout()
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
            later = {"schema": "run-failure.v1", "run_id": layout.run_id, "stage": "CHANGE_SET", "reason_code": "CHANGE_SET_MISMATCH", "run_manifest": None, "created_at": "2026-07-24T00:00:00Z", "terminal": True}
            with self.assertRaises(RunStoreError) as early:
                layout.record_first_failure(later)
            self.assertEqual(early.exception.code, "STAGE_ORDER_UNSAFE")
            with self.assertRaises(RunStoreError) as owner_early:
                layout.record_first_failure(later, _snapshot_lease=lease)
            self.assertEqual(owner_early.exception.code, "STAGE_ORDER_UNSAFE")
            forged = store.SnapshotPublicationTicket(ticket.run_id, ticket.expected_head_sha, ticket.publication, ticket.identity, ticket._nonce)
            with self.assertRaises(RunStoreError) as copied:
                layout.linearize_snapshot_success(forged, lease=lease)
            self.assertEqual(copied.exception.code, "TICKET_INVALID")
            self.assertEqual(layout.linearize_snapshot_success(ticket, lease=lease), ticket.publication)
            self.assertIsNone(layout._snapshot_ticket)
            with self.assertRaises(RunStoreError) as replay:
                layout.linearize_snapshot_success(ticket, lease=lease)
            self.assertEqual(replay.exception.code, "TICKET_INVALID")
        self.assertEqual(layout.record_first_failure(later).status, "RECORDED")

    def test_40_linearize_rechecks_public_layout_binding(self):
        layout = self.layout(); state = Path(layout.state_path); detached = self.base / "snapshot-detached"
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
            os.rename(state / "snapshot", detached); (state / "snapshot").mkdir(mode=0o700)
            with self.assertRaises(RunStoreError) as raised:
                layout.linearize_snapshot_success(ticket, lease=lease)
            self.assertTrue(raised.exception.published_may_exist)
            self.assertIn(raised.exception.code, {"PATH_DRIFT", "PUBLISH_VERIFY_FAILED"})

    def test_41_active_run_root_and_unhashable_stage_fail_typed(self):
        layout = self.layout()
        run_root = self._failure(layout)
        with layout.snapshot_capture_lease() as lease:
            with self.assertRaises(RunStoreError) as outsider:
                layout.record_first_failure(run_root)
            self.assertEqual(outsider.exception.code, "STAGE_ORDER_UNSAFE")
            with self.assertRaises(RunStoreError) as owner:
                layout.record_first_failure(run_root, _snapshot_lease=lease)
            self.assertEqual(owner.exception.code, "STAGE_ORDER_UNSAFE")
            invalid = dict(run_root); invalid["stage"] = []
            with self.assertRaises(RunStoreError) as unhashable:
                layout.record_first_failure(invalid, _snapshot_lease=lease)
            self.assertEqual(unhashable.exception.code, "FAILURE_INVALID")

    def test_42_snapshot_failure_consumes_pending_or_enters_published_failed(self):
        layout = self.layout()
        failure = {"schema": "run-failure.v1", "run_id": layout.run_id, "stage": "SNAPSHOT",
                   "reason_code": "SNAPSHOT_FAILED", "run_manifest": None,
                   "created_at": "2026-07-24T00:00:00Z", "terminal": True}
        with layout.snapshot_capture_lease() as lease:
            layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
            with self.assertRaises(RunStoreError) as pending:
                with layout.snapshot_capture_lease():
                    pass
            self.assertEqual(pending.exception.code, "ACTIVE_OPERATION")
            self.assertEqual(layout.record_first_failure(failure, _snapshot_lease=lease).status, "RECORDED")
            self.assertEqual(layout._snapshot_state, "TERMINAL")
            self.assertIsNone(layout._snapshot_ticket)
        with self.assertRaises(RunStoreError) as terminal:
            with layout.snapshot_capture_lease():
                pass
        self.assertEqual(terminal.exception.code, "SNAPSHOT_UNAVAILABLE")
        layout.close()

        self.tearDown(); self.setUp(); layout = self.layout()
        failure["run_id"] = layout.run_id
        with layout.snapshot_capture_lease() as lease:
            layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
            with mock.patch.object(store, "_publish", side_effect=RunStoreError("FAILURE_WRITE_FAILED")):
                with self.assertRaises(RunStoreError):
                    layout.record_first_failure(failure, _snapshot_lease=lease)
            self.assertEqual(layout._snapshot_state, "PUBLISHED_FAILED")
            self.assertIsNone(layout._snapshot_ticket)
            later = dict(failure); later.update({"stage": "CHANGE_SET", "reason_code": "CHANGE_SET_MISMATCH"})
            with self.assertRaises(RunStoreError) as blocked:
                layout.record_first_failure(later)
            self.assertEqual(blocked.exception.code, "STAGE_ORDER_UNSAFE")
            with self.assertRaises(RunStoreError) as unavailable:
                with layout.snapshot_capture_lease():
                    pass
            self.assertEqual(unavailable.exception.code, "SNAPSHOT_UNAVAILABLE")
        layout.close()

    def test_43_attempt0_is_bound_to_finalized_snapshot_and_cannot_be_generic(self):
        layout = self.layout()
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
            layout.linearize_snapshot_success(ticket, lease=lease)
            with self.assertRaises(RunStoreError) as generic:
                layout.publish_json("attempts", "attempt-0.json", {})
            self.assertEqual(generic.exception.code, "PUBLISH_AREA_INVALID")
            manifest = layout.begin_attempt0()
            self.assertEqual(manifest["head_sha"], "a" * 40)
            with self.assertRaises(RunStoreError) as duplicate:
                layout.begin_attempt0()
            self.assertEqual(duplicate.exception.code, "ATTEMPT_DUPLICATE")
            decision = adjudicate_parent_event("SPAWN_EXEC_FAILED", None, layout.run_id, "SUITE-RUE05A", "ENTRY-RUE05A-ATTEMPT0", 0)
            published = layout.publish_attempt0_decision(decision)
            self.assertEqual(published.leaf, "attempt-0.json")
            with self.assertRaises(RunStoreError) as replay:
                layout.publish_attempt0_decision(decision)
            self.assertEqual(replay.exception.code, "ATTEMPT_DUPLICATE")

    def test_44_attempt0_rejects_snapshot_name_replacement_before_claim(self):
        layout = self.layout()
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
            layout.linearize_snapshot_success(ticket, lease=lease)
        replacement = Path(layout.state_path) / "snapshot" / "replacement"
        replacement.write_bytes(b'{"entries":[],"entry_count":0,"head_sha":"' + b"a" * 40 + b'","run_id":"' + layout.run_id.encode() + b'","schema":"source-snapshot-manifest.v1","snapshot_mode":"clean-commit","total_bytes":0}')
        os.replace(replacement, Path(layout.state_path) / "snapshot" / "source-snapshot-manifest.json")
        with self.assertRaises(RunStoreError) as raised:
            layout.begin_attempt0()
        self.assertEqual(raised.exception.code, "SNAPSHOT_BINDING_MISMATCH")

    def test_45_terminal_failure_blocks_claim_and_publication_under_layout_lock(self):
        layout = self.layout()
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
            layout.linearize_snapshot_success(ticket, lease=lease)
        failure = {"schema": "run-failure.v1", "run_id": layout.run_id, "stage": "EXECUTE",
                   "reason_code": "INTERNAL_ERROR", "run_manifest": None,
                   "created_at": "2026-07-25T00:00:00Z", "terminal": True}
        layout.record_first_failure(failure)
        with self.assertRaises(RunStoreError) as blocked:
            layout.begin_attempt0()
        self.assertEqual(blocked.exception.code, "TERMINAL_CONFLICT")

        self.tearDown(); self.setUp(); layout = self.layout()
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
            layout.linearize_snapshot_success(ticket, lease=lease)
        layout.begin_attempt0()
        failure["run_id"] = layout.run_id
        layout.record_first_failure(failure)
        decision = adjudicate_parent_event("SPAWN_EXEC_FAILED", None, layout.run_id, "SUITE-RUE05A", "ENTRY-RUE05A-ATTEMPT0", 0)
        with self.assertRaises(RunStoreError) as coexist:
            layout.publish_attempt0_decision(decision)
        self.assertEqual(coexist.exception.code, "TERMINAL_CONFLICT")

    def test_46_publish_revalidates_snapshot_and_fixed_attempt_identity(self):
        def finalized_started():
            layout = self.layout()
            with layout.snapshot_capture_lease() as lease:
                ticket = layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
                layout.linearize_snapshot_success(ticket, lease=lease)
            layout.begin_attempt0()
            return layout

        decision_for = lambda layout, suite, entry: adjudicate_parent_event(
            "SPAWN_EXEC_FAILED", None, layout.run_id, suite, entry, 0
        )
        layout = finalized_started()
        forged = decision_for(layout, "SUITE-OTHER", "ENTRY-OTHER",)
        with self.assertRaises(RunStoreError) as identity:
            layout.publish_attempt0_decision(forged)
        self.assertEqual(identity.exception.code, "ATTEMPT_BINDING_MISMATCH")
        self.assertFalse((Path(layout.state_path) / "attempts/attempt-0.json").exists())

        for replacement_raw in (b"corrupt", None):
            layout = finalized_started()
            snapshot = Path(layout.state_path) / "snapshot"
            replacement = snapshot / "replacement"
            if replacement_raw is None:
                fake = self._snapshot_manifest(layout)
                fake["entries"] = [{"path": "x", "type": "file", "mode": "100644", "size": 0,
                                    "sha256": hashlib.sha256(b"").hexdigest()}]
                fake["entry_count"] = 1
                replacement_raw = store.canonical_json_bytes(fake)
            replacement.write_bytes(replacement_raw)
            os.chmod(replacement, 0o600)
            os.replace(replacement, snapshot / "source-snapshot-manifest.json")
            decision = decision_for(layout, "SUITE-RUE05A", "ENTRY-RUE05A-ATTEMPT0")
            with self.assertRaises(RunStoreError) as changed:
                layout.publish_attempt0_decision(decision)
            self.assertEqual(changed.exception.code, "SNAPSHOT_BINDING_MISMATCH")
            self.assertFalse((Path(layout.state_path) / "attempts/attempt-0.json").exists())

    def test_47_attempt0_publication_claim_is_one_way_across_leaf_deletion_replacement_and_failure(self):
        def started():
            layout = self.layout()
            with layout.snapshot_capture_lease() as lease:
                ticket = layout.publish_snapshot_manifest(self._snapshot_manifest(layout), expected_head_sha="a" * 40, lease=lease)
                layout.linearize_snapshot_success(ticket, lease=lease)
            layout.begin_attempt0()
            return layout

        def decisions(layout):
            infra = adjudicate_parent_event("SPAWN_EXEC_FAILED", None, layout.run_id, "SUITE-RUE05A", "ENTRY-RUE05A-ATTEMPT0", 0)
            adapter = {"schema": "adapter-result.v1", "run_id": layout.run_id, "suite_id": "SUITE-RUE05A",
                       "entrypoint_id": "ENTRY-RUE05A-ATTEMPT0", "attempt_index": 0,
                       "outcome_hint": "PASS", "classification_hint": "NONE", "reason_code": "NONE"}
            passed = adjudicate_adapter_attempt(adapter, 0, layout.run_id, "SUITE-RUE05A", "ENTRY-RUE05A-ATTEMPT0", 0)
            return infra, passed

        layout = started(); infra, passed = decisions(layout)
        layout.publish_attempt0_decision(infra)
        leaf = Path(layout.state_path) / "attempts/attempt-0.json"
        leaf.unlink()
        with self.assertRaises(RunStoreError) as deleted:
            layout.publish_attempt0_decision(passed)
        self.assertEqual(deleted.exception.code, "ATTEMPT_DUPLICATE")
        self.assertFalse(leaf.exists())

        layout = started(); infra, passed = decisions(layout)
        layout.publish_attempt0_decision(infra)
        replacement = Path(layout.state_path) / "attempts/replacement"
        replacement.write_bytes(b"foreign")
        os.replace(replacement, Path(layout.state_path) / "attempts/attempt-0.json")
        with self.assertRaises(RunStoreError) as replaced:
            layout.publish_attempt0_decision(passed)
        self.assertEqual(replaced.exception.code, "ATTEMPT_DUPLICATE")
        self.assertEqual((Path(layout.state_path) / "attempts/attempt-0.json").read_bytes(), b"foreign")

        layout = started(); infra, passed = decisions(layout)
        with mock.patch.object(store, "_publish", side_effect=RunStoreError("PUBLISH_VERIFY_FAILED", published_may_exist=True)):
            with self.assertRaises(RunStoreError):
                layout.publish_attempt0_decision(infra)
        with self.assertRaises(RunStoreError) as uncertain:
            layout.publish_attempt0_decision(passed)
        self.assertEqual(uncertain.exception.code, "ATTEMPT_DUPLICATE")

    def test_48_snapshot_ticket_never_adopts_same_byte_replacement_after_publish(self):
        layout = self.layout()
        real_publish = store._publish

        def publish_then_replace(*args, **kwargs):
            publication = real_publish(*args, **kwargs)
            if args[2] == "source-snapshot-manifest.json":
                leaf = Path(layout.state_path) / "snapshot/source-snapshot-manifest.json"
                replacement = leaf.parent / "replacement"
                replacement.write_bytes(leaf.read_bytes())
                os.chmod(replacement, 0o600)
                os.replace(replacement, leaf)
            return publication

        with layout.snapshot_capture_lease() as lease:
            with mock.patch.object(store, "_publish", side_effect=publish_then_replace):
                with self.assertRaises(RunStoreError) as raised:
                    layout.publish_snapshot_manifest(
                        self._snapshot_manifest(layout),
                        expected_head_sha="a" * 40,
                        lease=lease,
                    )
            self.assertEqual(raised.exception.code, "PUBLISH_VERIFY_FAILED")
            self.assertTrue(raised.exception.published_may_exist)
            self.assertNotEqual(layout._snapshot_state, "FINALIZED")
            self.assertIsNone(layout._snapshot_ticket)

    def test_49_finalized_snapshot_replacement_is_rejected_before_untrusted_size_read(self):
        for replacement_raw in (None, b"x" * (2 * 1024 * 1024)):
            with self.subTest(
                replacement="same-byte" if replacement_raw is None else "large",
            ):
                layout = self.layout()
                with layout.snapshot_capture_lease() as lease:
                    ticket = layout.publish_snapshot_manifest(
                        self._snapshot_manifest(layout),
                        expected_head_sha="a" * 40,
                        lease=lease,
                    )
                    layout.linearize_snapshot_success(ticket, lease=lease)
                leaf = (
                    Path(layout.state_path)
                    / "snapshot/source-snapshot-manifest.json"
                )
                raw = leaf.read_bytes() if replacement_raw is None else replacement_raw
                replacement = leaf.parent / "replacement"
                replacement.write_bytes(raw)
                os.chmod(replacement, 0o600)
                os.replace(replacement, leaf)
                replacement_identity = (leaf.stat().st_dev, leaf.stat().st_ino)
                real_read = store._read_exact

                def reject_replacement_read(fd, size, *, code):
                    item = os.fstat(fd)
                    if (item.st_dev, item.st_ino) == replacement_identity:
                        raise AssertionError("untrusted snapshot replacement was read")
                    return real_read(fd, size, code=code)

                with mock.patch.object(
                    store, "_read_exact", side_effect=reject_replacement_read,
                ):
                    with self.assertRaises(RunStoreError) as raised:
                        layout.begin_attempt0()
                self.assertEqual(
                    raised.exception.code, "SNAPSHOT_BINDING_MISMATCH",
                )

    def test_50_pending_snapshot_replacement_is_rejected_before_linearize_read(self):
        for replacement_raw in (None, b"x" * (2 * 1024 * 1024)):
            with self.subTest(
                replacement="same-byte" if replacement_raw is None else "large",
            ):
                layout = self.layout()
                with layout.snapshot_capture_lease() as lease:
                    ticket = layout.publish_snapshot_manifest(
                        self._snapshot_manifest(layout),
                        expected_head_sha="a" * 40,
                        lease=lease,
                    )
                    leaf = (
                        Path(layout.state_path)
                        / "snapshot/source-snapshot-manifest.json"
                    )
                    raw = leaf.read_bytes() if replacement_raw is None else replacement_raw
                    replacement = leaf.parent / "replacement"
                    replacement.write_bytes(raw)
                    os.chmod(replacement, 0o600)
                    os.replace(replacement, leaf)
                    replacement_identity = (leaf.stat().st_dev, leaf.stat().st_ino)
                    real_read = store._read_exact

                    def reject_replacement_read(fd, size, *, code):
                        item = os.fstat(fd)
                        if (item.st_dev, item.st_ino) == replacement_identity:
                            raise AssertionError(
                                "untrusted pending snapshot replacement was read"
                            )
                        return real_read(fd, size, code=code)

                    with mock.patch.object(
                        store,
                        "_read_exact",
                        side_effect=reject_replacement_read,
                    ):
                        with self.assertRaises(RunStoreError) as raised:
                            layout.linearize_snapshot_success(
                                ticket, lease=lease,
                            )
                    self.assertEqual(
                        raised.exception.code, "PUBLISH_VERIFY_FAILED",
                    )
                    self.assertTrue(raised.exception.published_may_exist)
                    self.assertNotEqual(layout._snapshot_state, "FINALIZED")

    def test_51_second_publish_verify_rejects_mode_drift_from_first_identity(self):
        layout = self.layout()
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(
                self._snapshot_manifest(layout),
                expected_head_sha="a" * 40,
                lease=lease,
            )
            layout.linearize_snapshot_success(ticket, lease=lease)
        layout.begin_attempt0()
        decision = adjudicate_parent_event(
            "SPAWN_EXEC_FAILED",
            None,
            layout.run_id,
            "SUITE-RUE05A",
            "ENTRY-RUE05A-ATTEMPT0",
            0,
        )
        leaf = Path(layout.state_path) / "attempts/attempt-0.json"
        real_fsync = store._fsync
        parent_fsyncs = {"count": 0}

        def chmod_between_verifications(fd, code="PUBLISH_IO_FAILED"):
            result = real_fsync(fd, code)
            if fd == layout._attempts_fd_required():
                parent_fsyncs["count"] += 1
                if parent_fsyncs["count"] == 2:
                    os.chmod(leaf, 0o644)
            return result

        with mock.patch.object(
            store, "_fsync", side_effect=chmod_between_verifications,
        ):
            with self.assertRaises(RunStoreError) as raised:
                layout.publish_attempt0_decision(decision)
        self.assertTrue(raised.exception.published_may_exist)
        self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o644)
        self.assertIsNone(layout._attempt0_publication)


if __name__ == "__main__":
    unittest.main(verbosity=2)
