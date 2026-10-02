"""Fake-only end-to-end tests for the public source runtime orchestration."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from test.quality.run_evidence.atomic_store import RunStoreError
from test.quality.run_evidence.attempt0_runner import TrustedCommandResult
from test.quality.run_evidence.manifest_contracts import canonical_json_bytes
from test.quality.source_gate import runtime as source_runtime
from test.quality.source_gate.runtime import (
    SourceRuntimeError,
    SourceRuntimeDependencies,
    SourceRuntimeInputs,
    _dependency_inventory,
    _materialize_bound_dependency_view,
    execute_source_gate_with_dependencies,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
HEAD = "a" * 40
BASE = "b" * 40
ZERO = "0" * 64


class SourceGateRuntime(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        )
        self.root = Path(self.temp.name) / "output"
        self.root.mkdir(mode=0o700)
        self.registry = Path(self.temp.name) / "cargo-registry"
        self.registry.mkdir(mode=0o700)
        self.cargo_roots = {}
        for leaf in ("index", "cache", "src"):
            path = self.registry / leaf
            path.mkdir(mode=0o755)
            path.chmod(0o755)
            self.cargo_roots["registry/" + leaf] = str(path)
        (self.registry / "index" / "config.json").write_bytes(b"{}\n")
        self.root_fd = os.open(
            self.root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        self.addCleanup(os.close, self.root_fd)
        self.addCleanup(self.temp.cleanup)
        self.catalog = json.loads(
            (REPO_ROOT / "quality/test-catalog.v1.json").read_text("utf-8"),
        )
        self.gates = json.loads(
            (REPO_ROOT / "quality/release-gates.v1.json").read_text("utf-8"),
        )
        self.inventory = (
            REPO_ROOT
            / "test/quality/fixtures/source_gate/expected_test_ids.v1.json"
        ).read_bytes()
        self.calls: list[tuple[str, int | None, str | None]] = []
        self.fail_suite: str | None = None

    def _inputs(self):
        return SourceRuntimeInputs(
            catalog=self.catalog,
            gates=self.gates,
            inventory_raw=self.inventory,
            head_sha=HEAD,
            merge_base_sha=BASE,
            tools={
                "PYTHON": "/fixed/bin/python3",
                "BASH": "/fixed/bin/bash",
                "NODE": "/fixed/bin/node",
                "CARGO": "/fixed/bin/cargo",
                "RUSTC": "/fixed/bin/rustc",
                "GIT": "/fixed/bin/git",
            },
            tool_identity_sha256="c" * 64,
            input_digests={
                "schema_bundle": ZERO,
                "catalog": ZERO,
                "gates": ZERO,
                "runner": ZERO,
                "fixtures": ZERO,
                "build_recipes": ZERO,
                "sanitized_environment": ZERO,
                "tools": ZERO,
            },
            rustup_home="/fixed/rustup",
            started_at="2026-07-26T00:00:00Z",
            completed_at="2026-07-26T00:01:00Z",
            platform={
                "os": "fake",
                "arch": "fake",
                "toolchain": "fake-only",
            },
            cargo_registry_root=str(self.registry),
            cargo_dependency_roots=self.cargo_roots,
        )

    @staticmethod
    def _capture(layout, inputs):
        snapshot = {
            "schema": "source-snapshot-manifest.v1",
            "run_id": layout.run_id,
            "head_sha": inputs.head_sha,
            "snapshot_mode": "clean-commit",
            "entry_count": 0,
            "total_bytes": 0,
            "entries": [],
        }
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(
                snapshot,
                expected_head_sha=inputs.head_sha,
                lease=lease,
            )
            layout.linearize_snapshot_success(ticket, lease=lease)
        return snapshot

    def _run_one(self, layout, plan, config):
        expected_tmp = Path(layout.state_path).parents[1] / "t"
        actual_tmp = Path(plan.environment["TMPDIR"])
        self.assertEqual(actual_tmp, expected_tmp)
        self.assertTrue(actual_tmp.is_dir())
        self.assertEqual(stat.S_IMODE(actual_tmp.stat().st_mode), 0o700)
        expected = list(plan.expected_test_ids)
        skipped = list(plan.approved_skipped_test_ids)
        ignored = list(plan.approved_ignored_test_ids)
        failed = plan.suite["id"] == self.fail_suite
        failed_ids = (
            [
                test_id for test_id in expected
                if test_id not in skipped and test_id not in ignored
            ][:1]
            if failed else []
        )
        observation = {
            "schema": "source-observation.v1",
            "run_id": layout.run_id,
            "suite_id": plan.suite["id"],
            "entrypoint_id": plan.suite["entrypoint_id"],
            "attempt_index": 0,
            "command_argv_sha256": plan.command_argv_sha256,
            "environment_sha256": plan.environment_sha256,
            "tool_identity_sha256": plan.tool_identity_sha256,
            "raw_process": {
                "state": "EXITED",
                "process_exit": 1 if failed else 0,
            },
            "adapter_exit": 10 if failed else 0,
            "executed": len(expected),
            "passed": (
                len(expected) - len(skipped) - len(ignored)
                - (1 if failed else 0)
            ),
            "failed": 1 if failed else 0,
            "skipped": len(skipped),
            "ignored": len(ignored),
            "todo": 0,
            "not_run": 0,
            "discovered_test_ids": expected,
            "executed_test_ids": expected,
            "failed_test_ids": failed_ids,
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
            "derived_tool": (
                {
                    "path": (
                        plan.driver_config["target_dir"]
                        + "/debug/csswitch-gateway"
                    ),
                    "mode": "0755",
                    "size": 7,
                    "sha256": "d" * 64,
                }
                if plan.suite["id"] == "SUITE-PY-LOOPBACK"
                else None
            ),
            "outcome_hint": "FAIL" if failed else "PASS",
            "classification_hint": "NONE",
            "reason_code": "ASSERTION_FAILED" if failed else "NONE",
        }
        return TrustedCommandResult(
            raw_process={
                "state": "EXITED",
                "process_exit": 10 if failed else 0,
            },
            stdout=b"",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            observation=observation,
            observation_acked=True,
        )

    def _recheck(self, stage, index, plan):
        self.calls.append((
            stage,
            index,
            None if plan is None else plan.suite["id"],
        ))
        return True

    def test_fake_fifteen_suite_run_seals_and_returns_zero(self):
        dependencies = SourceRuntimeDependencies(
            preflight=self._inputs,
            capture_snapshot=self._capture,
            run_one=self._run_one,
            recheck=self._recheck,
        )
        original_tmp_check = source_runtime._assert_source_tmp_binding
        checked_tmp_fds = []

        def check_cloexec(path, held_fd, *, require_empty=False):
            checked_tmp_fds.append(held_fd)
            self.assertTrue(
                fcntl.fcntl(held_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
            )
            return original_tmp_check(
                path,
                held_fd,
                require_empty=require_empty,
            )

        with mock.patch.object(
            source_runtime,
            "_assert_source_tmp_binding",
            side_effect=check_cloexec,
        ):
            rc, summary = execute_source_gate_with_dependencies(
                str(self.root),
                self.root_fd,
                dependencies,
            )
        self.assertGreaterEqual(len(checked_tmp_fds), 34)
        self.assertEqual(rc, 0)
        self.assertEqual(summary["aggregate_decision"], "PASS")
        run_root = (
            self.root / "evidence" / "runs" / summary["run_id"]
        )
        self.assertTrue((run_root / "completion-seal.json").is_file())
        self.assertTrue((run_root / "evidence-manifest.json").is_file())
        self.assertEqual(
            len(list((run_root / "results").glob("*.observation.json"))),
            15,
        )
        self.assertEqual(
            len([
                item
                for item in (run_root / "results").glob("*.json")
                if not item.name.endswith(".observation.json")
            ]),
            15,
        )
        self.assertEqual(
            [stage for stage, _, _ in self.calls].count("suite-before"),
            15,
        )
        self.assertEqual(
            [stage for stage, _, _ in self.calls].count("suite-after"),
            15,
        )
        self.assertEqual(self.calls[-1][0], "before-seal")
        state_run = next((self.root / "state" / "runs").iterdir())
        cargo_home = state_run / "cargo-home"
        self.assertFalse((cargo_home / "registry").is_symlink())
        self.assertEqual(
            (cargo_home / "registry/index/config.json").read_bytes(),
            b"{}\n",
        )
        self.assertIn(
            "offline = true",
            (cargo_home / "config.toml").read_text("utf-8"),
        )
        source_tmp = self.root / "state" / "t"
        source_tmp_fd = os.open(
            source_tmp,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            child = source_tmp / "ordinary-suite-child"
            child.write_bytes(b"ok")
            source_runtime._assert_source_tmp_binding(
                str(source_tmp),
                source_tmp_fd,
            )
            child.unlink()
            source_tmp.chmod(0o755)
            with self.assertRaisesRegex(
                SourceRuntimeError,
                "source temp binding lost",
            ):
                source_runtime._assert_source_tmp_binding(
                    str(source_tmp),
                    source_tmp_fd,
                )
            source_tmp.chmod(0o700)

            displaced = source_tmp.with_name("t-held")
            source_tmp.rename(displaced)
            source_tmp.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                SourceRuntimeError,
                "source temp binding lost",
            ):
                source_runtime._assert_source_tmp_binding(
                    str(source_tmp),
                    source_tmp_fd,
                )
            source_tmp.rmdir()
            displaced.rename(source_tmp)

            source_tmp.rename(displaced)
            source_tmp.symlink_to(displaced, target_is_directory=True)
            with self.assertRaisesRegex(
                SourceRuntimeError,
                "source temp binding lost",
            ):
                source_runtime._assert_source_tmp_binding(
                    str(source_tmp),
                    source_tmp_fd,
                )
            source_tmp.unlink()
            displaced.rename(source_tmp)
        finally:
            os.close(source_tmp_fd)

    def test_rust_desktop_worst_case_observation_fits_source_limit(self):
        inputs = self._inputs()
        plans = source_runtime.build_source_plans(
            inputs.catalog,
            inputs.gates,
            inputs.inventory_raw,
            tools=inputs.tools,
            tool_identity_sha256=inputs.tool_identity_sha256,
            run_home="/fixed/source-home",
            run_tmp="/fixed/source-tmp",
            offline_cargo_home="/fixed/cargo-home",
            rustup_home=inputs.rustup_home,
            gateway_target="/fixed/gateway-target",
        )
        desktop = next(
            plan
            for plan in plans
            if plan.suite["id"] == "SUITE-RUST-DESKTOP"
        )
        bound = source_runtime._source_observation_size_bound(desktop)
        self.assertEqual(len(desktop.expected_test_ids), 443)
        self.assertGreater(bound, 64 * 1024)
        self.assertLessEqual(
            bound,
            source_runtime._SOURCE_OBSERVATION_LIMIT_BYTES,
        )
        suffix_bytes = len(os.fsencode("/state/t"))
        exact_root_bytes = (
            source_runtime._DARWIN_UNIX_PATH_MAX_BYTES
            - source_runtime._SOURCE_TMP_DESCENDANT_BUDGET_BYTES
            - suffix_bytes
        )
        exact_root = "/" + ("a" * (exact_root_bytes - 1))
        exact_tmp = source_runtime._source_tmp_path(
            exact_root,
            {"os": "darwin"},
        )
        self.assertEqual(
            len(os.fsencode(exact_tmp))
            + source_runtime._SOURCE_TMP_DESCENDANT_BUDGET_BYTES,
            source_runtime._DARWIN_UNIX_PATH_MAX_BYTES,
        )
        with self.assertRaisesRegex(
            SourceRuntimeError,
            "source temp socket capacity",
        ):
            source_runtime._source_tmp_path(
                exact_root + "a",
                {"os": "darwin"},
            )
        multibyte_root = exact_root[:-1] + "é"
        self.assertEqual(len(multibyte_root), len(exact_root))
        with self.assertRaisesRegex(
            SourceRuntimeError,
            "source temp socket capacity",
        ):
            source_runtime._source_tmp_path(
                multibyte_root,
                {"os": "darwin"},
            )

    def test_observation_capacity_precheck_stops_before_run_manifest(self):
        run_calls = 0

        def run_one(layout, plan, config):
            nonlocal run_calls
            run_calls += 1
            return self._run_one(layout, plan, config)

        dependencies = SourceRuntimeDependencies(
            preflight=self._inputs,
            capture_snapshot=self._capture,
            run_one=run_one,
            recheck=self._recheck,
        )
        with mock.patch.object(
            source_runtime,
            "_SOURCE_OBSERVATION_LIMIT_BYTES",
            64 * 1024,
        ):
            with self.assertRaisesRegex(
                SourceRuntimeError,
                "source observation capacity",
            ):
                execute_source_gate_with_dependencies(
                    str(self.root),
                    self.root_fd,
                    dependencies,
                )
        self.assertEqual(run_calls, 0)
        self.assertFalse(any(
            self.root.glob("evidence/runs/*/run-manifest.json"),
        ))
        with tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        ) as temp:
            output = Path(temp) / "output"
            output.mkdir(mode=0o700)
            root_fd = os.open(
                output,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )

            def darwin_inputs():
                return replace(
                    self._inputs(),
                    platform={
                        "os": "darwin",
                        "arch": "arm64",
                        "toolchain": "fake-only",
                    },
                )

            dependencies = SourceRuntimeDependencies(
                preflight=darwin_inputs,
                capture_snapshot=self._capture,
                run_one=self._run_one,
                recheck=self._recheck,
            )
            try:
                with mock.patch.object(
                    source_runtime,
                    "_SOURCE_TMP_DESCENDANT_BUDGET_BYTES",
                    4096,
                ):
                    with self.assertRaisesRegex(
                        SourceRuntimeError,
                        "source temp socket capacity",
                    ):
                        execute_source_gate_with_dependencies(
                            str(output),
                            root_fd,
                            dependencies,
                        )
            finally:
                os.close(root_fd)
            self.assertEqual(list(output.iterdir()), [])
        for unsafe_kind in ("file", "symlink", "wrong-mode-directory"):
            with self.subTest(
                unsafe_kind=unsafe_kind,
            ), tempfile.TemporaryDirectory(
                dir=os.path.realpath(tempfile.gettempdir()),
            ) as temp:
                output = Path(temp) / "output"
                output.mkdir(mode=0o700)
                root_fd = os.open(
                    output,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                )

                def capture_with_preoccupied_tmp(layout, inputs):
                    snapshot = self._capture(layout, inputs)
                    source_tmp = output / "state" / "t"
                    if unsafe_kind == "file":
                        source_tmp.write_bytes(b"foreign")
                    elif unsafe_kind == "symlink":
                        source_tmp.symlink_to(output, target_is_directory=True)
                    else:
                        source_tmp.mkdir(mode=0o755)
                    return snapshot

                dependencies = SourceRuntimeDependencies(
                    preflight=self._inputs,
                    capture_snapshot=capture_with_preoccupied_tmp,
                    run_one=self._run_one,
                    recheck=self._recheck,
                )
                try:
                    with self.assertRaisesRegex(
                        SourceRuntimeError,
                        "source temp creation",
                    ):
                        execute_source_gate_with_dependencies(
                            str(output),
                            root_fd,
                            dependencies,
                        )
                finally:
                    os.close(root_fd)
                self.assertFalse(any(
                    output.glob("evidence/runs/*/completion-seal.json"),
                ))

    def test_preseal_drift_leaves_no_completion_seal(self):
        bound_digest = None
        scan_errors = []

        def recheck(stage, index, plan):
            nonlocal bound_digest
            self.calls.append((
                stage,
                index,
                None if plan is None else plan.suite["id"],
            ))
            if (
                stage == "suite-before"
                and bound_digest is None
                and "CARGO_HOME" in plan.environment
            ):
                cargo_home = Path(plan.environment["CARGO_HOME"])
                roots = {
                    "registry/index": str(cargo_home / "registry/index"),
                    "registry/cache": str(cargo_home / "registry/cache"),
                    "registry/src": str(cargo_home / "registry/src"),
                }
                try:
                    _, bound_digest = _dependency_inventory(roots)
                except SourceRuntimeError as exc:
                    scan_errors.append(str(exc))
                    return False
            if stage == "before-seal":
                self.assertIsNotNone(bound_digest)
                cargo_home = next(
                    (self.root / "state" / "runs").iterdir(),
                ) / "cargo-home"
                target = cargo_home / "registry/index/config.json"
                target.write_bytes(b'{"changed":true}\n')
                roots = {
                    "registry/index": str(cargo_home / "registry/index"),
                    "registry/cache": str(cargo_home / "registry/cache"),
                    "registry/src": str(cargo_home / "registry/src"),
                }
                _, actual = _dependency_inventory(roots)
                return actual == bound_digest
            return True

        dependencies = SourceRuntimeDependencies(
            preflight=self._inputs,
            capture_snapshot=self._capture,
            run_one=self._run_one,
            recheck=recheck,
        )
        caught = None
        try:
            execute_source_gate_with_dependencies(
                str(self.root),
                self.root_fd,
                dependencies,
            )
        except Exception as exc:
            caught = exc
        self.assertIsNotNone(caught)
        self.assertEqual(scan_errors, [])
        self.assertEqual(
            self.calls[-1][0],
            "before-seal",
            repr(caught),
        )
        self.assertFalse(any(
            self.root.glob("evidence/runs/*/completion-seal.json"),
        ))
        failure_path = next(
            self.root.glob("evidence/runs/*/run-failure.json"),
        )
        failure = json.loads(failure_path.read_text("utf-8"))
        self.assertEqual(failure["stage"], "AGGREGATE")
        self.assertEqual(failure["reason_code"], "INPUT_DRIFT")
        self.assertIsNone(failure["run_manifest"])
        with tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        ) as temp:
            output = Path(temp) / "output"
            output.mkdir(mode=0o700)
            root_fd = os.open(
                output,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            mutated = False

            def mutate_tmp_after_suite(layout, plan, config):
                nonlocal mutated
                result = self._run_one(layout, plan, config)
                if not mutated:
                    Path(plan.environment["TMPDIR"]).chmod(0o755)
                    mutated = True
                return result

            dependencies = SourceRuntimeDependencies(
                preflight=self._inputs,
                capture_snapshot=self._capture,
                run_one=mutate_tmp_after_suite,
                recheck=self._recheck,
            )
            try:
                with self.assertRaisesRegex(
                    SourceRuntimeError,
                    "source temp binding lost",
                ):
                    execute_source_gate_with_dependencies(
                        str(output),
                        root_fd,
                        dependencies,
                    )
            finally:
                tmp_path = output / "state" / "t"
                if tmp_path.exists():
                    tmp_path.chmod(0o700)
                os.close(root_fd)
            self.assertTrue(mutated)
            self.assertFalse(any(
                output.glob("evidence/runs/*/completion-seal.json"),
            ))

    def test_one_failed_suite_still_seals_fail_and_returns_ten(self):
        self.fail_suite = "SUITE-QUALITY-METADATA"
        dependencies = SourceRuntimeDependencies(
            preflight=self._inputs,
            capture_snapshot=self._capture,
            run_one=self._run_one,
            recheck=self._recheck,
        )
        rc, summary = execute_source_gate_with_dependencies(
            str(self.root),
            self.root_fd,
            dependencies,
        )
        self.assertEqual(rc, 10)
        self.assertEqual(summary["aggregate_decision"], "FAIL")
        run_root = (
            self.root / "evidence" / "runs" / summary["run_id"]
        )
        self.assertTrue((run_root / "completion-seal.json").is_file())

    def test_gateway_driver_or_parent_failure_runs_once_and_never_seals(self):
        for reason in ("gateway build failed", "derived parent mismatch"):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(
                dir=os.path.realpath(tempfile.gettempdir()),
            ) as temp:
                output = Path(temp) / "output"
                output.mkdir(mode=0o700)
                root_fd = os.open(
                    output,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                )
                calls: list[str] = []

                def run_one(layout, plan, config):
                    calls.append(plan.suite["id"])
                    if plan.suite["id"] == "SUITE-PY-LOOPBACK":
                        raise SourceRuntimeError(reason)
                    return self._run_one(layout, plan, config)

                dependencies = SourceRuntimeDependencies(
                    preflight=self._inputs,
                    capture_snapshot=self._capture,
                    run_one=run_one,
                    recheck=self._recheck,
                )
                try:
                    with self.assertRaisesRegex(
                        SourceRuntimeError,
                        reason,
                    ):
                        execute_source_gate_with_dependencies(
                            str(output),
                            root_fd,
                            dependencies,
                        )
                finally:
                    os.close(root_fd)
                self.assertEqual(
                    calls.count("SUITE-PY-LOOPBACK"),
                    1,
                )
                self.assertNotIn(
                    "SUITE-SHELL-SCRIPTS",
                    calls,
                )
                self.assertFalse(any(
                    output.glob(
                        "evidence/runs/*/completion-seal.json",
                    ),
                ))

    def test_execute_exception_publishes_partial_failure_and_never_seals(self):
        primary = SourceRuntimeError("suite transport failed")
        calls: list[str] = []

        def run_one(layout, plan, config):
            calls.append(plan.suite["id"])
            if plan.suite["id"] == "SUITE-RUST-DESKTOP":
                raise primary
            return self._run_one(layout, plan, config)

        dependencies = SourceRuntimeDependencies(
            preflight=self._inputs,
            capture_snapshot=self._capture,
            run_one=run_one,
            recheck=self._recheck,
        )
        with self.assertRaises(SourceRuntimeError) as raised:
            execute_source_gate_with_dependencies(
                str(self.root),
                self.root_fd,
                dependencies,
            )
        self.assertIs(raised.exception, primary)
        self.assertEqual(calls[-1], "SUITE-RUST-DESKTOP")
        run_root = next((self.root / "evidence/runs").iterdir())
        failure = json.loads(
            (run_root / "run-failure.json").read_text("utf-8"),
        )
        self.assertEqual(failure["stage"], "EXECUTE")
        self.assertEqual(failure["reason_code"], "PARTIAL_RESULTS")
        self.assertIsNone(failure["run_manifest"])
        self.assertFalse((run_root / "completion-seal.json").exists())
        self.assertEqual(
            len(list((run_root / "results").glob("*.observation.json"))),
            8,
        )

    def test_failure_record_error_does_not_replace_execute_primary(self):
        primary = SourceRuntimeError("primary execute failure")
        secondary = RunStoreError(
            "FAILURE_PUBLISH_FAILED",
            stage="FAILURE",
        )

        def run_one(layout, plan, config):
            raise primary

        dependencies = SourceRuntimeDependencies(
            preflight=self._inputs,
            capture_snapshot=self._capture,
            run_one=run_one,
            recheck=self._recheck,
        )
        with mock.patch.object(
            source_runtime.RunLayout,
            "record_first_failure",
            side_effect=secondary,
        ):
            with self.assertRaises(SourceRuntimeError) as raised:
                execute_source_gate_with_dependencies(
                    str(self.root),
                    self.root_fd,
                    dependencies,
                )
        self.assertIs(raised.exception, primary)
        self.assertFalse(any(
            self.root.glob("evidence/runs/*/completion-seal.json"),
        ))

    def test_preflight_dependency_drift_stops_before_run_and_seal(self):
        expected_inventory, expected_digest = _dependency_inventory(
            self.cargo_roots,
        )
        run_calls = 0
        drifted = False

        def recheck(stage, index, plan):
            nonlocal drifted
            if stage == "after-snapshot":
                # Model drift immediately after the recheck's closing read and
                # before materialization starts.
                target = self.registry / "index" / "config.json"
                target.write_bytes(b'{"drifted":true}\n')
                drifted = True
            return True

        def prepare(inputs, cargo_home):
            _materialize_bound_dependency_view(
                inputs.cargo_dependency_roots,
                cargo_home,
                expected_inventory=expected_inventory,
                expected_digest=expected_digest,
            )

        def run_one(layout, plan, config):
            nonlocal run_calls
            run_calls += 1
            return self._run_one(layout, plan, config)

        dependencies = SourceRuntimeDependencies(
            preflight=self._inputs,
            capture_snapshot=self._capture,
            run_one=run_one,
            recheck=recheck,
            prepare_cargo_view=prepare,
        )
        with self.assertRaisesRegex(
            SourceRuntimeError,
            "offline dependency preflight drift",
        ):
            execute_source_gate_with_dependencies(
                str(self.root),
                self.root_fd,
                dependencies,
            )
        self.assertTrue(drifted)
        self.assertEqual(run_calls, 0)
        self.assertFalse(any(
            self.root.glob("evidence/runs/*/completion-seal.json"),
        ))


class ProductionInputAuthority(unittest.TestCase):
    def _controlled_production_input_digests(
        self,
        root: Path,
        offline_records,
        *,
        repeat: int = 1,
    ):
        account_home = root / "account"
        rustup_home = account_home / ".rustup"
        cargo_registry = account_home / ".cargo/registry"
        rustup_home.mkdir(parents=True, mode=0o755, exist_ok=True)
        for leaf in ("index", "cache", "src"):
            (cargo_registry / leaf).mkdir(
                parents=True,
                mode=0o755,
                exist_ok=True,
            )
        paths = (str(rustup_home), str(cargo_registry))
        records = dict(zip(paths, offline_records))

        def tool_record(path):
            return {
                "path": path,
                "resolved_path": path,
                "mode": 0o755,
                "owner": os.geteuid(),
                "nlink": 1,
                "size": 1,
                "sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
            }

        python_authority = {
            "launcher": tool_record("/usr/bin/python3"),
            "process_executable": tool_record("/controlled/Python"),
        }
        plan = source_runtime.SourceSuitePlan(
            suite={
                "id": "SUITE-CONTROLLED",
                "source_paths": ["test/controlled-runner.py"],
                "fixture_paths": ["test/controlled-fixture.json"],
                "build_recipe_paths": ["test/controlled-build.txt"],
            },
            argv=("/fixed/bin/python3",),
            environment={"HOME": "/controlled/home"},
            expected_test_ids=("controlled.test",),
            approved_skipped_test_ids=(),
            approved_ignored_test_ids=(),
            approved_ignored_tests={},
            command_argv_sha256="1" * 64,
            environment_sha256="2" * 64,
            tool_identity_sha256="3" * 64,
        )
        snapshot = {
            "entries": [
                {
                    "path": path,
                    "type": "file",
                    "mode": "0644",
                    "size": 1,
                    "sha256": "4" * 64,
                }
                for path in (
                    "quality/schema/controlled.json",
                    "test/controlled-runner.py",
                    "test/controlled-fixture.json",
                    "test/controlled-build.txt",
                )
            ],
        }
        dependency_root = str(root / "python-dependencies")
        git_binding = (HEAD, "c" * 40, BASE)
        rue_cli = mock.Mock()
        rue_cli._read_regular.side_effect = lambda path: (
            path.read_bytes(),
            path.stat(),
        )
        rue_cli._dependency_bootstrap.return_value = (
            dependency_root,
            [{"name": "controlled", "version": "1"}],
        )
        rue_cli._git_binding.return_value = git_binding
        rue_cli._now.return_value = "2026-07-26T00:00:00Z"
        with (
            mock.patch.dict(
                source_runtime.sys.modules,
                {"test.quality.run_evidence.cli": rue_cli},
            ),
            mock.patch.object(
                source_runtime.pwd,
                "getpwuid",
                return_value=mock.Mock(pw_dir=str(account_home)),
            ),
            mock.patch.object(
                source_runtime,
                "_open_python_composite_authority",
                return_value=({}, python_authority),
            ),
            mock.patch.object(
                source_runtime,
                "_tool_record",
                side_effect=tool_record,
            ),
            mock.patch.object(
                source_runtime,
                "_directory_record",
                side_effect=lambda path: records[path],
            ),
        ):
            dependencies = source_runtime._production_dependencies(-1)
            inputs = dependencies.preflight()
        try:
            digests = tuple(
                dependencies.input_digests(snapshot, (plan,), inputs)
                for _ in range(repeat)
            )
            return (
                digests[0] if repeat == 1 else digests,
                inputs.catalog,
            )
        finally:
            dependencies.close()

    def test_production_input_digests_accept_bound_directory_records(self):
        with tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        ) as temp:
            digests, _ = self._controlled_production_input_digests(
                Path(temp),
                (
                    (1, 2, stat.S_IFDIR | 0o755, os.geteuid(), 2, 3, 4),
                    (5, 6, stat.S_IFDIR | 0o755, os.geteuid(), 3, 7, 8),
                ),
            )
        self.assertEqual(set(digests), source_runtime._DIGEST_KEYS)
        self.assertTrue(all(
            len(value) == 64
            and all(char in "0123456789abcdef" for char in value)
            for value in digests.values()
        ))

    def test_production_input_digests_are_stable_for_same_identity(self):
        records = (
            (1, 2, stat.S_IFDIR | 0o755, os.geteuid(), 2, 3, 4),
            (5, 6, stat.S_IFDIR | 0o755, os.geteuid(), 3, 7, 8),
        )
        with tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        ) as temp:
            digests, _ = self._controlled_production_input_digests(
                Path(temp),
                records,
                repeat=2,
            )
        self.assertEqual(digests[0], digests[1])

    def test_offline_root_identity_and_path_only_change_tools_digest(self):
        records = (
            (1, 2, stat.S_IFDIR | 0o755, os.geteuid(), 2, 3, 4),
            (5, 6, stat.S_IFDIR | 0o755, os.geteuid(), 3, 7, 8),
        )
        changed_records = (
            (1, 9, stat.S_IFDIR | 0o755, os.geteuid(), 2, 3, 4),
            records[1],
        )
        with tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        ) as temp:
            root = Path(temp)
            baseline, baseline_catalog = (
                self._controlled_production_input_digests(
                    root / "same-path",
                    records,
                )
            )
            changed_identity, changed_catalog = (
                self._controlled_production_input_digests(
                    root / "same-path",
                    changed_records,
                )
            )
            changed_path, path_catalog = (
                self._controlled_production_input_digests(
                    root / "changed-path",
                    records,
                )
            )
        self.assertNotEqual(baseline["tools"], changed_identity["tools"])
        self.assertNotEqual(baseline["tools"], changed_path["tools"])
        for changed in (changed_identity, changed_path):
            self.assertEqual(
                {
                    key: value
                    for key, value in baseline.items()
                    if key != "tools"
                },
                {
                    key: value
                    for key, value in changed.items()
                    if key != "tools"
                },
            )
        self.assertEqual(
            baseline["catalog"],
            hashlib.sha256(
                (REPO_ROOT / "quality/test-catalog.v1.json").read_bytes(),
            ).hexdigest(),
        )
        self.assertEqual(baseline_catalog, changed_catalog)
        self.assertEqual(baseline_catalog, path_catalog)

    def test_malformed_offline_root_records_cannot_produce_digest(self):
        valid = (
            1,
            2,
            stat.S_IFDIR | 0o755,
            os.geteuid(),
            2,
            3,
            4,
        )
        malformed = (
            list(valid),
            valid[:-1],
            (*valid[:-1], "4"),
            (*valid[:-1], True),
            (valid[0], valid[1], stat.S_IFREG | 0o755, *valid[3:]),
            (valid[0], valid[1], valid[2], os.geteuid() + 1, *valid[4:]),
        )
        for index, record in enumerate(malformed):
            with self.subTest(index=index), tempfile.TemporaryDirectory(
                dir=os.path.realpath(tempfile.gettempdir()),
            ) as temp:
                with self.assertRaisesRegex(
                    SourceRuntimeError,
                    "offline Rust view identity",
                ):
                    self._controlled_production_input_digests(
                        Path(temp),
                        (record, valid),
                    )

    def test_real_schema_and_only_three_tracked_locks_are_read(self):
        payloads = {
            path: (REPO_ROOT / path).read_bytes()
            for path in (
                *source_runtime._SOURCE_METADATA_PATHS.values(),
                *source_runtime._SELECTED_CARGO_LOCK_PATHS,
            )
        }
        seen: list[str] = []

        def read(path):
            seen.append(path)
            return payloads[path]

        raw, paths, catalog, gates = (
            source_runtime._read_production_inputs(read)
        )
        self.assertEqual(
            paths["kernel"],
            "quality/schema/quality-kernel.v1.schema.json",
        )
        self.assertNotIn("quality/quality-kernel.v1.json", seen)
        self.assertNotIn("desktop/codex-network/Cargo.lock", seen)
        self.assertEqual(
            tuple(
                path for path in seen
                if path.endswith("/Cargo.lock")
            ),
            source_runtime._SELECTED_CARGO_LOCK_PATHS,
        )
        self.assertEqual(raw["catalog"], payloads[paths["catalog"]])
        self.assertEqual(catalog["schema"], "test-catalog.v1")
        self.assertEqual(gates["schema"], "release-gates.v1")

    def test_missing_real_schema_cannot_fall_back_to_legacy_looking_path(self):
        payloads = {
            path: (REPO_ROOT / path).read_bytes()
            for path in (
                *source_runtime._SOURCE_METADATA_PATHS.values(),
                *source_runtime._SELECTED_CARGO_LOCK_PATHS,
            )
        }
        real = "quality/schema/quality-kernel.v1.schema.json"
        payloads.pop(real)
        payloads["quality/quality-kernel.v1.json"] = b"{}\n"
        seen: list[str] = []

        def read(path):
            seen.append(path)
            return payloads[path]

        with self.assertRaisesRegex(
            SourceRuntimeError,
            "source metadata input missing",
        ):
            source_runtime._read_production_inputs(read)
        self.assertIn(real, seen)
        self.assertNotIn("quality/quality-kernel.v1.json", seen)
        self.assertNotIn("desktop/codex-network/Cargo.lock", seen)

    def test_process_image_lookup_rejects_unavailable_and_truncated(self):
        capacity = source_runtime._PROC_PIDPATH_CAPACITY
        invalid = (
            ("unavailable", lambda pid, size: (0, b"")),
            (
                "truncated",
                lambda pid, size: (
                    capacity - 1,
                    b"x" * (capacity - 1),
                ),
            ),
            ("embedded-nul", lambda pid, size: (4, b"/x\x00")),
        )
        for label, query in invalid:
            with self.subTest(label=label), self.assertRaises(
                SourceRuntimeError,
            ):
                source_runtime._current_process_image_path(query)

    def test_composite_authority_rejects_alternate_image_and_named_drift(self):
        default_fds, default_authority = (
            source_runtime._open_python_composite_authority()
        )
        try:
            self.assertTrue(
                source_runtime._recheck_python_composite_authority(
                    default_fds,
                    default_authority,
                ),
            )
        finally:
            for fd in default_fds.values():
                os.close(fd)
        with tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        ) as temp:
            root = Path(temp)
            launcher = root / "python3"
            process = root / "Python"
            alternate = root / "Alternate"
            for path, raw in (
                (launcher, b"launcher"),
                (process, b"process"),
                (alternate, b"alternate"),
            ):
                path.write_bytes(raw)
                path.chmod(0o755)
            fds, authority = (
                source_runtime._open_python_composite_authority(
                    launcher_path=str(launcher),
                    image_path=str(process),
                    entry_path=str(process),
                    reviewed_entry_path=str(process),
                    reviewed_image_path=str(process),
                )
            )
            try:
                self.assertTrue(
                    source_runtime._recheck_python_composite_authority(
                        fds,
                        authority,
                        launcher_path=str(launcher),
                        image_path=str(process),
                        entry_path=str(process),
                        reviewed_entry_path=str(process),
                        reviewed_image_path=str(process),
                    ),
                )
                self.assertFalse(
                    source_runtime._recheck_python_composite_authority(
                        fds,
                        authority,
                        launcher_path=str(launcher),
                        image_path=str(alternate),
                        entry_path=str(alternate),
                        reviewed_entry_path=str(process),
                        reviewed_image_path=str(process),
                    ),
                )
                replacement = root / "replacement"
                replacement.write_bytes(b"replacement")
                replacement.chmod(0o755)
                os.replace(replacement, launcher)
                self.assertFalse(
                    source_runtime._recheck_python_composite_authority(
                        fds,
                        authority,
                        launcher_path=str(launcher),
                        image_path=str(process),
                        entry_path=str(process),
                        reviewed_entry_path=str(process),
                        reviewed_image_path=str(process),
                    ),
                )
            finally:
                for fd in fds.values():
                    os.close(fd)
            with self.assertRaisesRegex(
                SourceRuntimeError,
                "process executable unreviewed",
            ):
                source_runtime._open_python_composite_authority(
                    launcher_path=str(launcher),
                    image_path=str(alternate),
                    entry_path=str(alternate),
                    reviewed_entry_path=str(process),
                    reviewed_image_path=str(process),
                )


class DerivedGatewayAuthority(unittest.TestCase):
    def _target(self, root: Path):
        target = root / "gateway-target"
        debug = target / "debug"
        debug.mkdir(parents=True, mode=0o755)
        target.chmod(0o700)
        debug.chmod(0o755)
        binary = debug / "csswitch-gateway"
        binary.write_bytes(b"current-source-gateway")
        binary.chmod(0o755)
        fd = os.open(
            target,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        return target, binary, fd

    def test_parent_happy_and_marker_mismatch(self):
        with tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        ) as temp:
            target, binary, fd = self._target(Path(temp))
            try:
                record = source_runtime._parent_gateway_record(
                    fd,
                    str(target),
                )
                self.assertEqual(
                    record["sha256"],
                    hashlib.sha256(binary.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    source_runtime._verify_parent_gateway_record(
                        fd,
                        str(target),
                        record,
                    ),
                    record,
                )
                with self.assertRaisesRegex(
                    SourceRuntimeError,
                    "derived gateway parent mismatch",
                ):
                    source_runtime._verify_parent_gateway_record(
                        fd,
                        str(target),
                        {**record, "sha256": "0" * 64},
                    )
            finally:
                os.close(fd)

    def test_parent_rejects_binary_mutation_and_path_rebind(self):
        for case in ("mutate", "rebind"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                dir=os.path.realpath(tempfile.gettempdir()),
            ) as temp:
                target, binary, fd = self._target(Path(temp))
                real_read = source_runtime.os.read
                fired = False

                def race(read_fd, size):
                    nonlocal fired
                    chunk = real_read(read_fd, size)
                    if chunk and not fired:
                        item = os.fstat(read_fd)
                        if (
                            stat.S_ISREG(item.st_mode)
                            and stat.S_IMODE(item.st_mode) == 0o755
                        ):
                            fired = True
                            if case == "mutate":
                                binary.write_bytes(b"mutated-gateway")
                                binary.chmod(0o755)
                            else:
                                replacement = binary.with_name(
                                    "replacement",
                                )
                                replacement.write_bytes(
                                    b"replacement-gateway",
                                )
                                replacement.chmod(0o755)
                                os.replace(replacement, binary)
                    return chunk

                try:
                    with mock.patch.object(
                        source_runtime.os,
                        "read",
                        side_effect=race,
                    ):
                        with self.assertRaises(SourceRuntimeError):
                            source_runtime._parent_gateway_record(
                                fd,
                                str(target),
                            )
                    self.assertTrue(fired)
                finally:
                    os.close(fd)


class CargoDependencyInventory(unittest.TestCase):
    def _roots(self, base: Path):
        registry = base / "registry"
        roots = {}
        for leaf in ("index", "cache", "src"):
            path = registry / leaf
            path.mkdir(parents=True, mode=0o755)
            path.chmod(0o755)
            roots["registry/" + leaf] = str(path)
        nested = registry / "src" / "mirror" / "crate-1.0.0"
        nested.mkdir(parents=True, mode=0o755)
        for parent in (registry / "src" / "mirror", nested):
            parent.chmod(0o755)
        (nested / "Cargo.toml").write_bytes(b"[package]\nname='crate'\n")
        (registry / "cache" / "crate-1.0.0.crate").write_bytes(b"crate")
        (registry / "index" / "config.json").write_bytes(b"{}\n")
        return roots, nested / "Cargo.toml"

    def test_happy_inventory_is_deterministic_and_content_bound(self):
        with tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        ) as temp:
            roots, target = self._roots(Path(temp))
            first, first_digest = _dependency_inventory(roots)
            second, second_digest = _dependency_inventory(roots)
            self.assertEqual((first, first_digest), (second, second_digest))
            self.assertEqual(first["entry_count"], len(first["entries"]))
            self.assertEqual(
                first_digest,
                hashlib.sha256(canonical_json_bytes(first)).hexdigest(),
            )
            self.assertEqual(
                [item["path"] for item in first["entries"]],
                sorted(
                    (item["path"] for item in first["entries"]),
                    key=lambda item: item.encode("utf-8"),
                ),
            )
            target.write_bytes(b"[package]\nname='other'\n")
            changed, changed_digest = _dependency_inventory(roots)
            self.assertNotEqual(changed_digest, first_digest)
            self.assertNotEqual(changed, first)

    def test_add_remove_rename_change_bound_inventory(self):
        for operation in ("add", "remove", "rename"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(
                dir=os.path.realpath(tempfile.gettempdir()),
            ) as temp:
                roots, target = self._roots(Path(temp))
                _, expected = _dependency_inventory(roots)
                if operation == "add":
                    target.with_name("added").write_bytes(b"added")
                elif operation == "remove":
                    target.unlink()
                else:
                    target.rename(target.with_name("renamed"))
                _, actual = _dependency_inventory(roots)
                self.assertNotEqual(actual, expected)

    def test_symlink_hardlink_special_owner_and_mode_fail_closed(self):
        for case in (
            "symlink", "hardlink", "special", "owner", "mode",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                dir=os.path.realpath(tempfile.gettempdir()),
            ) as temp:
                roots, target = self._roots(Path(temp))
                patcher = None
                if case == "symlink":
                    target.with_name("link").symlink_to(target)
                elif case == "hardlink":
                    os.link(target, target.with_name("hardlink"))
                elif case == "special":
                    os.mkfifo(target.with_name("fifo"), 0o600)
                elif case == "owner":
                    patcher = mock.patch.object(
                        source_runtime.os,
                        "geteuid",
                        return_value=os.geteuid() + 1,
                    )
                    patcher.start()
                else:
                    target.chmod(0o600)
                try:
                    with self.assertRaises(SourceRuntimeError):
                        _dependency_inventory(roots)
                finally:
                    if patcher is not None:
                        patcher.stop()

    def test_count_size_path_and_toctou_faults_fail_closed(self):
        limit_cases = (
            ("_DEPENDENCY_MAX_ENTRIES", 1),
            ("_DEPENDENCY_MAX_TOTAL_BYTES", 1),
            ("_DEPENDENCY_MAX_FILE_BYTES", 1),
            ("_DEPENDENCY_MAX_PATH_BYTES", 8),
            ("_DEPENDENCY_MAX_COMPONENTS", 1),
        )
        for attribute, value in limit_cases:
            with self.subTest(limit=attribute), tempfile.TemporaryDirectory(
                dir=os.path.realpath(tempfile.gettempdir()),
            ) as temp:
                roots, _ = self._roots(Path(temp))
                with mock.patch.object(source_runtime, attribute, value):
                    with self.assertRaises(SourceRuntimeError):
                        _dependency_inventory(roots)

        for event in ("after-list", "before-open", "after-read"):
            with self.subTest(event=event), tempfile.TemporaryDirectory(
                dir=os.path.realpath(tempfile.gettempdir()),
            ) as temp:
                roots, target = self._roots(Path(temp))
                fired = False

                def fault(observed_event, logical):
                    nonlocal fired
                    if fired or observed_event != event:
                        return
                    if event == "after-list" and logical == "registry/src":
                        fired = True
                        (Path(roots["registry/src"]) / "late").write_bytes(
                            b"late",
                        )
                    elif (
                        event == "before-open"
                        and logical.endswith("/Cargo.toml")
                    ):
                        fired = True
                        old = target.with_name("old")
                        target.rename(old)
                        target.write_bytes(old.read_bytes())
                    elif (
                        event == "after-read"
                        and logical.endswith("/Cargo.toml")
                    ):
                        fired = True
                        target.write_bytes(b"[package]\nname='other'\n")

                with self.assertRaises(SourceRuntimeError):
                    _dependency_inventory(roots, fault_hook=fault)
                self.assertTrue(fired)


if __name__ == "__main__":
    unittest.main()
