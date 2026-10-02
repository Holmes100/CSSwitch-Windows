"""Adversarial fixed aggregation and completion-seal tests."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test.quality.run_evidence.aggregation_runner as aggregation
import test.quality.run_evidence.atomic_store as store
from test.quality.run_evidence.aggregation_runner import (
    complete_fixed_run,
    prepare_fixed_run,
)
from test.quality.run_evidence.atomic_store import (
    RunStoreError,
    create_run_layout,
)
from test.quality.run_evidence.attempt0_runner import _run_attempt0
from test.quality.run_evidence.manifest_contracts import (
    canonical_json_bytes,
    validate_fixed_single_suite_seal,
)
from test.quality.run_evidence.retry_runner import _retry_attempt1
from jsonschema import Draft202012Validator


class AggregationRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        )
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.state = self.base / "state"
        self.evidence = self.base / "evidence"
        self.state.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)
        self.fixture = (
            self.repo
            / "test/quality/fixtures/run_evidence/attempt0_fixture.py"
        )
        self.fixture.parent.mkdir(parents=True)
        shutil.copyfile(
            Path(__file__).parent
            / "fixtures/run_evidence/attempt0_fixture.py",
            self.fixture,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _close(layout) -> None:
        try:
            layout.close()
        except RunStoreError:
            pass

    def _layout(self):
        layout = create_run_layout(str(self.state), str(self.evidence))
        self.addCleanup(self._close, layout)
        raw = self.fixture.read_bytes()
        snapshot = {
            "schema": "source-snapshot-manifest.v1",
            "run_id": layout.run_id,
            "head_sha": "a" * 40,
            "snapshot_mode": "clean-commit",
            "entry_count": 1,
            "total_bytes": len(raw),
            "entries": [{
                "path": (
                    "test/quality/fixtures/run_evidence/"
                    "attempt0_fixture.py"
                ),
                "type": "file",
                "mode": "100644",
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }],
        }
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(
                snapshot, expected_head_sha="a" * 40, lease=lease,
            )
            layout.linearize_snapshot_success(ticket, lease=lease)
        return layout

    @staticmethod
    def _run_manifest(layout):
        snapshot = layout._finalized_snapshot_binding.publication
        return {
            "schema": "run-manifest.v1",
            "run_id": layout.run_id,
            "profile": "focused",
            "head_sha": "a" * 40,
            "comparison_base": {
                "policy": "merge-base-origin-main",
                "sha": "b" * 40,
            },
            "source_snapshot_manifest": {
                "path": snapshot.path,
                "sha256": snapshot.sha256,
            },
            "change_set": None,
            "invocation_argv": ["rue-fixed-api.v1"],
            "expected_suites": [{
                "suite_id": "SUITE-RUE05A",
                "entrypoint_id": "ENTRY-RUE05A-ATTEMPT0",
            }],
            "input_digests": {
                name: "c" * 64 for name in (
                    "schema_bundle", "catalog", "gates", "runner",
                    "fixtures", "build_recipes", "sanitized_environment",
                    "tools",
                )
            },
            "platform": {
                "os": "macos",
                "arch": "arm64",
                "toolchain": "python3",
            },
            "started_at": "2026-07-25T00:00:00Z",
        }

    def _prepared(self):
        layout = self._layout()
        run = self._run_manifest(layout)
        self.assertEqual(prepare_fixed_run(layout, run), run)
        return layout

    def _complete_scenario(self, scenario):
        layout = self._prepared()
        _run_attempt0(
            repo_root=str(self.repo), layout=layout, scenario=scenario,
        )
        seal = complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        result = json.loads(
            (
                Path(layout.evidence_path)
                / "results/SUITE-RUE05A.json"
            ).read_text("utf-8")
        )
        return layout, result, seal

    def test_01_public_api_is_fixed_and_pass_seal_is_result_derived(self):
        self.assertEqual(
            tuple(inspect.signature(prepare_fixed_run).parameters),
            ("layout", "run_manifest"),
        )
        self.assertEqual(
            tuple(inspect.signature(complete_fixed_run).parameters),
            ("layout", "completed_at"),
        )
        layout, result, seal = self._complete_scenario("normal")
        self.assertEqual(
            (result["gate_decision"], result["runner_exit"]), ("PASS", 0),
        )
        self.assertEqual(
            (seal["aggregate_decision"], seal["runner_exit"]), ("PASS", 0),
        )
        self.assertTrue(
            (Path(layout.evidence_path) / "evidence-manifest.json").is_file(),
        )
        self.assertTrue(
            (Path(layout.evidence_path) / "completion-seal.json").is_file(),
        )

    def test_02_every_legal_nonpass_seals_with_the_matching_decision(self):
        cases = {
            "test-fail": ("FAIL", 10),
            "env": ("BLOCKED", 11),
            "real": ("BLOCKED", 11),
            "ignored": ("BLOCKED", 11),
            "skipped": ("BLOCKED", 11),
            "timeout": ("FAIL", 13),
            "malformed": ("FAIL", 12),
        }
        for scenario, expected in cases.items():
            with self.subTest(scenario=scenario):
                _, result, seal = self._complete_scenario(scenario)
                self.assertEqual(
                    (result["gate_decision"], result["runner_exit"]),
                    expected,
                )
                self.assertEqual(
                    (seal["aggregate_decision"], seal["runner_exit"]),
                    expected,
                )

    def test_03_full_retry_results_seal_blocked_never_hidden_pass(self):
        for scenario, expected in (
            ("normal", ("FLAKY_RETRY", "BLOCKED", 11)),
            ("readiness", ("READINESS_EXHAUSTED", "BLOCKED", 13)),
        ):
            with self.subTest(scenario=scenario):
                layout = self._prepared()
                _run_attempt0(
                    repo_root=str(self.repo),
                    layout=layout,
                    scenario="readiness",
                )
                _retry_attempt1(
                    repo_root=str(self.repo),
                    layout=layout,
                    scenario=scenario,
                )
                seal = complete_fixed_run(
                    layout, "2026-07-25T00:00:01Z",
                )
                result = json.loads(
                    (
                        Path(layout.evidence_path)
                        / "results/SUITE-RUE05A.json"
                    ).read_text("utf-8")
                )
                self.assertEqual(
                    (
                        result["kind"],
                        seal["aggregate_decision"],
                        seal["runner_exit"],
                    ),
                    expected,
                )

    def test_04_prepare_rejects_every_fixed_plan_override_without_publish(self):
        mutations = (
            ("profile", "source"),
            ("comparison_base", {"policy": "head", "sha": "b" * 40}),
            ("head_sha", "d" * 40),
            ("source_snapshot_manifest", {
                "path": "snapshot/source-snapshot-manifest.json",
                "sha256": "d" * 64,
            }),
            ("change_set", {
                "path": "inputs/change-set.json", "sha256": "d" * 64,
            }),
            ("invocation_argv", ["spoof"]),
            ("expected_suites", [{
                "suite_id": "SUITE-SPOOF",
                "entrypoint_id": "ENTRY-SPOOF",
            }]),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                layout = self._layout()
                run = self._run_manifest(layout)
                run[key] = value
                with self.assertRaises(RunStoreError):
                    prepare_fixed_run(layout, run)
                self.assertFalse(
                    (Path(layout.evidence_path) / "run-manifest.json").exists(),
                )

    def test_05_missing_partial_and_unretried_readiness_never_seal(self):
        layout = self._prepared()
        with self.assertRaises(RunStoreError) as missing:
            complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertEqual(missing.exception.code, "PARTIAL_RESULTS")
        self.assertFalse(
            (Path(layout.evidence_path) / "completion-seal.json").exists(),
        )
        with self.assertRaises(RunStoreError) as late:
            _run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual(late.exception.code, "ATTEMPT_STATE_UNSAFE")
        with self.assertRaises(RunStoreError) as replay:
            complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertEqual(replay.exception.code, "REPLAYED_RESULT")

        layout = self._prepared()
        _run_attempt0(
            repo_root=str(self.repo), layout=layout, scenario="readiness",
        )
        with self.assertRaises(RunStoreError) as readiness:
            complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertEqual(readiness.exception.code, "PARTIAL_RESULTS")
        self.assertFalse(
            (Path(layout.evidence_path) / "completion-seal.json").exists(),
        )

    def test_06_generic_critical_publication_is_denied(self):
        layout = self._layout()
        for area, leaf in (
            ("root", "run-manifest.json"),
            ("results", "SUITE-RUE05A.json"),
            ("root", "evidence-manifest.json"),
            ("root", "completion-seal.json"),
        ):
            with self.subTest(area=area, leaf=leaf):
                with self.assertRaises(RunStoreError) as raised:
                    layout.publish_json(area, leaf, {})
                self.assertEqual(
                    raised.exception.code, "PUBLISH_AREA_INVALID",
                )

    def test_07_same_byte_result_rebind_before_final_read_leaves_no_seal(self):
        layout = self._prepared()
        _run_attempt0(repo_root=str(self.repo), layout=layout)
        original = layout._read_bound_publication
        calls = {"result": 0}

        def replace_result(publication, **kwargs):
            if kwargs.get("expected_area") == "results":
                calls["result"] += 1
                if calls["result"] == 2:
                    leaf = (
                        Path(layout.evidence_path)
                        / "results/SUITE-RUE05A.json"
                    )
                    replacement = leaf.parent / "replacement"
                    replacement.write_bytes(leaf.read_bytes())
                    os.chmod(replacement, 0o600)
                    os.replace(replacement, leaf)
            return original(publication, **kwargs)

        with mock.patch.object(
            layout, "_read_bound_publication", side_effect=replace_result,
        ):
            with self.assertRaises(RunStoreError):
                complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertFalse(
            (Path(layout.evidence_path) / "completion-seal.json").exists(),
        )

    def test_08_evidence_publication_uncertainty_never_reaches_seal(self):
        layout = self._prepared()
        _run_attempt0(repo_root=str(self.repo), layout=layout)
        original = aggregation._publish

        def uncertain(target, area, leaf, raw, **kwargs):
            publication = original(target, area, leaf, raw, **kwargs)
            if leaf == "evidence-manifest.json":
                raise RunStoreError(
                    "PUBLISH_VERIFY_FAILED",
                    stage="VERIFY",
                    run_id=target.run_id,
                    published_may_exist=True,
                    final_leaf=leaf,
                )
            return publication

        with mock.patch.object(aggregation, "_publish", side_effect=uncertain):
            with self.assertRaises(RunStoreError) as raised:
                complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertTrue(raised.exception.published_may_exist)
        self.assertFalse(
            (Path(layout.evidence_path) / "completion-seal.json").exists(),
        )

    def test_09_invalid_completion_time_consumes_slot_and_replay_cannot_seal(self):
        layout = self._prepared()
        _run_attempt0(repo_root=str(self.repo), layout=layout)
        with self.assertRaises(RunStoreError):
            complete_fixed_run(layout, "not-a-time")
        self.assertTrue(
            (
                Path(layout.evidence_path)
                / "results/SUITE-RUE05A.json"
            ).is_file(),
        )
        self.assertTrue(
            (Path(layout.evidence_path) / "evidence-manifest.json").is_file(),
        )
        self.assertFalse(
            (Path(layout.evidence_path) / "completion-seal.json").exists(),
        )
        with self.assertRaises(RunStoreError) as replay:
            complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertEqual(replay.exception.code, "REPLAYED_RESULT")
        self.assertFalse(
            (Path(layout.evidence_path) / "completion-seal.json").exists(),
        )

    def test_10_fixed_validator_rejects_fail_result_with_pass_seal(self):
        layout, _, seal = self._complete_scenario("test-fail")
        root = Path(layout.evidence_path)
        snapshot_path = (
            Path(layout.state_path)
            / "snapshot/source-snapshot-manifest.json"
        )
        run = json.loads((root / "run-manifest.json").read_text("utf-8"))
        snapshot = json.loads(snapshot_path.read_text("utf-8"))
        evidence = json.loads(
            (root / "evidence-manifest.json").read_text("utf-8"),
        )
        artifacts = {
            "snapshot/source-snapshot-manifest.json":
                snapshot_path.read_bytes(),
            "run-manifest.json": (root / "run-manifest.json").read_bytes(),
            "results/SUITE-RUE05A.json":
                (root / "results/SUITE-RUE05A.json").read_bytes(),
            "evidence-manifest.json":
                (root / "evidence-manifest.json").read_bytes(),
        }
        spoofed = dict(seal, aggregate_decision="PASS", runner_exit=0)
        with self.assertRaises(Exception):
            validate_fixed_single_suite_seal(
                spoofed, run, snapshot, evidence, artifacts,
            )

    def test_11_seal_rename_is_last_fallible_success_linearization(self):
        layout = self._prepared()
        _run_attempt0(repo_root=str(self.repo), layout=layout)
        real_fsync = store._fsync
        post_rename_parent_fsyncs = []
        seal_path = Path(layout.evidence_path) / "completion-seal.json"

        def forbid_old_second_parent_fsync(fd, code="PUBLISH_IO_FAILED"):
            if fd == layout._evidence_fd and seal_path.exists():
                post_rename_parent_fsyncs.append(fd)
                raise RunStoreError(
                    "PUBLISH_IO_FAILED",
                    stage="VERIFY",
                    run_id=layout.run_id,
                    published_may_exist=True,
                )
            return real_fsync(fd, code)

        with mock.patch.object(
            store, "_fsync", side_effect=forbid_old_second_parent_fsync,
        ):
            seal = complete_fixed_run(
                layout, "2026-07-25T00:00:01Z",
            )
        self.assertEqual(post_rename_parent_fsyncs, [])
        self.assertIsNotNone(layout._fixed_seal_publication)
        persisted = json.loads(seal_path.read_text("utf-8"))
        self.assertEqual(persisted, seal)
        schema = json.loads(
            (
                Path(__file__).parents[2]
                / "quality/schema/completion-seal.v1.schema.json"
            ).read_text("utf-8")
        )
        Draft202012Validator(schema).validate(persisted)

        root = Path(layout.evidence_path)
        snapshot_path = (
            Path(layout.state_path)
            / "snapshot/source-snapshot-manifest.json"
        )
        run = json.loads((root / "run-manifest.json").read_text("utf-8"))
        snapshot = json.loads(snapshot_path.read_text("utf-8"))
        evidence = json.loads(
            (root / "evidence-manifest.json").read_text("utf-8"),
        )
        artifacts = {
            "snapshot/source-snapshot-manifest.json":
                snapshot_path.read_bytes(),
            "run-manifest.json": (root / "run-manifest.json").read_bytes(),
            "results/SUITE-RUE05A.json":
                (root / "results/SUITE-RUE05A.json").read_bytes(),
            "evidence-manifest.json":
                (root / "evidence-manifest.json").read_bytes(),
        }
        validate_fixed_single_suite_seal(
            persisted, run, snapshot, evidence, artifacts,
        )

    def test_12_pre_rename_parent_fsync_failure_has_no_final_seal(self):
        layout = self._prepared()
        _run_attempt0(repo_root=str(self.repo), layout=layout)
        real_fsync = store._fsync
        seal_path = Path(layout.evidence_path) / "completion-seal.json"

        def fail_terminal_pre_rename(fd, code="PUBLISH_IO_FAILED"):
            if (
                fd == layout._evidence_fd
                and layout._fixed_evidence_publication is not None
                and not seal_path.exists()
            ):
                raise RunStoreError(
                    "PUBLISH_IO_FAILED",
                    stage="RENAME",
                    run_id=layout.run_id,
                )
            return real_fsync(fd, code)

        with mock.patch.object(
            store, "_fsync", side_effect=fail_terminal_pre_rename,
        ):
            with self.assertRaises(RunStoreError):
                complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertFalse(seal_path.exists())
        self.assertIsNone(layout._fixed_seal_publication)

    def test_13_rename_error_propagates_without_final_resolution_io(self):
        layout = self._prepared()
        _run_attempt0(repo_root=str(self.repo), layout=layout)
        seal_path = Path(layout.evidence_path) / "completion-seal.json"
        real_rename = store._rename_exclusive
        real_stat = store.os.stat
        real_read_exact = store._read_exact
        rename_failed = {"value": False}
        resolution_calls = []

        def fail_rename(parent_fd, temp_leaf, final_leaf):
            if final_leaf != "completion-seal.json":
                return real_rename(parent_fd, temp_leaf, final_leaf)
            rename_failed["value"] = True
            raise RunStoreError(
                "RENAME_FAILED",
                stage="RENAME",
                run_id=layout.run_id,
            )

        def forbid_final_stat(path, *args, **kwargs):
            if (
                rename_failed["value"]
                and path == "completion-seal.json"
            ):
                resolution_calls.append(("stat", path))
                raise AssertionError("rename error must not resolve final")
            return real_stat(path, *args, **kwargs)

        def forbid_resolution_read(fd, size, *, code):
            if rename_failed["value"]:
                resolution_calls.append(("read", code))
                raise AssertionError("rename error must not read final")
            return real_read_exact(fd, size, code=code)

        with mock.patch.object(
            store, "_rename_exclusive", side_effect=fail_rename,
        ), mock.patch.object(
            store.os, "stat", side_effect=forbid_final_stat,
        ), mock.patch.object(
            store, "_read_exact", side_effect=forbid_resolution_read,
        ):
            with self.assertRaises(RunStoreError) as raised:
                complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertEqual(raised.exception.code, "RENAME_FAILED")
        self.assertEqual(resolution_calls, [])
        self.assertIsNone(layout._fixed_seal_publication)
        self.assertFalse(seal_path.exists())

    def test_14_pre_rename_verify_failure_has_no_final_seal(self):
        layout = self._prepared()
        _run_attempt0(repo_root=str(self.repo), layout=layout)
        seal_path = Path(layout.evidence_path) / "completion-seal.json"
        original = store._read_exact

        def fail_terminal_verify(fd, size, *, code):
            if (
                code == "PUBLISH_VERIFY_FAILED"
                and layout._fixed_evidence_publication is not None
                and not seal_path.exists()
            ):
                raise RunStoreError(
                    "PUBLISH_VERIFY_FAILED",
                    stage="SEAL",
                    run_id=layout.run_id,
                )
            return original(fd, size, code=code)

        with mock.patch.object(
            store, "_read_exact", side_effect=fail_terminal_verify,
        ):
            with self.assertRaises(RunStoreError):
                complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertFalse(seal_path.exists())
        self.assertIsNone(layout._fixed_seal_publication)

    def test_15_final_temp_read_inplace_rewrite_blocks_seal_rename(self):
        layout = self._prepared()
        _run_attempt0(repo_root=str(self.repo), layout=layout)
        seal_path = Path(layout.evidence_path) / "completion-seal.json"
        original = store._read_exact
        mutated = {"value": False}

        def rewrite_after_final_read(fd, size, *, code):
            raw = original(fd, size, code=code)
            if (
                not mutated["value"]
                and code == "PUBLISH_VERIFY_FAILED"
                and layout._fixed_evidence_publication is not None
                and not seal_path.exists()
            ):
                os.lseek(fd, 0, os.SEEK_SET)
                os.write(fd, b"X")
                os.fsync(fd)
                mutated["value"] = True
            return raw

        with mock.patch.object(
            store, "_read_exact", side_effect=rewrite_after_final_read,
        ):
            with self.assertRaises(RunStoreError) as raised:
                complete_fixed_run(layout, "2026-07-25T00:00:01Z")
        self.assertTrue(mutated["value"])
        self.assertEqual(raised.exception.code, "PUBLISH_VERIFY_FAILED")
        self.assertFalse(seal_path.exists())
        self.assertIsNone(layout._fixed_seal_publication)
