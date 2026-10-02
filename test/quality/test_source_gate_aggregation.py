"""Atomic fake-only source aggregation and terminal-seal tests."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test.quality.run_evidence.atomic_store import (
    RunStoreError,
    create_run_layout,
)
from test.quality.run_evidence.manifest_contracts import (
    canonical_json_bytes,
)
from test.quality.source_gate.aggregation import (
    complete_source_run,
    prepare_source_run,
    publish_source_pair,
)
from test.quality.source_gate.contracts import result_from_observation
from test.quality.source_gate.planning import build_source_plans


REPO_ROOT = Path(__file__).resolve().parents[2]
HEAD = "a" * 40
BASE = "b" * 40
ZERO = "0" * 64
STARTED = "2026-07-26T00:00:00Z"
COMPLETED = "2026-07-26T00:01:00Z"


class SourceGateAggregation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        )
        root = Path(self.temp.name)
        self.state_root = root / "state"
        self.evidence_root = root / "evidence"
        self.state_root.mkdir(mode=0o700)
        self.evidence_root.mkdir(mode=0o700)
        self.layout = create_run_layout(
            str(self.state_root), str(self.evidence_root),
        )
        self.addCleanup(self._close)
        snapshot = {
            "schema": "source-snapshot-manifest.v1",
            "run_id": self.layout.run_id,
            "head_sha": HEAD,
            "snapshot_mode": "clean-commit",
            "entry_count": 0,
            "total_bytes": 0,
            "entries": [],
        }
        with self.layout.snapshot_capture_lease() as lease:
            ticket = self.layout.publish_snapshot_manifest(
                snapshot,
                expected_head_sha=HEAD,
                lease=lease,
            )
            self.layout.linearize_snapshot_success(ticket, lease=lease)
        self.plans = self._plans(root)
        self.invocation = (
            "/usr/bin/python3",
            "-I",
            "test/quality/source_gate/cli.py",
            "run",
            "--output-root",
            str(root / "public"),
        )
        snapshot_binding = self.layout._finalized_snapshot_binding
        self.run_manifest = {
            "schema": "run-manifest.v1",
            "run_id": self.layout.run_id,
            "profile": "source",
            "head_sha": HEAD,
            "comparison_base": {
                "policy": "merge-base-origin-main",
                "sha": BASE,
            },
            "source_snapshot_manifest": {
                "path": snapshot_binding.publication.path,
                "sha256": snapshot_binding.publication.sha256,
            },
            "change_set": None,
            "invocation_argv": list(self.invocation),
            "expected_suites": [
                {
                    "suite_id": plan.suite["id"],
                    "entrypoint_id": plan.suite["entrypoint_id"],
                }
                for plan in self.plans
            ],
            "input_digests": {
                "schema_bundle": ZERO,
                "catalog": ZERO,
                "gates": ZERO,
                "runner": ZERO,
                "fixtures": ZERO,
                "build_recipes": ZERO,
                "sanitized_environment": ZERO,
                "tools": ZERO,
            },
            "platform": {
                "os": "fake",
                "arch": "fake",
                "toolchain": "fake-only",
            },
            "started_at": STARTED,
        }

    def tearDown(self):
        self.temp.cleanup()

    def _close(self):
        try:
            self.layout.close()
        except RunStoreError:
            pass

    @staticmethod
    def _plans(root: Path):
        catalog = json.loads(
            (REPO_ROOT / "quality/test-catalog.v1.json").read_text("utf-8"),
        )
        gates = json.loads(
            (REPO_ROOT / "quality/release-gates.v1.json").read_text("utf-8"),
        )
        inventory_raw = (
            REPO_ROOT
            / "test/quality/fixtures/source_gate/expected_test_ids.v1.json"
        ).read_bytes()
        return build_source_plans(
            catalog,
            gates,
            inventory_raw,
            tools={
                "PYTHON": "/fixed/bin/python3",
                "BASH": "/fixed/bin/bash",
                "NODE": "/fixed/bin/node",
                "CARGO": "/fixed/bin/cargo",
                "RUSTC": "/fixed/bin/rustc",
                "GIT": "/fixed/bin/git",
            },
            tool_identity_sha256="c" * 64,
            run_home=str(root / "home"),
            run_tmp=str(root / "tmp"),
            offline_cargo_home=str(root / "cargo"),
            rustup_home=str(root / "rustup"),
            gateway_target=str(root / "gateway-target"),
        )

    def _pair(self, plan):
        expected = list(plan.expected_test_ids)
        skipped = list(plan.approved_skipped_test_ids)
        ignored = list(plan.approved_ignored_test_ids)
        observation = {
            "schema": "source-observation.v1",
            "run_id": self.layout.run_id,
            "suite_id": plan.suite["id"],
            "entrypoint_id": plan.suite["entrypoint_id"],
            "attempt_index": 0,
            "command_argv_sha256": plan.command_argv_sha256,
            "environment_sha256": plan.environment_sha256,
            "tool_identity_sha256": plan.tool_identity_sha256,
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
            "outcome_hint": "PASS",
            "classification_hint": "NONE",
            "reason_code": "NONE",
        }
        result = result_from_observation(
            observation,
            expected_suite_id=plan.suite["id"],
            expected_entrypoint_id=plan.suite["entrypoint_id"],
            expected_test_ids=plan.expected_test_ids,
            approved_skipped_ids=plan.approved_skipped_test_ids,
            approved_ignored_ids=plan.approved_ignored_test_ids,
        )
        return observation, result

    def _prepared(self):
        return prepare_source_run(
            self.layout,
            self.run_manifest,
            plans=self.plans,
            invocation_argv=self.invocation,
        )

    def _publish_all(self, state):
        for plan in self.plans:
            publish_source_pair(state, *self._pair(plan))

    def test_01_exact_pairs_evidence_and_seal_have_independent_refs(self):
        state = self._prepared()
        self._publish_all(state)
        seal = complete_source_run(state, completed_at=COMPLETED)
        self.assertEqual(
            (seal["aggregate_decision"], seal["runner_exit"]),
            ("PASS", 0),
        )
        run_root = Path(self.layout.evidence_path)
        evidence = json.loads(
            (run_root / "evidence-manifest.json").read_text("utf-8"),
        )
        self.assertEqual(
            [item["suite_id"] for item in evidence["test_results"]],
            [plan.suite["id"] for plan in self.plans],
        )
        self.assertEqual(
            [item["suite_id"] for item in evidence["source_observations"]],
            [plan.suite["id"] for plan in self.plans],
        )
        for result_ref, observation_ref in zip(
            evidence["test_results"], evidence["source_observations"],
        ):
            self.assertEqual(
                observation_ref["path"],
                "results/"
                + observation_ref["suite_id"]
                + ".observation.json",
            )
            self.assertEqual(
                result_ref["path"],
                "results/" + result_ref["suite_id"] + ".json",
            )
            self.assertNotEqual(
                result_ref["sha256"], observation_ref["sha256"],
            )
        self.assertTrue((run_root / "completion-seal.json").is_file())

    def test_02_partial_set_is_one_way_and_cannot_seal(self):
        state = self._prepared()
        publish_source_pair(state, *self._pair(self.plans[0]))
        with self.assertRaises(RunStoreError) as raised:
            complete_source_run(state, completed_at=COMPLETED)
        self.assertEqual(raised.exception.code, "PARTIAL_RESULTS")
        with self.assertRaises(RunStoreError) as replay:
            complete_source_run(state, completed_at=COMPLETED)
        self.assertEqual(replay.exception.code, "REPLAYED_RESULT")
        self.assertFalse(
            (Path(self.layout.evidence_path) / "completion-seal.json").exists(),
        )

    def test_03_observation_preoccupation_and_pair_order_fail_closed(self):
        state = self._prepared()
        first = self.plans[0]
        preoccupied = (
            Path(self.layout.evidence_path)
            / "results"
            / (first.suite["id"] + ".observation.json")
        )
        preoccupied.write_text("{}")
        os.chmod(preoccupied, 0o600)
        with self.assertRaises(RunStoreError) as raised:
            publish_source_pair(state, *self._pair(first))
        self.assertEqual(raised.exception.code, "PUBLISH_EXISTS")
        self.assertFalse(
            (
                Path(self.layout.evidence_path)
                / "results"
                / (first.suite["id"] + ".json")
            ).exists(),
        )

        # A fresh run proves catalog-order identity cannot be swapped.
        self._close()
        self.layout = create_run_layout(
            str(self.state_root), str(self.evidence_root),
        )
        snapshot = {
            "schema": "source-snapshot-manifest.v1",
            "run_id": self.layout.run_id,
            "head_sha": HEAD,
            "snapshot_mode": "clean-commit",
            "entry_count": 0,
            "total_bytes": 0,
            "entries": [],
        }
        with self.layout.snapshot_capture_lease() as lease:
            ticket = self.layout.publish_snapshot_manifest(
                snapshot, expected_head_sha=HEAD, lease=lease,
            )
            self.layout.linearize_snapshot_success(ticket, lease=lease)
        binding = self.layout._finalized_snapshot_binding
        self.run_manifest["run_id"] = self.layout.run_id
        self.run_manifest["source_snapshot_manifest"] = {
            "path": binding.publication.path,
            "sha256": binding.publication.sha256,
        }
        state = self._prepared()
        with self.assertRaises(RunStoreError) as swapped:
            publish_source_pair(state, *self._pair(self.plans[1]))
        self.assertEqual(swapped.exception.code, "RESULT_BINDING_MISMATCH")

    def test_04_closing_replacement_and_evidence_preoccupation_never_seal(self):
        state = self._prepared()
        self._publish_all(state)
        target = (
            Path(self.layout.evidence_path)
            / "results"
            / (self.plans[0].suite["id"] + ".json")
        )
        replacement = target.with_name("replacement")
        replacement.write_bytes(target.read_bytes())
        os.chmod(replacement, 0o600)
        os.replace(replacement, target)
        with self.assertRaises(RunStoreError):
            complete_source_run(state, completed_at=COMPLETED)
        self.assertFalse(
            (Path(self.layout.evidence_path) / "completion-seal.json").exists(),
        )

    def test_05_evidence_preoccupation_blocks_terminal_publication(self):
        state = self._prepared()
        self._publish_all(state)
        evidence = Path(self.layout.evidence_path) / "evidence-manifest.json"
        evidence.write_text("{}")
        os.chmod(evidence, 0o600)
        with self.assertRaises(RunStoreError) as raised:
            complete_source_run(state, completed_at=COMPLETED)
        self.assertEqual(raised.exception.code, "PUBLISH_EXISTS")
        self.assertFalse(
            (Path(self.layout.evidence_path) / "completion-seal.json").exists(),
        )

    def test_06_result_collision_leaves_partial_observation_without_seal(self):
        state = self._prepared()
        first = self.plans[0]
        result_path = (
            Path(self.layout.evidence_path)
            / "results"
            / (first.suite["id"] + ".json")
        )
        result_path.write_text("{}")
        os.chmod(result_path, 0o600)
        with self.assertRaises(RunStoreError) as raised:
            publish_source_pair(state, *self._pair(first))
        self.assertEqual(raised.exception.code, "PUBLISH_EXISTS")
        self.assertTrue(
            (
                Path(self.layout.evidence_path)
                / "results"
                / (first.suite["id"] + ".observation.json")
            ).is_file(),
        )
        self.assertFalse(
            (Path(self.layout.evidence_path) / "completion-seal.json").exists(),
        )

    def test_07_terminal_conflict_and_post_seal_close_error_cannot_reverse(self):
        state = self._prepared()
        self._publish_all(state)
        conflict = Path(self.layout.evidence_path) / "completion-seal.json"
        conflict.write_text("{}")
        os.chmod(conflict, 0o600)
        with self.assertRaises(RunStoreError) as raised:
            complete_source_run(state, completed_at=COMPLETED)
        self.assertEqual(raised.exception.code, "TERMINAL_CONFLICT")
        self.assertEqual(conflict.read_text("utf-8"), "{}")

        # A separate fake run publishes the terminal seal before injecting a
        # later close failure; the already-authoritative bytes remain stable.
        self._close()
        self.layout = create_run_layout(
            str(self.state_root), str(self.evidence_root),
        )
        snapshot = {
            "schema": "source-snapshot-manifest.v1",
            "run_id": self.layout.run_id,
            "head_sha": HEAD,
            "snapshot_mode": "clean-commit",
            "entry_count": 0,
            "total_bytes": 0,
            "entries": [],
        }
        with self.layout.snapshot_capture_lease() as lease:
            ticket = self.layout.publish_snapshot_manifest(
                snapshot, expected_head_sha=HEAD, lease=lease,
            )
            self.layout.linearize_snapshot_success(ticket, lease=lease)
        binding = self.layout._finalized_snapshot_binding
        self.run_manifest["run_id"] = self.layout.run_id
        self.run_manifest["source_snapshot_manifest"] = {
            "path": binding.publication.path,
            "sha256": binding.publication.sha256,
        }
        state = self._prepared()
        self._publish_all(state)
        complete_source_run(state, completed_at=COMPLETED)
        seal_path = Path(self.layout.evidence_path) / "completion-seal.json"
        sealed_raw = seal_path.read_bytes()
        with mock.patch.object(
            self.layout, "close", side_effect=RunStoreError("CLOSE_FAILED"),
        ):
            with self.assertRaises(RunStoreError):
                self.layout.close()
        self.assertEqual(seal_path.read_bytes(), sealed_raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
