"""Focused RUE-06 retry policy and evidence-boundary tests."""
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

import test.quality.run_evidence.atomic_store as store
import test.quality.run_evidence.attempt0_runner as attempt_runner
from test.quality.run_evidence.atomic_store import RunStoreError, create_run_layout
from test.quality.run_evidence.attempt0_runner import _run_attempt0, run_attempt0
from test.quality.run_evidence.contracts import (
    AttemptDecisionV1,
    AttemptRecord,
    validate_result,
)
from test.quality.run_evidence.retry_runner import (
    _final_result,
    _retry_attempt1,
    retry_attempt1,
)

from jsonschema import Draft202012Validator


class RetryRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir()))
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.state = self.base / "state"
        self.evidence = self.base / "evidence"
        self.state.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)
        self.fixture = self.repo / "test/quality/fixtures/run_evidence/attempt0_fixture.py"
        self.fixture.parent.mkdir(parents=True)
        shutil.copyfile(
            Path(__file__).parent / "fixtures/run_evidence/attempt0_fixture.py",
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
        manifest = {
            "schema": "source-snapshot-manifest.v1",
            "run_id": layout.run_id,
            "head_sha": "a" * 40,
            "snapshot_mode": "clean-commit",
            "entry_count": 1,
            "total_bytes": len(raw),
            "entries": [{
                "path": "test/quality/fixtures/run_evidence/attempt0_fixture.py",
                "type": "file", "mode": "100644", "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }],
        }
        with layout.snapshot_capture_lease() as lease:
            ticket = layout.publish_snapshot_manifest(
                manifest, expected_head_sha="a" * 40, lease=lease,
            )
            layout.linearize_snapshot_success(ticket, lease=lease)
        return layout

    def _eligible(self):
        layout = self._layout()
        decision = _run_attempt0(
            repo_root=str(self.repo), layout=layout, scenario="readiness",
        )
        self.assertEqual(
            (decision.disposition, decision.reason_code, decision.attempt_record.process_exit),
            ("READINESS", "READINESS_TIMEOUT", 13),
        )
        return layout

    def _assert_result_valid(self, result):
        validate_result(result)
        schema = json.loads(
            (
                Path(__file__).parents[2]
                / "quality/schema/test-result.v1.schema.json"
            ).read_text()
        )
        self.assertEqual(
            list(Draft202012Validator(schema).iter_errors(result)), [],
        )

    @staticmethod
    def _replace_same_bytes(leaf: Path) -> None:
        replacement = leaf.parent / "replacement"
        replacement.write_bytes(leaf.read_bytes())
        os.chmod(replacement, 0o600)
        os.replace(replacement, leaf)

    def test_01_public_attempt0_still_has_no_retry_and_retry_api_has_no_overrides(self):
        self.assertEqual(
            tuple(inspect.signature(run_attempt0).parameters), ("repo_root", "layout"),
        )
        self.assertEqual(
            tuple(inspect.signature(retry_attempt1).parameters), ("repo_root", "layout"),
        )
        layout = self._layout()
        self.assertEqual(
            run_attempt0(repo_root=str(self.repo), layout=layout).disposition, "PASS",
        )
        self.assertFalse((Path(layout.state_path) / "attempts/attempt-1.json").exists())
        self.assertEqual(list((Path(layout.evidence_path) / "results").iterdir()), [])

    def test_02_only_exact_persisted_readiness_timeout_is_eligible(self):
        for scenario in (
            "normal", "test-fail", "env", "real", "ignored", "skipped",
            "timeout", "malformed",
        ):
            with self.subTest(scenario=scenario):
                layout = self._layout()
                _run_attempt0(
                    repo_root=str(self.repo), layout=layout, scenario=scenario,
                )
                with self.assertRaises(RunStoreError) as raised:
                    retry_attempt1(repo_root=str(self.repo), layout=layout)
                self.assertEqual(raised.exception.code, "ATTEMPT_NOT_ELIGIBLE")
                self.assertFalse((Path(layout.state_path) / "attempts/attempt-1.json").exists())
        layout = self._layout()
        with mock.patch.object(
            attempt_runner.os, "posix_spawn", side_effect=OSError("spawn"),
        ):
            decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual(
            (decision.disposition, decision.reason_code, decision.attempt_record.process_exit),
            ("INFRA", "EXEC_FAILED", None),
        )
        with self.assertRaises(RunStoreError) as no_child:
            retry_attempt1(repo_root=str(self.repo), layout=layout)
        self.assertEqual(no_child.exception.code, "ATTEMPT_NOT_ELIGIBLE")

    def test_03_13_then_13_is_readiness_exhausted_and_not_published(self):
        layout = self._eligible()
        result = _retry_attempt1(
            repo_root=str(self.repo), layout=layout, scenario="readiness",
        )
        self.assertEqual(
            (result["kind"], result["gate_decision"], result["runner_exit"]),
            ("READINESS_EXHAUSTED", "BLOCKED", 13),
        )
        self.assertEqual(
            [record["process_exit"] for record in result["attempt_records"]], [13, 13],
        )
        self.assertEqual(list((Path(layout.evidence_path) / "results").iterdir()), [])
        self._assert_result_valid(result)

    def test_04_recovered_valid_outcomes_are_flaky_blocked_never_pass(self):
        cases = {"normal": 0, "test-fail": 10, "env": 11, "real": 11, "ignored": 11, "skipped": 11}
        for scenario, rc in cases.items():
            with self.subTest(scenario=scenario):
                layout = self._eligible()
                result = _retry_attempt1(
                    repo_root=str(self.repo), layout=layout, scenario=scenario,
                )
                self.assertEqual(
                    (result["kind"], result["classification"], result["gate_decision"], result["runner_exit"]),
                    ("FLAKY_RETRY", "FLAKY", "BLOCKED", 11),
                )
                self.assertEqual(
                    [record["process_exit"] for record in result["attempt_records"]],
                    [13, rc],
                )
                self._assert_result_valid(result)

    def test_05_attempt1_hard_timeout_and_infra_keep_existing_result_kinds(self):
        for scenario, expected in (
            ("timeout", ("HARD_TIMEOUT", "PROCESS_TIMEOUT")),
            ("malformed", ("INFRA", "ADAPTER_MALFORMED")),
        ):
            with self.subTest(scenario=scenario):
                layout = self._eligible()
                result = _retry_attempt1(
                    repo_root=str(self.repo), layout=layout, scenario=scenario,
                )
                self.assertEqual((result["kind"], result["reason_code"]), expected)
                self.assertEqual(result["gate_decision"], "FAIL")
                self.assertEqual(len(result["attempt_records"]), 2)
                persisted = json.loads(
                    (
                        Path(layout.state_path) / "attempts/attempt-1.json"
                    ).read_text()
                )
                self.assertEqual(
                    result["attempt_records"][1]["process_exit"],
                    persisted["process_exit"],
                )
                self._assert_result_valid(result)

        layout = self._eligible()
        with mock.patch.object(
            attempt_runner.os, "posix_spawn", side_effect=OSError("spawn"),
        ):
            result = retry_attempt1(repo_root=str(self.repo), layout=layout)
        self.assertEqual(
            (
                result["kind"], result["reason_code"],
                [record["process_exit"] for record in result["attempt_records"]],
            ),
            ("INFRA", "EXEC_FAILED", [13, None]),
        )
        self._assert_result_valid(result)

    def test_06_attempt1_is_one_shot_and_uses_an_independent_cache_leaf(self):
        layout = self._eligible()
        retry_attempt1(repo_root=str(self.repo), layout=layout)
        cache = Path(layout.state_path) / "cache"
        self.assertTrue((cache / "attempt0-fixture.py").is_file())
        self.assertTrue((cache / "attempt1-fixture.py").is_file())
        with self.assertRaises(RunStoreError) as raised:
            retry_attempt1(repo_root=str(self.repo), layout=layout)
        self.assertEqual(raised.exception.code, "ATTEMPT_DUPLICATE")

    def test_07_attempt0_canonical_content_or_binding_drift_fails_before_attempt1(self):
        for mode in ("binding", "content", "noncanonical"):
            with self.subTest(mode=mode):
                layout = self._eligible()
                leaf = Path(layout.state_path) / "attempts/attempt-0.json"
                if mode == "binding":
                    self._replace_same_bytes(leaf)
                elif mode == "content":
                    value = json.loads(leaf.read_text())
                    value["reason_code"] = "NONE"
                    leaf.write_bytes(store.canonical_json_bytes(value))
                else:
                    leaf.write_bytes(b'{"attempt_index": 0}')
                with self.assertRaises(RunStoreError) as raised:
                    retry_attempt1(repo_root=str(self.repo), layout=layout)
                self.assertEqual(raised.exception.code, "ATTEMPT_STATE_UNSAFE")
                self.assertFalse((leaf.parent / "attempt-1.json").exists())

    def test_08_attempt1_replacement_prevents_final_result(self):
        layout = self._eligible()
        real_read = layout.read_retry_decisions

        def replace_then_read():
            leaf = Path(layout.state_path) / "attempts/attempt-1.json"
            self._replace_same_bytes(leaf)
            return real_read()

        with mock.patch.object(layout, "read_retry_decisions", side_effect=replace_then_read):
            with self.assertRaises(RunStoreError) as raised:
                retry_attempt1(repo_root=str(self.repo), layout=layout)
        self.assertEqual(raised.exception.code, "ATTEMPT_STATE_UNSAFE")

    def test_09_attempt1_publication_uncertainty_returns_no_final_and_consumes_slot(self):
        layout = self._eligible()
        real_publish = store._publish

        def uncertain(*args, **kwargs):
            if args[2] == "attempt-1.json":
                real_publish(*args, **kwargs)
                raise RunStoreError(
                    "PUBLISH_VERIFY_FAILED", published_may_exist=True,
                    final_leaf="attempt-1.json",
                )
            return real_publish(*args, **kwargs)

        with mock.patch.object(store, "_publish", side_effect=uncertain):
            with self.assertRaises(RunStoreError):
                retry_attempt1(repo_root=str(self.repo), layout=layout)
        with self.assertRaises(RunStoreError) as replay:
            retry_attempt1(repo_root=str(self.repo), layout=layout)
        self.assertEqual(replay.exception.code, "ATTEMPT_DUPLICATE")
        self.assertTrue(
            (Path(layout.state_path) / "attempts/attempt-1.json").is_file(),
        )

    def test_10_ambient_overrides_are_ignored_by_both_public_apis(self):
        ambient = {
            "RUE05A_PRIVATE_SCENARIO": "timeout",
            "RUE05A_ENTRYPOINT": "ENTRY-FOREIGN",
            "CSSWITCH_LOOPBACK_TEST_CMD": "false",
        }
        with mock.patch.dict(os.environ, ambient):
            layout = self._layout()
            decision = run_attempt0(repo_root=str(self.repo), layout=layout)
        self.assertEqual(
            (decision.disposition, decision.attempt_record.process_exit),
            ("PASS", 0),
        )

        layout = self._eligible()
        with mock.patch.dict(os.environ, ambient):
            result = retry_attempt1(repo_root=str(self.repo), layout=layout)
        self.assertEqual(
            (result["kind"], result["attempt_records"][1]["process_exit"]),
            ("FLAKY_RETRY", 0),
        )
        self._assert_result_valid(result)

    def test_11_preexisting_attempt1_is_no_clobber(self):
        layout = self._eligible()
        leaf = Path(layout.state_path) / "attempts/attempt-1.json"
        leaf.write_bytes(b"foreign")
        with self.assertRaises(RunStoreError) as raised:
            retry_attempt1(repo_root=str(self.repo), layout=layout)
        self.assertEqual(raised.exception.code, "ATTEMPT_DUPLICATE")
        self.assertEqual(leaf.read_bytes(), b"foreign")

    def test_12_snapshot_drift_after_attempt0_blocks_attempt1_and_final(self):
        layout = self._eligible()
        snapshot = Path(layout.state_path) / "snapshot/source-snapshot-manifest.json"
        self._replace_same_bytes(snapshot)
        with self.assertRaises(RunStoreError) as before_attempt1:
            retry_attempt1(repo_root=str(self.repo), layout=layout)
        self.assertEqual(
            before_attempt1.exception.code, "SNAPSHOT_BINDING_MISMATCH",
        )
        self.assertFalse(
            (Path(layout.state_path) / "attempts/attempt-1.json").exists(),
        )

        layout = self._eligible()
        real_read = layout.read_retry_decisions

        def drift_then_read():
            self._replace_same_bytes(
                Path(layout.state_path)
                / "snapshot/source-snapshot-manifest.json"
            )
            return real_read()

        with mock.patch.object(
            layout, "read_retry_decisions", side_effect=drift_then_read,
        ):
            with self.assertRaises(RunStoreError) as before_final:
                retry_attempt1(repo_root=str(self.repo), layout=layout)
        self.assertEqual(
            before_final.exception.code, "SNAPSHOT_BINDING_MISMATCH",
        )

    def test_13_final_adjudication_rejects_ineligible_or_cross_identity_records(self):
        eligible = AttemptDecisionV1(
            "a" * 32, "SUITE-RUE05A", "ENTRY-RUE05A-ATTEMPT0", 0,
            AttemptRecord(0, 13), "READINESS", "READINESS_TIMEOUT",
        )
        ineligible = AttemptDecisionV1(
            "a" * 32, "SUITE-RUE05A", "ENTRY-RUE05A-ATTEMPT0", 0,
            AttemptRecord(0, 0), "PASS", "NONE",
        )
        retry = AttemptDecisionV1(
            "a" * 32, "SUITE-RUE05A", "ENTRY-RUE05A-ATTEMPT0", 1,
            AttemptRecord(1, 0), "PASS", "NONE",
        )
        foreign = AttemptDecisionV1(
            "b" * 32, "SUITE-RUE05A", "ENTRY-RUE05A-ATTEMPT0", 1,
            AttemptRecord(1, 0), "PASS", "NONE",
        )
        with self.assertRaisesRegex(ValueError, "ATTEMPT0_NOT_ELIGIBLE"):
            _final_result(ineligible, retry)
        with self.assertRaisesRegex(ValueError, "ATTEMPT_IDENTITY_MISMATCH"):
            _final_result(eligible, foreign)

    def test_14_attempt_replacement_is_rejected_before_untrusted_size_read(self):
        for replacement_raw in (None, b"x" * (2 * 1024 * 1024)):
            with self.subTest(
                replacement="same-byte" if replacement_raw is None else "large",
            ):
                layout = self._eligible()
                leaf = Path(layout.state_path) / "attempts/attempt-0.json"
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
                        raise AssertionError("untrusted attempt replacement was read")
                    return real_read(fd, size, code=code)

                with mock.patch.object(
                    store, "_read_exact", side_effect=reject_replacement_read,
                ):
                    with self.assertRaises(RunStoreError) as raised:
                        retry_attempt1(repo_root=str(self.repo), layout=layout)
                self.assertEqual(raised.exception.code, "ATTEMPT_STATE_UNSAFE")

    def test_15_closing_pass_catches_attempt0_replacement_after_initial_read(self):
        layout = self._eligible()
        attempt_runner._run_attempt(
            repo_root=str(self.repo), layout=layout, attempt_index=1,
        )
        real_read = layout._read_bound_attempt
        calls = {"count": 0}

        def replace_after_initial_attempt0(attempt_index):
            decision = real_read(attempt_index)
            calls["count"] += 1
            if calls["count"] == 1:
                self.assertEqual(attempt_index, 0)
                self._replace_same_bytes(
                    Path(layout.state_path) / "attempts/attempt-0.json",
                )
            return decision

        with mock.patch.object(
            layout,
            "_read_bound_attempt",
            side_effect=replace_after_initial_attempt0,
        ):
            with self.assertRaises(RunStoreError) as raised:
                layout.read_retry_decisions()
        self.assertEqual(raised.exception.code, "ATTEMPT_STATE_UNSAFE")
        self.assertEqual(list((Path(layout.evidence_path) / "results").iterdir()), [])
