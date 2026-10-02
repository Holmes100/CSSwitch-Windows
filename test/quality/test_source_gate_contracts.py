"""Malicious in-memory tests for the source observation and aggregate ABI."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest
from pathlib import Path

from test.quality.run_evidence.contracts import ContractViolation
import test.quality.run_evidence.attempt0_runner as runner
from test.quality.run_evidence.attempt0_runner import TrustedCommandResult
from test.quality.run_evidence.manifest_contracts import (
    canonical_json_bytes,
    validate_source_observation,
)
from test.quality.source_gate.adapter import (
    SourceAdapterError,
    _read_config,
    build_observation,
)
from test.quality.source_gate.contracts import (
    SOURCE_SUITE_ORDER,
    aggregate_results,
    result_from_observation,
)
from test.quality.source_gate.executor import (
    adjudicate_source_observation,
    execute_source_plans,
)
from test.quality.source_gate.planning import build_source_plans


RUN_ID = "0123456789abcdef0123456789abcdef"
SUITE = SOURCE_SUITE_ORDER[0]
ENTRY = "ENTRY-SOURCE-QUALITY-METADATA"
ZERO = "0" * 64
REPO_ROOT = Path(__file__).resolve().parents[2]


def adapter_config(*, suite_id: str = SUITE, entrypoint_id: str = ENTRY) -> dict:
    return {
        "schema": "source-adapter-config.v1",
        "run_id": RUN_ID,
        "suite_id": suite_id,
        "entrypoint_id": entrypoint_id,
        "kind": "meta",
        "argv": ["/usr/bin/true"],
        "environment": {"PATH": "/usr/bin:/bin"},
        "timeout_seconds": 1,
        "output_limit_bytes": 4096,
        "expected_test_ids": ["command:metadata-validator"],
        "approved_skipped_test_ids": [],
        "approved_ignored_test_ids": [],
        "approved_ignored_tests": {},
        "command_argv_sha256": ZERO,
        "environment_sha256": ZERO,
        "tool_identity_sha256": ZERO,
        "driver_config": None,
    }


def source_suite(suite_id: str = SUITE, entrypoint_id: str = ENTRY) -> dict:
    return {
        "id": suite_id,
        "entrypoint_id": entrypoint_id,
        "adapter_protocol": "source-observation.v1",
        "retry_policy": "none",
    }


def observation() -> dict:
    return {
        "schema": "source-observation.v1",
        "run_id": RUN_ID,
        "suite_id": SUITE,
        "entrypoint_id": ENTRY,
        "attempt_index": 0,
        "command_argv_sha256": ZERO,
        "environment_sha256": ZERO,
        "tool_identity_sha256": ZERO,
        "raw_process": {"state": "EXITED", "process_exit": 0},
        "adapter_exit": 0,
        "executed": 1,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
        "ignored": 0,
        "todo": 0,
        "not_run": 0,
        "discovered_test_ids": ["metadata"],
        "executed_test_ids": ["metadata"],
        "failed_test_ids": [],
        "skipped_test_ids": [],
        "ignored_test_ids": [],
        "todo_test_ids": [],
        "not_run_test_ids": [],
        "stdout": {"bytes": 0, "sha256": ZERO, "truncated": False},
        "stderr": {"bytes": 0, "sha256": ZERO, "truncated": False},
        "derived_tool": None,
        "outcome_hint": "PASS",
        "classification_hint": "NONE",
        "reason_code": "NONE",
    }


class SourceGateContracts(unittest.TestCase):
    def _real_plans(self):
        catalog = json.loads(
            (REPO_ROOT / "quality/test-catalog.v1.json").read_text("utf-8"),
        )
        gates = json.loads(
            (REPO_ROOT / "quality/release-gates.v1.json").read_text("utf-8"),
        )
        inventory_path = (
            REPO_ROOT
            / "test/quality/fixtures/source_gate/expected_test_ids.v1.json"
        )
        inventory_raw = inventory_path.read_bytes()
        tools = {
            "PYTHON": "/fixed/bin/python3",
            "BASH": "/fixed/bin/bash",
            "NODE": "/fixed/bin/node",
            "CARGO": "/fixed/bin/cargo",
            "RUSTC": "/fixed/bin/rustc",
            "GIT": "/fixed/bin/git",
        }
        return build_source_plans(
            catalog,
            gates,
            inventory_raw,
            tools=tools,
            tool_identity_sha256="a" * 64,
            run_home="/private/tmp/source-fake/home",
            run_tmp="/private/tmp/source-fake/tmp",
            offline_cargo_home="/private/tmp/source-fake/cargo-home",
            rustup_home="/private/tmp/source-fake/rustup-home",
            gateway_target="/private/tmp/source-fake/gateway-target",
        )

    def test_01_valid_observation_maps_to_existing_pass_result(self):
        item = observation()
        validate_source_observation(item)
        result = result_from_observation(
            item, expected_suite_id=SUITE, expected_entrypoint_id=ENTRY,
            expected_test_ids=["metadata"],
        )
        self.assertEqual((result["kind"], result["gate_decision"], result["runner_exit"]), ("PASS", "PASS", 0))

    def test_01b_derived_tool_is_closed_and_loopback_only(self):
        item = observation()
        item["suite_id"] = "SUITE-PY-LOOPBACK"
        item["entrypoint_id"] = "ENTRY-SOURCE-PY-LOOPBACK"
        item["derived_tool"] = {
            "path": "/private/tmp/run/gateway-target/debug/csswitch-gateway",
            "mode": "0755",
            "size": 7,
            "sha256": "1" * 64,
        }
        validate_source_observation(item)
        for label, mutate in (
            ("missing", lambda value: value.pop("derived_tool")),
            (
                "extra",
                lambda value: value["derived_tool"].__setitem__(
                    "owner",
                    0,
                ),
            ),
            (
                "malformed",
                lambda value: value["derived_tool"].__setitem__(
                    "mode",
                    "0644",
                ),
            ),
        ):
            with self.subTest(label=label):
                candidate = copy.deepcopy(item)
                mutate(candidate)
                with self.assertRaises(ContractViolation):
                    validate_source_observation(candidate)
        item["suite_id"] = SUITE
        item["entrypoint_id"] = ENTRY
        with self.assertRaises(ContractViolation):
            validate_source_observation(item)

    def test_01c_loopback_marker_missing_extra_malformed_and_late_fail(self):
        config = adapter_config(
            suite_id="SUITE-PY-LOOPBACK",
            entrypoint_id="ENTRY-SOURCE-PY-LOOPBACK",
        )
        config["kind"] = "python"
        config["driver_config"] = {
            "schema": "gateway-driver-config.v1",
            "target_dir": "/private/tmp/run/gateway-target",
            "cargo_path": "/fixed/cargo",
            "python_path": "/fixed/python3",
            "environment": dict(config["environment"]),
        }
        valid = {
            "path": (
                "/private/tmp/run/gateway-target/"
                "debug/csswitch-gateway"
            ),
            "mode": "0755",
            "size": 7,
            "sha256": "1" * 64,
        }
        cases = {
            "missing": (None, None, False),
            "extra": ({**valid, "owner": 0}, None, True),
            "malformed": ({**valid, "mode": "0644"}, None, True),
            "late": (valid, "ADAPTER_LATE", True),
        }
        for label, (derived, error, acked) in cases.items():
            with self.subTest(label=label):
                raw = TrustedCommandResult(
                    raw_process={"state": "EXITED", "process_exit": 0},
                    stdout=b"",
                    stderr=b"",
                    stdout_truncated=False,
                    stderr_truncated=False,
                    observation=derived,
                    observation_error=error,
                    observation_acked=acked,
                )
                with self.assertRaises(SourceAdapterError):
                    build_observation(config, raw)

    def test_02_zero_discovery_never_maps_to_pass(self):
        item = observation()
        for key in ("discovered_test_ids", "executed_test_ids"):
            item[key] = []
        item["executed"] = item["passed"] = 0
        with self.assertRaises(ContractViolation):
            result_from_observation(
                item, expected_suite_id=SUITE, expected_entrypoint_id=ENTRY,
                expected_test_ids=[],
            )

    def test_03_unknown_missing_duplicate_and_order_drift_fail_closed(self):
        for ids in (["other"], [], ["metadata", "metadata"]):
            item = observation()
            item["discovered_test_ids"] = ids
            item["executed_test_ids"] = ids
            item["executed"] = item["passed"] = len(ids)
            if ids == ["metadata", "metadata"]:
                with self.assertRaises(ContractViolation):
                    result_from_observation(
                        item, expected_suite_id=SUITE,
                        expected_entrypoint_id=ENTRY,
                        expected_test_ids=["metadata"],
                    )
            else:
                result = result_from_observation(
                    item, expected_suite_id=SUITE,
                    expected_entrypoint_id=ENTRY,
                    expected_test_ids=["metadata"],
                )
                self.assertEqual((result["kind"], result["runner_exit"]), ("INFRA", 12))

    def test_04_marker_pass_with_raw_nonzero_cannot_green(self):
        item = observation()
        item["raw_process"]["process_exit"] = 7
        item["adapter_exit"] = 12
        result = result_from_observation(
            item, expected_suite_id=SUITE, expected_entrypoint_id=ENTRY,
            expected_test_ids=["metadata"],
        )
        self.assertNotEqual(result["gate_decision"], "PASS")

    def test_05_skip_ignore_todo_and_not_run_cannot_green(self):
        variants = (
            ("skipped", "skipped_test_ids"),
            ("ignored", "ignored_test_ids"),
            ("todo", "todo_test_ids"),
        )
        for count_key, ids_key in variants:
            item = observation()
            item["passed"] = 0
            item[count_key] = 1
            item[ids_key] = ["metadata"]
            result = result_from_observation(
                item, expected_suite_id=SUITE,
                expected_entrypoint_id=ENTRY,
                expected_test_ids=["metadata"],
            )
            self.assertEqual(result["gate_decision"], "BLOCKED")
        item = observation()
        item["executed"] = item["passed"] = 0
        item["executed_test_ids"] = []
        item["not_run"] = 1
        item["not_run_test_ids"] = ["metadata"]
        result = result_from_observation(
            item, expected_suite_id=SUITE, expected_entrypoint_id=ENTRY,
            expected_test_ids=["metadata"],
        )
        self.assertNotEqual(result["gate_decision"], "PASS")

    def test_06_attempt_one_and_unknown_fields_are_rejected(self):
        for mutate in (
            lambda item: item.__setitem__("attempt_index", 1),
            lambda item: item.__setitem__("scenario", "pass"),
        ):
            item = observation()
            mutate(item)
            with self.assertRaises(ContractViolation):
                validate_source_observation(item)

        failed = observation()
        failed.update({
            "raw_process": {"state": "EXITED", "process_exit": 1},
            "adapter_exit": 10,
            "passed": 0,
            "failed": 1,
            "failed_test_ids": ["metadata"],
            "outcome_hint": "FAIL",
            "reason_code": "ASSERTION_FAILED",
        })
        validate_source_observation(failed)
        for mutate in (
            lambda item: item.__setitem__("failed_test_ids", []),
            lambda item: item.__setitem__("failed_test_ids", ["other"]),
            lambda item: item.update(
                skipped=1,
                skipped_test_ids=["metadata"],
            ),
        ):
            candidate = copy.deepcopy(failed)
            mutate(candidate)
            with self.assertRaises(ContractViolation):
                validate_source_observation(candidate)

    def test_07_raw_signal_and_typed_state_shapes_are_closed(self):
        item = observation()
        item["raw_process"] = {"state": "SIGNALED", "process_signal": 9}
        validate_source_observation(item)
        item["raw_process"]["process_exit"] = 0
        with self.assertRaises(ContractViolation):
            validate_source_observation(item)

    def test_08_aggregate_precedence_and_exact_order(self):
        results = []
        for suite_id in SOURCE_SUITE_ORDER:
            item = observation()
            item["suite_id"] = suite_id
            item["entrypoint_id"] = "ENTRY-" + suite_id.removeprefix("SUITE-")
            if suite_id == "SUITE-PY-LOOPBACK":
                item["derived_tool"] = {
                    "path": (
                        "/private/tmp/run/gateway-target/"
                        "debug/csswitch-gateway"
                    ),
                    "mode": "0755",
                    "size": 7,
                    "sha256": "1" * 64,
                }
            results.append(result_from_observation(
                item,
                expected_suite_id=suite_id,
                expected_entrypoint_id=item["entrypoint_id"],
                expected_test_ids=["metadata"],
            ))
        self.assertEqual(aggregate_results(results), ("PASS", 0))
        failed = copy.deepcopy(results)
        failed[4].update(
            kind="TEST_FAIL", outcome="FAIL", classification="NONE",
            gate_decision="FAIL", reason_code="ASSERTION_FAILED",
            runner_exit=10, attempt_records=[{"attempt_index": 0, "process_exit": 10}],
        )
        self.assertEqual(aggregate_results(failed), ("FAIL", 10))
        with self.assertRaises(ContractViolation):
            aggregate_results(list(reversed(results)))

    def test_09_fake_raw_result_closes_adapter_result_and_aggregate_loop(self):
        ordinary_raw = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 0},
            b"metadata validator passed\n",
            b"",
            False,
            False,
        )
        results = []
        for suite_id in SOURCE_SUITE_ORDER:
            entrypoint_id = "ENTRY-" + suite_id.removeprefix("SUITE-")
            config = adapter_config(
                suite_id=suite_id,
                entrypoint_id=entrypoint_id,
            )
            raw = ordinary_raw
            if suite_id == "SUITE-PY-LOOPBACK":
                config["kind"] = "python"
                config["expected_test_ids"] = [
                    "example.Example.test_metadata",
                ]
                config["driver_config"] = {
                    "schema": "gateway-driver-config.v1",
                    "target_dir": "/private/tmp/run/gateway-target",
                    "cargo_path": "/fixed/cargo",
                    "python_path": "/fixed/python3",
                    "environment": dict(config["environment"]),
                }
                raw = TrustedCommandResult(
                    {"state": "EXITED", "process_exit": 0},
                    (
                        b"test_metadata (example.Example)"
                        b" ... ok\n"
                        b"----------------------------------------------------------------------\n"
                        b"Ran 1 test in 0.001s\nOK\n"
                    ),
                    b"",
                    False,
                    False,
                    observation={
                        "path": (
                            "/private/tmp/run/gateway-target/"
                            "debug/csswitch-gateway"
                        ),
                        "mode": "0755",
                        "size": 7,
                        "sha256": "1" * 64,
                    },
                    observation_acked=True,
                )
            item = build_observation(config, raw)
            result = adjudicate_source_observation(
                item,
                parent_adapter_exit=0,
                suite=source_suite(suite_id, entrypoint_id),
                expected_test_ids=config["expected_test_ids"],
                command_argv_sha256=ZERO,
                environment_sha256=ZERO,
                tool_identity_sha256=ZERO,
            )
            self.assertEqual(
                (item["raw_process"]["process_exit"], result["runner_exit"]),
                (0, 0),
            )
            results.append(result)
        self.assertEqual(aggregate_results(results), ("PASS", 0))

    def test_10_parent_status_and_all_three_bindings_are_authority(self):
        config = adapter_config()
        item = build_observation(
            config,
            TrustedCommandResult(
                {"state": "EXITED", "process_exit": 0},
                b"",
                b"",
                False,
                False,
            ),
        )
        cases = (
            {"parent_adapter_exit": 12},
            {"command_argv_sha256": "1" * 64},
            {"environment_sha256": "1" * 64},
            {"tool_identity_sha256": "1" * 64},
        )
        base = {
            "parent_adapter_exit": 0,
            "suite": source_suite(),
            "expected_test_ids": config["expected_test_ids"],
            "command_argv_sha256": ZERO,
            "environment_sha256": ZERO,
            "tool_identity_sha256": ZERO,
        }
        for changed in cases:
            with self.subTest(changed=tuple(changed)):
                result = adjudicate_source_observation(
                    item, **{**base, **changed},
                )
                self.assertEqual(
                    (result["kind"], result["runner_exit"]),
                    ("INFRA", 12),
                )

    def test_11_real_adapter_process_frames_observation_and_waits_for_ack(self):
        adapter_fd = os.open(
            REPO_ROOT / "test/quality/source_gate/adapter.py",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        self.addCleanup(os.close, adapter_fd)
        bootstrap = (
            "import os;"
            "os.lseek(198,0,0);"
            "p='/dev/fd/198';"
            "exec(compile(open(p,'rb').read(),p,'exec'))"
        )
        fd_probe = (
            "import os,subprocess,sys;"
            "own=os.path.exists('/dev/fd/199');"
            "child=subprocess.run([sys.executable,'-I','-S','-c',"
            "\"import os;raise SystemExit(97 if "
            "os.path.exists('/dev/fd/199') else 0)\"],"
            "close_fds=False);"
            "raise SystemExit(97 if own or child.returncode else 0)"
        )
        for command, expected in (
            (["/usr/bin/true"], (0, 0)),
            (
                [
                    os.path.realpath(os.sys.executable),
                    "-I",
                    "-S",
                    "-c",
                    fd_probe,
                ],
                (0, 0),
            ),
            (["/usr/bin/false"], (10, 7)),
        ):
            with self.subTest(command=command[0]):
                config = adapter_config()
                if command[0].endswith("false"):
                    command = [
                        os.path.realpath(os.sys.executable), "-I", "-S", "-c",
                        "raise SystemExit(7)",
                    ]
                config["argv"] = command
                raw = canonical_json_bytes(config)
                supervised = runner.supervise_raw_command(
                    argv=(
                        os.path.realpath(os.sys.executable),
                        "-I",
                        "-c",
                        bootstrap,
                        "--config-fd",
                        "197",
                        "--observation-fd",
                        "199",
                    ),
                    environment={
                        "HOME": os.path.realpath(os.getenv("TMPDIR", "/tmp")),
                        "PATH": os.defpath,
                    },
                    timeout_seconds=3.0,
                    output_limit_bytes=4096,
                    framed_config=len(raw).to_bytes(4, "big") + raw,
                    inherited_fds=((adapter_fd, 198),),
                )
                self.assertEqual(
                    supervised.raw_process,
                    {"state": "EXITED", "process_exit": expected[0]},
                )
                self.assertIsNone(supervised.observation_error)
                self.assertTrue(supervised.observation_acked)
                self.assertEqual(
                    supervised.observation["raw_process"],
                    {"state": "EXITED", "process_exit": expected[1]},
                )

    def test_12_unittest_parser_binds_exact_ids_and_approved_skip(self):
        config = adapter_config()
        config.update(
            kind="python",
            expected_test_ids=[
                "example.Example.test_a",
                "example.Example.test_b",
                "example.Example.test_c",
            ],
            approved_skipped_test_ids=["example.Example.test_b"],
        )
        raw = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 1},
            b"",
            (
                b"test_a (example.Example) ... ok\n"
                b"test_b (example.Example) ... skipped 'offline'\n"
                b"test_c (example.Example) ... FAIL\n"
                b"\nFAIL: test_c (example.Example)\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 3 tests in 0.001s\n"
                b"\nFAILED (failures=1, skipped=1)\n"
            ),
            False,
            False,
        )
        item = build_observation(config, raw)
        self.assertEqual(
            (
                item["discovered_test_ids"],
                item["executed_test_ids"],
                item["skipped_test_ids"],
                item["failed_test_ids"],
                item["failed"],
                item["adapter_exit"],
            ),
            (
                config["expected_test_ids"],
                config["expected_test_ids"],
                ["example.Example.test_b"],
                ["example.Example.test_c"],
                1,
                10,
            ),
        )
        cases = {
            "missing": (
                b"test_a (example.Example) ... ok\n"
                b"test_b (example.Example) ... skipped 'offline'\n",
                [
                    "example.Example.test_a",
                    "example.Example.test_b",
                ],
                ["example.Example.test_c"],
            ),
            "unknown-class-prefix": (
                raw.stderr
                + b"test_c (prefix.example.Example) ... FAIL\n",
                [
                    "example.Example.test_a",
                    "example.Example.test_b",
                    "example.Example.test_c",
                    "prefix.example.Example.test_c",
                ],
                [],
            ),
            "inside-method-mismatch": (
                raw.stderr
                + b"other (example.Example) ... FAIL\n",
                [
                    "example.Example.other",
                    "example.Example.test_a",
                    "example.Example.test_b",
                    "example.Example.test_c",
                ],
                [],
            ),
            "duplicate": (
                raw.stderr
                + b"test_a (example.Example) ... ok\n",
                config["expected_test_ids"],
                [],
            ),
            "forged-old-fixture": (
                b"test_a (example.Example.test_a) ... ok\n"
                b"test_b (example.Example) ... skipped 'offline'\n"
                b"test_c (example.Example) ... FAIL\n",
                [
                    "example.Example.test_a.test_a",
                    "example.Example.test_b",
                    "example.Example.test_c",
                ],
                ["example.Example.test_a"],
            ),
        }
        for label, (stderr, discovered, not_run) in cases.items():
            with self.subTest(label=label):
                malformed = TrustedCommandResult(
                    raw.raw_process,
                    b"",
                    stderr,
                    False,
                    False,
                )
                observed = build_observation(config, malformed)
                self.assertEqual(observed["adapter_exit"], 12)
                self.assertEqual(
                    observed["discovered_test_ids"],
                    sorted(discovered),
                )
                self.assertEqual(
                    observed["executed_test_ids"],
                    sorted(discovered),
                )
                self.assertEqual(observed["not_run_test_ids"], not_run)

    def test_13_unittest_parser_retains_identity_across_child_stderr(self):
        config = adapter_config()
        config.update(
            kind="python",
            expected_test_ids=[
                "example.Example.test_direct_error",
                "example.Example.test_error",
                "example.Example.test_pass",
            ],
        )
        raw = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 1},
            b"",
            (
                b"test_direct_error (example.Example) ... ERROR\n"
                b"test_error (example.Example) ... child stderr before failure\n"
                b"test_pass (example.Example) ... child stderr before pass\n"
                b"ok\n"
                b"\nERROR: test_direct_error (example.Example)\n"
                b"\nERROR: test_error (example.Example)\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 3 tests in 0.001s\n"
                b"\nFAILED (errors=2)\n"
            ),
            False,
            False,
        )
        item = build_observation(config, raw)
        self.assertEqual(item["discovered_test_ids"], config["expected_test_ids"])
        self.assertEqual(item["executed_test_ids"], config["expected_test_ids"])
        self.assertEqual(item["failed"], 2)
        self.assertEqual(
            item["failed_test_ids"],
            [
                "example.Example.test_direct_error",
                "example.Example.test_error",
            ],
        )
        self.assertEqual(item["passed"], 1)
        self.assertEqual(item["not_run"], 0)
        self.assertEqual(item["adapter_exit"], 10)

        parent = "example.Example.test_parent"
        next_id = "example.Example.test_next"
        for event_count in (1, 2, 3):
            for next_state in ("ok", "FAIL", "ERROR", "skipped 'approved'"):
                with self.subTest(
                    event_count=event_count,
                    next_state=next_state,
                ):
                    sub_config = adapter_config()
                    sub_config.update(
                        kind="python",
                        expected_test_ids=sorted([parent, next_id]),
                        approved_skipped_test_ids=(
                            [next_id] if next_state.startswith("skipped ") else []
                        ),
                    )
                    failure_headers = b"".join(
                        (
                            b"\nFAIL: test_parent (example.Example) "
                            + f"(failure_point={index})\n".encode()
                        )
                        for index in range(event_count)
                    )
                    next_header = (
                        b"\n"
                        + next_state.encode()
                        + b": test_next (example.Example)\n"
                        if next_state in {"FAIL", "ERROR"}
                        else b""
                    )
                    failures = event_count + (next_state == "FAIL")
                    errors = int(next_state == "ERROR")
                    skipped = int(next_state.startswith("skipped "))
                    fields = []
                    if failures:
                        fields.append(f"failures={failures}")
                    if errors:
                        fields.append(f"errors={errors}")
                    if skipped:
                        fields.append(f"skipped={skipped}")
                    stderr = (
                        b"test_parent (example.Example) ... "
                        b"test_next (example.Example) ... "
                        + next_state.encode()
                        + b"\n"
                        + failure_headers
                        + next_header
                        + b"----------------------------------------------------------------------\n"
                        + b"Ran 2 tests in 0.001s\n"
                        + b"\nFAILED ("
                        + ", ".join(fields).encode()
                        + b")\n"
                    )
                    observed = build_observation(
                        sub_config,
                        TrustedCommandResult(
                            {"state": "EXITED", "process_exit": 1},
                            b"",
                            stderr,
                            False,
                            False,
                        ),
                    )
                    expected_failed = [parent] + (
                        [next_id] if next_state in {"FAIL", "ERROR"} else []
                    )
                    self.assertEqual(observed["adapter_exit"], 10)
                    self.assertEqual(
                        observed["discovered_test_ids"],
                        [next_id, parent],
                    )
                    self.assertEqual(
                        observed["executed_test_ids"],
                        [next_id, parent],
                    )
                    self.assertEqual(
                        observed["failed_test_ids"],
                        sorted(expected_failed),
                    )
                    self.assertEqual(observed["not_run_test_ids"], [])

        mixed = build_observation(
            {
                **adapter_config(),
                "kind": "python",
                "expected_test_ids": sorted([parent, next_id]),
            },
            TrustedCommandResult(
                {"state": "EXITED", "process_exit": 1},
                b"",
                (
                    b"test_parent (example.Example) ... "
                    b"test_next (example.Example) ... ok\n"
                    b"\nFAIL: test_parent (example.Example) (case='fail')\n"
                    b"\nERROR: test_parent (example.Example) (case='error')\n"
                    b"----------------------------------------------------------------------\n"
                    b"Ran 2 tests in 0.001s\n"
                    b"\nFAILED (failures=1, errors=1)\n"
                ),
                False,
                False,
            ),
        )
        self.assertEqual(mixed["adapter_exit"], 10)
        self.assertEqual(mixed["failed"], 1)
        self.assertEqual(mixed["failed_test_ids"], [parent])

        unapproved_skip_config = adapter_config()
        unapproved_skip_config.update(
            kind="python",
            expected_test_ids=sorted([parent, next_id]),
        )
        unapproved_skip = build_observation(
            unapproved_skip_config,
            TrustedCommandResult(
                {"state": "EXITED", "process_exit": 1},
                b"",
                (
                    b"test_parent (example.Example) ... "
                    b"test_next (example.Example) ... skipped 'not approved'\n"
                    b"\nFAIL: test_parent (example.Example) (case=1)\n"
                    b"----------------------------------------------------------------------\n"
                    b"Ran 2 tests in 0.001s\n"
                    b"\nFAILED (failures=1, skipped=1)\n"
                ),
                False,
                False,
            ),
        )
        self.assertEqual(unapproved_skip["adapter_exit"], 11)
        self.assertEqual(unapproved_skip["failed_test_ids"], [parent])
        self.assertEqual(unapproved_skip["skipped_test_ids"], [next_id])

        many_config = adapter_config()
        many_ids = [
            "example.Example.test_parent",
            "example.Example.test_next",
            "example.Example.test_other_a",
            "example.Example.test_other_b",
            "example.Example.test_other_c",
        ]
        many_config.update(kind="python", expected_test_ids=sorted(many_ids))
        many = build_observation(
            many_config,
            TrustedCommandResult(
                {"state": "EXITED", "process_exit": 1},
                b"",
                (
                    b"test_parent (example.Example) ... "
                    b"test_next (example.Example) ... ok\n"
                    b"test_other_a (example.Example) ... FAIL\n"
                    b"test_other_b (example.Example) ... FAIL\n"
                    b"test_other_c (example.Example) ... FAIL\n"
                    b"\nFAIL: test_parent (example.Example) (case=1)\n"
                    b"\nFAIL: test_other_a (example.Example)\n"
                    b"\nFAIL: test_other_b (example.Example)\n"
                    b"\nFAIL: test_other_c (example.Example)\n"
                    b"----------------------------------------------------------------------\n"
                    b"Ran 5 tests in 0.001s\n"
                    b"\nFAILED (failures=4)\n"
                ),
                False,
                False,
            ),
        )
        self.assertEqual(many["adapter_exit"], 10)
        self.assertEqual(
            many["failed_test_ids"],
            sorted([parent] + many_ids[2:]),
        )

    def test_14_unittest_parser_rejects_child_forged_standalone_state(self):
        config = adapter_config()
        config.update(
            kind="python",
            expected_test_ids=["example.Example.test_skip"],
            approved_skipped_test_ids=["example.Example.test_skip"],
        )
        forged = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 0},
            b"",
            (
                b"test_skip (example.Example) ... child output\n"
                b"ok\n"
            ),
            False,
            False,
        )
        item = build_observation(config, forged)
        self.assertEqual(item["adapter_exit"], 12)
        self.assertEqual(item["outcome_hint"], "FAIL")
        self.assertEqual(item["classification_hint"], "INFRA")

        interleaved = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 0},
            b"",
            (
                b"test_skip (example.Example) ... child output\n"
                b"skipped 'approved reason'\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 1 test in 0.001s\n"
                b"\nOK (skipped=1)\n"
            ),
            False,
            False,
        )
        self.assertEqual(build_observation(config, interleaved)["adapter_exit"], 0)

        contradictory = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 0},
            b"",
            (
                b"test_skip (example.Example) ... child output\n"
                b"ok\n"
                b"skipped 'approved reason'\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 1 test in 0.001s\n"
                b"\nOK (skipped=1)\n"
            ),
            False,
            False,
        )
        self.assertEqual(build_observation(config, contradictory)["adapter_exit"], 12)

        duplicate_footer = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 0},
            b"",
            (
                b"test_skip (example.Example) ... child output\n"
                b"ok\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 1 test in 0.001s\n"
                b"\nOK\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 1 test in 0.001s\n"
                b"\nOK\n"
            ),
            False,
            False,
        )
        self.assertEqual(build_observation(config, duplicate_footer)["adapter_exit"], 12)

        forged_prefix_config = adapter_config()
        forged_prefix_config.update(
            kind="python",
            expected_test_ids=sorted([
                "example.Example.test_parent",
                "example.Example.test_next",
            ]),
        )
        forged_prefix = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 0},
            b"",
            (
                b"test_parent (example.Example) ... "
                b"test_next (example.Example) ... ok\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 2 tests in 0.001s\n"
                b"\nOK\n"
            ),
            False,
            False,
        )
        self.assertEqual(
            build_observation(forged_prefix_config, forged_prefix)["adapter_exit"],
            12,
        )

        malformed_footers = (
            (
                0,
                b"test_skip (example.Example) ... skipped 'approved reason'\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 2 tests in 0.001s\n"
                b"\nOK (skipped=1)\n",
            ),
            (
                0,
                b"test_skip (example.Example) ... skipped 'approved reason'\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 1 test in 0.001s\n"
                b"\nOK\n",
            ),
            (
                1,
                b"test_skip (example.Example) ... FAIL\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 1 test in 0.001s\n"
                b"\nFAILED (failures=0)\n",
            ),
            (
                1,
                b"test_skip (example.Example) ... FAIL\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 1 test in 0.001s\n"
                b"\nFAILED (unknown=1)\n",
            ),
            (
                1,
                b"test_skip (example.Example) ... FAIL\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 1 test in 0.001s\n"
                b"\nFAILED (failures=1, skipped=1)\n",
            ),
            (
                0,
                b"test_skip (example.Example) ... skipped 'approved reason'\n"
                b"----------------------------------------------------------------------\n"
                b"Ran 1 test in 0.001s\n"
                b"\nOK (skipped=1)\n"
                b"child output after footer\n",
            ),
        )
        for process_exit, stderr in malformed_footers:
            with self.subTest(stderr=stderr):
                malformed = TrustedCommandResult(
                    {"state": "EXITED", "process_exit": process_exit},
                    b"",
                    stderr,
                    False,
                    False,
                )
                self.assertEqual(
                    build_observation(config, malformed)["adapter_exit"],
                    12,
                )

    def test_15_rust_parser_requires_exact_known_ignored_identity(self):
        config = adapter_config()
        config.update(
            kind="rust",
            expected_test_ids=[
                "desktop/example/Cargo.toml::lib::module::ignored_test",
                "desktop/example/Cargo.toml::lib::module::passes",
            ],
            approved_ignored_test_ids=[
                "desktop/example/Cargo.toml::lib::module::ignored_test",
            ],
            approved_ignored_tests={
                "desktop/example/Cargo.toml::lib::module::ignored_test": {
                    "boundary": "acceptance",
                    "reason": "explicit Acceptance boundary host smoke",
                },
            },
        )
        raw = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 0},
            (
                b"test module::passes ... ok\n"
                b"test module::ignored_test ... ignored, explicit Acceptance boundary host smoke\n"
            ),
            b"",
            False,
            False,
        )
        item = build_observation(config, raw)
        self.assertEqual(
            (
                item["discovered_test_ids"],
                item["executed_test_ids"],
                item["ignored_test_ids"],
                item["adapter_exit"],
            ),
            (
                config["expected_test_ids"],
                config["expected_test_ids"],
                config["approved_ignored_test_ids"],
                0,
            ),
        )
        for line in (
            b"test module::ignored_test ... ignored, now flaky and in-scope\n",
            b"test module::ignored_test ... ignored\n",
        ):
            with self.subTest(line=line):
                changed = TrustedCommandResult(
                    {"state": "EXITED", "process_exit": 0},
                    b"test module::passes ... ok\n" + line,
                    b"",
                    False,
                    False,
                )
                self.assertEqual(
                    build_observation(config, changed)["adapter_exit"],
                    12,
                )
        invalid_config = copy.deepcopy(config)
        invalid_config["approved_ignored_tests"][
            "desktop/example/Cargo.toml::lib::module::ignored_test"
        ]["boundary"] = "flaky"
        config_raw = canonical_json_bytes(invalid_config)
        config_read, config_write = os.pipe()
        try:
            os.write(config_write, len(config_raw).to_bytes(4, "big") + config_raw)
            os.close(config_write)
            config_write = -1
            with self.assertRaises(SourceAdapterError):
                _read_config(config_read)
        finally:
            os.close(config_read)
            if config_write >= 0:
                os.close(config_write)
        config["approved_ignored_test_ids"] = []
        config["approved_ignored_tests"] = {}
        self.assertEqual(build_observation(config, raw)["adapter_exit"], 12)

    def test_16_node_parser_surfaces_todo_and_unknown_identity(self):
        config = adapter_config()
        config.update(
            kind="frontend",
            expected_test_ids=[
                "test/a.test.mjs::passes",
                "test/a.test.mjs::todo case",
            ],
        )
        raw = TrustedCommandResult(
            {"state": "EXITED", "process_exit": 0},
            (
                b"TAP version 13\n"
                b"# Subtest: passes\n"
                b"ok 1 - passes\n"
                b"# Subtest: todo case\n"
                b"ok 2 - todo case # TODO later\n"
            ),
            b"",
            False,
            False,
        )
        item = build_observation(config, raw)
        self.assertEqual(
            (
                item["discovered_test_ids"],
                item["todo_test_ids"],
                item["adapter_exit"],
            ),
            (
                config["expected_test_ids"],
                ["test/a.test.mjs::todo case"],
                11,
            ),
        )
        config["expected_test_ids"] = [
            "test/a.test.mjs::different",
            "test/a.test.mjs::passes",
        ]
        self.assertEqual(build_observation(config, raw)["adapter_exit"], 12)

    def test_17_shell_parser_surfaces_explicit_not_run(self):
        config = adapter_config()
        config.update(
            kind="shell",
            expected_test_ids=[
                "shell:test/a.sh",
                "shell:test/b.sh",
            ],
        )
        item = build_observation(
            config,
            TrustedCommandResult(
                {"state": "EXITED", "process_exit": 0},
                (
                    b"SOURCE_GATE_COMPONENT test/a.sh PASS\n"
                    b"SOURCE_GATE_COMPONENT test/b.sh NOT_RUN\n"
                ),
                b"",
                False,
                False,
            ),
        )
        self.assertEqual(
            (
                item["discovered_test_ids"],
                item["executed_test_ids"],
                item["not_run_test_ids"],
                item["adapter_exit"],
            ),
            (
                config["expected_test_ids"],
                ["shell:test/a.sh"],
                ["shell:test/b.sh"],
                11,
            ),
        )

    def test_16_exact_plans_have_fixed_tools_sanitized_env_and_offline_rust(self):
        plans = self._real_plans()
        self.assertEqual(
            tuple(plan.suite["id"] for plan in plans),
            SOURCE_SUITE_ORDER,
        )
        for plan in plans:
            self.assertTrue(plan.argv[0].startswith("/fixed/bin/"))
            self.assertFalse(
                {
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                    "AWS_ACCESS_KEY_ID", "SSH_AUTH_SOCK",
                    "CSSWITCH_LOOPBACK_TEST_CMD",
                }
                & set(plan.environment)
            )
            self.assertEqual(
                plan.command_argv_sha256,
                hashlib.sha256(
                    canonical_json_bytes(
                        (
                            {
                                "driver_argv": list(plan.argv),
                                "driver_config": dict(
                                    plan.driver_config,
                                ),
                            }
                            if plan.driver_config is not None
                            else list(plan.argv)
                        ),
                    ),
                ).hexdigest(),
            )
            self.assertEqual(
                plan.environment_sha256,
                hashlib.sha256(
                    canonical_json_bytes(dict(plan.environment)),
                ).hexdigest(),
            )
            if plan.suite["kind"] == "rust":
                self.assertEqual(
                    plan.environment["CARGO_NET_OFFLINE"], "true",
                )
                self.assertEqual(
                    plan.environment["CARGO_HOME"],
                    "/private/tmp/source-fake/cargo-home",
                )
            if plan.suite["environment_allowlist"] == [
                "CSSWITCH_GATEWAY_BIN",
            ]:
                self.assertEqual(
                    plan.environment["CSSWITCH_GATEWAY_BIN"],
                    (
                        "/private/tmp/source-fake/gateway-target/"
                        "debug/csswitch-gateway"
                    ),
                )

    def test_17_sequential_executor_calls_each_exact_plan_once(self):
        plans = self._real_plans()
        calls = []
        checks = []

        def run_one(plan, config):
            calls.append(plan.suite["id"])
            expected = list(plan.expected_test_ids)
            skipped = list(plan.approved_skipped_test_ids)
            ignored = list(plan.approved_ignored_test_ids)
            item = observation()
            item.update({
                "run_id": RUN_ID,
                "suite_id": plan.suite["id"],
                "entrypoint_id": plan.suite["entrypoint_id"],
                "command_argv_sha256": plan.command_argv_sha256,
                "environment_sha256": plan.environment_sha256,
                "tool_identity_sha256": plan.tool_identity_sha256,
                "executed": len(expected),
                "passed": len(expected) - len(skipped) - len(ignored),
                "skipped": len(skipped),
                "ignored": len(ignored),
                "discovered_test_ids": expected,
                "executed_test_ids": expected,
                "failed_test_ids": [],
                "skipped_test_ids": skipped,
                "ignored_test_ids": ignored,
            })
            if plan.suite["id"] == "SUITE-PY-LOOPBACK":
                item["derived_tool"] = {
                    "path": (
                        plan.driver_config["target_dir"]
                        + "/debug/csswitch-gateway"
                    ),
                    "mode": "0755",
                    "size": 7,
                    "sha256": "1" * 64,
                }
            return TrustedCommandResult(
                raw_process={"state": "EXITED", "process_exit": 0},
                stdout=b"",
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                observation=item,
                observation_error=None,
                observation_acked=True,
            )

        def recheck(phase, index, plan):
            checks.append((phase, index, plan.suite["id"]))
            return True

        observations, results, aggregate = execute_source_plans(
            plans,
            run_id=RUN_ID,
            run_one=run_one,
            recheck=recheck,
        )
        self.assertEqual(calls, list(SOURCE_SUITE_ORDER))
        self.assertEqual(len(calls), len(set(calls)))
        self.assertEqual(len(observations), 15)
        self.assertEqual(len(results), 15)
        self.assertEqual(aggregate, ("PASS", 0))
        self.assertEqual(
            [phase for phase, _, _ in checks],
            ["before", "after"] * 15,
        )

        failure_calls = []

        def one_failure(plan, config):
            failure_calls.append(plan.suite["id"])
            expected = list(plan.expected_test_ids)
            skipped = list(plan.approved_skipped_test_ids)
            ignored = list(plan.approved_ignored_test_ids)
            failed = plan is plans[0]
            item = observation()
            item.update({
                "run_id": RUN_ID,
                "suite_id": plan.suite["id"],
                "entrypoint_id": plan.suite["entrypoint_id"],
                "command_argv_sha256": plan.command_argv_sha256,
                "environment_sha256": plan.environment_sha256,
                "tool_identity_sha256": plan.tool_identity_sha256,
                "raw_process": {
                    "state": "EXITED",
                    "process_exit": 7 if failed else 0,
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
                "discovered_test_ids": expected,
                "executed_test_ids": expected,
                "failed_test_ids": expected[:1] if failed else [],
                "skipped_test_ids": skipped,
                "ignored_test_ids": ignored,
                "outcome_hint": "FAIL" if failed else "PASS",
                "classification_hint": "NONE",
                "reason_code": (
                    "ASSERTION_FAILED" if failed else "NONE"
                ),
            })
            if plan.suite["id"] == "SUITE-PY-LOOPBACK":
                item["derived_tool"] = {
                    "path": (
                        plan.driver_config["target_dir"]
                        + "/debug/csswitch-gateway"
                    ),
                    "mode": "0755",
                    "size": 7,
                    "sha256": "1" * 64,
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
                observation=item,
                observation_error=None,
                observation_acked=True,
            )

        _, _, failed_aggregate = execute_source_plans(
            plans,
            run_id=RUN_ID,
            run_one=one_failure,
            recheck=lambda phase, index, plan: True,
        )
        self.assertEqual(failure_calls, list(SOURCE_SUITE_ORDER))
        self.assertEqual(len(failure_calls), len(set(failure_calls)))
        self.assertEqual(failed_aggregate, ("FAIL", 10))

    def test_18_plan_inventory_drift_and_execution_recheck_fail_closed(self):
        plans = self._real_plans()
        checks = []

        def reject_after_first(phase, index, plan):
            checks.append((phase, index))
            return not (phase == "after" and index == 0)

        with self.assertRaises(ContractViolation):
            execute_source_plans(
                plans,
                run_id=RUN_ID,
                run_one=lambda plan, config: None,
                recheck=reject_after_first,
            )
        self.assertEqual(checks, [("before", 0), ("after", 0)])

        for drift_kind in (
            "source", "catalog", "tool", "environment", "git", "worktree",
        ):
            with self.subTest(drift_kind=drift_kind):
                seen = []

                def named_drift(phase, index, plan):
                    seen.append((drift_kind, phase, index))
                    return False

                with self.assertRaises(ContractViolation):
                    execute_source_plans(
                        plans,
                        run_id=RUN_ID,
                        run_one=lambda plan, config: None,
                        recheck=named_drift,
                    )
                self.assertEqual(
                    seen, [(drift_kind, "before", 0)],
                )

        catalog = json.loads(
            (REPO_ROOT / "quality/test-catalog.v1.json").read_text("utf-8"),
        )
        catalog["suites"] = [
            suite for suite in catalog["suites"]
            if suite["id"] != SOURCE_SUITE_ORDER[-1]
        ]
        gates = json.loads(
            (REPO_ROOT / "quality/release-gates.v1.json").read_text("utf-8"),
        )
        inventory_path = (
            REPO_ROOT
            / "test/quality/fixtures/source_gate/expected_test_ids.v1.json"
        )
        inventory_raw = inventory_path.read_bytes()
        with self.assertRaises(ContractViolation):
            build_source_plans(
                catalog,
                gates,
                inventory_raw,
                tools={
                    "PYTHON": "/fixed/python", "BASH": "/fixed/bash",
                    "NODE": "/fixed/node", "CARGO": "/fixed/cargo",
                    "RUSTC": "/fixed/rustc", "GIT": "/fixed/git",
                },
                tool_identity_sha256="a" * 64,
                run_home="/private/tmp/fake/home",
                run_tmp="/private/tmp/fake/tmp",
                offline_cargo_home="/private/tmp/fake/cargo",
                rustup_home="/private/tmp/fake/rustup",
                gateway_target="/private/tmp/fake/gateway-target",
            )
        inventory_value = json.loads(inventory_raw)
        inventory_value["suites"]["QUALITY-METADATA"][
            "discovered_test_ids"
        ] = ["command:forged"]
        forged_raw = json.dumps(
            inventory_value, ensure_ascii=False, indent=2,
        ).encode("utf-8") + b"\n"
        with self.assertRaises(ContractViolation):
            build_source_plans(
                json.loads(
                    (REPO_ROOT / "quality/test-catalog.v1.json").read_text(
                        "utf-8",
                    ),
                ),
                gates,
                forged_raw,
                tools={
                    "PYTHON": "/fixed/python", "BASH": "/fixed/bash",
                    "NODE": "/fixed/node", "CARGO": "/fixed/cargo",
                    "RUSTC": "/fixed/rustc", "GIT": "/fixed/git",
                },
                tool_identity_sha256="a" * 64,
                run_home="/private/tmp/fake/home",
                run_tmp="/private/tmp/fake/tmp",
                offline_cargo_home="/private/tmp/fake/cargo",
                rustup_home="/private/tmp/fake/rustup",
                gateway_target="/private/tmp/fake/gateway-target",
            )


if __name__ == "__main__":
    unittest.main()
