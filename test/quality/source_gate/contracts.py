"""Closed source-gate contracts layered over the frozen RUE result ABI."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from test.quality.run_evidence.contracts import ContractViolation, make_result
from test.quality.run_evidence.manifest_contracts import validate_source_observation


SOURCE_SUITE_ORDER = (
    "SUITE-QUALITY-METADATA",
    "SUITE-QUALITY-FOCUSED",
    "SUITE-RUN-EVIDENCE-CONTRACT",
    "SUITE-QUALITY-INVENTORY",
    "SUITE-PY-OFFLINE",
    "SUITE-RUST-GATEWAY",
    "SUITE-PY-LOOPBACK",
    "SUITE-SHELL-SCRIPTS",
    "SUITE-RUST-DESKTOP",
    "SUITE-RUST-CODEX-NETWORK",
    "SUITE-RUST-SKILL-PACKAGE",
    "SUITE-MJS-FRONTEND",
    "SUITE-ORPHAN-SKILL-BRIDGE",
    "SUITE-ORPHAN-SKILL-BOUNDARY",
    "SUITE-SOURCE-GATE-CONTRACT",
)


def _fail(message: str) -> None:
    raise ContractViolation("ADAPTER_MALFORMED", message)


def validate_source_catalog(catalog: Any, gates: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(catalog, Mapping) or catalog.get("schema") != "test-catalog.v1":
        _fail("source catalog shape")
    suites = catalog.get("suites")
    rules = catalog.get("selection_rules")
    if not isinstance(suites, list) or not isinstance(rules, list):
        _fail("source catalog collections")
    by_id = {
        suite.get("id"): suite
        for suite in suites
        if isinstance(suite, Mapping) and isinstance(suite.get("id"), str)
    }
    source_rules = [rule for rule in rules if isinstance(rule, Mapping) and rule.get("name") == "source-gate"]
    if len(source_rules) != 1 or tuple(source_rules[0].get("suite_ids", ())) != SOURCE_SUITE_ORDER or source_rules[0].get("executor_implemented") is not True:
        _fail("source selection drift")
    selected = []
    for suite_id in SOURCE_SUITE_ORDER:
        suite = by_id.get(suite_id)
        if not isinstance(suite, Mapping):
            _fail("missing source suite")
        if (
            suite.get("adapter_protocol") != "source-observation.v1"
            or suite.get("retry_policy") != "none"
            or suite.get("status") != "implemented"
            or suite.get("expected_status") != "PASS"
            or not isinstance(suite.get("command_argv"), list)
            or not suite["command_argv"]
            or not isinstance(suite.get("timeout_seconds"), int)
            or not isinstance(suite.get("test_identity"), Mapping)
            or suite.get("gate_ids") != ["GATE-SOURCE"]
        ):
            _fail("source suite contract drift")
        selected.append(suite)
    if not isinstance(gates, Mapping) or gates.get("schema") != "release-gates.v1":
        _fail("source gates shape")
    source_gates = [
        gate for gate in gates.get("gates", ())
        if isinstance(gate, Mapping) and gate.get("id") == "GATE-SOURCE"
    ]
    if (
        len(source_gates) != 1
        or source_gates[0].get("status") != "active"
        or tuple(source_gates[0].get("required_suite_ids", ())) != SOURCE_SUITE_ORDER
        or source_gates[0].get("requires_clean") is not True
        or source_gates[0].get("release_claim") != "source-green"
    ):
        _fail("source gate drift")
    return tuple(selected)


def result_from_observation(
    observation: Mapping[str, Any],
    *,
    expected_suite_id: str,
    expected_entrypoint_id: str,
    expected_test_ids: Sequence[str],
    approved_skipped_ids: Sequence[str] = (),
    approved_ignored_ids: Sequence[str] = (),
) -> dict[str, Any]:
    validate_source_observation(observation)
    if (
        observation["suite_id"] != expected_suite_id
        or observation["entrypoint_id"] != expected_entrypoint_id
    ):
        _fail("source observation identity drift")
    expected = sorted(expected_test_ids, key=lambda item: item.encode("utf-8"))
    if not expected or len(expected) != len(set(expected)):
        _fail("empty or duplicate expected identities")
    discovered = observation["discovered_test_ids"]
    executed = observation["executed_test_ids"]
    allowed_skipped = sorted(approved_skipped_ids, key=lambda item: item.encode("utf-8"))
    allowed_ignored = sorted(approved_ignored_ids, key=lambda item: item.encode("utf-8"))
    if discovered != expected or executed != expected:
        return make_result(
            "INFRA", observation["run_id"], expected_suite_id,
            expected_entrypoint_id,
            attempt_records=[{"attempt_index": 0, "process_exit": observation["adapter_exit"]}],
            runner_exit=12, reason_code="ADAPTER_MALFORMED",
        )
    if observation["skipped_test_ids"] != allowed_skipped:
        return make_result(
            "SKIPPED", observation["run_id"], expected_suite_id,
            expected_entrypoint_id,
            attempt_records=[{"attempt_index": 0, "process_exit": 11}],
        )
    if observation["ignored_test_ids"] != allowed_ignored:
        return make_result(
            "IGNORED", observation["run_id"], expected_suite_id,
            expected_entrypoint_id,
            attempt_records=[{"attempt_index": 0, "process_exit": 11}],
        )
    if observation["todo"] or observation["not_run"]:
        return make_result("NOTRUN", observation["run_id"], expected_suite_id, expected_entrypoint_id)
    raw = observation["raw_process"]
    if raw.get("state") == "HARD_TIMEOUT":
        return make_result(
            "HARD_TIMEOUT", observation["run_id"], expected_suite_id,
            expected_entrypoint_id,
            attempt_records=[{"attempt_index": 0, "process_exit": observation["adapter_exit"]}],
            runner_exit=13,
        )
    if raw.get("state") != "EXITED":
        return make_result(
            "INFRA", observation["run_id"], expected_suite_id,
            expected_entrypoint_id,
            attempt_records=[{"attempt_index": 0, "process_exit": observation["adapter_exit"]}],
            runner_exit=12, reason_code="ADAPTER_MALFORMED",
        )
    if (
        raw["process_exit"] == 0
        and observation["adapter_exit"] == 0
        and observation["failed"] == 0
        and observation["outcome_hint"] == "PASS"
        and observation["classification_hint"] == "NONE"
        and observation["reason_code"] == "NONE"
    ):
        return make_result(
            "PASS", observation["run_id"], expected_suite_id,
            expected_entrypoint_id,
            attempt_records=[{"attempt_index": 0, "process_exit": 0}],
        )
    if observation["adapter_exit"] == 11:
        kind = "ENV" if observation["classification_hint"] == "ENVIRONMENT" else "REAL"
        return make_result(
            kind, observation["run_id"], expected_suite_id, expected_entrypoint_id,
            attempt_records=[{"attempt_index": 0, "process_exit": 11}],
        )
    if observation["adapter_exit"] == 10:
        return make_result(
            "TEST_FAIL", observation["run_id"], expected_suite_id,
            expected_entrypoint_id,
            attempt_records=[{"attempt_index": 0, "process_exit": 10}],
        )
    return make_result(
        "INFRA", observation["run_id"], expected_suite_id,
        expected_entrypoint_id,
        attempt_records=[{"attempt_index": 0, "process_exit": observation["adapter_exit"]}],
        runner_exit=12, reason_code="ADAPTER_MALFORMED",
    )


def aggregate_results(results: Sequence[Mapping[str, Any]]) -> tuple[str, int]:
    if len(results) != len(SOURCE_SUITE_ORDER):
        _fail("partial source result set")
    identities = tuple(result.get("suite_id") for result in results)
    if identities != SOURCE_SUITE_ORDER or len(set(identities)) != len(identities):
        _fail("source result order")
    decisions = [result.get("gate_decision") for result in results]
    exits = [result.get("runner_exit") for result in results]
    if all(item == "PASS" for item in decisions):
        return "PASS", 0
    if "FAIL" in decisions:
        return "FAIL", 13 if 13 in exits else (12 if 12 in exits else 10)
    if "BLOCKED" in decisions:
        return "BLOCKED", 13 if 13 in exits else 11
    _fail("unknown aggregate state")
