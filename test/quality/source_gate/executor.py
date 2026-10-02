"""Fail-closed adjudication for catalog-bound source adapter observations."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from test.quality.run_evidence.contracts import ContractViolation, make_result
from test.quality.run_evidence.manifest_contracts import validate_source_observation
from test.quality.source_gate.contracts import result_from_observation
from test.quality.source_gate.contracts import aggregate_results
from test.quality.source_gate.planning import SourceSuitePlan


def adjudicate_source_observation(
    observation: Mapping[str, Any],
    *,
    parent_adapter_exit: int,
    suite: Mapping[str, Any],
    expected_test_ids: Sequence[str],
    approved_skipped_ids: Sequence[str] = (),
    approved_ignored_ids: Sequence[str] = (),
    command_argv_sha256: str,
    environment_sha256: str,
    tool_identity_sha256: str,
) -> dict[str, Any]:
    """Bind parent status, catalog identity and observation before normalization."""
    validate_source_observation(observation)
    suite_id = suite.get("id")
    entrypoint_id = suite.get("entrypoint_id")
    if (
        not isinstance(parent_adapter_exit, int)
        or isinstance(parent_adapter_exit, bool)
        or parent_adapter_exit not in {0, 10, 11, 12, 13}
        or observation["adapter_exit"] != parent_adapter_exit
        or observation["suite_id"] != suite_id
        or observation["entrypoint_id"] != entrypoint_id
        or observation["command_argv_sha256"] != command_argv_sha256
        or observation["environment_sha256"] != environment_sha256
        or observation["tool_identity_sha256"] != tool_identity_sha256
        or suite.get("adapter_protocol") != "source-observation.v1"
        or suite.get("retry_policy") != "none"
    ):
        if not isinstance(suite_id, str) or not isinstance(entrypoint_id, str):
            raise ContractViolation("ADAPTER_MALFORMED", "source suite identity")
        return make_result(
            "INFRA",
            observation["run_id"],
            suite_id,
            entrypoint_id,
            attempt_records=[{
                "attempt_index": 0,
                "process_exit": (
                    parent_adapter_exit
                    if parent_adapter_exit in {0, 10, 11, 12, 13}
                    else 12
                ),
            }],
            runner_exit=12,
            reason_code="ADAPTER_MALFORMED",
        )
    return result_from_observation(
        observation,
        expected_suite_id=suite_id,
        expected_entrypoint_id=entrypoint_id,
        expected_test_ids=expected_test_ids,
        approved_skipped_ids=approved_skipped_ids,
        approved_ignored_ids=approved_ignored_ids,
    )


def execute_source_plans(
    plans: Sequence[SourceSuitePlan],
    *,
    run_id: str,
    run_one,
    recheck,
    on_pair=None,
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]], tuple[str, int]]:
    """Execute every frozen plan once, sequentially, through private seams."""
    if not isinstance(plans, Sequence) or not plans:
        raise ContractViolation("ADAPTER_MALFORMED", "empty source plan")
    observations: list[Mapping[str, Any]] = []
    results: list[Mapping[str, Any]] = []
    for index, plan in enumerate(plans):
        if recheck("before", index, plan) is not True:
            raise ContractViolation("ADAPTER_MALFORMED", "source input drift")
        supervised = run_one(plan, plan.adapter_config(run_id))
        if recheck("after", index, plan) is not True:
            raise ContractViolation("ADAPTER_MALFORMED", "source input drift")
        raw_parent = getattr(supervised, "raw_process", None)
        observation = getattr(supervised, "observation", None)
        if (
            not isinstance(raw_parent, Mapping)
            or raw_parent.get("state") != "EXITED"
            or raw_parent.get("process_exit") not in {0, 10, 11, 12, 13}
            or not isinstance(observation, Mapping)
            or getattr(supervised, "observation_error", None) is not None
            or getattr(supervised, "observation_acked", False) is not True
        ):
            raise ContractViolation(
                "ADAPTER_MALFORMED", "source adapter authority",
            )
        result = adjudicate_source_observation(
            observation,
            parent_adapter_exit=raw_parent["process_exit"],
            suite=plan.suite,
            expected_test_ids=plan.expected_test_ids,
            approved_skipped_ids=plan.approved_skipped_test_ids,
            approved_ignored_ids=plan.approved_ignored_test_ids,
            command_argv_sha256=plan.command_argv_sha256,
            environment_sha256=plan.environment_sha256,
            tool_identity_sha256=plan.tool_identity_sha256,
        )
        observations.append(observation)
        results.append(result)
        if on_pair is not None:
            on_pair(observation, result)
    return observations, results, aggregate_results(results)
