"""RUE-06 explicit readiness retry policy over the fixed RUE-05 executor."""
from __future__ import annotations

import os
from typing import Any

from .atomic_store import RunLayout
from .attempt0_runner import _run_attempt
from .contracts import (
    EXECUTED_INFRA_REASONS,
    NO_CHILD_INFRA_REASONS,
    AttemptDecisionV1,
    make_result,
    validate_result,
)


def _final_result(
    attempt0: AttemptDecisionV1, attempt1: AttemptDecisionV1,
) -> dict[str, Any]:
    if (
        not isinstance(attempt0, AttemptDecisionV1)
        or attempt0.attempt_index != 0
        or attempt0.attempt_record.attempt_index != 0
        or (
            attempt0.disposition, attempt0.reason_code,
            attempt0.attempt_record.process_exit,
        ) != ("READINESS", "READINESS_TIMEOUT", 13)
    ):
        raise ValueError("ATTEMPT0_NOT_ELIGIBLE")
    if (
        not isinstance(attempt1, AttemptDecisionV1)
        or attempt1.attempt_index != 1
        or attempt1.attempt_record.attempt_index != 1
        or (
            attempt1.run_id, attempt1.suite_id, attempt1.entrypoint_id,
        ) != (attempt0.run_id, attempt0.suite_id, attempt0.entrypoint_id)
    ):
        raise ValueError("ATTEMPT_IDENTITY_MISMATCH")
    records = [
        attempt0.attempt_record.as_dict(),
        attempt1.attempt_record.as_dict(),
    ]
    state = (
        attempt1.disposition, attempt1.reason_code,
        attempt1.attempt_record.process_exit,
    )
    fixed = {
        ("READINESS", "READINESS_TIMEOUT", 13): ("READINESS_EXHAUSTED", None),
        ("PASS", "NONE", 0): ("FLAKY_RETRY", None),
        ("TEST_FAIL", "ASSERTION_FAILED", 10): ("FLAKY_RETRY", None),
        ("ENV", "ENVIRONMENT", 11): ("FLAKY_RETRY", None),
        ("REAL", "REAL_MACHINE_REQUIRED", 11): ("FLAKY_RETRY", None),
        ("IGNORED", "ADAPTER_REPORTED_IGNORED", 11): ("FLAKY_RETRY", None),
        ("SKIPPED", "ADAPTER_REPORTED_SKIPPED", 11): ("FLAKY_RETRY", None),
    }
    if state in fixed:
        kind, reason = fixed[state]
    elif (
        attempt1.disposition == "HARD_TIMEOUT"
        and attempt1.reason_code == "PROCESS_TIMEOUT"
        and attempt1.attempt_record.process_exit is not None
    ):
        kind, reason = "HARD_TIMEOUT", None
    elif (
        attempt1.disposition == "INFRA"
        and (
            (
                attempt1.reason_code in NO_CHILD_INFRA_REASONS
                and attempt1.attempt_record.process_exit is None
            )
            or (
                attempt1.reason_code in EXECUTED_INFRA_REASONS
                and attempt1.attempt_record.process_exit is not None
            )
        )
    ):
        kind, reason = "INFRA", attempt1.reason_code
    else:
        raise ValueError("ATTEMPT1_UNREACHABLE")
    result = make_result(
        kind, attempt0.run_id, attempt0.suite_id, attempt0.entrypoint_id,
        attempt_records=records, reason_code=reason,
    )
    validate_result(result)
    if result["gate_decision"] == "PASS":
        raise ValueError("RETRY_CANNOT_PASS")
    return result


def _retry_attempt1(
    *, repo_root: str | os.PathLike[str], layout: RunLayout,
    scenario: str = "normal",
) -> dict[str, Any]:
    _run_attempt(
        repo_root=repo_root, layout=layout, attempt_index=1, scenario=scenario,
    )
    attempt0, attempt1 = layout.read_retry_decisions()
    return _final_result(attempt0, attempt1)


def retry_attempt1(
    *, repo_root: str | os.PathLike[str], layout: RunLayout,
) -> dict[str, Any]:
    """Run one fixed eligible retry; callers cannot override policy or child."""
    return _retry_attempt1(repo_root=repo_root, layout=layout)
