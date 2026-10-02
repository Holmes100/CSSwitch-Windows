"""Pure, in-memory RUE-01 run-evidence contracts.

This module deliberately decides one completed attempt only.  Retry scheduling
and final retry aggregation belong to later RUE work.
"""

from __future__ import annotations

import re
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Dict, Mapping as TypingMapping, Optional, Sequence


SCHEMA_NAMES = frozenset(("adapter-result.v1", "test-result.v1"))
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}(?![\s\S])")
SUITE_ID_RE = re.compile(r"^SUITE-[A-Z0-9][A-Z0-9-]{0,31}(?![\s\S])")
ENTRYPOINT_ID_RE = re.compile(r"^ENTRY-[A-Z0-9][A-Z0-9-]{0,31}(?![\s\S])")
INFRA_REASONS = frozenset((
    "EXEC_FAILED", "ADAPTER_MISSING", "ADAPTER_MALFORMED",
    "ADAPTER_BINDING_MISMATCH", "EXIT_STATUS_MISMATCH", "ADAPTER_LATE",
    "OUTPUT_LIMIT", "TOOL_IDENTITY_CHANGED", "ATTEMPT_DUPLICATE",
))
NO_CHILD_INFRA_REASONS = frozenset(("EXEC_FAILED", "TOOL_IDENTITY_CHANGED"))
EXECUTED_INFRA_REASONS = frozenset((
    "ADAPTER_MISSING", "ADAPTER_MALFORMED", "ADAPTER_BINDING_MISMATCH",
    "EXIT_STATUS_MISMATCH", "ADAPTER_LATE", "OUTPUT_LIMIT",
))
REASON_CODES = frozenset((
    "NONE", "ASSERTION_FAILED", "PROCESS_TIMEOUT", *INFRA_REASONS,
    "ENVIRONMENT", "REAL_MACHINE_REQUIRED", "PROFILE_NOT_WIRED",
    "ADAPTER_REPORTED_IGNORED", "ADAPTER_REPORTED_SKIPPED",
    "READINESS_TIMEOUT", "QUARANTINED", "READINESS_RETRY_CHANGED",
))
ATTEMPT_DISPOSITIONS = frozenset(("PASS", "TEST_FAIL", "ENV", "REAL", "IGNORED", "SKIPPED", "READINESS", "HARD_TIMEOUT", "INFRA"))

RESULT_TABLE: Dict[str, Dict[str, Any]] = {
    "PASS": {"outcome": "PASS", "classification": "NONE", "gate_decision": "PASS", "reason_code": "NONE", "runner_exit": 0},
    "TEST_FAIL": {"outcome": "FAIL", "classification": "NONE", "gate_decision": "FAIL", "reason_code": "ASSERTION_FAILED", "runner_exit": 10},
    "HARD_TIMEOUT": {"outcome": "TIMEOUT", "classification": "NONE", "gate_decision": "FAIL", "reason_code": "PROCESS_TIMEOUT", "runner_exit": 13},
    "INFRA": {"outcome": "INFRA_ERROR", "classification": "NONE", "gate_decision": "FAIL", "reason_code": None, "runner_exit": 12},
    "ENV": {"outcome": "ENV-BLOCKED", "classification": "NONE", "gate_decision": "BLOCKED", "reason_code": "ENVIRONMENT", "runner_exit": 11},
    "REAL": {"outcome": "NEEDS-REAL-MACHINE", "classification": "NONE", "gate_decision": "BLOCKED", "reason_code": "REAL_MACHINE_REQUIRED", "runner_exit": 11},
    "NOTRUN": {"outcome": "NOT-RUN", "classification": "NONE", "gate_decision": "BLOCKED", "reason_code": "PROFILE_NOT_WIRED", "runner_exit": 11},
    "IGNORED": {"outcome": "IGNORED", "classification": "NONE", "gate_decision": "BLOCKED", "reason_code": "ADAPTER_REPORTED_IGNORED", "runner_exit": 11},
    "SKIPPED": {"outcome": "SKIPPED", "classification": "NONE", "gate_decision": "BLOCKED", "reason_code": "ADAPTER_REPORTED_SKIPPED", "runner_exit": 11},
    "READINESS_EXHAUSTED": {"outcome": "TIMEOUT", "classification": "READINESS_TIMEOUT", "gate_decision": "BLOCKED", "reason_code": "READINESS_TIMEOUT", "runner_exit": 13},
    "QUARANTINE": {"outcome": "NOT-RUN", "classification": "QUARANTINED", "gate_decision": "BLOCKED", "reason_code": "QUARANTINED", "runner_exit": 11},
    "FLAKY_RETRY": {"outcome": "FAIL", "classification": "FLAKY", "gate_decision": "BLOCKED", "reason_code": "READINESS_RETRY_CHANGED", "runner_exit": 11},
}
ADAPTER_TABLE = {
    ("PASS", "NONE", "NONE"): ("PASS", "NONE", 0),
    ("FAIL", "NONE", "ASSERTION_FAILED"): ("TEST_FAIL", "ASSERTION_FAILED", 10),
    ("ENV-BLOCKED", "NONE", "ENVIRONMENT"): ("ENV", "ENVIRONMENT", 11),
    ("NEEDS-REAL-MACHINE", "NONE", "REAL_MACHINE_REQUIRED"): ("REAL", "REAL_MACHINE_REQUIRED", 11),
    ("IGNORED", "NONE", "ADAPTER_REPORTED_IGNORED"): ("IGNORED", "ADAPTER_REPORTED_IGNORED", 11),
    ("SKIPPED", "NONE", "ADAPTER_REPORTED_SKIPPED"): ("SKIPPED", "ADAPTER_REPORTED_SKIPPED", 11),
    ("TIMEOUT", "READINESS_TIMEOUT", "READINESS_TIMEOUT"): ("READINESS", "READINESS_TIMEOUT", 13),
}
RESULT_FIELDS = frozenset(("schema", "run_id", "suite_id", "entrypoint_id", "kind", "outcome", "classification", "gate_decision", "reason_code", "runner_exit", "attempt_records"))
ADAPTER_FIELDS = frozenset(("schema", "run_id", "suite_id", "entrypoint_id", "attempt_index", "outcome_hint", "classification_hint", "reason_code"))
ATTEMPT_FIELDS = frozenset(("attempt_index", "process_exit"))


class ContractViolation(ValueError):
    """Inputs are corrupt; no substitute result may be invented."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


@dataclass(frozen=True)
class AttemptRecord:
    attempt_index: int
    process_exit: Optional[int]

    def __post_init__(self) -> None:
        if not _is_int(self.attempt_index) or self.attempt_index not in (0, 1):
            raise ContractViolation("ADAPTER_MALFORMED", "invalid attempt index")
        _require_child_rc(self.process_exit, nullable=True)

    def as_dict(self) -> Dict[str, Optional[int]]:
        return {"attempt_index": self.attempt_index, "process_exit": self.process_exit}


@dataclass(frozen=True)
class AttemptDecisionV1:
    run_id: str
    suite_id: str
    entrypoint_id: str
    attempt_index: int
    attempt_record: AttemptRecord
    disposition: str
    reason_code: str

    def __post_init__(self) -> None:
        _require_expected_identity(self.run_id, self.suite_id, self.entrypoint_id, self.attempt_index)
        if not isinstance(self.attempt_record, AttemptRecord) or self.attempt_record.attempt_index != self.attempt_index:
            raise ContractViolation("ADAPTER_MALFORMED", "attempt decision record does not bind its index")
        if self.disposition not in ATTEMPT_DISPOSITIONS or self.reason_code not in REASON_CODES:
            raise ContractViolation("ADAPTER_MALFORMED", "invalid atomic attempt decision")
        rc = self.attempt_record.process_exit
        fixed = {
            ("PASS", "NONE"): 0,
            ("TEST_FAIL", "ASSERTION_FAILED"): 10,
            ("ENV", "ENVIRONMENT"): 11,
            ("REAL", "REAL_MACHINE_REQUIRED"): 11,
            ("IGNORED", "ADAPTER_REPORTED_IGNORED"): 11,
            ("SKIPPED", "ADAPTER_REPORTED_SKIPPED"): 11,
            ("READINESS", "READINESS_TIMEOUT"): 13,
        }
        if (self.disposition, self.reason_code) in fixed:
            if rc != fixed[(self.disposition, self.reason_code)]:
                raise ContractViolation("ADAPTER_MALFORMED", "atomic decision exit does not match its disposition")
        elif self.disposition == "HARD_TIMEOUT" and self.reason_code == "PROCESS_TIMEOUT":
            if rc is None:
                raise ContractViolation("ADAPTER_MALFORMED", "hard timeout requires a reaped child exit")
        elif self.disposition == "INFRA" and self.reason_code in NO_CHILD_INFRA_REASONS:
            if rc is not None:
                raise ContractViolation("ADAPTER_MALFORMED", "pre-launch infra requires null child exit")
        elif self.disposition == "INFRA" and self.reason_code in EXECUTED_INFRA_REASONS:
            if rc is None:
                raise ContractViolation("ADAPTER_MALFORMED", "executed infra requires a child exit")
        else:
            raise ContractViolation("ADAPTER_MALFORMED", "invalid atomic disposition/reason pair")


def load_schema(schema_name: str) -> Dict[str, str]:
    if not isinstance(schema_name, str) or schema_name not in SCHEMA_NAMES:
        raise ContractViolation("ADAPTER_MALFORMED", "unknown result schema")
    return {"schema": schema_name}


def _is_int(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value) and value.is_integer()


def _valid_id(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _require_expected_identity(run_id: Any, suite_id: Any, entrypoint_id: Any, attempt_index: Any) -> None:
    if not _valid_id(RUN_ID_RE, run_id) or not _valid_id(SUITE_ID_RE, suite_id) or not _valid_id(ENTRYPOINT_ID_RE, entrypoint_id):
        raise ContractViolation("ADAPTER_MALFORMED", "expected canonical identity is invalid")
    if not _is_int(attempt_index) or attempt_index not in (0, 1):
        raise ContractViolation("ADAPTER_MALFORMED", "expected attempt index is invalid")


def _require_child_rc(value: Any, *, nullable: bool = False) -> Optional[int]:
    if value is None and nullable:
        return None
    if not _is_int(value) or not -255 <= value <= 255:
        raise ContractViolation("ADAPTER_MALFORMED", "child process exit must be an integer from -255 to 255")
    return value


def _record_from_mapping(value: Any, expected_index: Optional[int] = None) -> AttemptRecord:
    if not isinstance(value, Mapping) or set(value) != ATTEMPT_FIELDS:
        raise ContractViolation("ADAPTER_MALFORMED", "invalid attempt record")
    index = value["attempt_index"]
    if not _is_int(index) or index not in (0, 1):
        raise ContractViolation("ADAPTER_MALFORMED", "invalid attempt index")
    if expected_index is not None and index != expected_index:
        raise ContractViolation("ADAPTER_BINDING_MISMATCH", "attempt records must be ordered and gapless")
    return AttemptRecord(index, _require_child_rc(value["process_exit"], nullable=True))


def _records(records: Any) -> tuple[AttemptRecord, ...]:
    if not isinstance(records, list) or len(records) > 2:
        raise ContractViolation("ADAPTER_MALFORMED", "attempt history must have zero to two entries")
    return tuple(_record_from_mapping(record, index) for index, record in enumerate(records))


def check_adapter_result(adapter: Any, expected_run_id: Any = None, expected_suite_id: Any = None, expected_entrypoint_id: Any = None, expected_attempt_index: Any = None) -> Optional[str]:
    """Return a classification for adapter *data*, without normalizing it."""
    if adapter is None:
        return "ADAPTER_MISSING"
    if not isinstance(adapter, Mapping) or set(adapter) != ADAPTER_FIELDS or adapter.get("schema") != "adapter-result.v1":
        return "ADAPTER_MALFORMED"
    if not _valid_id(RUN_ID_RE, adapter.get("run_id")) or not _valid_id(SUITE_ID_RE, adapter.get("suite_id")) or not _valid_id(ENTRYPOINT_ID_RE, adapter.get("entrypoint_id")):
        return "ADAPTER_MALFORMED"
    index = adapter.get("attempt_index")
    if not _is_int(index) or index not in (0, 1):
        return "ADAPTER_MALFORMED"
    if (expected_run_id is not None and adapter["run_id"] != expected_run_id) or (expected_suite_id is not None and adapter["suite_id"] != expected_suite_id) or (expected_entrypoint_id is not None and adapter["entrypoint_id"] != expected_entrypoint_id) or (expected_attempt_index is not None and index != expected_attempt_index):
        return "ADAPTER_BINDING_MISMATCH"
    return None if (adapter.get("outcome_hint"), adapter.get("classification_hint"), adapter.get("reason_code")) in ADAPTER_TABLE else "ADAPTER_MALFORMED"


validate_adapter_result = check_adapter_result


def is_valid_adapter_result(adapter: Any, **bindings: Any) -> bool:
    return check_adapter_result(adapter, **bindings) is None


def _decision(run_id: str, suite_id: str, entrypoint_id: str, attempt_index: int, process_exit: Optional[int], disposition: str, reason_code: str) -> AttemptDecisionV1:
    return AttemptDecisionV1(run_id, suite_id, entrypoint_id, attempt_index, AttemptRecord(attempt_index, process_exit), disposition, reason_code)


def adjudicate_adapter_attempt(adapter: Any, child_process_exit: Any, expected_run_id: str, expected_suite_id: str, expected_entrypoint_id: str, expected_attempt_index: int) -> AttemptDecisionV1:
    """Adjudicate exactly one completed child attempt using parent identity."""
    _require_expected_identity(expected_run_id, expected_suite_id, expected_entrypoint_id, expected_attempt_index)
    rc = _require_child_rc(child_process_exit)
    error = check_adapter_result(adapter, expected_run_id, expected_suite_id, expected_entrypoint_id, expected_attempt_index)
    if error is not None:
        return _decision(expected_run_id, expected_suite_id, expected_entrypoint_id, expected_attempt_index, rc, "INFRA", error)
    disposition, reason, expected_rc = ADAPTER_TABLE[(adapter["outcome_hint"], adapter["classification_hint"], adapter["reason_code"])]
    if rc != expected_rc:
        return _decision(expected_run_id, expected_suite_id, expected_entrypoint_id, expected_attempt_index, rc, "INFRA", "EXIT_STATUS_MISMATCH")
    return _decision(expected_run_id, expected_suite_id, expected_entrypoint_id, expected_attempt_index, rc, disposition, reason)


def adjudicate_parent_event(event: str, child_process_exit: Any, expected_run_id: str, expected_suite_id: str, expected_entrypoint_id: str, expected_attempt_index: int) -> AttemptDecisionV1:
    """Make parent-known event decisions; adapter data is intentionally absent."""
    _require_expected_identity(expected_run_id, expected_suite_id, expected_entrypoint_id, expected_attempt_index)
    if event in {"SPAWN_EXEC_FAILED", "TOOL_IDENTITY_CHANGED"}:
        if child_process_exit is not None:
            raise ContractViolation("ADAPTER_MALFORMED", "pre-launch event requires null child rc")
        reason = "EXEC_FAILED" if event == "SPAWN_EXEC_FAILED" else "TOOL_IDENTITY_CHANGED"
        return _decision(expected_run_id, expected_suite_id, expected_entrypoint_id, expected_attempt_index, None, "INFRA", reason)
    if event == "OUTPUT_LIMIT":
        return _decision(expected_run_id, expected_suite_id, expected_entrypoint_id, expected_attempt_index, _require_child_rc(child_process_exit), "INFRA", "OUTPUT_LIMIT")
    if event == "HARD_TIMEOUT":
        return _decision(expected_run_id, expected_suite_id, expected_entrypoint_id, expected_attempt_index, _require_child_rc(child_process_exit), "HARD_TIMEOUT", "PROCESS_TIMEOUT")
    raise ContractViolation("ADAPTER_MALFORMED", "unknown parent event")


def _history_for_kind(kind: str, reason: str, records: tuple[AttemptRecord, ...]) -> None:
    exits = [record.process_exit for record in records]
    if kind in {"NOTRUN", "QUARANTINE"}:
        valid = not records
    elif kind == "PASS": valid = exits == [0]
    elif kind == "TEST_FAIL": valid = exits == [10]
    elif kind in {"ENV", "REAL", "IGNORED", "SKIPPED"}: valid = exits == [11]
    elif kind == "READINESS_EXHAUSTED": valid = exits == [13, 13]
    elif kind == "FLAKY_RETRY": valid = len(exits) == 2 and exits[0] == 13 and exits[1] in (0, 10, 11)
    elif kind == "HARD_TIMEOUT": valid = len(exits) in (1, 2) and all(rc is not None for rc in exits) and (len(exits) == 1 or exits[0] == 13)
    elif kind == "INFRA" and reason in NO_CHILD_INFRA_REASONS: valid = exits == [None] or (len(exits) == 2 and exits[0] == 13 and exits[1] is None)
    elif kind == "INFRA" and reason in EXECUTED_INFRA_REASONS: valid = len(exits) in (1, 2) and all(rc is not None for rc in exits) and (len(exits) == 1 or exits[0] == 13)
    else: valid = False
    if not valid:
        raise ContractViolation("ADAPTER_MALFORMED", "attempt history is unreachable for final result")


def validate_result(result: Any) -> None:
    if not isinstance(result, Mapping) or set(result) != RESULT_FIELDS or result.get("schema") != "test-result.v1":
        raise ContractViolation("ADAPTER_MALFORMED", "invalid test result shape")
    _require_expected_identity(result.get("run_id"), result.get("suite_id"), result.get("entrypoint_id"), 0)
    kind = result.get("kind")
    spec = RESULT_TABLE.get(kind)
    if spec is None or any(result.get(field) != spec[field] for field in ("outcome", "classification", "gate_decision")):
        raise ContractViolation("ADAPTER_MALFORMED", "result state does not match the approved table")
    reason = result.get("reason_code")
    if (kind == "INFRA" and reason not in INFRA_REASONS - {"ATTEMPT_DUPLICATE"}) or (kind != "INFRA" and reason != spec["reason_code"]):
        raise ContractViolation("ADAPTER_MALFORMED", "invalid result reason")
    runner_exit = result.get("runner_exit")
    if not _is_int(runner_exit) or runner_exit != spec["runner_exit"]:
        raise ContractViolation("ADAPTER_MALFORMED", "invalid runner exit")
    _history_for_kind(kind, reason, _records(result.get("attempt_records")))


def _default_records(kind: str, reason: str) -> list[dict[str, Optional[int]]]:
    if kind in {"NOTRUN", "QUARANTINE"}: return []
    if kind == "INFRA" and reason in NO_CHILD_INFRA_REASONS: return [{"attempt_index": 0, "process_exit": None}]
    exits = {"PASS": 0, "TEST_FAIL": 10, "ENV": 11, "REAL": 11, "IGNORED": 11, "SKIPPED": 11}.get(kind)
    if exits is None: raise ContractViolation("ADAPTER_MALFORMED", "explicit retry history is required")
    return [{"attempt_index": 0, "process_exit": exits}]


def make_result(kind: str, run_id: str, suite_id: str, entrypoint_id: str, attempt_records: Optional[Sequence[TypingMapping[str, Any]]] = None, runner_exit: Optional[int] = None, reason_code: Optional[str] = None) -> Dict[str, Any]:
    _require_expected_identity(run_id, suite_id, entrypoint_id, 0)
    spec = RESULT_TABLE.get(kind)
    if spec is None: raise ContractViolation("ADAPTER_MALFORMED", "unknown result kind")
    reason = spec["reason_code"] if reason_code is None else reason_code
    records = _default_records(kind, reason) if attempt_records is None else [dict(record) for record in attempt_records]
    result = {"schema": "test-result.v1", "run_id": run_id, "suite_id": suite_id, "entrypoint_id": entrypoint_id, "kind": kind, "outcome": spec["outcome"], "classification": spec["classification"], "gate_decision": spec["gate_decision"], "reason_code": reason, "runner_exit": spec["runner_exit"] if runner_exit is None else runner_exit, "attempt_records": records}
    validate_result(result)
    return result


# Compatibility aliases for only the existing pure-test import surface.
check_result = validate_result
adjudicate = adjudicate_adapter_attempt
