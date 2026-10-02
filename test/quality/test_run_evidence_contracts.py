#!/usr/bin/env python3
"""Table-driven RUE-01 contract tests; no runner, filesystem, or retry policy."""

import re
import unittest
from math import inf, nan

try:
    from run_evidence.contracts import (
        ADAPTER_TABLE, AttemptDecisionV1, AttemptRecord, ContractViolation, ENTRYPOINT_ID_RE, RESULT_TABLE, RUN_ID_RE, SUITE_ID_RE,
        adjudicate_adapter_attempt, adjudicate_parent_event, check_adapter_result,
        load_schema, make_result, validate_result,
    )
except ModuleNotFoundError:
    from test.quality.run_evidence.contracts import (
        ADAPTER_TABLE, AttemptDecisionV1, AttemptRecord, ContractViolation, ENTRYPOINT_ID_RE, RESULT_TABLE, RUN_ID_RE, SUITE_ID_RE,
        adjudicate_adapter_attempt, adjudicate_parent_event, check_adapter_result,
        load_schema, make_result, validate_result,
    )
try:
    from validate_quality_metadata import ROOT, Validator
except ModuleNotFoundError:
    from test.quality.validate_quality_metadata import ROOT, Validator


RUN_ID = "0123456789abcdef0123456789abcdef"
SUITE_ID = "SUITE-RUN-EVIDENCE-CONTRACT"
ENTRYPOINT_ID = "ENTRY-RUE-CONTRACT"


def attempts(*exits):
    return [{"attempt_index": index, "process_exit": value} for index, value in enumerate(exits)]


def adapter_for(hint, index=0, **changes):
    value = {
        "schema": "adapter-result.v1", "run_id": RUN_ID, "suite_id": SUITE_ID,
        "entrypoint_id": ENTRYPOINT_ID, "attempt_index": index,
        "outcome_hint": hint[0], "classification_hint": hint[1], "reason_code": hint[2],
    }
    value.update(changes)
    return value


class RunEvidenceContracts(unittest.TestCase):
    def setUp(self):
        self.validator = Validator(ROOT)
        self.validator.load_schemas()

    def schema_errors(self, name, value):
        self.validator.errors = []
        schema = self.validator.schemas[name]
        self.validator.validate_instance(value, schema, schema, "fixture." + name)
        return "\n".join(self.validator.errors)

    def assert_valid(self, value):
        validate_result(value)
        self.assertFalse(self.schema_errors("test-result.v1.schema.json", value))

    def assert_invalid(self, value):
        with self.assertRaises(ContractViolation):
            validate_result(value)
        self.assertTrue(self.schema_errors("test-result.v1.schema.json", value))

    def official_schema_errors(self, name, value):
        try:
            import jsonschema
        except ModuleNotFoundError:
            return None
        return list(jsonschema.Draft202012Validator(self.validator.schemas[name]).iter_errors(value))

    def test_all_twelve_reachable_final_rows_cross_validate_schema(self):
        cases = {
            "PASS": ("NONE", [0]), "TEST_FAIL": ("ASSERTION_FAILED", [10]),
            "HARD_TIMEOUT": ("PROCESS_TIMEOUT", [-9]), "INFRA": ("ADAPTER_MISSING", [-9]),
            "ENV": ("ENVIRONMENT", [11]), "REAL": ("REAL_MACHINE_REQUIRED", [11]),
            "NOTRUN": ("PROFILE_NOT_WIRED", []), "IGNORED": ("ADAPTER_REPORTED_IGNORED", [11]),
            "SKIPPED": ("ADAPTER_REPORTED_SKIPPED", [11]), "READINESS_EXHAUSTED": ("READINESS_TIMEOUT", [13, 13]),
            "QUARANTINE": ("QUARANTINED", []), "FLAKY_RETRY": ("READINESS_RETRY_CHANGED", [13, 10]),
        }
        self.assertEqual(set(cases), set(RESULT_TABLE))
        for kind, (reason, exits) in cases.items():
            result = make_result(kind, RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(*exits), reason_code=reason)
            self.assert_valid(result)

    def test_final_history_matrix_rejects_adjacent_unreachable_histories(self):
        cases = {
            "PASS": ("NONE", [0], [10]), "TEST_FAIL": ("ASSERTION_FAILED", [10], [0]),
            "ENV": ("ENVIRONMENT", [11], [11, 11]), "REAL": ("REAL_MACHINE_REQUIRED", [11], [11, 11]),
            "IGNORED": ("ADAPTER_REPORTED_IGNORED", [11], [11, 13]), "SKIPPED": ("ADAPTER_REPORTED_SKIPPED", [11], [11, 0]),
            "NOTRUN": ("PROFILE_NOT_WIRED", [], [11]), "QUARANTINE": ("QUARANTINED", [], [11]),
            "READINESS_EXHAUSTED": ("READINESS_TIMEOUT", [13, 13], [13]), "FLAKY_RETRY": ("READINESS_RETRY_CHANGED", [13, 0], [13, 13]),
            "HARD_TIMEOUT": ("PROCESS_TIMEOUT", [-9], [None]), "INFRA": ("ADAPTER_MISSING", [-9], [None]),
        }
        for kind, (reason, good, bad) in cases.items():
            valid = make_result(kind, RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(*good), reason_code=reason)
            self.assert_valid(valid)
            self.assert_invalid(dict(valid, attempt_records=attempts(*bad)))
        for bad in ([10, 0], [0, 10], [13, 13], [13, -9]):
            flaky = make_result("FLAKY_RETRY", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(13, 10))
            self.assert_invalid(dict(flaky, attempt_records=attempts(*bad)))

    def test_null_and_timeout_infra_histories_have_only_the_specified_paths(self):
        for reason in ("EXEC_FAILED", "TOOL_IDENTITY_CHANGED"):
            for exits in ([None], [13, None]):
                self.assert_valid(make_result("INFRA", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(*exits), reason_code=reason))
        for reason in ("ADAPTER_MISSING", "ADAPTER_MALFORMED", "ADAPTER_BINDING_MISMATCH", "EXIT_STATUS_MISMATCH", "ADAPTER_LATE", "OUTPUT_LIMIT"):
            self.assert_valid(make_result("INFRA", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(-9), reason_code=reason))
            self.assert_valid(make_result("INFRA", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(13, -9), reason_code=reason))
            with self.assertRaises(ContractViolation):
                make_result("INFRA", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(None), reason_code=reason)
        self.assert_valid(make_result("HARD_TIMEOUT", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(-9)))
        self.assert_valid(make_result("HARD_TIMEOUT", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(13, -9)))

    def test_hard_timeout_schema_and_python_require_13_before_second_attempt(self):
        valid = make_result("HARD_TIMEOUT", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(13, -9))
        self.assert_valid(valid)
        malformed = dict(valid, attempt_records=attempts(0, -9))
        self.assert_invalid(malformed)
        official_errors = self.official_schema_errors("test-result.v1.schema.json", malformed)
        if official_errors is not None:
            self.assertTrue(official_errors)
        with self.assertRaises(ContractViolation):
            make_result("HARD_TIMEOUT", RUN_ID, SUITE_ID, ENTRYPOINT_ID)

    def test_direct_dataclass_construction_cannot_bypass_atomic_contract(self):
        for index, rc in ((-1, 0), (2, 0), (True, 0), (0, True), (0, "0"), (0, -256), (0, 256)):
            with self.assertRaises(ContractViolation):
                AttemptRecord(index, rc)
        record = AttemptRecord(0, 0)
        invalid_decisions = (
            (RUN_ID + "\n", SUITE_ID, ENTRYPOINT_ID, 0, record, "PASS", "NONE"),
            (RUN_ID, SUITE_ID, ENTRYPOINT_ID, 1, record, "PASS", "NONE"),
            (RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0, record, "PASS", "ASSERTION_FAILED"),
            (RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0, AttemptRecord(0, None), "HARD_TIMEOUT", "PROCESS_TIMEOUT"),
            (RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0, AttemptRecord(0, 0), "INFRA", "EXEC_FAILED"),
            (RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0, AttemptRecord(0, None), "INFRA", "ADAPTER_MISSING"),
            (RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0, AttemptRecord(0, 0), "INFRA", "ATTEMPT_DUPLICATE"),
        )
        for args in invalid_decisions:
            with self.assertRaises(ContractViolation):
                AttemptDecisionV1(*args)

    def test_draft_integer_float_semantics_align_python_custom_and_official(self):
        pass_result = make_result("PASS", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(0))
        float_pass = dict(pass_result, runner_exit=0.0, attempt_records=[{"attempt_index": 0.0, "process_exit": 0.0}])
        self.assert_valid(float_pass)
        hard_timeout = make_result("HARD_TIMEOUT", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(13, -9))
        float_timeout = dict(hard_timeout, runner_exit=13.0, attempt_records=[{"attempt_index": 0.0, "process_exit": 13.0}, {"attempt_index": 1.0, "process_exit": -9.0}])
        self.assert_valid(float_timeout)
        adapter = adapter_for(("PASS", "NONE", "NONE"), index=0.0)
        self.assertIsNone(check_adapter_result(adapter))
        self.assertFalse(self.schema_errors("adapter-result.v1.schema.json", adapter))
        for name, value in (("test-result.v1.schema.json", float_pass), ("test-result.v1.schema.json", float_timeout), ("adapter-result.v1.schema.json", adapter)):
            official_errors = self.official_schema_errors(name, value)
            if official_errors is not None:
                self.assertFalse(official_errors)
        self.assertEqual(AttemptRecord(0.0, 13.0).process_exit, 13.0)

        result_cases = (
            ("runner_exit", True), ("runner_exit", 0.5), ("runner_exit", nan), ("runner_exit", inf),
            ("attempt_records", [{"attempt_index": True, "process_exit": 0}]),
            ("attempt_records", [{"attempt_index": 0.5, "process_exit": 0}]),
            ("attempt_records", [{"attempt_index": nan, "process_exit": 0}]),
            ("attempt_records", [{"attempt_index": inf, "process_exit": 0}]),
            ("attempt_records", [{"attempt_index": 0, "process_exit": True}]),
            ("attempt_records", [{"attempt_index": 0, "process_exit": 0.5}]),
            ("attempt_records", [{"attempt_index": 0, "process_exit": nan}]),
            ("attempt_records", [{"attempt_index": 0, "process_exit": inf}]),
        )
        for field, value in result_cases:
            broken = dict(pass_result, **{field: value})
            self.assert_invalid(broken)
            official_errors = self.official_schema_errors("test-result.v1.schema.json", broken)
            if official_errors is not None:
                self.assertTrue(official_errors)
        for bad_index in (True, 0.5, nan, inf):
            broken_adapter = adapter_for(("PASS", "NONE", "NONE"), index=bad_index)
            self.assertEqual(check_adapter_result(broken_adapter), "ADAPTER_MALFORMED")
            self.assertTrue(self.schema_errors("adapter-result.v1.schema.json", broken_adapter))
            official_errors = self.official_schema_errors("adapter-result.v1.schema.json", broken_adapter)
            if official_errors is not None:
                self.assertTrue(official_errors)

    def test_adapter_schema_has_canonical_identity_and_no_not_run_branch(self):
        for hint, (_, _, rc) in ADAPTER_TABLE.items():
            adapter = adapter_for(hint, index=1 if hint[0] == "TIMEOUT" else 0)
            self.assertIsNone(check_adapter_result(adapter))
            self.assertFalse(self.schema_errors("adapter-result.v1.schema.json", adapter))
            self.assertNotIn("process_exit", adapter)
        not_run = adapter_for(("NOT-RUN", "NONE", "PROFILE_NOT_WIRED"))
        self.assertEqual(check_adapter_result(not_run), "ADAPTER_MALFORMED")
        self.assertTrue(self.schema_errors("adapter-result.v1.schema.json", not_run))

    def test_adapter_adjudication_preserves_rc_and_parent_identity(self):
        pass_hint = ("PASS", "NONE", "NONE")
        cases = [
            (None, 0, "INFRA", "ADAPTER_MISSING"),
            ({"bad": "shape"}, -9, "INFRA", "ADAPTER_MALFORMED"),
            (adapter_for(pass_hint, run_id="f" * 32), 0, "INFRA", "ADAPTER_BINDING_MISMATCH"),
            (adapter_for(pass_hint), 10, "INFRA", "EXIT_STATUS_MISMATCH"),
            (adapter_for(pass_hint), 0, "PASS", "NONE"),
        ]
        for adapter, rc, disposition, reason in cases:
            decision = adjudicate_adapter_attempt(adapter, rc, RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0)
            self.assertIsInstance(decision, AttemptDecisionV1)
            self.assertEqual((decision.disposition, decision.reason_code, decision.attempt_record.process_exit), (disposition, reason, rc))
            self.assertEqual((decision.run_id, decision.suite_id, decision.entrypoint_id, decision.attempt_index), (RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0))

    def test_every_legal_adapter_hint_rc_matrix_preserves_real_exit(self):
        for hint, (disposition, reason, expected_rc) in ADAPTER_TABLE.items():
            index = 1 if disposition == "READINESS" else 0
            adapter = adapter_for(hint, index=index)
            for rc in (-9, 0, 10, 11, 13):
                decision = adjudicate_adapter_attempt(adapter, rc, RUN_ID, SUITE_ID, ENTRYPOINT_ID, index)
                expected = (disposition, reason) if rc == expected_rc else ("INFRA", "EXIT_STATUS_MISMATCH")
                self.assertEqual((decision.disposition, decision.reason_code), expected)
                self.assertEqual(decision.attempt_record.process_exit, rc)
        for changed in ({"entrypoint_id": "ENTRY-OTHER"}, {"attempt_index": 1}):
            decision = adjudicate_adapter_attempt(adapter_for(("PASS", "NONE", "NONE"), **changed), -9, RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0)
            self.assertEqual((decision.disposition, decision.reason_code, decision.attempt_record.process_exit), ("INFRA", "ADAPTER_BINDING_MISMATCH", -9))

    def test_readiness_is_atomic_not_a_final_retry_result(self):
        decision = adjudicate_adapter_attempt(adapter_for(("TIMEOUT", "READINESS_TIMEOUT", "READINESS_TIMEOUT")), 13, RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0)
        self.assertEqual((decision.disposition, decision.reason_code), ("READINESS", "READINESS_TIMEOUT"))
        self.assertFalse(hasattr(decision, "kind"))

    def test_parent_events_are_separate_from_adapter_priority(self):
        cases = {
            "SPAWN_EXEC_FAILED": (None, "INFRA", "EXEC_FAILED"),
            "TOOL_IDENTITY_CHANGED": (None, "INFRA", "TOOL_IDENTITY_CHANGED"),
            "OUTPUT_LIMIT": (-9, "INFRA", "OUTPUT_LIMIT"),
            "HARD_TIMEOUT": (-9, "HARD_TIMEOUT", "PROCESS_TIMEOUT"),
        }
        for event, (rc, disposition, reason) in cases.items():
            decision = adjudicate_parent_event(event, rc, RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0)
            self.assertEqual((decision.disposition, decision.reason_code, decision.attempt_record.process_exit), (disposition, reason, rc))
        for event, rc in (("SPAWN_EXEC_FAILED", 0), ("OUTPUT_LIMIT", None), ("HARD_TIMEOUT", True), ("UNKNOWN", 0)):
            with self.assertRaises(ContractViolation):
                adjudicate_parent_event(event, rc, RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0)

    def test_invalid_expected_identity_rc_and_history_fail_closed(self):
        adapter = adapter_for(("PASS", "NONE", "NONE"))
        for bad in ("RUN-A", "A" * 32, "0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdef0", RUN_ID + "\n", "550e8400-e29b-41d4-a716-446655440000"):
            with self.assertRaises(ContractViolation):
                adjudicate_adapter_attempt(adapter, 0, bad, SUITE_ID, ENTRYPOINT_ID, 0)
        for bad in ("suite-a", "SUITE-A\n"):
            with self.assertRaises(ContractViolation):
                adjudicate_adapter_attempt(adapter, 0, RUN_ID, bad, ENTRYPOINT_ID, 0)
        for bad in ("entry-a", "ENTRY-A\n"):
            with self.assertRaises(ContractViolation):
                adjudicate_adapter_attempt(adapter, 0, RUN_ID, SUITE_ID, bad, 0)
        for rc in ("0", True, -256, 256, None):
            with self.assertRaises(ContractViolation):
                adjudicate_adapter_attempt(adapter, rc, RUN_ID, SUITE_ID, ENTRYPOINT_ID, 0)
        base = make_result("INFRA", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(-9), reason_code="ADAPTER_MISSING")
        for history in ([{"attempt_index": 0, "process_exit": -9}, {"attempt_index": 0, "process_exit": -9}], [{"attempt_index": 1, "process_exit": -9}], [{"attempt_index": 0, "process_exit": -9}, {"attempt_index": 2, "process_exit": -9}]):
            self.assert_invalid(dict(base, attempt_records=history))
        with self.assertRaises(ContractViolation):
            make_result("INFRA", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(-9), reason_code="ATTEMPT_DUPLICATE")

    def test_python_and_schema_reject_identity_boundary_cases(self):
        valid = make_result("PASS", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(0))
        for field, values in {
            "run_id": ("RUN-A", "A" * 32, RUN_ID[:-1], RUN_ID + "0", RUN_ID + "\n"),
            "suite_id": ("suite-a", "SUITE-A\n"), "entrypoint_id": ("entry-a", "ENTRY-A\n"),
        }.items():
            for bad in values:
                broken = dict(valid, **{field: bad})
                self.assert_invalid(broken)
                adapter = adapter_for(("PASS", "NONE", "NONE"), **{field: bad})
                self.assertEqual(check_adapter_result(adapter), "ADAPTER_MALFORMED")
                self.assertTrue(self.schema_errors("adapter-result.v1.schema.json", adapter))

    def test_identity_patterns_reject_trailing_newline_with_search_and_official_schema(self):
        for pattern, identity in ((RUN_ID_RE, RUN_ID), (SUITE_ID_RE, SUITE_ID), (ENTRYPOINT_ID_RE, ENTRYPOINT_ID)):
            self.assertIsNotNone(re.search(pattern, identity))
            self.assertIsNone(re.search(pattern, identity + "\n"))
        valid = make_result("PASS", RUN_ID, SUITE_ID, ENTRYPOINT_ID, attempts(0))
        invalid_result = dict(valid, suite_id=SUITE_ID + "\n")
        self.assert_invalid(invalid_result)
        invalid_adapter = adapter_for(("PASS", "NONE", "NONE"), suite_id=SUITE_ID + "\n")
        self.assertTrue(self.schema_errors("adapter-result.v1.schema.json", invalid_adapter))
        for name, value in (("test-result.v1.schema.json", invalid_result), ("adapter-result.v1.schema.json", invalid_adapter)):
            official_errors = self.official_schema_errors(name, value)
            if official_errors is not None:
                self.assertTrue(official_errors)

    def test_schema_identity_loader_is_pure(self):
        self.assertEqual(load_schema("test-result.v1"), {"schema": "test-result.v1"})
        with self.assertRaises(ContractViolation):
            load_schema("unknown.v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
