#!/usr/bin/env python3
"""Focused source/unit tests for the quality kernel.

The tests use in-memory malicious fixtures and read-only inspection of the
current repository.  They do not run providers, Science, SSH, databases,
network, installed apps, or the existing run_all gate.
"""

import copy
import pathlib
import tempfile
import unittest
from unittest import mock

try:
    from validate_quality_metadata import PRODUCT_BUG_IDS, Validator, ROOT
except ModuleNotFoundError:
    from test.quality.validate_quality_metadata import PRODUCT_BUG_IDS, Validator, ROOT


class QualityKernelFocused(unittest.TestCase):
    def fresh(self):
        validator = Validator(ROOT)
        validator.load_schemas()
        validator.load_data()
        validator.errors = []
        return validator

    def errors_after(self, validator, method):
        validator.errors = []
        method()
        return "\n".join(validator.errors)

    def test_metadata_registry_is_closed_and_product_eight_are_independent(self):
        validator = self.fresh()
        self.assertTrue(validator.run("metadata"), "\n".join(validator.errors))
        self.assertEqual(PRODUCT_BUG_IDS, {bug_id for bug_id in validator.bugs if bug_id in PRODUCT_BUG_IDS})
        for bug_id in PRODUCT_BUG_IDS:
            bug = validator.bugs[bug_id]
            self.assertEqual(bug["status"], "active")
            self.assertIn(
                bug["resolution_state"],
                {"open-not-fixed", "source-fixed-product-pending"},
            )
            self.assertEqual(len(bug["change_ids"]), 1)
            self.assertTrue(any(gate.startswith("GATE-") for gate in bug["expected_gate_ids"]))
        ssh_late = validator.bugs["BUG-083-SSH-LATE"]
        self.assertEqual(
            ssh_late["resolution_state"],
            "source-fixed-product-pending",
        )
        self.assertEqual(ssh_late["reproduction_state"], "source-reproduced")
        science = validator.bugs["BUG-083-SCIENCE-REATTACH"]
        self.assertEqual(science["resolution_state"], "source-fixed-product-pending")
        self.assertEqual(science["reproduction_state"], "source-reproduced")
        science["reproduction_state"] = "historical-observed"
        errors = self.errors_after(validator, validator.check_lifecycle)
        self.assertIn(
            "source-fixed-product-pending bug requires source-reproduced evidence",
            errors,
        )

    def test_unknown_field_and_foreign_key_fail(self):
        validator = self.fresh()
        requirement_schema = validator.kernel["$defs"]["RequirementV1"]
        before = len(validator.errors)
        validator.validate_instance({"id": "REQ-BAD", "unknown": True}, requirement_schema, validator.kernel, "fixture.requirement")
        self.assertGreater(len(validator.errors), before)
        validator = self.fresh()
        validator.changes["CHG-QUALITY-KERNEL"]["requirement_ids"] = ["REQ-NOT-REAL"]
        errors = self.errors_after(validator, validator.check_references)
        self.assertIn("unknown requirement foreign key REQ-NOT-REAL", errors)

    def test_duplicate_cycle_and_tombstone_fail(self):
        validator = self.fresh()
        duplicate = copy.deepcopy(validator.bugs["BUG-083-RC"])
        validator.add_record(validator.bugs, duplicate, "bug", "malicious-duplicate")
        self.assertTrue(any("duplicate global ID BUG-083-RC" in error for error in validator.errors))

        validator = self.fresh()
        validator.requirements["REQ-083-SCHEMA"]["depends_on"] = ["REQ-083-FOCUSED"]
        validator.requirements["REQ-083-FOCUSED"]["depends_on"] = ["REQ-083-SCHEMA"]
        errors = self.errors_after(validator, validator.check_requirement_cycles)
        self.assertIn("requirement dependency cycle", errors)

        validator = self.fresh()
        validator.bugs["BUG-083-RC"]["status"] = "retired"
        validator.bugs["BUG-083-RC"]["resolution_state"] = "retired"
        validator.bugs["BUG-083-RC"]["retirement"] = None
        errors = self.errors_after(validator, validator.check_lifecycle)
        self.assertIn("retired record requires a tombstone", errors)

    def test_illegal_high_risk_exemption_fails_closed(self):
        validator = self.fresh()
        impact = validator.changes["CHG-QUALITY-KERNEL"]["test_impact"]
        impact["kind"] = "not-yet-automatable"
        errors = self.errors_after(validator, validator.check_test_impact)
        self.assertIn("high-risk change cannot use manual-evidence/not-yet-automatable", errors)

    def test_lineage_target_and_base_rules_fail(self):
        validator = self.fresh()
        self.assertNotIn("candidate_head_sha", validator.lineage)
        validator.lineage["previous_release"]["tag_object_sha"] = "0" * 40
        errors = self.errors_after(validator, validator.check_lineage)
        self.assertIn("refs/tags/v0.8.2 does not match tag_object_sha", errors)
        validator = self.fresh()
        errors = self.errors_after(validator, lambda: validator.check_impact("impact-pr", None))
        self.assertIn("impact-pr requires an explicit --target-ref", errors)
        validator = self.fresh()
        errors = self.errors_after(validator, lambda: validator.check_impact("impact-pr", "ref-that-does-not-exist"))
        self.assertIn("target ref does not resolve", errors)

    def test_dirty_untracked_unknown_and_rename_delete_fail(self):
        validator = self.fresh()
        errors = self.errors_after(validator, lambda: validator.check_changed_paths([("??", "mystery-production/file.py")], "impact-release"))
        self.assertIn("unknown production path", errors)
        errors = self.errors_after(validator, lambda: validator.check_changed_paths([("D", "quality/requirements.v1.json")], "impact-release"))
        self.assertIn("rename/delete/copy status is fail-closed", errors)

        original_git = validator.git

        def git_with_dirty_fixture(args, allow_failure=False):
            if list(args) == ["status", "--porcelain=v1"]:
                return 0, " M docs/README.md", ""
            return original_git(args, allow_failure=allow_failure)

        validator.git = git_with_dirty_fixture
        errors = self.errors_after(validator, lambda: validator.check_impact("impact-release", None))
        self.assertIn("worktree must be clean", errors)

    def test_orphan_and_cargo_manifest_inventory_is_closed(self):
        validator = self.fresh()
        orphan_ids = {
            "SUITE-ORPHAN-AGGREGATOR",
            "SUITE-ORPHAN-RETRY",
            "SUITE-ORPHAN-SKILL-BRIDGE",
            "SUITE-ORPHAN-SKILL-BOUNDARY",
        }
        self.assertTrue(orphan_ids.issubset(validator.suites))
        self.assertEqual(
            {
                item: validator.suites[item]["status"]
                for item in orphan_ids
            },
            {
                "SUITE-ORPHAN-AGGREGATOR": "retired",
                "SUITE-ORPHAN-RETRY": "retired",
                "SUITE-ORPHAN-SKILL-BRIDGE": "implemented",
                "SUITE-ORPHAN-SKILL-BOUNDARY": "implemented",
            },
        )
        self.assertEqual(
            validator.suites["SUITE-ORPHAN-SKILL-BRIDGE"]["gate_ids"],
            ["GATE-SOURCE"],
        )
        self.assertEqual(
            validator.suites["SUITE-ORPHAN-SKILL-BOUNDARY"]["gate_ids"],
            ["GATE-SOURCE"],
        )
        manifests = sorted((ROOT / "desktop").glob("**/Cargo.toml"))
        self.assertEqual(
            {path.relative_to(ROOT).as_posix() for path in manifests},
            {
                "desktop/codex-network/Cargo.toml",
                "desktop/gateway/Cargo.toml",
                "desktop/skill-package/Cargo.toml",
                "desktop/src-tauri/Cargo.toml",
            },
        )
        catalog_paths = {path for suite in validator.suites.values() for path in suite["source_paths"]}
        self.assertTrue({path.relative_to(ROOT).as_posix() for path in manifests}.issubset(catalog_paths))

    def test_trusted_source_gate_exact_selection_and_identity_inventory_fail_closed(self):
        validator = self.fresh()
        self.assertTrue(validator.run("metadata"), "\n".join(validator.errors))
        source_rule = next(
            rule for rule in validator.catalog["selection_rules"]
            if rule["name"] == "source-gate"
        )
        self.assertEqual(source_rule["suite_ids"], list(validator.gates["GATE-SOURCE"]["required_suite_ids"]))
        self.assertEqual(len(source_rule["suite_ids"]), 15)

        validator = self.fresh()
        rule = next(
            rule for rule in validator.catalog["selection_rules"]
            if rule["name"] == "source-gate"
        )
        rule["suite_ids"] = rule["suite_ids"][:-1]
        errors = self.errors_after(validator, validator.check_source_gate_catalog)
        self.assertIn("trusted source selection drifted", errors)

        validator = self.fresh()
        validator.suites["SUITE-PY-OFFLINE"]["retry_policy"] = "readiness-timeout-once"
        errors = self.errors_after(validator, validator.check_source_gate_catalog)
        self.assertIn("trusted source suite contract drifted", errors)

        validator = self.fresh()
        validator.suites["SUITE-RUST-DESKTOP"]["test_identity"]["sha256"] = "0" * 64
        errors = self.errors_after(validator, validator.check_source_gate_catalog)
        self.assertIn("trusted source suite contract drifted", errors)

        validator = self.fresh()
        manifests = list((ROOT / "desktop").glob("**/Cargo.toml"))
        with mock.patch.object(
            pathlib.Path,
            "glob",
            return_value=[
                *manifests,
                ROOT / "desktop/fifth/Cargo.toml",
            ],
        ):
            errors = self.errors_after(
                validator, validator.check_source_gate_catalog,
            )
        self.assertIn(
            "trusted source Cargo manifest inventory drifted", errors,
        )

        validator = self.fresh()
        rule = next(
            rule for rule in validator.catalog["selection_rules"]
            if rule["name"] == "source-gate"
        )
        rule["suite_ids"][-1] = "SUITE-QUALITY-ARTIFACT"
        errors = self.errors_after(
            validator, validator.check_source_gate_catalog,
        )
        self.assertIn("trusted source selection drifted", errors)

    def test_test_result_pass_marker_exit7_fails(self):
        validator = self.fresh()
        schema = validator.schemas["test-result.v1.schema.json"]
        valid = {
            "schema": "test-result.v1",
            "run_id": "0123456789abcdef0123456789abcdef",
            "suite_id": "SUITE-QUALITY-FOCUSED",
            "entrypoint_id": "ENTRY-PASS-MARKER",
            "kind": "PASS",
            "outcome": "PASS",
            "classification": "NONE",
            "gate_decision": "PASS",
            "reason_code": "NONE",
            "runner_exit": 0,
            "attempt_records": [{"attempt_index": 0, "process_exit": 0}],
        }
        validator.validate_instance(valid, schema, schema, "fixture.valid-result")
        validator.check_test_result_semantics(valid)
        self.assertFalse(validator.errors)
        invalid = dict(valid)
        invalid["runner_exit"] = 7
        validator.errors = []
        validator.validate_instance(invalid, schema, schema, "fixture.pass-marker-exit7")
        validator.check_test_result_semantics(invalid)
        errors = "\n".join(validator.errors)
        self.assertIn("must match exactly one schema branch", errors)
        self.assertIn("PASS requires runner_exit=0", errors)

    def test_test_result_three_dimensions_reject_contradictions_and_bind_downstream(self):
        validator = self.fresh()
        schema = validator.schemas["test-result.v1.schema.json"]
        base = {
            "schema": "test-result.v1",
            "run_id": "0123456789abcdef0123456789abcdef",
            "suite_id": "SUITE-QUALITY-FOCUSED",
            "entrypoint_id": "ENTRY-BOUNDARY",
            "kind": "TEST_FAIL",
            "outcome": "FAIL",
            "classification": "NONE",
            "gate_decision": "FAIL",
            "reason_code": "ASSERTION_FAILED",
            "runner_exit": 10,
            "attempt_records": [{"attempt_index": 0, "process_exit": 10}],
        }
        validator.validate_instance(base, schema, schema, "fixture.valid-fail")
        validator.check_test_result_semantics(base)
        self.assertFalse(validator.errors)

        for name, invalid in (
            ("fail-runner0", dict(base, runner_exit=0)),
            ("missing-dimensions", {key: value for key, value in base.items() if key not in {"outcome", "classification", "gate_decision"}}),
            ("flaky-pass", dict(base, kind="FLAKY_RETRY", outcome="PASS", classification="FLAKY", gate_decision="BLOCKED", reason_code="READINESS_RETRY_CHANGED", runner_exit=0, attempt_records=[{"attempt_index": 0, "process_exit": 0}, {"attempt_index": 1, "process_exit": 0}])),
            ("env-pass", dict(base, kind="ENV", outcome="ENV-BLOCKED", classification="NONE", gate_decision="PASS", reason_code="ENVIRONMENT", runner_exit=11)),
        ):
            validator.errors = []
            validator.validate_instance(invalid, schema, schema, "fixture." + name)
            validator.check_test_result_semantics(invalid)
            self.assertTrue(validator.errors, name)

        evidence_schema = validator.schemas["evidence-manifest.v1.schema.json"]
        evidence = {
            "schema": "evidence-manifest.v1",
            "run_id": "0123456789abcdef0123456789abcdef",
            "run_manifest": {"path": "run-manifest.json", "sha256": "0" * 64},
            "test_results": [{
                "suite_id": "SUITE-QUALITY-FOCUSED",
                "entrypoint_id": "ENTRY-BOUNDARY",
                "path": "results/SUITE-QUALITY-FOCUSED.json",
                "sha256": "0" * 64
            }]
        }
        validator.errors = []
        validator.validate_instance(evidence, evidence_schema, evidence_schema, "fixture.evidence-manifest")
        self.assertFalse(validator.errors)

        valid_downstream = copy.deepcopy(evidence)
        valid_downstream["test_results"][0]["sha256"] = "1" * 64
        validator.errors = []
        validator.validate_instance(valid_downstream, evidence_schema, evidence_schema, "fixture.valid-downstream-evidence")
        self.assertFalse(validator.errors)

        malicious_downstream = copy.deepcopy(evidence)
        malicious_downstream["test_results"][0]["outcome"] = "PASS"
        validator.errors = []
        validator.validate_instance(malicious_downstream, evidence_schema, evidence_schema, "fixture.pass-flaky-blocked-zero")
        self.assertTrue(validator.errors)

        run_schema = validator.schemas["run-manifest.v1.schema.json"]
        run_manifest = {
            "schema": "run-manifest.v1",
            "run_id": "0123456789abcdef0123456789abcdef",
            "profile": "source",
            "head_sha": "0" * 40,
            "comparison_base": {"policy": "merge-base-origin-main", "sha": "0" * 40},
            "source_snapshot_manifest": {"path": "snapshot/source-snapshot-manifest.json", "sha256": "0" * 64},
            "change_set": None,
            "invocation_argv": ["python3"],
            "expected_suites": [{"suite_id": "SUITE-QUALITY-FOCUSED", "entrypoint_id": "ENTRY-BOUNDARY"}],
            "input_digests": {key: "0" * 64 for key in ("schema_bundle", "catalog", "gates", "runner", "fixtures", "build_recipes", "sanitized_environment", "tools")},
            "platform": {"os": "test", "arch": "test", "toolchain": "test"},
            "started_at": "2026-07-24T00:00:00Z"
        }
        validator.errors = []
        validator.validate_instance(run_manifest, run_schema, run_schema, "fixture.run-manifest")
        self.assertFalse(validator.errors)
        candidate_schema = validator.schemas["release-candidate.v1.schema.json"]
        candidate = {
            "schema": "release-candidate.v1",
            "version": "v0.8.3",
            "candidate_head_sha": "0" * 40,
            "previous_release": {"tag": "v0.8.2", "tag_object_sha": "0" * 40, "peeled_sha": "1" * 40},
            "gate_ids": ["GATE-QUALITY-RELEASE"],
            "completion_seal": {"path": "completion-seal.json", "sha256": "0" * 64}
        }
        validator.errors = []
        validator.validate_instance(candidate, candidate_schema, candidate_schema, "fixture.release-candidate")
        self.assertFalse(validator.errors)

    def test_production_policy_requires_active_change_and_exact_policy_closure(self):
        validator = self.fresh()
        change = validator.changes["CHG-QUALITY-KERNEL"]
        change["test_impact"]["required_suite_ids"] = ["SUITE-PY-OFFLINE"]
        change["test_impact"]["required_gate_ids"] = ["GATE-S0-LEGACY"]
        errors = self.errors_after(
            validator,
            lambda: validator.check_changed_paths([("M", "quality/schema/test-result.v1.schema.json")], "impact-pr"),
        )
        self.assertIn("misses policy required suites", errors)
        self.assertIn("misses policy required gates", errors)

        validator = self.fresh()
        validator.changes["CHG-QUALITY-KERNEL"]["status"] = "retired"
        validator.changes["CHG-SOURCE-GATE"]["status"] = "retired"
        errors = self.errors_after(
            validator,
            lambda: validator.check_changed_paths([("M", "quality/schema/test-result.v1.schema.json")], "impact-pr"),
        )
        self.assertIn("no active matching ChangeRecordV1", errors)

    def test_replacement_cycle_and_retired_gate_need_tombstone(self):
        validator = self.fresh()
        validator.suites["SUITE-QUALITY-METADATA"]["replacement_id"] = "SUITE-QUALITY-FOCUSED"
        validator.suites["SUITE-QUALITY-FOCUSED"]["replacement_id"] = "SUITE-QUALITY-METADATA"
        errors = self.errors_after(validator, validator.check_replacement_graph)
        self.assertIn("replacement graph cycle", errors)
        validator = self.fresh()
        gate = validator.gates["GATE-QUALITY-META"]
        gate["status"] = "retired"
        gate["replacement_id"] = "GATE-QUALITY-PR"
        gate["retirement"] = None
        errors = self.errors_after(validator, validator.check_lifecycle)
        self.assertIn("retired gate requires a tombstone", errors)

    def test_discovery_is_dynamic_and_unregistered_fixture_fails(self):
        validator = self.fresh()
        self.assertEqual(set(validator.catalog["discovery_paths"]), validator.discover_catalog_paths())
        with tempfile.TemporaryDirectory() as directory:
            fixture_root = pathlib.Path(directory)
            fixture = fixture_root / "test" / "test_new_fixture.py"
            fixture.parent.mkdir()
            fixture.write_text("# temporary discovery fixture\n", encoding="utf-8")
            self.assertIn("test/test_new_fixture.py", Validator(fixture_root).discover_catalog_paths())
        errors = self.errors_after(
            validator,
            lambda: validator.check_discovery_set(set(validator.catalog["discovery_paths"]), set(validator.catalog["discovery_paths"]) | {"test/test_new_fixture.py"}),
        )
        self.assertIn("discovered entrypoint is not registered", errors)

    def test_fixed_run_evidence_suite_rule_and_gate_boundary_fail_closed(self):
        validator = self.fresh()
        self.assertEqual(
            validator.suites["SUITE-RUE05A"]["gate_ids"],
            [],
        )
        self.assertEqual(
            validator.suites["SUITE-RUE05A"]["retry_policy"],
            "readiness-timeout-once",
        )
        self.assertFalse(
            any(
                "SUITE-RUE05A" in gate.get("required_suite_ids", [])
                for gate in validator.gates.values()
            ),
        )
        self.assertFalse(
            self.errors_after(
                validator,
                validator.check_fixed_run_evidence_catalog,
            ),
        )

        validator = self.fresh()
        validator.suites["SUITE-RUE05A"]["command_argv"][-1] = "/tmp/free"
        errors = self.errors_after(
            validator,
            validator.check_fixed_run_evidence_catalog,
        )
        self.assertIn("catalog record drifted", errors)

        validator = self.fresh()
        validator.catalog["selection_rules"][0]["suite_ids"].append(
            "SUITE-QUALITY-METADATA",
        )
        errors = self.errors_after(
            validator,
            validator.check_fixed_run_evidence_catalog,
        )
        self.assertIn("selection rule drifted", errors)

        validator = self.fresh()
        validator.suites["SUITE-QUALITY-METADATA"]["retry_policy"] = (
            "readiness-timeout-once"
        )
        errors = self.errors_after(
            validator,
            validator.check_fixed_run_evidence_catalog,
        )
        self.assertIn("only SUITE-RUE05A", errors)

        validator = self.fresh()
        validator.gates["GATE-QUALITY-META"]["required_suite_ids"].append(
            "SUITE-RUE05A",
        )
        errors = self.errors_after(
            validator,
            validator.check_fixed_run_evidence_catalog,
        )
        self.assertIn("must not be promoted into a gate", errors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
