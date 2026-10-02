#!/usr/bin/env python3
"""RUE-02 schema-plus-semantic manifest contracts, entirely in memory."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import pathlib
import unittest
from typing import Any, Callable

from jsonschema import Draft202012Validator, ValidationError

try:
    from run_evidence.contracts import ContractViolation, make_result
    from run_evidence.manifest_contracts import (
        canonical_json_bytes, load_canonical_json, validate_change_set,
        validate_complete_run, validate_completion_seal, validate_evidence_manifest,
        validate_release_candidate, validate_run_manifest, validate_source_snapshot,
        validate_terminal_set,
    )
except ModuleNotFoundError:
    from test.quality.run_evidence.contracts import ContractViolation, make_result
    from test.quality.run_evidence.manifest_contracts import (
        canonical_json_bytes, load_canonical_json, validate_change_set,
        validate_complete_run, validate_completion_seal, validate_evidence_manifest,
        validate_release_candidate, validate_run_manifest, validate_source_snapshot,
        validate_terminal_set,
    )


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUN = "0123456789abcdef0123456789abcdef"
HEAD = "a" * 40
OTHER_HEAD = "c" * 40
SHA = "b" * 64
SUITE = "SUITE-RUN-EVIDENCE-CONTRACT"
ENTRY = "ENTRY-RUE-CONTRACT"

SCHEMA_FILES = {
    "source-snapshot-manifest.v1": "source-snapshot-manifest.v1.schema.json",
    "change-set.v1": "change-set.v1.schema.json",
    "run-manifest.v1": "run-manifest.v1.schema.json",
    "evidence-manifest.v1": "evidence-manifest.v1.schema.json",
    "completion-seal.v1": "completion-seal.v1.schema.json",
    "run-failure.v1": "run-failure.v1.schema.json",
    "release-candidate.v1": "release-candidate.v1.schema.json",
    "test-result.v1": "test-result.v1.schema.json",
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def ref(path: str, raw: bytes) -> dict[str, str]:
    return {"path": path, "sha256": digest(raw)}


class RUE02Manifests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validators = {
            name: Draft202012Validator(json.loads((ROOT / "quality/schema" / filename).read_text("utf-8")))
            for name, filename in SCHEMA_FILES.items()
        }

    def schema_validator(self, schema_name: str, instance: Any) -> None:
        self.validators[schema_name].validate(instance)

    def fixture(self, gates_doc: dict[str, Any] | None = None) -> dict[str, Any]:
        snapshot = {
            "schema": "source-snapshot-manifest.v1", "run_id": RUN, "head_sha": HEAD,
            "snapshot_mode": "clean-commit", "entry_count": 1, "total_bytes": 3,
            "entries": [{"path": "test/a.py", "type": "file", "mode": "100644", "size": 3, "sha256": SHA}],
        }
        snapshot_raw = canonical_json_bytes(snapshot)
        result = make_result("PASS", RUN, SUITE, ENTRY)
        result_raw = canonical_json_bytes(result)
        change = {
            "schema": "change-set.v1", "head_sha": HEAD, "raw_status_sha256": SHA,
            "created_at": "2026-07-24T00:00:00Z", "entries": [{
                "path": "test/a.py", "xy_status": "??", "head_blob_sha": None,
                "index_blob_sha": None, "worktree_sha256": SHA, "mode": "100644",
                "size": 0, "dev": 0, "ino": 0, "mtime_ns": 0,
            }],
        }
        if gates_doc is None:
            gates_doc = {
                "schema": "release-gates.v1", "version": "v0.8.3",
                "gates": [{"id": "GATE-ONE", "status": "active", "candidate_policy": "required", "required_suite_ids": [SUITE]}],
            }
        catalog_doc = {
            "schema": "test-catalog.v1", "catalog_id": "SUITE-CATALOG-V1", "version": "v0.8.3",
            "discovery_paths": [], "selection_rules": [],
            "suites": [{"id": SUITE, "entrypoint_id": ENTRY}],
        }
        gates_raw = canonical_json_bytes(gates_doc)
        catalog_raw = canonical_json_bytes(catalog_doc)
        run = {
            "schema": "run-manifest.v1", "run_id": RUN, "profile": "release", "head_sha": HEAD,
            "comparison_base": {"policy": "previous-release-peeled", "sha": HEAD},
            "source_snapshot_manifest": ref("snapshot/source-snapshot-manifest.json", snapshot_raw),
            "change_set": None, "invocation_argv": ["python3"],
            "expected_suites": [{"suite_id": SUITE, "entrypoint_id": ENTRY}],
            "input_digests": {**{key: SHA for key in ("schema_bundle", "runner", "fixtures", "build_recipes", "sanitized_environment", "tools")}, "gates": digest(gates_raw), "catalog": digest(catalog_raw)},
            "platform": {"os": "macos", "arch": "arm64", "toolchain": "python"},
            "started_at": "2026-07-24T00:00:00Z",
        }
        run_raw = canonical_json_bytes(run)
        evidence = {
            "schema": "evidence-manifest.v1", "run_id": RUN,
            "run_manifest": ref("run-manifest.json", run_raw),
            "test_results": [{"suite_id": SUITE, "entrypoint_id": ENTRY, "path": "results/{}.json".format(SUITE), "sha256": digest(result_raw)}],
        }
        evidence_raw = canonical_json_bytes(evidence)
        seal = {
            "schema": "completion-seal.v1", "run_id": RUN,
            "run_manifest": ref("run-manifest.json", run_raw),
            "source_snapshot_manifest": ref("snapshot/source-snapshot-manifest.json", snapshot_raw),
            "evidence_manifest": ref("evidence-manifest.json", evidence_raw),
            "input_digest_set_sha256": digest(canonical_json_bytes(run["input_digests"])),
            "aggregate_decision": "PASS", "runner_exit": 0, "completed_at": "2026-07-24T00:00:01Z",
        }
        seal_raw = canonical_json_bytes(seal)
        candidate = {
            "schema": "release-candidate.v1", "version": "v0.8.3", "candidate_head_sha": HEAD,
            "previous_release": {"tag": "v0.8.2", "tag_object_sha": HEAD, "peeled_sha": HEAD},
            "gate_ids": ["GATE-ONE"], "completion_seal": ref("completion-seal.json", seal_raw),
        }
        failure = {
            "schema": "run-failure.v1", "run_id": RUN, "stage": "INTERRUPT",
            "reason_code": "INTERRUPTED", "run_manifest": None,
            "created_at": "2026-07-24T00:00:00Z", "terminal": True,
        }
        artifacts = {
            "snapshot/source-snapshot-manifest.json": snapshot_raw,
            "run-manifest.json": run_raw,
            "results/{}.json".format(SUITE): result_raw,
            "evidence-manifest.json": evidence_raw,
            "completion-seal.json": seal_raw,
        }
        return {"snapshot": snapshot, "change": change, "run": run, "evidence": evidence,
                "seal": seal, "candidate": candidate, "failure": failure, "artifacts": artifacts,
                "gates_raw": gates_raw, "catalog_raw": catalog_raw}

    def semantic_cases(self, data: dict[str, Any]) -> dict[str, Callable[[Any], None]]:
        return {
            "source-snapshot-manifest.v1": validate_source_snapshot,
            "change-set.v1": validate_change_set,
            "run-manifest.v1": lambda value: validate_run_manifest(value, data["artifacts"]),
            "evidence-manifest.v1": lambda value: validate_evidence_manifest(value, data["run"], data["artifacts"]),
            "completion-seal.v1": lambda value: validate_completion_seal(value, data["run"], data["snapshot"], data["evidence"], data["artifacts"]),
            "run-failure.v1": lambda value: validate_terminal_set(None, value, run_manifest=data["run"], artifacts=data["artifacts"]),
            "release-candidate.v1": lambda value: validate_release_candidate(value, data["artifacts"], data["gates_raw"], data["catalog_raw"]),
        }

    def assert_dual_reject(self, schema_name: str, value: Any, semantic: Callable[[Any], None]) -> None:
        with self.assertRaises(ValidationError, msg=schema_name + " schema accepted invalid value"):
            self.schema_validator(schema_name, value)
        with self.assertRaises(ContractViolation, msg=schema_name + " semantic validator accepted invalid value"):
            semantic(value)

    def test_all_rue02_schemas_dual_validate_and_closed_reject(self):
        data = self.fixture()
        values = {
            "source-snapshot-manifest.v1": data["snapshot"], "change-set.v1": data["change"],
            "run-manifest.v1": data["run"], "evidence-manifest.v1": data["evidence"],
            "completion-seal.v1": data["seal"], "run-failure.v1": data["failure"],
            "release-candidate.v1": data["candidate"],
        }
        semantic = self.semantic_cases(data)
        for name, value in values.items():
            with self.subTest(name=name, case="valid"):
                self.schema_validator(name, value)
                semantic[name](value)
            with self.subTest(name=name, case="unknown"):
                invalid = dict(value, unknown=True)
                self.assert_dual_reject(name, invalid, semantic[name])
            with self.subTest(name=name, case="missing"):
                invalid = dict(value)
                del invalid[next(key for key in invalid if key != "schema")]
                self.assert_dual_reject(name, invalid, semantic[name])

    def test_schema_and_semantic_reject_unsafe_path_and_bounds(self):
        data = self.fixture()
        semantic = self.semantic_cases(data)
        cases = [
            ("source-snapshot-manifest.v1", lambda value: value["entries"][0].update(path="../unsafe")),
            ("change-set.v1", lambda value: value["entries"][0].update(path="../unsafe")),
            ("run-manifest.v1", lambda value: value["source_snapshot_manifest"].update(path="../unsafe")),
            ("evidence-manifest.v1", lambda value: value["test_results"][0].update(path="../unsafe")),
            ("completion-seal.v1", lambda value: value["run_manifest"].update(path="../unsafe")),
            ("run-failure.v1", lambda value: value.update(run_manifest={"path": "../unsafe", "sha256": SHA})),
            ("release-candidate.v1", lambda value: value["completion_seal"].update(path="../unsafe")),
            ("source-snapshot-manifest.v1", lambda value: value.update(total_bytes=1073741825)),
            ("change-set.v1", lambda value: value["entries"][0].update(size=67108865)),
            ("run-manifest.v1", lambda value: value.update(invocation_argv=["x"] * 65)),
            ("evidence-manifest.v1", lambda value: value.update(test_results=[])),
            ("completion-seal.v1", lambda value: value.update(runner_exit=256)),
            ("run-failure.v1", lambda value: value.update(run_id="x" * 31)),
            ("release-candidate.v1", lambda value: value.update(version="v0.8.3\n")),
        ]
        values = {"source-snapshot-manifest.v1": data["snapshot"], "change-set.v1": data["change"], "run-manifest.v1": data["run"], "evidence-manifest.v1": data["evidence"], "completion-seal.v1": data["seal"], "run-failure.v1": data["failure"], "release-candidate.v1": data["candidate"]}
        for schema_name, mutate in cases:
            with self.subTest(schema=schema_name, mutate=mutate):
                invalid = copy.deepcopy(values[schema_name])
                mutate(invalid)
                self.assert_dual_reject(schema_name, invalid, semantic[schema_name])

    def test_c2_binding_counterexamples_are_closed(self):
        data = self.fixture()
        snapshot = copy.deepcopy(data["snapshot"])
        target = "target/é"
        snapshot["entries"] = [{"path": "link", "type": "symlink", "mode": "120000", "size": len(target.encode("utf-8")), "sha256": digest(target.encode("utf-8")), "symlink_target": target}]
        snapshot["entry_count"] = 1
        snapshot["total_bytes"] = len(target.encode("utf-8"))
        validate_source_snapshot(snapshot)
        for mutate in (lambda value: value["entries"][0].update(size=1), lambda value: value["entries"][0].update(sha256=SHA)):
            invalid = copy.deepcopy(snapshot)
            mutate(invalid)
            with self.assertRaises(ContractViolation):
                validate_source_snapshot(invalid)
        host = copy.deepcopy(data["run"])
        host.update(profile="host", comparison_base={"policy": "head", "sha": OTHER_HEAD})
        with self.assertRaises(ContractViolation):
            validate_run_manifest(host, data["artifacts"])
        seal_cases = [
            lambda value: value.update(run_id="f" * 32),
            lambda value: value.update(input_digest_set_sha256=SHA),
            lambda value: value["source_snapshot_manifest"].update(sha256=SHA),
            lambda value: value["evidence_manifest"].update(path="wrong.json"),
        ]
        for mutate in seal_cases:
            invalid = copy.deepcopy(data["seal"])
            mutate(invalid)
            with self.assertRaises(ContractViolation):
                validate_completion_seal(invalid, data["run"], data["snapshot"], data["evidence"], data["artifacts"])
        candidate_cases = [
            (data["candidate"], canonical_json_bytes({"schema": "release-gates.v1", "version": "v0.8.3", "gates": [{"id": "GATE-ONE", "status": "active", "candidate_policy": "required", "required_suite_ids": [SUITE]}]}), canonical_json_bytes({"schema": "test-catalog.v1", "catalog_id": "SUITE-CATALOG-V1", "version": "v0.8.3", "discovery_paths": [], "selection_rules": [], "suites": [{"id": SUITE, "entrypoint_id": "ENTRY-SPOOFED"}]})),
            (dict(data["candidate"], gate_ids=[]), data["gates_raw"], data["catalog_raw"]),
            (dict(data["candidate"], completion_seal={"path": "completion-seal.json", "sha256": SHA}), data["gates_raw"], data["catalog_raw"]),
        ]
        for candidate, gates_raw, catalog_raw in candidate_cases:
            with self.assertRaises(ContractViolation):
                validate_release_candidate(candidate, data["artifacts"], gates_raw, catalog_raw)
        failure_cases = [
            dict(data["failure"], reason_code="NOPE"), dict(data["failure"], stage="NOPE"),
            dict(data["failure"], run_id="f" * 32),
            dict(data["failure"], run_manifest={"path": "../run", "sha256": SHA}),
        ]
        for failure in failure_cases:
            with self.assertRaises(ContractViolation):
                validate_terminal_set(None, failure, run_manifest=data["run"], artifacts=data["artifacts"])

    def test_composed_validation_requires_schema_callback_and_rejects_extra(self):
        data = self.fixture()
        with self.assertRaises(ContractViolation):
            validate_complete_run(data["run"], data["evidence"], data["seal"], None, data["artifacts"], schema_validator=None)
        snapshot, change = validate_complete_run(
            data["run"], data["evidence"], data["seal"], None, data["artifacts"],
            schema_validator=self.schema_validator, candidate=data["candidate"], release_gates_raw=data["gates_raw"], test_catalog_raw=data["catalog_raw"],
        )
        self.assertEqual(snapshot, data["snapshot"])
        self.assertIsNone(change)
        invalid = dict(data["run"], extra=True)
        with self.assertRaises((ValidationError, ContractViolation)):
            validate_complete_run(invalid, data["evidence"], data["seal"], None, data["artifacts"], schema_validator=self.schema_validator)

    def test_candidate_binds_canonical_raw_release_inputs_to_the_sealed_run(self):
        data = self.fixture()
        validate_release_candidate(data["candidate"], data["artifacts"], data["gates_raw"], data["catalog_raw"])
        forged_gates = canonical_json_bytes({
            "schema": "release-gates.v1", "version": "v0.8.3",
            "gates": [{"id": "GATE-FORGED", "status": "active", "candidate_policy": "required", "required_suite_ids": [SUITE]}],
        })
        forged_catalog = canonical_json_bytes({
            "schema": "test-catalog.v1", "catalog_id": "SUITE-CATALOG-V1", "version": "v0.8.3",
            "discovery_paths": [], "selection_rules": [],
            "suites": [{"id": SUITE, "entrypoint_id": "ENTRY-SPOOFED"}],
        })
        for gates_raw, catalog_raw in ((forged_gates, data["catalog_raw"]), (data["gates_raw"][:-1], data["catalog_raw"]), (data["gates_raw"], forged_catalog)):
            with self.assertRaises(ContractViolation):
                validate_release_candidate(data["candidate"], data["artifacts"], gates_raw, catalog_raw)

    def test_release_gates_reject_duplicate_ids_after_sealed_chain_rebuild(self):
        required = {"id": "GATE-ONE", "status": "active", "candidate_policy": "required", "required_suite_ids": [SUITE]}
        cases = [
            [required, {"id": "GATE-ONE", "status": "inactive", "candidate_policy": "excluded", "required_suite_ids": []}],
            [required, dict(required)],
        ]
        for gates in cases:
            with self.subTest(gates=gates):
                data = self.fixture({"schema": "release-gates.v1", "version": "v0.8.3", "gates": gates})
                with self.assertRaises(ContractViolation):
                    validate_release_candidate(data["candidate"], data["artifacts"], data["gates_raw"], data["catalog_raw"])

    def test_canonical_input_and_hash_rejections(self):
        self.assertEqual(canonical_json_bytes({"z": 1, "a": "é"}), '{"a":"é","z":1}'.encode())
        self.assertEqual(load_canonical_json(b'{"a":0}'), {"a": 0})
        invalid = [b'{ "a":0}', b'{"a":0}\n', b'{"a":0.0}', b'{"a":1,"a":2}', b'{"a":"e\\u0301"}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}']
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises(ContractViolation):
                    load_canonical_json(raw)
        data = self.fixture()
        bad_run = copy.deepcopy(data["run"])
        bad_run["source_snapshot_manifest"]["sha256"] = SHA
        with self.assertRaises(ContractViolation):
            validate_run_manifest(bad_run, data["artifacts"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
