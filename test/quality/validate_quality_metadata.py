#!/usr/bin/env python3
"""Validate the checked-in CSSwitch quality kernel with Python's stdlib only.

This is intentionally a metadata/impact validator, not a test runner.  It uses
read-only Git commands for lineage and impact inventory and never reads user
credentials, databases, Science state, installed apps, or other worktrees.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[2]
QUALITY = ROOT / "quality"
SCHEMA_DIR = QUALITY / "schema"
VERSION = "v0.8.3"
PRODUCT_BUG_IDS = {
    "BUG-083-SCIENCE-UPDATER",
    "BUG-083-DEEPSEEK-THINKING",
    "BUG-083-DATABASE-ERROR",
    "BUG-083-GITHUB-BUNDLE",
    "BUG-083-MCP-BOUNDARY",
    "BUG-083-OPENCODE-65",
    "BUG-083-SCIENCE-MACHO",
    "BUG-083-SSH-LATE",
}
PRODUCT_REQUIREMENTS = {
    "REQ-083-SCIENCE-UPDATER",
    "REQ-083-DEEPSEEK-THINKING",
    "REQ-083-DATABASE-ERROR",
    "REQ-083-GITHUB-BUNDLE",
    "REQ-083-MCP-BOUNDARY",
    "REQ-083-OPENCODE-65",
    "REQ-083-MACHO-METADATA",
    "REQ-083-SSH-LATE",
}
PRODUCT_CHANGES = {
    "CHG-SCIENCE-UPDATER",
    "CHG-DEEPSEEK-THINKING",
    "CHG-DATABASE-ERROR",
    "CHG-GITHUB-BUNDLE",
    "CHG-MCP-BOUNDARY",
    "CHG-OPENCODE-65",
    "CHG-SCIENCE-MACHO",
    "CHG-SSH-LATE",
}
PRODUCT_GATES = {
    "GATE-SCIENCE-UPDATER",
    "GATE-DEEPSEEK-THINKING",
    "GATE-DATABASE-ERROR",
    "GATE-GITHUB-BUNDLE",
    "GATE-MCP-BOUNDARY",
    "GATE-OPENCODE-65",
    "GATE-SCIENCE-MACHO",
    "GATE-SSH-LATE",
}
LAYERS = {
    "source-test",
    "isolated-test-app",
    "final-dmg",
    "installed-final",
    "live",
    "signing",
    "public",
}
ID_PATTERNS = {
    "REQ": re.compile(r"^REQ-[A-Z0-9][A-Z0-9-]{0,31}$"),
    "CHG": re.compile(r"^CHG-[A-Z0-9][A-Z0-9-]{0,31}$"),
    "BUG": re.compile(r"^BUG-[A-Z0-9][A-Z0-9-]{0,31}$"),
    "SUITE": re.compile(r"^SUITE-[A-Z0-9][A-Z0-9-]{0,31}$"),
    "GATE": re.compile(r"^GATE-[A-Z0-9][A-Z0-9-]{0,31}$"),
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}([.-][A-Za-z0-9.-]{1,24})?$")
RUE_SUITE_ID = "SUITE-RUE05A"
RUE_RULE_NAME = "run-evidence-fixed-one-suite"
RUE_SUITE_SHA256 = "05e4f38d179a36af2b2c0dcc5298881016b1cab12a014a40ab951ac9a415784c"
RUE_RULE_SHA256 = "c87f2d0e751368d8b670a8f033a086969d258db229a7cc0920b364f9a5cde4d5"
SOURCE_GATE_ID = "GATE-SOURCE"
SOURCE_RULE_NAME = "source-gate"
SOURCE_IDENTITY_PATH = "test/quality/fixtures/source_gate/expected_test_ids.v1.json"
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


class ValidationError(Exception):
    pass


class Validator:
    def __init__(self, repo: Path) -> None:
        self.repo = repo.resolve()
        self.quality = self.repo / "quality"
        self.schema_dir = self.quality / "schema"
        self.errors: List[str] = []
        self.schemas: Dict[str, Any] = {}
        self.kernel: Optional[Dict[str, Any]] = None
        self.requirements: Dict[str, Dict[str, Any]] = {}
        self.changes: Dict[str, Dict[str, Any]] = {}
        self.bugs: Dict[str, Dict[str, Any]] = {}
        self.suites: Dict[str, Dict[str, Any]] = {}
        self.gates: Dict[str, Dict[str, Any]] = {}
        self.global_ids: Dict[str, str] = {}
        self.catalog: Dict[str, Any] = {}
        self.lineage: Dict[str, Any] = {}
        self.path_policy: Dict[str, Any] = {}

    def error(self, path: str, message: str) -> None:
        self.errors.append("{}: {}".format(path, message))

    def run(self, profile: str, target_ref: Optional[str] = None) -> bool:
        self.load_schemas()
        self.load_data()
        self.check_cross_file_contract()
        if profile in ("impact-pr", "impact-release"):
            self.check_impact(profile, target_ref)
        elif target_ref is not None:
            self.error("cli", "--target-ref is only valid for impact-pr")
        return not self.errors

    # ----- strict JSON schema subset -----

    def load_schemas(self) -> None:
        if not self.schema_dir.is_dir():
            self.error("quality/schema", "schema directory is missing")
            return
        for path in sorted(self.schema_dir.glob("*.schema.json")):
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                self.error(str(path.relative_to(self.repo)), "invalid JSON schema: {}".format(exc))
                continue
            self.schemas[path.name] = document
            self.check_schema_is_closed(document, str(path.relative_to(self.repo)))
        kernel = self.schemas.get("quality-kernel.v1.schema.json")
        if not isinstance(kernel, dict):
            self.error("quality/schema/quality-kernel.v1.schema.json", "kernel schema is missing")
            return
        self.kernel = kernel
        required_defs = {
            "RequirementV1",
            "ChangeRecordV1",
            "BugRecordV1",
            "TestSuiteCatalogV1",
            "ReleaseGateV1",
            "ReleaseLineageV1",
            "ProductionPathPolicyV1",
        }
        defs = kernel.get("$defs", {})
        missing = sorted(required_defs - set(defs)) if isinstance(defs, dict) else sorted(required_defs)
        if missing:
            self.error("quality/schema/quality-kernel.v1.schema.json", "missing definitions: {}".format(", ".join(missing)))

    def check_schema_is_closed(self, node: Any, path: str) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object" and node.get("additionalProperties") is not False:
                self.error(path, "object schema must set additionalProperties=false")
            for key, value in node.items():
                self.check_schema_is_closed(value, path + "." + str(key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                self.check_schema_is_closed(value, "{}[{}]".format(path, index))

    def resolve_ref(self, ref: str, root_schema: Dict[str, Any]) -> Any:
        if not ref.startswith("#/"):
            raise ValidationError("only local schema refs are supported")
        value: Any = root_schema
        for component in ref[2:].split("/"):
            value = value[component.replace("~1", "/").replace("~0", "~")]
        return value

    def validate_instance(self, value: Any, schema: Dict[str, Any], root_schema: Dict[str, Any], path: str) -> None:
        if schema is True:
            return
        if schema is False:
            self.error(path, "must not contain a value")
            return
        if "$ref" in schema:
            self.validate_instance(value, self.resolve_ref(schema["$ref"], root_schema), root_schema, path)
            return
        if "anyOf" in schema:
            branch_errors: List[List[str]] = []
            for branch in schema["anyOf"]:
                before = len(self.errors)
                self.validate_instance(value, branch, root_schema, path)
                if len(self.errors) == before:
                    return
                branch_errors.append(self.errors[before:])
                del self.errors[before:]
            self.error(path, "does not match any schema branch")
            return
        if "oneOf" in schema:
            matches = 0
            for branch in schema["oneOf"]:
                before = len(self.errors)
                self.validate_instance(value, branch, root_schema, path)
                if len(self.errors) == before:
                    matches += 1
                del self.errors[before:]
            if matches != 1:
                self.error(path, "must match exactly one schema branch")
            return
        if "allOf" in schema:
            for branch in schema["allOf"]:
                self.validate_instance(value, branch, root_schema, path)
        if "const" in schema and value != schema["const"]:
            self.error(path, "must equal {!r}".format(schema["const"]))
        if "enum" in schema and value not in schema["enum"]:
            self.error(path, "must be one of {!r}".format(schema["enum"]))
        expected_type = schema.get("type")
        if expected_type is not None and not self.instance_type_matches(value, expected_type):
            self.error(path, "expected {}, got {}".format(expected_type, type(value).__name__))
            return
        if isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                self.error(path, "string shorter than minLength")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                self.error(path, "string longer than maxLength")
            if "pattern" in schema:
                try:
                    matches = re.fullmatch(schema["pattern"], value)
                except re.error as exc:
                    self.error(path, "invalid schema pattern: {}".format(exc))
                    matches = True
                if not matches:
                    self.error(path, "does not match declared pattern")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                self.error(path, "number is below minimum")
            if "maximum" in schema and value > schema["maximum"]:
                self.error(path, "number is above maximum")
        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                self.error(path, "array shorter than minItems")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                self.error(path, "array longer than maxItems")
            if schema.get("uniqueItems"):
                normalized = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
                if len(set(normalized)) != len(normalized):
                    self.error(path, "array items must be unique")
            prefix_items = schema.get("prefixItems", [])
            for index, item_schema in enumerate(prefix_items):
                if index < len(value):
                    self.validate_instance(value[index], item_schema, root_schema, "{}[{}]".format(path, index))
            if "items" in schema:
                if schema["items"] is False:
                    if len(value) > len(prefix_items):
                        self.error(path, "array contains an item beyond prefixItems")
                else:
                    for index in range(len(prefix_items), len(value)):
                        self.validate_instance(value[index], schema["items"], root_schema, "{}[{}]".format(path, index))
        if isinstance(value, dict):
            required = schema.get("required", [])
            for key in required:
                if key not in value:
                    self.error(path, "missing required field {!r}".format(key))
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                for key in value:
                    if key not in properties:
                        self.error(path, "unknown field {!r}".format(key))
            for key, child_schema in properties.items():
                if key in value:
                    self.validate_instance(value[key], child_schema, root_schema, path + "." + key)

    @staticmethod
    def instance_type_matches(value: Any, expected: Any) -> bool:
        if expected == "object":
            return isinstance(value, dict)
        if expected == "array":
            return isinstance(value, list)
        if expected == "string":
            return isinstance(value, str)
        if expected == "integer":
            return Validator.is_json_integer(value)
        if expected == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "null":
            return value is None
        return True

    @staticmethod
    def is_json_integer(value: Any) -> bool:
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        return isinstance(value, float) and math.isfinite(value) and value.is_integer()

    # ----- data loading -----

    def load_json(self, path: Path) -> Optional[Any]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.error(str(path.relative_to(self.repo)), "invalid JSON: {}".format(exc))
            return None

    def validate_data_file(self, path: Path, document: Any, definition: str) -> None:
        if self.kernel is None:
            return
        schema = {"$ref": "#/$defs/" + definition}
        self.validate_instance(document, schema, self.kernel, str(path.relative_to(self.repo)))

    def load_data(self) -> None:
        if self.kernel is None:
            return
        self.requirements.clear()
        self.changes.clear()
        self.bugs.clear()
        self.suites.clear()
        self.gates.clear()
        self.global_ids.clear()
        self.catalog = {}
        self.lineage = {}
        self.path_policy = {}
        requirements_path = self.quality / "requirements.v1.json"
        if requirements_path.exists():
            document = self.load_json(requirements_path)
            if document is not None:
                self.validate_data_file(requirements_path, document, "RequirementsDocumentV1")
                if isinstance(document, dict):
                    for item in document.get("requirements", []):
                        if isinstance(item, dict):
                            self.add_record(self.requirements, item, "requirement", "requirements.v1.json")
        else:
            self.error("quality/requirements.v1.json", "required registry is missing")

        change_dir = self.quality / "changes" / VERSION
        if not change_dir.is_dir():
            self.error("quality/changes/" + VERSION, "required change directory is missing")
        else:
            for path in sorted(change_dir.glob("*.json")):
                document = self.load_json(path)
                if document is not None:
                    self.validate_data_file(path, document, "ChangeDocumentV1")
                    item = document.get("change") if isinstance(document, dict) else None
                    if isinstance(item, dict):
                        self.add_record(self.changes, item, "change", str(path.relative_to(self.repo)))

        bug_dir = self.quality / "bugs"
        if not bug_dir.is_dir():
            self.error("quality/bugs", "required bug directory is missing")
        else:
            for path in sorted(bug_dir.glob("*.json")):
                document = self.load_json(path)
                if document is not None:
                    self.validate_data_file(path, document, "BugDocumentV1")
                    item = document.get("bug") if isinstance(document, dict) else None
                    if isinstance(item, dict):
                        self.add_record(self.bugs, item, "bug", str(path.relative_to(self.repo)))

        single_files = [
            ("test-catalog.v1.json", "TestSuiteCatalogV1", "catalog"),
            ("release-gates.v1.json", "ReleaseGatesDocumentV1", "gates"),
            ("release-lineage.v1.json", "ReleaseLineageV1", "lineage"),
            ("production-paths.v1.json", "ProductionPathPolicyV1", "path_policy"),
        ]
        for filename, definition, attribute in single_files:
            path = self.quality / filename
            if not path.exists():
                self.error(str(path.relative_to(self.repo)), "required registry is missing")
                continue
            document = self.load_json(path)
            if document is None:
                continue
            self.validate_data_file(path, document, definition)
            if attribute == "catalog" and isinstance(document, dict):
                self.catalog = document
                for item in document.get("suites", []):
                    if isinstance(item, dict):
                        self.add_record(self.suites, item, "suite", str(path.relative_to(self.repo)))
                catalog_id = document.get("catalog_id")
                if isinstance(catalog_id, str):
                    self.add_global_id(catalog_id, str(path.relative_to(self.repo)))
            elif attribute == "gates" and isinstance(document, dict):
                for item in document.get("gates", []):
                    if isinstance(item, dict):
                        self.add_record(self.gates, item, "gate", str(path.relative_to(self.repo)))
            elif attribute == "lineage" and isinstance(document, dict):
                self.lineage = document
            elif attribute == "path_policy" and isinstance(document, dict):
                self.path_policy = document

    def add_global_id(self, record_id: str, source: str) -> None:
        # Stored separately so catalog_id participates in the no-reuse namespace.
        existing = self.global_ids.get(record_id)
        if existing is not None:
            self.error(source, "duplicate global ID {} (already in {})".format(record_id, existing))
        else:
            self.global_ids[record_id] = source

    def add_record(self, target: Dict[str, Dict[str, Any]], item: Dict[str, Any], kind: str, source: str) -> None:
        record_id = item.get("id")
        if not isinstance(record_id, str):
            self.error(source, "{} record has no string id".format(kind))
            return
        self.add_global_id(record_id, source)
        if record_id in target:
            self.error(source, "duplicate {} ID {}".format(kind, record_id))
        else:
            target[record_id] = item

    # ----- cross-file contract -----

    def check_cross_file_contract(self) -> None:
        if not self.catalog or not self.lineage or not self.path_policy:
            return
        self.check_versions()
        self.check_references()
        self.check_lifecycle()
        self.check_replacement_graph()
        self.check_requirement_cycles()
        self.check_test_impact()
        self.check_evidence_boundaries()
        self.check_product_issue_closure()
        self.check_lineage()
        self.check_production_policy_shape()
        self.check_catalog_discovery()
        self.check_fixed_run_evidence_catalog()
        self.check_source_gate_catalog()

    @staticmethod
    def canonical_record_sha256(value: Any) -> str:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def check_fixed_run_evidence_catalog(self) -> None:
        suite = self.suites.get(RUE_SUITE_ID)
        if (
            not isinstance(suite, dict)
            or self.canonical_record_sha256(suite) != RUE_SUITE_SHA256
        ):
            self.error(
                RUE_SUITE_ID,
                "fixed one-suite NODE-RUN-EVIDENCE catalog record drifted",
            )
        rules = [
            rule
            for rule in self.catalog.get("selection_rules", [])
            if isinstance(rule, dict)
            and (
                rule.get("name") == RUE_RULE_NAME
                or RUE_SUITE_ID in rule.get("suite_ids", [])
            )
        ]
        if (
            len(rules) != 1
            or self.canonical_record_sha256(rules[0]) != RUE_RULE_SHA256
        ):
            self.error(
                "quality/test-catalog.v1.json",
                "fixed one-suite NODE-RUN-EVIDENCE selection rule drifted",
            )
        for suite_id, record in self.suites.items():
            if (
                suite_id != RUE_SUITE_ID
                and record.get("retry_policy") != "none"
            ):
                self.error(
                    suite_id,
                    "only SUITE-RUE05A may use the fixed readiness retry",
                )
            if (
                suite_id != RUE_SUITE_ID
                and record.get("status") in {"active", "implemented"}
                and not record.get("gate_ids")
            ):
                self.error(
                    suite_id,
                    "only SUITE-RUE05A may be explicitly gate-free",
                )
        for gate_id, gate in self.gates.items():
            if RUE_SUITE_ID in gate.get("required_suite_ids", []):
                self.error(
                    gate_id,
                    "SUITE-RUE05A must not be promoted into a gate",
                )

    def check_source_gate_catalog(self) -> None:
        expected_cargo_manifests = {
            "desktop/codex-network/Cargo.toml",
            "desktop/gateway/Cargo.toml",
            "desktop/skill-package/Cargo.toml",
            "desktop/src-tauri/Cargo.toml",
        }
        actual_cargo_manifests = {
            path.relative_to(self.repo).as_posix()
            for path in (self.repo / "desktop").glob("**/Cargo.toml")
        }
        if actual_cargo_manifests != expected_cargo_manifests:
            self.error(
                "quality/test-catalog.v1.json",
                "trusted source Cargo manifest inventory drifted",
            )
        rules = [
            rule for rule in self.catalog.get("selection_rules", [])
            if isinstance(rule, dict) and rule.get("name") == SOURCE_RULE_NAME
        ]
        if (
            len(rules) != 1
            or rules[0].get("suite_ids") != list(SOURCE_SUITE_ORDER)
            or rules[0].get("executor_implemented") is not True
        ):
            self.error("quality/test-catalog.v1.json", "trusted source selection drifted")
            return
        gate = self.gates.get(SOURCE_GATE_ID)
        if (
            not isinstance(gate, dict)
            or gate.get("status") != "active"
            or gate.get("profile") != "source"
            or gate.get("required_suite_ids") != list(SOURCE_SUITE_ORDER)
            or gate.get("requires_clean") is not True
            or gate.get("requires_non_shallow") is not True
            or gate.get("release_claim") != "source-green"
        ):
            self.error(SOURCE_GATE_ID, "trusted source gate drifted")
        identity_path = self.repo / SOURCE_IDENTITY_PATH
        try:
            raw = identity_path.read_bytes()
            identities = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.error(SOURCE_IDENTITY_PATH, "invalid source identity inventory: {}".format(exc))
            return
        if (
            not isinstance(identities, dict)
            or set(identities) != {"schema", "suites"}
            or identities.get("schema") != "source-test-identities.v1"
            or not isinstance(identities.get("suites"), dict)
        ):
            self.error(SOURCE_IDENTITY_PATH, "source identity inventory shape drifted")
            return
        digest = hashlib.sha256(raw).hexdigest()
        inventory = identities["suites"]
        seen_keys = set()
        for suite_id in SOURCE_SUITE_ORDER:
            suite = self.suites.get(suite_id)
            if not isinstance(suite, dict):
                self.error(suite_id, "trusted source suite is missing")
                continue
            identity = suite.get("test_identity")
            if (
                suite.get("adapter_protocol") != "source-observation.v1"
                or suite.get("retry_policy") != "none"
                or suite.get("status") != "implemented"
                or suite.get("expected_status") != "PASS"
                or suite.get("gate_ids") != [SOURCE_GATE_ID]
                or not isinstance(suite.get("command_argv"), list)
                or not suite["command_argv"]
                or not isinstance(suite.get("timeout_seconds"), int)
                or not isinstance(identity, dict)
                or identity.get("path") != SOURCE_IDENTITY_PATH
                or identity.get("sha256") != digest
            ):
                self.error(suite_id, "trusted source suite contract drifted")
                continue
            key = identity.get("suite_key")
            if not isinstance(key, str) or key in seen_keys or key not in inventory:
                self.error(suite_id, "source identity key is missing or duplicated")
                continue
            seen_keys.add(key)
            item = inventory[key]
            if not isinstance(item, dict) or set(item) != {
                "discovered_test_ids", "approved_skipped_test_ids",
                "approved_ignored_test_ids", "approved_ignored_tests",
            }:
                self.error(suite_id, "source identity record shape drifted")
                continue
            discovered = item["discovered_test_ids"]
            if (
                not isinstance(discovered, list)
                or not discovered
                or discovered != sorted(discovered, key=lambda value: value.encode("utf-8"))
                or len(discovered) != len(set(discovered))
            ):
                self.error(suite_id, "expected test identities must be nonempty sorted unique")
            for field in ("approved_skipped_test_ids", "approved_ignored_test_ids"):
                values = item[field]
                if (
                    not isinstance(values, list)
                    or values != sorted(values, key=lambda value: value.encode("utf-8"))
                    or len(values) != len(set(values))
                    or any(value not in discovered for value in values)
                ):
                    self.error(suite_id, "{} must be a sorted unique discovered subset".format(field))
            ignored_tests = item["approved_ignored_tests"]
            ignored_ids = item["approved_ignored_test_ids"]
            if (
                not isinstance(ignored_tests, dict)
                or list(ignored_tests) != ignored_ids
            ):
                self.error(suite_id, "approved ignored reason keys must exactly match ignored IDs")
                continue
            for test_id, value in ignored_tests.items():
                if (
                    not isinstance(value, dict)
                    or set(value) != {"boundary", "reason"}
                    or value.get("boundary") not in {
                        "real-machine", "installed", "public-network",
                        "provider", "acceptance",
                    }
                    or not isinstance(value.get("reason"), str)
                    or not value["reason"]
                    or len(value["reason"]) > 512
                    or any(ord(char) < 32 or ord(char) == 127 for char in value["reason"])
                ):
                    self.error(suite_id, "approved ignored reason contract drifted")
        if set(inventory) != seen_keys:
            self.error(SOURCE_IDENTITY_PATH, "source identity inventory has unknown or missing suites")

    def check_versions(self) -> None:
        for kind, records in (("requirement", self.requirements), ("change", self.changes), ("bug", self.bugs), ("gate", self.gates)):
            for record_id, record in records.items():
                if record.get("version") != VERSION:
                    self.error(record_id, "version must be {}".format(VERSION))
        for key in ("version",):
            if self.catalog.get(key) != VERSION:
                self.error("quality/test-catalog.v1.json", "version must be {}".format(VERSION))
            if self.lineage.get(key) != VERSION:
                self.error("quality/release-lineage.v1.json", "version must be {}".format(VERSION))
            if self.path_policy.get(key) != VERSION:
                self.error("quality/production-paths.v1.json", "version must be {}".format(VERSION))

    def check_ref_list(self, source: str, values: Any, target: Dict[str, Any], label: str) -> None:
        if not isinstance(values, list):
            return
        for value in values:
            if value not in target:
                self.error(source, "unknown {} foreign key {}".format(label, value))

    def check_references(self) -> None:
        for record_id, record in self.requirements.items():
            self.check_ref_list(record_id, record.get("depends_on"), self.requirements, "requirement")
        for record_id, record in self.changes.items():
            self.check_ref_list(record_id, record.get("requirement_ids"), self.requirements, "requirement")
            self.check_ref_list(record_id, record.get("bug_ids"), self.bugs, "bug")
            impact = record.get("test_impact", {})
            if isinstance(impact, dict):
                self.check_ref_list(record_id, impact.get("required_suite_ids"), self.suites, "suite")
                self.check_ref_list(record_id, impact.get("required_gate_ids"), self.gates, "gate")
            retirement = record.get("retirement")
            if isinstance(retirement, dict):
                self.check_same_namespace_replacement(record_id, retirement.get("replacement_id"), self.changes)
        for record_id, record in self.bugs.items():
            self.check_ref_list(record_id, record.get("requirement_ids"), self.requirements, "requirement")
            self.check_ref_list(record_id, record.get("change_ids"), self.changes, "change")
            self.check_ref_list(record_id, record.get("expected_suite_ids"), self.suites, "suite")
            self.check_ref_list(record_id, record.get("expected_gate_ids"), self.gates, "gate")
            retirement = record.get("retirement")
            if isinstance(retirement, dict):
                self.check_same_namespace_replacement(record_id, retirement.get("replacement_id"), self.bugs)
        for record_id, record in self.suites.items():
            self.check_ref_list(record_id, record.get("requirement_ids"), self.requirements, "requirement")
            self.check_ref_list(record_id, record.get("bug_ids"), self.bugs, "bug")
            self.check_ref_list(record_id, record.get("gate_ids"), self.gates, "gate")
            replacement = record.get("replacement_id")
            if replacement is not None and replacement not in self.suites:
                self.error(record_id, "unknown suite replacement {}".format(replacement))
        for record_id, record in self.gates.items():
            self.check_ref_list(record_id, record.get("required_suite_ids"), self.suites, "suite")
            self.check_ref_list(record_id, record.get("required_requirement_ids"), self.requirements, "requirement")
            replacement = record.get("replacement_id")
            if replacement is not None and replacement not in self.gates:
                self.error(record_id, "unknown gate replacement {}".format(replacement))
        for index, rule in enumerate(self.catalog.get("selection_rules", [])):
            if isinstance(rule, dict):
                self.check_ref_list("selection_rules[{}]".format(index), rule.get("suite_ids"), self.suites, "suite")
        for index, path_rule in enumerate(self.path_policy.get("paths", [])):
            if isinstance(path_rule, dict):
                source = "production-paths[{}]".format(index)
                self.check_ref_list(source, path_rule.get("requirement_ids"), self.requirements, "requirement")
                self.check_ref_list(source, path_rule.get("required_suite_ids"), self.suites, "suite")
                self.check_ref_list(source, path_rule.get("required_gate_ids"), self.gates, "gate")

    def check_same_namespace_replacement(self, source: str, replacement: Any, target: Dict[str, Any]) -> None:
        if replacement not in target:
            self.error(source, "replacement {} is missing".format(replacement))
        if replacement == source:
            self.error(source, "replacement cannot point to itself")

    def check_lifecycle(self) -> None:
        for kind, records in (("requirement", self.requirements), ("change", self.changes), ("bug", self.bugs)):
            for record_id, record in records.items():
                status = record.get("status")
                retirement = record.get("retirement")
                if status != "retired" and retirement is not None:
                    self.error(record_id, "active record cannot have a retirement tombstone")
                if status == "retired" and not isinstance(retirement, dict):
                    self.error(record_id, "retired record requires a tombstone with replacement")
                if kind == "bug":
                    resolution = record.get("resolution_state")
                    if status == "retired":
                        if resolution != "retired":
                            self.error(record_id, "retired bug resolution_state must be retired")
                    elif resolution not in {"open-not-fixed", "source-fixed-product-pending"}:
                        self.error(
                            record_id,
                            "active bug resolution_state must be open-not-fixed or source-fixed-product-pending",
                        )
                    elif (
                        resolution == "source-fixed-product-pending"
                        and record.get("reproduction_state") != "source-reproduced"
                    ):
                        self.error(
                            record_id,
                            "source-fixed-product-pending bug requires source-reproduced evidence",
                        )
                if kind == "change" and record.get("does_not_claim_fix") is not True:
                    self.error(record_id, "change must explicitly set does_not_claim_fix=true")
        for record_id, record in self.suites.items():
            status = record.get("status")
            managed_statuses = {"manual", "legacy", "quarantine", "not-yet-automatable", "retired"}
            retirement = record.get("retirement")
            if status != "retired" and retirement is not None:
                self.error(record_id, "active suite cannot have a retirement tombstone")
            if status == "retired" and not isinstance(retirement, dict):
                self.error(record_id, "retired suite requires a tombstone with replacement")
            if status in managed_statuses:
                for field in ("owner", "reason", "expiry", "replacement_id"):
                    if not record.get(field):
                        self.error(record_id, "{} suite requires {}".format(status, field))
                if record.get("expected_status") == "PASS":
                    self.error(record_id, "{} suite cannot be expected PASS".format(status))
            if status in {"implemented", "active"} and record.get("expected_status") in {"IGNORED", "SKIPPED"}:
                self.error(record_id, "active/implemented suite cannot silently expect {}".format(record.get("expected_status")))
        for record_id, record in self.gates.items():
            status = record.get("status")
            retirement = record.get("retirement")
            if status != "retired" and retirement is not None:
                self.error(record_id, "active gate cannot have a retirement tombstone")
            if status == "retired" and not isinstance(retirement, dict):
                self.error(record_id, "retired gate requires a tombstone with replacement")
            if status == "legacy-known-unreliable":
                for field in ("reason", "expiry", "replacement_id"):
                    if not record.get(field):
                        self.error(record_id, "legacy gate requires {}".format(field))
                if record.get("release_claim") != "legacy-known-unreliable":
                    self.error(record_id, "legacy gate must use legacy-known-unreliable claim")
            if record.get("profile") == "product" and record.get("release_claim") != "product-open-not-run":
                self.error(record_id, "product gate must remain product-open-not-run")
            expected_base = {
                "metadata": "none",
                "impact-pr": "target-ref-merge-base",
                "impact-release": "previous-release-peeled",
                "source": "target-ref-merge-base",
                "product": "none",
                "legacy": "none",
            }.get(record.get("profile"))
            if record.get("base_policy") != expected_base:
                self.error(record_id, "base_policy must be {} for profile {}".format(expected_base, record.get("profile")))

    def check_replacement_graph(self) -> None:
        namespaces = (
            ("requirement", self.requirements),
            ("change", self.changes),
            ("bug", self.bugs),
            ("suite", self.suites),
            ("gate", self.gates),
        )
        for namespace, records in namespaces:
            edges: Dict[str, str] = {}
            for record_id, record in records.items():
                retirement = record.get("retirement")
                tombstone_target = retirement.get("replacement_id") if isinstance(retirement, dict) else None
                direct_target = record.get("replacement_id")
                if tombstone_target is not None and direct_target is not None and tombstone_target != direct_target:
                    self.error(record_id, "replacement graph has conflicting tombstone/direct replacement")
                replacement = tombstone_target if tombstone_target is not None else direct_target
                if replacement is None:
                    continue
                if replacement == record_id:
                    self.error(record_id, "replacement cannot point to itself")
                if replacement not in records:
                    self.error(record_id, "replacement {} is outside {} namespace or missing".format(replacement, namespace))
                elif records[replacement].get("status") == "retired":
                    self.error(record_id, "replacement {} is retired".format(replacement))
                edges[record_id] = replacement

            visiting: set = set()
            visited: set = set()

            def visit(record_id: str, stack: List[str]) -> None:
                if record_id in visited:
                    return
                if record_id in visiting:
                    self.error(record_id, "replacement graph cycle: {}".format(" -> ".join(stack + [record_id])))
                    return
                visiting.add(record_id)
                replacement = edges.get(record_id)
                if replacement is not None:
                    visit(replacement, stack + [record_id])
                visiting.remove(record_id)
                visited.add(record_id)

            for record_id in edges:
                visit(record_id, [])

    def check_requirement_cycles(self) -> None:
        visiting: Dict[str, bool] = {}
        visited: Dict[str, bool] = {}

        def visit(record_id: str, stack: List[str]) -> None:
            if visited.get(record_id):
                return
            if visiting.get(record_id):
                self.error(record_id, "requirement dependency cycle: {}".format(" -> ".join(stack + [record_id])))
                return
            visiting[record_id] = True
            for dependency in self.requirements.get(record_id, {}).get("depends_on", []):
                if dependency in self.requirements:
                    visit(dependency, stack + [record_id])
            visiting.pop(record_id, None)
            visited[record_id] = True

        for record_id in self.requirements:
            visit(record_id, [])

    def check_test_impact(self) -> None:
        high_risk = {"P0", "P1", "security", "migration", "release-gate"}
        allowed_kinds = {"add", "update", "existing-sufficient", "manual-evidence", "not-yet-automatable"}
        for record_id, record in self.changes.items():
            impact = record.get("test_impact")
            if not isinstance(impact, dict):
                continue
            kind = impact.get("kind")
            suite_ids = impact.get("required_suite_ids", [])
            gate_ids = impact.get("required_gate_ids", [])
            risk_classes = set(impact.get("risk_classes", []))
            if kind not in allowed_kinds:
                self.error(record_id, "test-impact kind must be one of the frozen five states")
            if kind in allowed_kinds and not suite_ids:
                self.error(record_id, "test-impact must name at least one suite")
            if kind in allowed_kinds and not gate_ids:
                self.error(record_id, "test-impact must name at least one gate")
            if kind in {"manual-evidence", "not-yet-automatable"} and risk_classes.intersection(high_risk):
                self.error(record_id, "high-risk change cannot use manual-evidence/not-yet-automatable")
            related_severity = {self.bugs[bug_id].get("severity") for bug_id in record.get("bug_ids", []) if bug_id in self.bugs}
            if related_severity.intersection({"P0", "P1"}) and kind in {"manual-evidence", "not-yet-automatable"}:
                self.error(record_id, "P0/P1-related change cannot use manual-evidence/not-yet-automatable")

    def check_test_result_semantics(self, result: Any, source: str = "test-result.v1") -> None:
        if not isinstance(result, dict):
            self.error(source, "test result must be an object")
            return
        required = ("kind", "outcome", "classification", "gate_decision", "reason_code", "runner_exit", "attempt_records")
        missing = [field for field in required if field not in result]
        if missing:
            self.error(source, "test result is missing dimensions: {}".format(", ".join(missing)))
            return
        outcome = result.get("outcome")
        classification = result.get("classification")
        gate_decision = result.get("gate_decision")
        runner_exit = result.get("runner_exit")
        if not self.is_json_integer(runner_exit) or not 0 <= runner_exit <= 255:
            self.error(source, "runner_exit must be an integer from 0 to 255")
            return
        if gate_decision == "PASS" and not (outcome == "PASS" and classification == "NONE" and runner_exit == 0):
            self.error(source, "gate PASS requires outcome PASS, classification NONE, and runner_exit=0")
        if outcome == "PASS":
            if classification != "NONE":
                self.error(source, "PASS cannot carry a non-NONE classification")
            if runner_exit != 0:
                self.error(source, "PASS requires runner_exit=0")
            if gate_decision != "PASS":
                self.error(source, "outcome PASS must have gate_decision PASS")
        else:
            if runner_exit == 0:
                self.error(source, "non-PASS outcome requires a nonzero runner_exit")
            if gate_decision == "PASS":
                self.error(source, "non-PASS outcome cannot have gate_decision PASS")
        if classification in {"FLAKY", "QUARANTINED"}:
            if outcome == "PASS":
                self.error(source, "FLAKY/QUARANTINED cannot be PASS")
            if gate_decision != "BLOCKED":
                self.error(source, "FLAKY/QUARANTINED requires gate_decision BLOCKED")
        if outcome in {"IGNORED", "SKIPPED", "ENV-BLOCKED", "NEEDS-REAL-MACHINE", "NOT-RUN"} and gate_decision != "BLOCKED":
            self.error(source, "environment/ignored/not-run outcomes require gate_decision BLOCKED")
        if classification == "READINESS_TIMEOUT" and gate_decision != "BLOCKED":
            self.error(source, "READINESS_TIMEOUT requires gate_decision BLOCKED")

    def check_evidence_boundaries(self) -> None:
        for kind, records in (("requirement", self.requirements), ("change", self.changes), ("bug", self.bugs)):
            for record_id, record in records.items():
                boundary = record.get("evidence_boundary", {})
                allowed = set(boundary.get("allowed_layers", [])) if isinstance(boundary, dict) else set()
                excluded = set(boundary.get("excluded_layers", [])) if isinstance(boundary, dict) else set()
                if not allowed.intersection(LAYERS):
                    self.error(record_id, "evidence boundary has no allowed layer")
                if allowed.intersection(excluded):
                    self.error(record_id, "evidence boundary allowed/excluded layers overlap")
                if kind in {"change", "bug"} and "source-test" not in allowed:
                    self.error(record_id, "change/bug records must include source-test evidence boundary")
                if kind == "bug" and record.get("resolution_state") not in {
                    "open-not-fixed",
                    "source-fixed-product-pending",
                    "retired",
                }:
                    self.error(
                        record_id,
                        "bug resolution state is outside open-not-fixed/source-fixed-product-pending/retired",
                    )
                if kind == "bug":
                    facts = record.get("confirmed_facts")
                    if record.get("claim_state") == "confirmed" and not facts:
                        self.error(record_id, "confirmed bug claim requires confirmed_facts evidence")
                    for index, fact in enumerate(facts if isinstance(facts, list) else []):
                        if not isinstance(fact, dict) or fact.get("verification_status") != "confirmed" or not fact.get("evidence_ref"):
                            self.error(record_id, "confirmed_facts[{}] must carry confirmed evidence".format(index))
                    for index, hypothesis in enumerate(record.get("hypotheses", []) if isinstance(record.get("hypotheses"), list) else []):
                        if isinstance(hypothesis, dict) and hypothesis.get("verification_status") == "confirmed":
                            self.error(record_id, "hypotheses[{}] cannot be confirmed evidence".format(index))

    def check_product_issue_closure(self) -> None:
        for bug_id in sorted(PRODUCT_BUG_IDS):
            bug = self.bugs.get(bug_id)
            if bug is None:
                self.error("product-registry", "missing required product bug {}".format(bug_id))
                continue
            if bug.get("status") != "active":
                self.error(bug_id, "product bug must remain active")
            if bug.get("resolution_state") not in {
                "open-not-fixed",
                "source-fixed-product-pending",
            }:
                self.error(
                    bug_id,
                    "active product bug resolution_state must be open-not-fixed or source-fixed-product-pending",
                )
            if len(bug.get("change_ids", [])) != 1:
                self.error(bug_id, "product bug must have exactly one independent CHG")
            else:
                change_id = bug["change_ids"][0]
                if change_id not in PRODUCT_CHANGES:
                    self.error(bug_id, "product bug must point to a product CHG")
                change = self.changes.get(change_id)
                if change is not None and change.get("bug_ids") != [bug_id]:
                    self.error(bug_id, "product CHG must point only to its product BUG")
            if not set(bug.get("requirement_ids", [])).intersection(PRODUCT_REQUIREMENTS):
                self.error(bug_id, "product bug needs an independent product REQ")
            if not any(suite_id.startswith("SUITE-PRODUCT-") for suite_id in bug.get("expected_suite_ids", [])):
                self.error(bug_id, "product bug needs an independent future product suite")
            if not any(gate_id in PRODUCT_GATES for gate_id in bug.get("expected_gate_ids", [])):
                self.error(bug_id, "product bug needs an independent product gate")
        for record_id, record in self.changes.items():
            if record_id in PRODUCT_CHANGES and not record.get("does_not_claim_fix"):
                self.error(record_id, "product CHG must not claim a fix")

    # ----- lineage and Git impact -----

    def git(self, args: Sequence[str], allow_failure: bool = False) -> Tuple[int, str, str]:
        try:
            result = subprocess.run(
                ["git"] + list(args),
                cwd=str(self.repo),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as exc:
            self.error("git", "cannot execute read-only git command: {}".format(exc))
            return 127, "", str(exc)
        if result.returncode != 0 and not allow_failure:
            self.error("git " + " ".join(args), result.stderr.strip() or "command failed")
        # Preserve the two-column leading status in porcelain output; only
        # remove trailing line breaks so a modified path is not truncated.
        return result.returncode, result.stdout.rstrip("\n"), result.stderr.strip()

    def check_lineage(self) -> None:
        lineage = self.lineage
        for field in ("audit_baseline_sha",):
            if not SHA_RE.fullmatch(str(lineage.get(field, ""))):
                self.error("lineage." + field, "must be a 40-character lowercase Git SHA")
        previous = lineage.get("previous_release", {})
        if not isinstance(previous, dict):
            return
        tag = previous.get("tag", "")
        if not re.fullmatch(r"^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$", str(tag)):
            self.error("lineage.previous_release.tag", "invalid release tag")
        for field in ("tag_object_sha", "peeled_sha"):
            if not SHA_RE.fullmatch(str(previous.get(field, ""))):
                self.error("lineage.previous_release." + field, "must be a 40-character lowercase Git SHA")
        if lineage.get("audit_baseline_sha") == previous.get("peeled_sha"):
            self.error("lineage", "audit baseline cannot be the release impact base")
        tag_object = str(previous.get("tag_object_sha", ""))
        peeled = str(previous.get("peeled_sha", ""))
        rc, object_type, _ = self.git(["cat-file", "-t", tag_object], allow_failure=True)
        if rc != 0 or object_type != "tag":
            self.error("lineage.previous_release.tag_object_sha", "must resolve to an annotated tag object")
        rc, tag_ref_object, _ = self.git(["rev-parse", "refs/tags/" + str(tag)], allow_failure=True)
        if rc != 0 or tag_ref_object != tag_object:
            self.error("lineage.previous_release.tag_object_sha", "refs/tags/{} does not match tag_object_sha".format(tag))
        rc, resolved_tag, _ = self.git(["rev-parse", "{}^{{}}".format(tag)], allow_failure=True)
        if rc != 0 or resolved_tag != peeled:
            self.error("lineage.previous_release", "tag peeled commit does not match the live Git tag")
        rc, _, _ = self.git(["cat-file", "-e", peeled], allow_failure=True)
        if rc != 0:
            self.error("lineage.previous_release.peeled_sha", "peeled commit is missing")
        rc, _, _ = self.git(["cat-file", "-e", lineage.get("audit_baseline_sha", "")], allow_failure=True)
        if rc != 0:
            self.error("lineage.audit_baseline_sha", "audit baseline object is missing")

    def discover_catalog_paths(self) -> set:
        discovered = set()
        for path in sorted(self.repo.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(self.repo)
            if any(part in {".git", "target"} for part in relative.parts):
                continue
            name = path.name
            if (name.startswith("test_") and path.suffix in {".py", ".sh"}) or name.endswith(".test.mjs"):
                discovered.add(relative.as_posix())
            elif name == "Cargo.toml" and relative.parts and relative.parts[0] == "desktop":
                discovered.add(relative.as_posix())
        return discovered

    def check_catalog_discovery(self) -> None:
        declared = set(self.catalog.get("discovery_paths", []))
        discovered = self.discover_catalog_paths()
        self.check_discovery_set(declared, discovered)
        required_categories = {"runner", "artifact", "host", "release"}
        categories = {suite.get("category") for suite in self.suites.values()}
        for category in sorted(required_categories - categories):
            self.error("test-catalog.suites", "required suite category is missing: {}".format(category))
        for suite_id, suite in self.suites.items():
            if not isinstance(suite.get("entrypoint"), str) or not suite.get("entrypoint"):
                self.error(suite_id, "suite entrypoint must be non-empty")
            for source_path in suite.get("source_paths", []):
                if not isinstance(source_path, str) or source_path.startswith("/") or ".." in Path(source_path).parts:
                    self.error(suite_id, "suite source path must be a relative path")
                    continue
                if not (self.repo / source_path).exists():
                    self.error(suite_id, "suite source path does not exist: {}".format(source_path))

    def check_discovery_set(self, declared: set, discovered: set) -> None:
        for path in sorted(discovered - declared):
            self.error("test-catalog.discovery_paths", "discovered entrypoint is not registered: {}".format(path))
        for path in sorted(declared - discovered):
            self.error("test-catalog.discovery_paths", "registered discovery path is not discovered: {}".format(path))

    def check_production_policy_shape(self) -> None:
        paths = self.path_policy.get("paths", [])
        seen: set = set()
        for index, item in enumerate(paths):
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            if path in seen:
                self.error("production-paths[{}]".format(index), "duplicate policy path")
            seen.add(path)
            if isinstance(path, str) and path.startswith("/"):
                self.error("production-paths[{}]".format(index), "policy path must be relative")
        if self.path_policy.get("unknown_path_policy") != "fail-closed":
            self.error("production-paths", "unknown path policy must be fail-closed")
        if self.path_policy.get("rename_delete_policy") != "fail-closed":
            self.error("production-paths", "rename/delete policy must be fail-closed")

    def check_impact(self, profile: str, target_ref: Optional[str]) -> None:
        gate_profile = self.gate_for_profile(profile)
        if gate_profile is None:
            return
        if profile == "impact-pr":
            if not target_ref:
                self.error("cli", "impact-pr requires an explicit --target-ref")
                return
            rc, target_sha, _ = self.git(["rev-parse", "--verify", "{}^{{commit}}".format(target_ref)], allow_failure=True)
            if rc != 0 or not target_sha:
                self.error("cli", "target ref does not resolve: {}".format(target_ref))
                return
            rc, head, _ = self.git(["rev-parse", "HEAD"])
            if rc != 0:
                return
            rc, merge_base, _ = self.git(["merge-base", target_sha, head], allow_failure=True)
            if rc != 0 or not merge_base:
                self.error("impact-pr", "target ref and HEAD have no merge-base")
                return
            if self.git(["merge-base", "--is-ancestor", merge_base, target_sha], allow_failure=True)[0] != 0:
                self.error("impact-pr", "merge-base is not an ancestor of target ref")
            if self.git(["merge-base", "--is-ancestor", merge_base, head], allow_failure=True)[0] != 0:
                self.error("impact-pr", "merge-base is not an ancestor of HEAD")
            changed = self.diff_paths(merge_base, head)
            changed.extend(self.status_paths())
            self.check_changed_paths(changed, "impact-pr")
        else:
            rc, status, _ = self.git(["status", "--porcelain=v1"], allow_failure=True)
            if rc != 0:
                return
            if status:
                self.error("impact-release", "worktree must be clean")
            rc, shallow, _ = self.git(["rev-parse", "--is-shallow-repository"], allow_failure=True)
            if rc == 0 and shallow == "true":
                self.error("impact-release", "shallow repository is not accepted")
            previous = self.lineage.get("previous_release", {})
            base = previous.get("peeled_sha") if isinstance(previous, dict) else None
            rc, head, _ = self.git(["rev-parse", "HEAD"], allow_failure=True)
            if not base or rc != 0:
                return
            if self.git(["merge-base", "--is-ancestor", str(base), head], allow_failure=True)[0] != 0:
                self.error("impact-release", "previous release peeled commit is not an ancestor of HEAD")
            changed = self.diff_paths(str(base), head)
            self.check_changed_paths(changed, "impact-release")

    def gate_for_profile(self, profile: str) -> Optional[Dict[str, Any]]:
        candidates = [gate for gate in self.gates.values() if gate.get("profile") == profile]
        if not candidates:
            self.error("gates", "no gate registered for profile {}".format(profile))
            return None
        if len(candidates) != 1:
            self.error("gates", "profile {} must have exactly one gate".format(profile))
        gate = candidates[0]
        if gate.get("status") != "active":
            self.error(gate.get("id", "gates"), "selected gate is not active")
        if profile == "impact-release" and gate.get("requires_clean") is not True:
            self.error(gate.get("id", "gates"), "impact-release gate must require clean")
        return gate

    def diff_paths(self, base: str, head: str) -> List[Tuple[str, str]]:
        rc, output, _ = self.git(["diff", "--name-status", base + ".." + head], allow_failure=True)
        if rc != 0:
            self.error("git diff", "could not inventory {}..{}".format(base, head))
            return []
        result: List[Tuple[str, str]] = []
        for line in output.splitlines():
            if not line:
                continue
            fields = line.split("\t")
            status = fields[0]
            if status.startswith("R") or status.startswith("C"):
                if len(fields) >= 3:
                    result.append((status, fields[1]))
                    result.append((status, fields[2]))
                continue
            if len(fields) >= 2:
                result.append((status, fields[1]))
        return result

    def status_paths(self) -> List[Tuple[str, str]]:
        rc, output, _ = self.git(["status", "--porcelain=v1"], allow_failure=True)
        if rc != 0:
            return []
        result: List[Tuple[str, str]] = []
        for line in output.splitlines():
            if len(line) < 3:
                continue
            status = line[:2].strip() or line[:2]
            path = line[3:]
            if " -> " in path:
                old_path, new_path = path.split(" -> ", 1)
                result.extend([(status or "R", old_path), (status or "R", new_path)])
            else:
                result.append((status, path))
        return result

    @staticmethod
    def path_matches(pattern: str, path: str) -> bool:
        if pattern.endswith("/"):
            prefix = pattern.rstrip("/")
            return path == prefix or path.startswith(pattern)
        return path == pattern

    def check_changed_paths(self, changed: Iterable[Tuple[str, str]], profile: str) -> None:
        policy_paths = [item for item in self.path_policy.get("paths", []) if isinstance(item, dict)]
        exemptions = [item for item in self.path_policy.get("narrative_exemptions", []) if isinstance(item, dict)]
        changes = list(self.changes.values())
        seen: set = set()
        for status, path in changed:
            if not path or path in seen:
                continue
            seen.add(path)
            if status.startswith("D") or status.startswith("R") or status.startswith("C"):
                self.error(profile, "rename/delete/copy status is fail-closed for {} ({})".format(path, status))
            matching = [item for item in policy_paths if self.path_matches(str(item.get("path", "")), path)]
            if matching:
                policy = sorted(matching, key=lambda item: len(str(item.get("path", ""))), reverse=True)[0]
                active_matches = [
                    change for change in changes
                    if change.get("status") == "active"
                    and any(self.path_matches(str(path_pattern), path) for path_pattern in change.get("changed_paths", []))
                ]
                if not active_matches:
                    self.error(path, "production path has no active matching ChangeRecordV1")
                    continue
                required_suites = set(policy.get("required_suite_ids", []))
                required_gates = set(policy.get("required_gate_ids", []))
                for change in active_matches:
                    change_id = str(change.get("id", "change"))
                    impact = change.get("test_impact", {})
                    declared_suites = set(impact.get("required_suite_ids", [])) if isinstance(impact, dict) else set()
                    declared_gates = set(impact.get("required_gate_ids", [])) if isinstance(impact, dict) else set()
                    missing_suites = sorted(required_suites - declared_suites)
                    missing_gates = sorted(required_gates - declared_gates)
                    if missing_suites:
                        self.error(path, "active change {} misses policy required suites: {}".format(change_id, ", ".join(missing_suites)))
                    if missing_gates:
                        self.error(path, "active change {} misses policy required gates: {}".format(change_id, ", ".join(missing_gates)))
                continue
            if any(self.path_matches(str(item.get("path", "")), path) for item in exemptions):
                continue
            self.error(path, "unknown production path; no policy or narrative exemption")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate CSSwitch quality metadata and fixed-base impact.")
    parser.add_argument("profile", choices=("metadata", "impact-pr", "impact-release"))
    parser.add_argument("--repo", default=str(ROOT), help=argparse.SUPPRESS)
    parser.add_argument("--target-ref", help="required explicit PR target ref for impact-pr")
    args = parser.parse_args(argv)
    if args.profile == "impact-pr" and not args.target_ref:
        parser.error("impact-pr requires --target-ref; arbitrary --base is not accepted")
    if args.profile != "impact-pr" and args.target_ref:
        parser.error("--target-ref is only accepted by impact-pr")
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    validator = Validator(Path(args.repo))
    ok = validator.run(args.profile, args.target_ref)
    if ok:
        print("QUALITY profile={} status=PASS evidence=source-test".format(args.profile))
        return 0
    print("QUALITY profile={} status=FAIL evidence=source-test".format(args.profile))
    for error in validator.errors:
        print("ERROR {}".format(error))
    return 1


if __name__ == "__main__":
    sys.exit(main())
