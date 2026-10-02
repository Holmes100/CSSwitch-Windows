"""Fixed catalog-to-process planning for the source gate."""
from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from test.quality.run_evidence.contracts import ContractViolation
from test.quality.run_evidence.manifest_contracts import canonical_json_bytes
from test.quality.source_gate.contracts import validate_source_catalog


_PLACEHOLDERS = {
    "{PYTHON}": "PYTHON",
    "{BASH}": "BASH",
    "{NODE}": "NODE",
    "{CARGO}": "CARGO",
}
_REQUIRED_TOOLS = frozenset(("PYTHON", "BASH", "NODE", "CARGO", "RUSTC", "GIT"))
_BASE_SYSTEM_PATHS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
_LOOPBACK_SUITE = "SUITE-PY-LOOPBACK"
_IGNORED_BOUNDARIES = frozenset((
    "real-machine", "installed", "public-network", "provider", "acceptance",
))


def _fail(message: str) -> None:
    raise ContractViolation("ADAPTER_MALFORMED", message)


def _safe_root(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value == "/"
        or value.endswith("/")
        or "//" in value
    ):
        _fail("unsafe source plan root")
    return value


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _load_inventory(raw: bytes) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or raw.startswith(b"\xef\xbb\xbf"):
        _fail("source inventory bytes")

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                _fail("duplicate source inventory key")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(value),
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _fail("source inventory JSON")
    if not isinstance(value, Mapping):
        _fail("source inventory shape")
    return value


def _safe_tool(path: Any) -> bool:
    return (
        isinstance(path, str)
        and path.startswith("/")
        and path != "/"
        and not path.endswith("/")
        and "//" not in path
        and ":" not in path
        and all(
            part not in {"", ".", ".."}
            for part in path.split("/")[1:]
        )
        and not any(ord(char) < 32 or ord(char) == 127 for char in path)
    )


@dataclass(frozen=True)
class SourceSuitePlan:
    suite: Mapping[str, Any]
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    expected_test_ids: tuple[str, ...]
    approved_skipped_test_ids: tuple[str, ...]
    approved_ignored_test_ids: tuple[str, ...]
    approved_ignored_tests: Mapping[str, Mapping[str, str]]
    command_argv_sha256: str
    environment_sha256: str
    tool_identity_sha256: str
    driver_config: Mapping[str, Any] | None = None

    def adapter_config(self, run_id: str) -> dict[str, Any]:
        return {
            "schema": "source-adapter-config.v1",
            "run_id": run_id,
            "suite_id": self.suite["id"],
            "entrypoint_id": self.suite["entrypoint_id"],
            "kind": self.suite["kind"],
            "argv": list(self.argv),
            "environment": dict(self.environment),
            "timeout_seconds": self.suite["timeout_seconds"],
            "output_limit_bytes": 64 * 1024 * 1024,
            "expected_test_ids": list(self.expected_test_ids),
            "approved_skipped_test_ids": list(
                self.approved_skipped_test_ids,
            ),
            "approved_ignored_test_ids": list(
                self.approved_ignored_test_ids,
            ),
            "approved_ignored_tests": {
                test_id: dict(value)
                for test_id, value in self.approved_ignored_tests.items()
            },
            "command_argv_sha256": self.command_argv_sha256,
            "environment_sha256": self.environment_sha256,
            "tool_identity_sha256": self.tool_identity_sha256,
            "driver_config": (
                None
                if self.driver_config is None
                else dict(self.driver_config)
            ),
        }


def build_source_plans(
    catalog: Mapping[str, Any],
    gates: Mapping[str, Any],
    inventory_raw: bytes,
    *,
    tools: Mapping[str, str],
    tool_identity_sha256: str,
    run_home: str,
    run_tmp: str,
    offline_cargo_home: str,
    rustup_home: str,
    gateway_target: str,
    python_dependency_root: str | None = None,
) -> tuple[SourceSuitePlan, ...]:
    suites = validate_source_catalog(catalog, gates)
    inventory = _load_inventory(inventory_raw)
    inventory_sha256 = hashlib.sha256(inventory_raw).hexdigest()
    roots = tuple(map(_safe_root, (
        run_home, run_tmp, offline_cargo_home, rustup_home, gateway_target,
    )))
    if (
        set(tools) != _REQUIRED_TOOLS
        or any(not _safe_tool(path) for path in tools.values())
        or not isinstance(tool_identity_sha256, str)
        or len(tool_identity_sha256) != 64
        or inventory.get("schema") != "source-test-identities.v1"
        or not isinstance(inventory.get("suites"), Mapping)
    ):
        _fail("source plan inputs")
    path_parts = []
    for name in ("PYTHON", "BASH", "NODE", "CARGO", "RUSTC", "GIT"):
        parent = os.path.dirname(tools[name])
        if parent not in path_parts:
            path_parts.append(parent)
    for parent in _BASE_SYSTEM_PATHS:
        if parent not in path_parts:
            path_parts.append(parent)
    base_environment = {
        "HOME": roots[0],
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": ":".join(path_parts),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": roots[1],
    }
    if python_dependency_root is not None:
        base_environment["PYTHONPATH"] = _safe_root(python_dependency_root)
    plans: list[SourceSuitePlan] = []
    inventory_keys: set[str] = set()
    for suite in suites:
        identity = suite["test_identity"]
        if (
            identity.get("path")
            != "test/quality/fixtures/source_gate/expected_test_ids.v1.json"
            or identity.get("sha256") != inventory_sha256
            or not isinstance(identity.get("suite_key"), str)
        ):
            _fail("source inventory binding")
        key = identity["suite_key"]
        inventory_keys.add(key)
        record = inventory["suites"].get(key)
        if not isinstance(record, Mapping) or set(record) != {
            "discovered_test_ids", "approved_skipped_test_ids",
            "approved_ignored_test_ids", "approved_ignored_tests",
        }:
            _fail("source inventory record")
        expected = record["discovered_test_ids"]
        skipped = record["approved_skipped_test_ids"]
        ignored = record["approved_ignored_test_ids"]
        ignored_tests = record["approved_ignored_tests"]
        for values in (expected, skipped, ignored):
            if (
                not isinstance(values, list)
                or (values is expected and not values)
                or not all(isinstance(item, str) and item for item in values)
                or values
                != sorted(values, key=lambda item: item.encode("utf-8"))
                or len(values) != len(set(values))
            ):
                _fail("source inventory identities")
        if not set(skipped).issubset(expected) or not set(ignored).issubset(expected):
            _fail("source inventory exclusions")
        if (
            not isinstance(ignored_tests, Mapping)
            or list(ignored_tests) != ignored
        ):
            _fail("source inventory ignored reasons")
        for test_id, value in ignored_tests.items():
            if (
                not isinstance(value, Mapping)
                or set(value) != {"boundary", "reason"}
                or value.get("boundary") not in _IGNORED_BOUNDARIES
                or not isinstance(value.get("reason"), str)
                or not value["reason"]
                or len(value["reason"]) > 512
                or any(ord(char) < 32 or ord(char) == 127 for char in value["reason"])
            ):
                _fail("source inventory ignored reason")
        argv = []
        for item in suite["command_argv"]:
            if item in _PLACEHOLDERS:
                item = tools[_PLACEHOLDERS[item]]
            if "{" in item or "}" in item:
                _fail("source command placeholder")
            argv.append(item)
        if not argv or not argv[0].startswith("/"):
            _fail("source command executable")
        environment = dict(base_environment)
        if (
            suite["kind"] == "rust"
            or suite["id"] == _LOOPBACK_SUITE
        ):
            environment.update({
                "CARGO_HOME": roots[2],
                "CARGO_NET_OFFLINE": "true",
                "RUSTC": tools["RUSTC"],
                "RUSTUP_HOME": roots[3],
            })
        allowed = suite["environment_allowlist"]
        if allowed == ["CSSWITCH_GATEWAY_BIN"]:
            environment["CSSWITCH_GATEWAY_BIN"] = os.path.join(
                roots[4],
                "debug",
                "csswitch-gateway",
            )
        elif allowed != []:
            _fail("source environment allowlist")
        driver_config = None
        command_binding: Any = argv
        if suite["id"] == _LOOPBACK_SUITE:
            driver_config = {
                "schema": "gateway-driver-config.v1",
                "target_dir": roots[4],
                "cargo_path": tools["CARGO"],
                "python_path": tools["PYTHON"],
                "environment": dict(environment),
            }
            command_binding = {
                "driver_argv": argv,
                "driver_config": driver_config,
            }
        plans.append(SourceSuitePlan(
            suite=suite,
            argv=tuple(argv),
            environment=environment,
            expected_test_ids=tuple(expected),
            approved_skipped_test_ids=tuple(skipped),
            approved_ignored_test_ids=tuple(ignored),
            approved_ignored_tests={
                test_id: dict(ignored_tests[test_id])
                for test_id in ignored
            },
            command_argv_sha256=_sha(command_binding),
            environment_sha256=_sha(environment),
            tool_identity_sha256=tool_identity_sha256,
            driver_config=driver_config,
        ))
    if inventory_keys != set(inventory["suites"]):
        _fail("source inventory suite drift")
    return tuple(plans)
