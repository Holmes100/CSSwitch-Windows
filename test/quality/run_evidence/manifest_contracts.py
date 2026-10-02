"""Pure RUE-02 manifest contracts; callers supply every artifact as bytes."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import unicodedata
from collections.abc import Callable, Mapping
from typing import Any

from .contracts import ContractViolation, _is_int, validate_result


RUN_RE = re.compile(r"^[0-9a-f]{32}(?![\s\S])")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}(?![\s\S])")
SHA_RE = re.compile(r"^[0-9a-f]{64}(?![\s\S])")
SUITE_RE = re.compile(r"^SUITE-[A-Z0-9][A-Z0-9-]{0,31}(?![\s\S])")
ENTRY_RE = re.compile(r"^ENTRY-[A-Z0-9][A-Z0-9-]{0,31}(?![\s\S])")
SEMVER_RE = re.compile(r"^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?![\s\S])")

RUN_FIELDS = frozenset(("schema", "run_id", "profile", "head_sha", "comparison_base", "source_snapshot_manifest", "change_set", "invocation_argv", "expected_suites", "input_digests", "platform", "started_at"))
SNAPSHOT_FIELDS = frozenset(("schema", "run_id", "head_sha", "snapshot_mode", "entry_count", "total_bytes", "entries"))
CHANGE_FIELDS = frozenset(("schema", "head_sha", "raw_status_sha256", "created_at", "entries"))
EVIDENCE_FIELDS = frozenset(("schema", "run_id", "run_manifest", "test_results"))
SOURCE_EVIDENCE_FIELDS = EVIDENCE_FIELDS | frozenset(("source_observations",))
SEAL_FIELDS = frozenset(("schema", "run_id", "run_manifest", "source_snapshot_manifest", "evidence_manifest", "input_digest_set_sha256", "aggregate_decision", "runner_exit", "completed_at"))
FAILURE_FIELDS = frozenset(("schema", "run_id", "stage", "reason_code", "run_manifest", "created_at", "terminal"))
CANDIDATE_FIELDS = frozenset(("schema", "version", "candidate_head_sha", "previous_release", "gate_ids", "completion_seal"))

PROFILES = {
    "focused": "merge-base-origin-main",
    "source": "merge-base-origin-main",
    "host": "head",
    "artifact": "head",
    "acceptance": "head",
    "release": "previous-release-peeled",
}
FAILURE_STAGES = frozenset(("RUN_ROOT", "SNAPSHOT", "CHANGE_SET", "PLAN", "EXECUTE", "AGGREGATE", "SEAL", "INTERRUPT", "INTERNAL"))
FAILURE_REASONS = frozenset(("RUN_ROOT_UNSAFE", "SNAPSHOT_FAILED", "CHANGE_SET_MISMATCH", "INPUT_DRIFT", "TOOL_DRIFT", "PARTIAL_RESULTS", "DUPLICATE_RESULTS", "REPLAYED_RESULT", "RESULT_BINDING_MISMATCH", "INTERRUPTED", "INTERNAL_ERROR"))


def _fail(message: str) -> None:
    raise ContractViolation("ADAPTER_MALFORMED", message)


def _keys(value: Any, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("invalid " + label + " shape")
    return value


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    _fail("non-finite JSON number: " + value)


def _normal(value: Any) -> Any:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            _fail("string is not NFC")
        return value
    if isinstance(value, bool) or value is None:
        return value
    if _is_int(value):
        return int(value)
    if isinstance(value, float):
        _fail("JSON number is not a finite mathematical integer")
    if isinstance(value, list):
        return [_normal(item) for item in value]
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) or unicodedata.normalize("NFC", key) != key for key in value):
            _fail("object key is not NFC text")
        return {key: _normal(value[key]) for key in sorted(value, key=lambda item: item.encode("utf-8"))}
    _fail("unsupported canonical JSON value")


def canonical_json_bytes(value: Any) -> bytes:
    """CanonicalJsonV1: UTF-8 NFC compact JSON with integral number lexemes."""
    return json.dumps(_normal(value), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def load_canonical_json(raw: bytes) -> Any:
    if not isinstance(raw, bytes) or raw.startswith(b"\xef\xbb\xbf"):
        _fail("artifact must be strict UTF-8 without BOM")
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("invalid JSON artifact: " + str(exc))
    if canonical_json_bytes(value) != raw:
        _fail("artifact bytes are not canonical JSON")
    return value


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha(value: Any, length: int = 64) -> bool:
    pattern = {32: RUN_RE, 40: GIT_SHA_RE, 64: SHA_RE}.get(length)
    return pattern is not None and _matches(pattern, value)


def _path(value: Any) -> None:
    if not isinstance(value, str) or not value or len(value) > 240 or value != unicodedata.normalize("NFC", value):
        _fail("invalid logical path")
    if value.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail("unsafe logical path")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        _fail("unsafe logical path segment")


def _time(value: Any) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("timestamp must be RFC3339 UTC Z")
    try:
        dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("timestamp is not a real date")


def _ref(value: Any, artifacts: Mapping[str, bytes]) -> Any:
    ref = _keys(value, frozenset(("path", "sha256")), "artifact reference")
    _path(ref["path"])
    if not _sha(ref["sha256"]) or ref["path"] not in artifacts:
        _fail("missing artifact reference")
    raw = artifacts[ref["path"]]
    if not isinstance(raw, bytes) or sha256_hex(raw) != ref["sha256"]:
        _fail("artifact hash mismatch")
    return load_canonical_json(raw)


def _fixed_ref(value: Any, artifacts: Mapping[str, bytes], path: str) -> Any:
    if not isinstance(value, Mapping) or value.get("path") != path:
        _fail("unexpected artifact path")
    return _ref(value, artifacts)


def _ordered(values: list[Any], key) -> None:
    if values != sorted(values, key=key) or len({key(item) for item in values}) != len(values):
        _fail("array must be sorted and unique")


def _utf8_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or value != unicodedata.normalize("NFC", value) or value.endswith("\n"):
        _fail("invalid symlink target")
    try:
        return value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        _fail("symlink target is not UTF-8")


def _test_ids(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 1000000:
        _fail("invalid " + label)
    if any(
        not isinstance(item, str)
        or not item
        or len(item) > 512
        or item != unicodedata.normalize("NFC", item)
        or any(ord(char) < 32 or ord(char) == 127 for char in item)
        for item in value
    ):
        _fail("invalid " + label)
    if value != sorted(value, key=lambda item: item.encode("utf-8")) or len(set(value)) != len(value):
        _fail(label + " must be sorted and unique")
    return value


def validate_source_observation(observation: Any) -> None:
    fields = frozenset((
        "schema", "run_id", "suite_id", "entrypoint_id", "attempt_index",
        "command_argv_sha256", "environment_sha256", "tool_identity_sha256",
        "raw_process", "adapter_exit", "executed", "passed", "failed",
        "skipped", "ignored", "todo", "not_run", "discovered_test_ids",
        "executed_test_ids", "failed_test_ids", "skipped_test_ids", "ignored_test_ids",
        "todo_test_ids", "not_run_test_ids", "stdout", "stderr",
        "derived_tool", "outcome_hint", "classification_hint", "reason_code",
    ))
    observation = _keys(observation, fields, "source observation")
    if (
        observation["schema"] != "source-observation.v1"
        or not _sha(observation["run_id"], 32)
        or not _matches(SUITE_RE, observation["suite_id"])
        or not _matches(ENTRY_RE, observation["entrypoint_id"])
        or observation["attempt_index"] != 0
    ):
        _fail("source observation identity")
    if any(
        not _sha(observation[key])
        for key in ("command_argv_sha256", "environment_sha256", "tool_identity_sha256")
    ):
        _fail("source observation digest")
    raw = observation["raw_process"]
    if not isinstance(raw, Mapping):
        _fail("source observation raw process")
    state = raw.get("state")
    if state == "EXITED":
        if set(raw) != {"state", "process_exit"} or not _is_int(raw["process_exit"]) or not 0 <= raw["process_exit"] <= 255:
            _fail("source observation raw exit")
    elif state == "SIGNALED":
        if set(raw) != {"state", "process_signal"} or not _is_int(raw["process_signal"]) or not 1 <= raw["process_signal"] <= 255:
            _fail("source observation raw signal")
    elif state in {
        "PRE_EXEC_FAILED", "HARD_TIMEOUT", "OUTPUT_LIMIT", "REAP_FAILED",
        "TERMINAL_DRAIN_INCOMPLETE", "PROCESS_GROUP_CLEANUP_FAILED",
    }:
        if set(raw) != {"state"}:
            _fail("source observation typed raw state")
    else:
        _fail("source observation raw state")
    if observation["adapter_exit"] not in {0, 10, 11, 12, 13}:
        _fail("source observation adapter exit")
    counts = {}
    for key in ("executed", "passed", "failed", "skipped", "ignored", "todo", "not_run"):
        value = observation[key]
        if not _is_int(value) or not 0 <= value <= 1000000:
            _fail("source observation count")
        counts[key] = value
    ids = {
        key: _test_ids(observation[key], key)
        for key in (
            "discovered_test_ids", "executed_test_ids", "failed_test_ids",
            "skipped_test_ids",
            "ignored_test_ids", "todo_test_ids", "not_run_test_ids",
        )
    }
    if len(ids["executed_test_ids"]) != counts["executed"]:
        _fail("source observation executed identity count")
    for key, count_key in (
        ("failed_test_ids", "failed"), ("skipped_test_ids", "skipped"),
        ("ignored_test_ids", "ignored"),
        ("todo_test_ids", "todo"), ("not_run_test_ids", "not_run"),
    ):
        if len(ids[key]) != counts[count_key]:
            _fail("source observation state identity count")
    executed_ids = set(ids["executed_test_ids"])
    state_id_sets = [
        set(ids[key])
        for key in (
            "failed_test_ids", "skipped_test_ids", "ignored_test_ids",
            "todo_test_ids",
        )
    ]
    if (
        any(not values <= executed_ids for values in state_id_sets)
        or any(
            left & right
            for index, left in enumerate(state_id_sets)
            for right in state_id_sets[index + 1:]
        )
        or set(ids["not_run_test_ids"]) & executed_ids
    ):
        _fail("source observation state identity partition")
    if counts["passed"] + counts["failed"] + counts["skipped"] + counts["ignored"] + counts["todo"] != counts["executed"]:
        _fail("source observation execution count")
    for key in ("stdout", "stderr"):
        output = _keys(observation[key], frozenset(("bytes", "sha256", "truncated")), "source output")
        if (
            not _is_int(output["bytes"]) or not 0 <= output["bytes"] <= 67108864
            or not _sha(output["sha256"]) or not isinstance(output["truncated"], bool)
        ):
            _fail("source output binding")
    derived = observation["derived_tool"]
    if observation["suite_id"] == "SUITE-PY-LOOPBACK":
        derived = _keys(
            derived,
            frozenset(("path", "mode", "size", "sha256")),
            "source derived tool",
        )
        path = derived["path"]
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path == "/"
            or path.endswith("/")
            or "//" in path
            or len(path.encode("utf-8", "strict")) > 4096
            or path != unicodedata.normalize("NFC", path)
            or any(
                part in {"", ".", ".."}
                for part in path.split("/")[1:]
            )
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
            or derived["mode"] != "0755"
            or not _is_int(derived["size"])
            or not 0 < derived["size"] <= 134217728
            or not _sha(derived["sha256"])
        ):
            _fail("source derived tool binding")
    elif derived is not None:
        _fail("unexpected source derived tool")
    if (
        observation["outcome_hint"] not in {"PASS", "FAIL", "BLOCKED"}
        or observation["classification_hint"] not in {"NONE", "ENVIRONMENT", "REAL_MACHINE", "QUARANTINED", "INFRA"}
        or not isinstance(observation["reason_code"], str)
        or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", observation["reason_code"]) is None
    ):
        _fail("source observation hints")


def validate_source_snapshot(manifest: Any) -> None:
    manifest = _keys(manifest, SNAPSHOT_FIELDS, "source snapshot")
    if manifest["schema"] != "source-snapshot-manifest.v1" or not _sha(manifest["run_id"], 32) or not _sha(manifest["head_sha"], 40):
        _fail("snapshot identity")
    if manifest["snapshot_mode"] not in {"clean-commit", "focused-overlay"}:
        _fail("snapshot mode")
    entries = manifest["entries"]
    count, total_bytes = manifest["entry_count"], manifest["total_bytes"]
    if not isinstance(entries, list) or len(entries) > 50000 or not _is_int(count) or not 0 <= count <= 50000 or count != len(entries):
        _fail("snapshot entry count")
    if not _is_int(total_bytes) or not 0 <= total_bytes <= 1073741824:
        _fail("snapshot total bytes")
    total = 0
    for entry in entries:
        if not isinstance(entry, Mapping) or entry.get("type") not in {"file", "symlink"}:
            _fail("snapshot entry")
        entry_type = entry["type"]
        fields = frozenset(("path", "type", "mode", "size", "sha256"))
        if entry_type == "symlink":
            fields |= {"symlink_target"}
        entry = _keys(entry, fields, "snapshot entry")
        _path(entry["path"])
        if not _is_int(entry["size"]) or not 0 <= entry["size"] <= 67108864 or not _sha(entry["sha256"]):
            _fail("snapshot entry bytes")
        if entry_type == "file":
            if entry["mode"] not in {"100644", "100755"}:
                _fail("file entry")
        else:
            if entry["mode"] != "120000":
                _fail("symlink entry mode")
            target_bytes = _utf8_bytes(entry["symlink_target"])
            if entry["size"] != len(target_bytes) or entry["sha256"] != sha256_hex(target_bytes):
                _fail("symlink target bytes are not bound")
        total += int(entry["size"])
    _ordered(entries, lambda entry: entry["path"])
    if total != total_bytes:
        _fail("snapshot total")


def validate_change_set(change_set: Any) -> None:
    change_set = _keys(change_set, CHANGE_FIELDS, "change-set")
    if change_set["schema"] != "change-set.v1" or not _sha(change_set["head_sha"], 40) or not _sha(change_set["raw_status_sha256"]):
        _fail("change-set identity")
    _time(change_set["created_at"])
    entries = change_set["entries"]
    if not isinstance(entries, list) or len(entries) > 4096:
        _fail("change-set entries")
    fields = frozenset(("path", "xy_status", "head_blob_sha", "index_blob_sha", "worktree_sha256", "mode", "size", "dev", "ino", "mtime_ns"))
    total = 0
    for entry in entries:
        entry = _keys(entry, fields, "change-set entry")
        _path(entry["path"])
        status, head, index = entry["xy_status"], entry["head_blob_sha"], entry["index_blob_sha"]
        if status not in {".M", "M.", "MM", "A.", "AM", "??"}:
            _fail("git status")
        if status == "??" and (not entry["path"].startswith("test/") or head is not None or index is not None):
            _fail("untracked change")
        if status in {"A.", "AM"} and (head is not None or not _sha(index, 40)):
            _fail("added change")
        if status not in {"??", "A.", "AM"} and (not _sha(head, 40) or not _sha(index, 40)):
            _fail("tracked change")
        if not _sha(entry["worktree_sha256"]) or entry["mode"] not in {"100644", "100755"}:
            _fail("change bytes")
        for key in ("size", "dev", "ino", "mtime_ns"):
            if not _is_int(entry[key]) or entry[key] < 0:
                _fail("change stat")
        if entry["size"] > 67108864:
            _fail("change size")
        total += int(entry["size"])
    _ordered(entries, lambda entry: entry["path"])
    if total > 536870912:
        _fail("change-set total")


def validate_run_manifest(manifest: Any, artifacts: Mapping[str, bytes]) -> tuple[Any, Any | None]:
    manifest = _keys(manifest, RUN_FIELDS, "run manifest")
    if manifest["schema"] != "run-manifest.v1" or not _sha(manifest["run_id"], 32) or not _sha(manifest["head_sha"], 40):
        _fail("run identity")
    _time(manifest["started_at"])
    profile = manifest["profile"]
    base = _keys(manifest["comparison_base"], frozenset(("policy", "sha")), "comparison base")
    if profile not in PROFILES or base["policy"] != PROFILES[profile] or not _sha(base["sha"], 40):
        _fail("comparison base")
    if profile in {"host", "artifact", "acceptance"} and base["sha"] != manifest["head_sha"]:
        _fail("head comparison base must equal head")
    snapshot_ref = manifest["source_snapshot_manifest"]
    snapshot = _fixed_ref(snapshot_ref, artifacts, "snapshot/source-snapshot-manifest.json")
    validate_source_snapshot(snapshot)
    change_ref = manifest["change_set"]
    change = None if change_ref is None else _fixed_ref(change_ref, artifacts, "inputs/change-set.json")
    if change is not None:
        validate_change_set(change)
    clean = snapshot["snapshot_mode"] == "clean-commit"
    if clean != (change is None) or (not clean and profile != "focused"):
        _fail("snapshot/change/profile binding")
    if snapshot["run_id"] != manifest["run_id"] or snapshot["head_sha"] != manifest["head_sha"] or (change is not None and change["head_sha"] != manifest["head_sha"]):
        _fail("manifest binding")
    argv = manifest["invocation_argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 64 or any(not isinstance(item, str) or len(item) > 1024 for item in argv):
        _fail("invocation argv")
    expected = manifest["expected_suites"]
    if not isinstance(expected, list) or not 1 <= len(expected) <= 128:
        _fail("expected suites")
    for item in expected:
        item = _keys(item, frozenset(("suite_id", "entrypoint_id")), "expected suite")
        if not _matches(SUITE_RE, item["suite_id"]) or not _matches(ENTRY_RE, item["entrypoint_id"]):
            _fail("expected suite identity")
    if profile == "source":
        if len({
            item["suite_id"] for item in expected
        }) != len(expected):
            _fail("expected source suites must be unique")
    else:
        _ordered(expected, lambda item: item["suite_id"])
    digests = _keys(manifest["input_digests"], frozenset(("schema_bundle", "catalog", "gates", "runner", "fixtures", "build_recipes", "sanitized_environment", "tools")), "input digests")
    if any(not _sha(value) for value in digests.values()):
        _fail("input digest")
    platform = _keys(manifest["platform"], frozenset(("os", "arch", "toolchain")), "platform")
    if any(not isinstance(value, str) or not value or len(value) > limit for value, limit in ((platform["os"], 64), (platform["arch"], 64), (platform["toolchain"], 240))):
        _fail("platform")
    return snapshot, change


def validate_evidence_manifest(manifest: Any, run_manifest: Any, artifacts: Mapping[str, bytes]) -> None:
    if not isinstance(manifest, Mapping) or set(manifest) not in {EVIDENCE_FIELDS, SOURCE_EVIDENCE_FIELDS}:
        _fail("invalid evidence manifest shape")
    run_manifest = _keys(run_manifest, RUN_FIELDS, "supplied run manifest")
    if manifest["schema"] != "evidence-manifest.v1" or manifest["run_id"] != run_manifest["run_id"]:
        _fail("evidence binding")
    run = _fixed_ref(manifest["run_manifest"], artifacts, "run-manifest.json")
    if run != run_manifest:
        _fail("evidence run manifest binding")
    results = manifest["test_results"]
    if not isinstance(results, list) or not 1 <= len(results) <= 128:
        _fail("evidence results")
    expected = {(item["suite_id"], item["entrypoint_id"]) for item in run_manifest["expected_suites"]}
    actual = set()
    for ref in results:
        ref = _keys(ref, frozenset(("suite_id", "entrypoint_id", "path", "sha256")), "result reference")
        if not _matches(SUITE_RE, ref["suite_id"]) or not _matches(ENTRY_RE, ref["entrypoint_id"]) or ref["path"] != "results/{}.json".format(ref["suite_id"]):
            _fail("result reference binding")
        result = _ref({"path": ref["path"], "sha256": ref["sha256"]}, artifacts)
        validate_result(result)
        if result.get("run_id") != manifest["run_id"] or result.get("suite_id") != ref["suite_id"] or result.get("entrypoint_id") != ref["entrypoint_id"]:
            _fail("result binding")
        actual.add((ref["suite_id"], ref["entrypoint_id"]))
    observations = manifest.get("source_observations")
    if observations is None:
        _ordered(results, lambda item: item["suite_id"])
        if actual != expected:
            _fail("evidence expected suites")
        return
    if actual != expected:
        _fail("evidence expected suites")
    if not isinstance(observations, list) or len(observations) != len(run_manifest["expected_suites"]):
        _fail("source observation references")
    expected_order = [
        (item["suite_id"], item["entrypoint_id"])
        for item in run_manifest["expected_suites"]
    ]
    actual_order = []
    for ref in observations:
        ref = _keys(ref, frozenset(("suite_id", "entrypoint_id", "path", "sha256")), "source observation reference")
        expected_path = "results/{}.observation.json".format(
            ref["suite_id"],
        )
        if (
            not _matches(SUITE_RE, ref["suite_id"])
            or not _matches(ENTRY_RE, ref["entrypoint_id"])
            or ref["path"] != expected_path
        ):
            _fail("source observation reference binding")
        observation = _ref({"path": ref["path"], "sha256": ref["sha256"]}, artifacts)
        validate_source_observation(observation)
        if (
            observation.get("run_id") != manifest["run_id"]
            or observation.get("suite_id") != ref["suite_id"]
            or observation.get("entrypoint_id") != ref["entrypoint_id"]
        ):
            _fail("source observation binding")
        actual_order.append((ref["suite_id"], ref["entrypoint_id"]))
    if actual_order != expected_order or len(set(actual_order)) != len(actual_order):
        _fail("source observation expected suites")
    result_order = [(item["suite_id"], item["entrypoint_id"]) for item in results]
    if result_order != expected_order:
        _fail("source result expected order")


def validate_completion_seal(seal: Any, run_manifest: Any, snapshot: Any, evidence: Any, artifacts: Mapping[str, bytes]) -> None:
    seal = _keys(seal, SEAL_FIELDS, "completion seal")
    if seal["schema"] != "completion-seal.v1":
        _fail("seal schema")
    bound_snapshot, _ = validate_run_manifest(run_manifest, artifacts)
    if bound_snapshot != snapshot:
        _fail("seal supplied snapshot binding")
    validate_evidence_manifest(evidence, run_manifest, artifacts)
    run = _fixed_ref(seal["run_manifest"], artifacts, "run-manifest.json")
    sealed_snapshot = _fixed_ref(seal["source_snapshot_manifest"], artifacts, "snapshot/source-snapshot-manifest.json")
    sealed_evidence = _fixed_ref(seal["evidence_manifest"], artifacts, "evidence-manifest.json")
    if run != run_manifest or sealed_snapshot != snapshot or sealed_evidence != evidence:
        _fail("seal artifact binding")
    if seal["source_snapshot_manifest"] != run_manifest["source_snapshot_manifest"] or evidence["run_manifest"] != seal["run_manifest"]:
        _fail("seal reference binding")
    if any(value.get("run_id") != run_manifest["run_id"] for value in (seal, snapshot, evidence)):
        _fail("seal run id binding")
    _time(seal["completed_at"])
    if (seal["aggregate_decision"], seal["runner_exit"]) not in {("PASS", 0), ("BLOCKED", 11), ("BLOCKED", 13), ("FAIL", 10), ("FAIL", 12), ("FAIL", 13)}:
        _fail("seal decision")
    if not _sha(seal["input_digest_set_sha256"]) or seal["input_digest_set_sha256"] != sha256_hex(canonical_json_bytes(run_manifest["input_digests"])):
        _fail("input digest set")


def validate_fixed_single_suite_seal(
    seal: Any,
    run_manifest: Any,
    snapshot: Any,
    evidence: Any,
    artifacts: Mapping[str, bytes],
) -> None:
    """Validate the fixed RUE05A seal and its result-derived decision.

    The general RUE-02 seal contract deliberately permits multi-suite
    aggregation.  This narrower validator closes the current one-suite
    vertical slice: the seal cannot claim PASS, FAIL, or BLOCKED independently
    of its sole durable ``TestResultV1``.
    """
    validate_completion_seal(
        seal, run_manifest, snapshot, evidence, artifacts,
    )
    expected = [{
        "suite_id": "SUITE-RUE05A",
        "entrypoint_id": "ENTRY-RUE05A-ATTEMPT0",
    }]
    if (
        run_manifest.get("profile") != "focused"
        or run_manifest.get("comparison_base", {}).get("policy")
        != "merge-base-origin-main"
        or run_manifest.get("change_set") is not None
        or run_manifest.get("invocation_argv") != ["rue-fixed-api.v1"]
        or run_manifest.get("expected_suites") != expected
        or evidence.get("test_results") is None
        or len(evidence["test_results"]) != 1
    ):
        _fail("fixed run binding")
    result_ref = evidence["test_results"][0]
    result = _ref(
        {"path": result_ref["path"], "sha256": result_ref["sha256"]},
        artifacts,
    )
    validate_result(result)
    if (
        result.get("suite_id") != "SUITE-RUE05A"
        or result.get("entrypoint_id") != "ENTRY-RUE05A-ATTEMPT0"
        or seal.get("aggregate_decision") != result.get("gate_decision")
        or seal.get("runner_exit") != result.get("runner_exit")
    ):
        _fail("fixed aggregate decision")


def validate_terminal_set(seal: Any | None, failure: Any | None, *, run_manifest: Any | None = None, artifacts: Mapping[str, bytes] | None = None) -> None:
    if seal is not None and failure is not None:
        _fail("seal and failure are mutually exclusive")
    if seal is None and failure is None:
        _fail("terminal outcome is required")
    if failure is None:
        return
    failure = _keys(failure, FAILURE_FIELDS, "run failure")
    if failure["schema"] != "run-failure.v1" or not _sha(failure["run_id"], 32) or failure["stage"] not in FAILURE_STAGES or failure["reason_code"] not in FAILURE_REASONS or failure["terminal"] is not True:
        _fail("run failure")
    _time(failure["created_at"])
    ref = failure["run_manifest"]
    if ref is not None:
        if artifacts is None:
            _fail("failure reference requires artifacts")
        bound_run = _ref(ref, artifacts)
        if not isinstance(bound_run, Mapping) or bound_run.get("schema") != "run-manifest.v1" or bound_run.get("run_id") != failure["run_id"]:
            _fail("failure run binding")
        if run_manifest is not None and bound_run != run_manifest:
            _fail("failure supplied run binding")
    if run_manifest is not None:
        run_manifest = _keys(run_manifest, RUN_FIELDS, "supplied run manifest")
        if failure["run_id"] != run_manifest["run_id"]:
            _fail("failure run id binding")


def _catalog_pairs(catalog_suites: Any) -> dict[str, str]:
    if not isinstance(catalog_suites, list):
        _fail("catalog suites")
    pairs = {}
    for suite in catalog_suites:
        if not isinstance(suite, Mapping) or set(("id", "entrypoint_id")) - set(suite):
            _fail("catalog suite")
        suite_id = suite["id"]
        if suite_id in pairs:
            _fail("duplicate catalog suite")
        pairs[suite_id] = suite["entrypoint_id"]
    if not pairs or any(not _matches(SUITE_RE, suite_id) or not _matches(ENTRY_RE, entry_id) for suite_id, entry_id in pairs.items()):
        _fail("catalog suite identity")
    return pairs


def _release_inputs(release_gates_raw: bytes, test_catalog_raw: bytes) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    gates_doc = _keys(load_canonical_json(release_gates_raw), frozenset(("schema", "version", "gates")), "release gates document")
    catalog_doc = _keys(load_canonical_json(test_catalog_raw), frozenset(("schema", "catalog_id", "version", "discovery_paths", "selection_rules", "suites")), "test catalog document")
    if gates_doc["schema"] != "release-gates.v1" or not _matches(SEMVER_RE, gates_doc["version"]) or not isinstance(gates_doc["gates"], list):
        _fail("release gates document")
    if catalog_doc["schema"] != "test-catalog.v1" or not isinstance(catalog_doc["catalog_id"], str) or not _matches(SEMVER_RE, catalog_doc["version"]) or not isinstance(catalog_doc["discovery_paths"], list) or not isinstance(catalog_doc["selection_rules"], list) or not isinstance(catalog_doc["suites"], list):
        _fail("test catalog document")
    return gates_doc, catalog_doc


def validate_release_candidate(candidate: Any, artifacts: Mapping[str, bytes], release_gates_raw: bytes, test_catalog_raw: bytes) -> None:
    """Close a release candidate over a fully validated release run and PASS seal."""
    candidate = _keys(candidate, CANDIDATE_FIELDS, "release candidate")
    if candidate["schema"] != "release-candidate.v1" or not _matches(SEMVER_RE, candidate["version"]) or not _sha(candidate["candidate_head_sha"], 40):
        _fail("candidate identity")
    previous = _keys(candidate["previous_release"], frozenset(("tag", "tag_object_sha", "peeled_sha")), "previous release")
    if not _matches(SEMVER_RE, previous["tag"]) or not _sha(previous["tag_object_sha"], 40) or not _sha(previous["peeled_sha"], 40):
        _fail("previous release")
    gates_doc, catalog_doc = _release_inputs(release_gates_raw, test_catalog_raw)
    seal = _fixed_ref(candidate["completion_seal"], artifacts, "completion-seal.json")
    if not isinstance(seal, Mapping) or seal.get("schema") != "completion-seal.v1":
        _fail("candidate seal")
    run = _fixed_ref(seal.get("run_manifest"), artifacts, "run-manifest.json")
    snapshot = _fixed_ref(seal.get("source_snapshot_manifest"), artifacts, "snapshot/source-snapshot-manifest.json")
    evidence = _fixed_ref(seal.get("evidence_manifest"), artifacts, "evidence-manifest.json")
    validate_completion_seal(seal, run, snapshot, evidence, artifacts)
    if (seal["aggregate_decision"], seal["runner_exit"]) != ("PASS", 0) or run["profile"] != "release":
        _fail("candidate seal")
    if run["head_sha"] != candidate["candidate_head_sha"] or run["comparison_base"] != {"policy": "previous-release-peeled", "sha": previous["peeled_sha"]}:
        _fail("candidate release binding")
    if sha256_hex(release_gates_raw) != run["input_digests"]["gates"] or sha256_hex(test_catalog_raw) != run["input_digests"]["catalog"]:
        _fail("candidate inputs do not bind sealed run")
    required = []
    covered: set[str] = set()
    seen_gate_ids: set[str] = set()
    for gate in gates_doc["gates"]:
        if not isinstance(gate, Mapping) or not _matches(re.compile(r"^GATE-[A-Z0-9][A-Z0-9-]{0,31}(?![\s\S])"), gate.get("id")):
            _fail("gate")
        if gate["id"] in seen_gate_ids:
            _fail("duplicate gate")
        seen_gate_ids.add(gate["id"])
        if gate.get("status") == "active" and gate.get("candidate_policy") == "required":
            suites = gate.get("required_suite_ids")
            if not isinstance(suites, list) or any(not _matches(SUITE_RE, suite_id) for suite_id in suites):
                _fail("required gate suites")
            required.append(gate["id"])
            covered.update(suites)
    required.sort()
    gate_ids = candidate["gate_ids"]
    if not isinstance(gate_ids, list) or gate_ids != required or len(gate_ids) != len(set(gate_ids)):
        _fail("candidate gate set")
    catalog = _catalog_pairs(catalog_doc["suites"])
    expected_pairs = {(item["suite_id"], item["entrypoint_id"]) for item in run["expected_suites"]}
    if any(catalog.get(suite_id) != entrypoint_id for suite_id, entrypoint_id in expected_pairs):
        _fail("catalog entrypoint binding")
    if not covered.issubset({suite_id for suite_id, _ in expected_pairs}):
        _fail("candidate required suites are not evidenced")


def _schema_validate(schema_validator: Callable[[str, Any], None] | None, schema: str, instance: Any) -> None:
    if not callable(schema_validator):
        _fail("complete validation requires a schema_validator callback")
    schema_validator(schema, instance)


def validate_complete_run(run_manifest: Any, evidence_manifest: Any, seal: Any | None, failure: Any | None, artifacts: Mapping[str, bytes], *, schema_validator: Callable[[str, Any], None] | None, candidate: Any | None = None, release_gates_raw: bytes | None = None, test_catalog_raw: bytes | None = None) -> tuple[Any, Any | None]:
    """Run schema callback plus every RUE-02 semantic binding in one call.

    ``schema_validator(schema_name, instance)`` is mandatory: this pure module
    deliberately does not import a production JSON Schema implementation.
    """
    _schema_validate(schema_validator, "run-manifest.v1", run_manifest)
    snapshot, change = validate_run_manifest(run_manifest, artifacts)
    _schema_validate(schema_validator, "source-snapshot-manifest.v1", snapshot)
    if change is not None:
        _schema_validate(schema_validator, "change-set.v1", change)
    _schema_validate(schema_validator, "evidence-manifest.v1", evidence_manifest)
    validate_evidence_manifest(evidence_manifest, run_manifest, artifacts)
    for ref in evidence_manifest["test_results"]:
        _schema_validate(schema_validator, "test-result.v1", _ref({"path": ref["path"], "sha256": ref["sha256"]}, artifacts))
    for ref in evidence_manifest.get("source_observations", []):
        _schema_validate(schema_validator, "source-observation.v1", _ref({"path": ref["path"], "sha256": ref["sha256"]}, artifacts))
    if seal is not None:
        _schema_validate(schema_validator, "completion-seal.v1", seal)
        validate_completion_seal(seal, run_manifest, snapshot, evidence_manifest, artifacts)
    if failure is not None:
        _schema_validate(schema_validator, "run-failure.v1", failure)
    validate_terminal_set(seal, failure, run_manifest=run_manifest, artifacts=artifacts)
    if candidate is not None:
        _schema_validate(schema_validator, "release-candidate.v1", candidate)
        if release_gates_raw is None or test_catalog_raw is None:
            _fail("candidate validation requires canonical release inputs")
        validate_release_candidate(candidate, artifacts, release_gates_raw, test_catalog_raw)
    return snapshot, change
