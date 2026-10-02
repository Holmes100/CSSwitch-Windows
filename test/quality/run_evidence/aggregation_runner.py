"""Fixed one-suite aggregation and completion seal for the RUE05A slice."""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .atomic_store import RunLayout, RunStoreError, _error, _publish
from .contracts import (
    EXECUTED_INFRA_REASONS,
    NO_CHILD_INFRA_REASONS,
    AttemptDecisionV1,
    make_result,
    validate_result,
)
from .manifest_contracts import (
    canonical_json_bytes,
    sha256_hex,
    validate_completion_seal,
    validate_evidence_manifest,
    validate_fixed_single_suite_seal,
    validate_run_manifest,
)
from .retry_runner import _final_result


_SUITE_ID = "SUITE-RUE05A"
_ENTRYPOINT_ID = "ENTRY-RUE05A-ATTEMPT0"
_INVOCATION_ARGV = ["rue-fixed-api.v1"]
_CATALOG_COMMAND_ARGV = [
    "/usr/bin/python3",
    "-I",
    "test/quality/run_evidence/cli.py",
    "run",
    "--output-root",
    "{ABS_EMPTY_0700_DIR}",
]
_EXPECTED_SUITES = [{
    "suite_id": _SUITE_ID,
    "entrypoint_id": _ENTRYPOINT_ID,
}]
_SCHEMA_ROOT = Path(__file__).resolve().parents[3] / "quality/schema"
_SCHEMA_FILES = {
    "run-manifest.v1": "run-manifest.v1.schema.json",
    "test-result.v1": "test-result.v1.schema.json",
    "evidence-manifest.v1": "evidence-manifest.v1.schema.json",
    "completion-seal.v1": "completion-seal.v1.schema.json",
}


def _bound_invocation_argv(layout: RunLayout) -> list[str]:
    value = getattr(layout, "_catalog_bound_invocation_argv", None)
    if value is None:
        return _INVOCATION_ARGV
    if (
        not isinstance(value, tuple)
        or len(value) != len(_CATALOG_COMMAND_ARGV)
        or list(value[:-1]) != _CATALOG_COMMAND_ARGV[:-1]
        or not isinstance(value[-1], str)
        or not value[-1].startswith("/")
        or value[-1] == "/"
    ):
        raise _error(
            "RUN_MANIFEST_INVALID",
            stage="PLAN",
            run_id=layout.run_id,
        )
    return list(value)


def _schema_validate(schema_name: str, value: Any) -> None:
    try:
        schema = json.loads(
            (_SCHEMA_ROOT / _SCHEMA_FILES[schema_name]).read_text("utf-8"),
        )
        Draft202012Validator(schema).validate(value)
    except Exception as exc:
        raise _error("AGGREGATE_CONTRACT_INVALID", stage="AGGREGATE") from exc


def _snapshot_artifacts(
    layout: RunLayout,
    snapshot: Mapping[str, Any],
) -> dict[str, bytes]:
    binding = layout._finalized_snapshot_binding
    if (
        binding is None
        or binding.run_id != layout.run_id
        or binding.publication.path
        != "snapshot/source-snapshot-manifest.json"
    ):
        raise _error(
            "SNAPSHOT_BINDING_MISMATCH",
            stage="AGGREGATE",
            run_id=layout.run_id,
        )
    raw = canonical_json_bytes(snapshot)
    if (
        len(raw) != binding.publication.size
        or sha256_hex(raw) != binding.publication.sha256
        or binding.publication.identity != binding.identity
    ):
        raise _error(
            "SNAPSHOT_BINDING_MISMATCH",
            stage="AGGREGATE",
            run_id=layout.run_id,
        )
    return {binding.publication.path: raw}


def _validate_fixed_run(
    layout: RunLayout,
    run_manifest: Any,
    snapshot: Mapping[str, Any],
    *,
    invocation_argv: list[str] = _INVOCATION_ARGV,
) -> dict[str, bytes]:
    artifacts = _snapshot_artifacts(layout, snapshot)
    try:
        _schema_validate("run-manifest.v1", run_manifest)
        bound_snapshot, change = validate_run_manifest(run_manifest, artifacts)
    except RunStoreError:
        raise
    except Exception as exc:
        raise _error(
            "RUN_MANIFEST_INVALID",
            stage="PLAN",
            run_id=layout.run_id,
        ) from exc
    binding = layout._finalized_snapshot_binding
    if (
        not isinstance(run_manifest, Mapping)
        or binding is None
        or run_manifest.get("run_id") != layout.run_id
        or run_manifest.get("profile") != "focused"
        or run_manifest.get("comparison_base", {}).get("policy")
        != "merge-base-origin-main"
        or run_manifest.get("head_sha") != binding.head_sha
        or run_manifest.get("source_snapshot_manifest")
        != {
            "path": binding.publication.path,
            "sha256": binding.publication.sha256,
        }
        or change is not None
        or bound_snapshot != snapshot
        or run_manifest.get("invocation_argv") != invocation_argv
        or run_manifest.get("expected_suites") != _EXPECTED_SUITES
    ):
        raise _error(
            "RUN_MANIFEST_INVALID",
            stage="PLAN",
            run_id=layout.run_id,
        )
    return artifacts


def _prepare_fixed_run(
    layout: RunLayout,
    run_manifest: Mapping[str, Any],
    *,
    invocation_argv: list[str],
) -> Mapping[str, Any]:
    if not isinstance(layout, RunLayout):
        raise TypeError("layout must be RunLayout")
    with layout._lock:
        layout._open()
        layout._snapshot_terminal_absent()
        if layout._fixed_prepare_started:
            raise _error(
                "REPLAYED_RESULT", stage="PLAN", run_id=layout.run_id,
            )
        try:
            os.stat(
                "run-manifest.json",
                dir_fd=layout._evidence_fd_required(),
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise _error(
                "RUN_MANIFEST_INVALID",
                stage="PLAN",
                run_id=layout.run_id,
            ) from exc
        else:
            raise _error(
                "REPLAYED_RESULT", stage="PLAN", run_id=layout.run_id,
            )
        snapshot = layout._read_bound_finalized_snapshot()
        _validate_fixed_run(
            layout,
            run_manifest,
            snapshot,
            invocation_argv=invocation_argv,
        )
        layout._fixed_prepare_started = True
        publication = _publish(
            layout,
            "root",
            "run-manifest.json",
            canonical_json_bytes(run_manifest),
            failure=False,
        )
        layout._fixed_run_publication = publication
        rebound = layout._read_bound_publication(
            publication,
            expected_area="root",
            expected_leaf="run-manifest.json",
            code="RUN_MANIFEST_INVALID",
        )
        closing_snapshot = layout._read_bound_finalized_snapshot()
        _validate_fixed_run(
            layout,
            rebound,
            closing_snapshot,
            invocation_argv=invocation_argv,
        )
        if rebound != run_manifest or closing_snapshot != snapshot:
            raise _error(
                "RUN_MANIFEST_INVALID",
                stage="PLAN",
                run_id=layout.run_id,
            )
        return rebound


def prepare_fixed_run(
    layout: RunLayout,
    run_manifest: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Bind and publish the sole fixed API run; callers cannot alter its plan."""
    return _prepare_fixed_run(
        layout,
        run_manifest,
        invocation_argv=_INVOCATION_ARGV,
    )


def _prepare_catalog_bound_run(
    layout: RunLayout,
    run_manifest: Mapping[str, Any],
    *,
    catalog_command_argv: Any,
    output_root: str,
) -> Mapping[str, Any]:
    """Private CLI bridge for the one exact catalog command template."""
    if (
        catalog_command_argv != _CATALOG_COMMAND_ARGV
        or not isinstance(output_root, str)
        or not output_root.startswith("/")
        or output_root == "/"
    ):
        raise _error(
            "RUN_MANIFEST_INVALID",
            stage="PLAN",
            run_id=getattr(layout, "run_id", None),
        )
    actual = [*catalog_command_argv[:-1], output_root]
    if (
        not isinstance(run_manifest, Mapping)
        or run_manifest.get("invocation_argv") != actual
    ):
        raise _error(
            "RUN_MANIFEST_INVALID",
            stage="PLAN",
            run_id=getattr(layout, "run_id", None),
        )
    setattr(layout, "_catalog_bound_invocation_argv", tuple(actual))
    return _prepare_fixed_run(layout, run_manifest, invocation_argv=actual)


def _single_attempt_result(attempt: AttemptDecisionV1) -> dict[str, Any]:
    state = (
        attempt.disposition,
        attempt.reason_code,
        attempt.attempt_record.process_exit,
    )
    fixed = {
        ("PASS", "NONE", 0): ("PASS", None),
        ("TEST_FAIL", "ASSERTION_FAILED", 10): ("TEST_FAIL", None),
        ("ENV", "ENVIRONMENT", 11): ("ENV", None),
        ("REAL", "REAL_MACHINE_REQUIRED", 11): ("REAL", None),
        ("IGNORED", "ADAPTER_REPORTED_IGNORED", 11): ("IGNORED", None),
        ("SKIPPED", "ADAPTER_REPORTED_SKIPPED", 11): ("SKIPPED", None),
    }
    if state in fixed:
        kind, reason = fixed[state]
    elif (
        attempt.disposition == "HARD_TIMEOUT"
        and attempt.reason_code == "PROCESS_TIMEOUT"
        and attempt.attempt_record.process_exit is not None
    ):
        kind, reason = "HARD_TIMEOUT", None
    elif (
        attempt.disposition == "INFRA"
        and (
            (
                attempt.reason_code in NO_CHILD_INFRA_REASONS
                and attempt.attempt_record.process_exit is None
            )
            or (
                attempt.reason_code in EXECUTED_INFRA_REASONS
                and attempt.attempt_record.process_exit is not None
            )
        )
    ):
        kind, reason = "INFRA", attempt.reason_code
    else:
        raise _error(
            "PARTIAL_RESULTS",
            stage="AGGREGATE",
            run_id=attempt.run_id,
        )
    result = make_result(
        kind,
        attempt.run_id,
        attempt.suite_id,
        attempt.entrypoint_id,
        attempt_records=[attempt.attempt_record.as_dict()],
        reason_code=reason,
    )
    validate_result(result)
    return result


def _read_attempt_result(layout: RunLayout) -> dict[str, Any]:
    if layout._attempt0_publication is None:
        raise _error(
            "PARTIAL_RESULTS", stage="AGGREGATE", run_id=layout.run_id,
        )
    attempt0 = layout._read_bound_attempt(0)
    if layout._attempt1_publication is None:
        if layout._attempt1_started or layout._attempt1_publication_started:
            raise _error(
                "PARTIAL_RESULTS", stage="AGGREGATE", run_id=layout.run_id,
            )
        result = _single_attempt_result(attempt0)
        if layout._read_bound_attempt(0) != attempt0:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )
        return result
    if not layout._attempt1_started or not layout._attempt1_publication_started:
        raise _error(
            "REPLAYED_RESULT", stage="AGGREGATE", run_id=layout.run_id,
        )
    attempt1 = layout._read_bound_attempt(1)
    try:
        result = _final_result(attempt0, attempt1)
    except Exception as exc:
        raise _error(
            "RESULT_BINDING_MISMATCH",
            stage="AGGREGATE",
            run_id=layout.run_id,
        ) from exc
    if (
        layout._read_bound_attempt(0) != attempt0
        or layout._read_bound_attempt(1) != attempt1
    ):
        raise _error(
            "RESULT_BINDING_MISMATCH",
            stage="AGGREGATE",
            run_id=layout.run_id,
        )
    return result


def _validate_result_artifact(result: Any) -> None:
    try:
        _schema_validate("test-result.v1", result)
        validate_result(result)
    except RunStoreError:
        raise
    except Exception as exc:
        raise _error("RESULT_BINDING_MISMATCH", stage="AGGREGATE") from exc


def _validate_bound_single_suite_seal(
    layout: RunLayout,
    seal: Mapping[str, Any],
    run: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    evidence: Mapping[str, Any],
    result: Mapping[str, Any],
    artifacts: Mapping[str, bytes],
) -> None:
    invocation = _bound_invocation_argv(layout)
    if invocation == _INVOCATION_ARGV:
        validate_fixed_single_suite_seal(
            seal,
            run,
            snapshot,
            evidence,
            artifacts,
        )
        return
    if (
        invocation[:-1] != _CATALOG_COMMAND_ARGV[:-1]
        or run.get("invocation_argv") != invocation
        or evidence.get("test_results")
        != [{
            "suite_id": _SUITE_ID,
            "entrypoint_id": _ENTRYPOINT_ID,
            "path": "results/" + _SUITE_ID + ".json",
            "sha256": sha256_hex(canonical_json_bytes(result)),
        }]
        or result.get("suite_id") != _SUITE_ID
        or result.get("entrypoint_id") != _ENTRYPOINT_ID
        or seal.get("aggregate_decision") != result.get("gate_decision")
        or seal.get("runner_exit") != result.get("runner_exit")
    ):
        raise ValueError("catalog-bound fixed seal")
    validate_completion_seal(
        seal,
        run,
        snapshot,
        evidence,
        artifacts,
    )


def complete_fixed_run(
    layout: RunLayout,
    completed_at: str,
) -> Mapping[str, Any]:
    """Publish result, evidence, then the result-derived terminal seal."""
    if not isinstance(layout, RunLayout):
        raise TypeError("layout must be RunLayout")
    with layout._lock:
        layout._open()
        layout._snapshot_terminal_absent()
        if (
            not layout._fixed_prepare_started
            or layout._fixed_run_publication is None
        ):
            raise _error(
                "PARTIAL_RESULTS", stage="AGGREGATE", run_id=layout.run_id,
            )
        if layout._fixed_completion_started:
            raise _error(
                "REPLAYED_RESULT", stage="AGGREGATE", run_id=layout.run_id,
            )
        snapshot = layout._read_bound_finalized_snapshot()
        run = layout._read_bound_publication(
            layout._fixed_run_publication,
            expected_area="root",
            expected_leaf="run-manifest.json",
            code="RUN_MANIFEST_INVALID",
        )
        snapshot_artifacts = _validate_fixed_run(
            layout,
            run,
            snapshot,
            invocation_argv=_bound_invocation_argv(layout),
        )
        # The completion claim is one-way even when the durable attempt set is
        # missing, malformed, or contradictory.  A late attempt cannot turn an
        # earlier failed completion request into a seal.
        layout._fixed_completion_started = True
        result = _read_attempt_result(layout)
        _validate_result_artifact(result)

        result_publication = _publish(
            layout,
            "results",
            _SUITE_ID + ".json",
            canonical_json_bytes(result),
            failure=False,
        )
        layout._fixed_result_publication = result_publication
        rebound_result = layout._read_bound_publication(
            result_publication,
            expected_area="results",
            expected_leaf=_SUITE_ID + ".json",
            code="RESULT_BINDING_MISMATCH",
        )
        _validate_result_artifact(rebound_result)
        if rebound_result != result:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )

        evidence = {
            "schema": "evidence-manifest.v1",
            "run_id": layout.run_id,
            "run_manifest": {
                "path": layout._fixed_run_publication.path,
                "sha256": layout._fixed_run_publication.sha256,
            },
            "test_results": [{
                "suite_id": _SUITE_ID,
                "entrypoint_id": _ENTRYPOINT_ID,
                "path": result_publication.path,
                "sha256": result_publication.sha256,
            }],
        }
        artifacts = {
            **snapshot_artifacts,
            layout._fixed_run_publication.path: canonical_json_bytes(run),
            result_publication.path: canonical_json_bytes(result),
        }
        try:
            _schema_validate("evidence-manifest.v1", evidence)
            validate_evidence_manifest(evidence, run, artifacts)
        except RunStoreError:
            raise
        except Exception as exc:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            ) from exc
        evidence_publication = _publish(
            layout,
            "root",
            "evidence-manifest.json",
            canonical_json_bytes(evidence),
            failure=False,
        )
        layout._fixed_evidence_publication = evidence_publication
        rebound_evidence = layout._read_bound_publication(
            evidence_publication,
            expected_area="root",
            expected_leaf="evidence-manifest.json",
            code="RESULT_BINDING_MISMATCH",
        )
        artifacts[evidence_publication.path] = canonical_json_bytes(evidence)
        try:
            _schema_validate("evidence-manifest.v1", rebound_evidence)
            validate_evidence_manifest(rebound_evidence, run, artifacts)
        except RunStoreError:
            raise
        except Exception as exc:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            ) from exc
        if rebound_evidence != evidence:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )

        # Final linearization: retain the same layout RLock while all durable
        # inputs are re-read, then reject any terminal conflict and publish the
        # no-clobber seal last.
        closing_snapshot = layout._read_bound_finalized_snapshot()
        closing_run = layout._read_bound_publication(
            layout._fixed_run_publication,
            expected_area="root",
            expected_leaf="run-manifest.json",
            code="RUN_MANIFEST_INVALID",
        )
        closing_result = layout._read_bound_publication(
            layout._fixed_result_publication,
            expected_area="results",
            expected_leaf=_SUITE_ID + ".json",
            code="RESULT_BINDING_MISMATCH",
        )
        closing_evidence = layout._read_bound_publication(
            layout._fixed_evidence_publication,
            expected_area="root",
            expected_leaf="evidence-manifest.json",
            code="RESULT_BINDING_MISMATCH",
        )
        closing_attempt_result = _read_attempt_result(layout)
        if (
            closing_snapshot != snapshot
            or closing_run != run
            or closing_result != result
            or closing_evidence != evidence
            or closing_attempt_result != result
        ):
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="SEAL",
                run_id=layout.run_id,
            )
        layout._snapshot_terminal_absent()
        seal = {
            "schema": "completion-seal.v1",
            "run_id": layout.run_id,
            "run_manifest": {
                "path": layout._fixed_run_publication.path,
                "sha256": layout._fixed_run_publication.sha256,
            },
            "source_snapshot_manifest": run["source_snapshot_manifest"],
            "evidence_manifest": {
                "path": evidence_publication.path,
                "sha256": evidence_publication.sha256,
            },
            "input_digest_set_sha256": sha256_hex(
                canonical_json_bytes(run["input_digests"]),
            ),
            "aggregate_decision": result["gate_decision"],
            "runner_exit": result["runner_exit"],
            "completed_at": completed_at,
        }
        artifacts[evidence_publication.path] = canonical_json_bytes(evidence)
        try:
            _schema_validate("completion-seal.v1", seal)
            _validate_bound_single_suite_seal(
                layout,
                seal,
                run,
                snapshot,
                evidence,
                result,
                artifacts,
            )
        except RunStoreError:
            raise
        except Exception as exc:
            raise _error(
                "AGGREGATE_CONTRACT_INVALID",
                stage="SEAL",
                run_id=layout.run_id,
            ) from exc
        seal_publication = _publish(
            layout,
            "root",
            "completion-seal.json",
            canonical_json_bytes(seal),
            failure=False,
            dedicated_terminal=True,
        )
        layout._fixed_seal_publication = seal_publication
        # The dedicated store path proves these bytes while the leaf is still
        # temporary and uses the exclusive final rename as the last fallible
        # operation.  A visible valid seal therefore cannot coexist with a
        # publication-uncertainty exception.
        return seal
