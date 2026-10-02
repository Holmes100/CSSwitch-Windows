"""Atomic source observation/result/evidence/seal publication."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from test.quality.run_evidence.atomic_store import (
    PublishedJson,
    RunLayout,
    RunStoreError,
    _error,
    _publish,
)
from test.quality.run_evidence.contracts import validate_result
from test.quality.run_evidence.manifest_contracts import (
    canonical_json_bytes,
    sha256_hex,
    validate_completion_seal,
    validate_evidence_manifest,
    validate_run_manifest,
    validate_source_observation,
)
from test.quality.source_gate.contracts import (
    SOURCE_SUITE_ORDER,
    aggregate_results,
    result_from_observation,
)
from test.quality.source_gate.planning import SourceSuitePlan


_SCHEMA_ROOT = Path(__file__).resolve().parents[3] / "quality/schema"
_SCHEMAS = {
    "run-manifest.v1": "run-manifest.v1.schema.json",
    "source-observation.v1": "source-observation.v1.schema.json",
    "test-result.v1": "test-result.v1.schema.json",
    "evidence-manifest.v1": "evidence-manifest.v1.schema.json",
    "completion-seal.v1": "completion-seal.v1.schema.json",
}


def _schema(name: str, value: Any) -> None:
    try:
        schema = json.loads(
            (_SCHEMA_ROOT / _SCHEMAS[name]).read_text("utf-8"),
        )
        Draft202012Validator(schema).validate(value)
    except Exception as exc:
        raise _error(
            "AGGREGATE_CONTRACT_INVALID", stage="AGGREGATE",
        ) from exc


def _snapshot_artifacts(
    layout: RunLayout,
    snapshot: Any,
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


@dataclass
class SourceRunState:
    layout: RunLayout
    plans: tuple[SourceSuitePlan, ...]
    invocation_argv: tuple[str, ...]
    run_publication: PublishedJson
    run_manifest: Any
    observation_publications: list[PublishedJson] = field(
        default_factory=list,
    )
    result_publications: list[PublishedJson] = field(default_factory=list)
    observations: list[Any] = field(default_factory=list)
    results: list[Any] = field(default_factory=list)
    completion_started: bool = False


def _validate_source_run(
    state_or_layout: SourceRunState | RunLayout,
    run_manifest: Any,
    snapshot: Any,
    *,
    plans: tuple[SourceSuitePlan, ...],
    invocation_argv: tuple[str, ...],
) -> dict[str, bytes]:
    layout = (
        state_or_layout.layout
        if isinstance(state_or_layout, SourceRunState)
        else state_or_layout
    )
    artifacts = _snapshot_artifacts(layout, snapshot)
    try:
        _schema("run-manifest.v1", run_manifest)
        bound_snapshot, change = validate_run_manifest(
            run_manifest, artifacts,
        )
    except RunStoreError:
        raise
    except Exception as exc:
        raise _error(
            "RUN_MANIFEST_INVALID",
            stage="PLAN",
            run_id=layout.run_id,
        ) from exc
    expected = [
        {
            "suite_id": plan.suite["id"],
            "entrypoint_id": plan.suite["entrypoint_id"],
        }
        for plan in plans
    ]
    if (
        tuple(item["suite_id"] for item in expected) != SOURCE_SUITE_ORDER
        or run_manifest.get("run_id") != layout.run_id
        or run_manifest.get("profile") != "source"
        or run_manifest.get("head_sha") != snapshot.get("head_sha")
        or run_manifest.get("comparison_base", {}).get("policy")
        != "merge-base-origin-main"
        or run_manifest.get("source_snapshot_manifest")
        != {
            "path": layout._finalized_snapshot_binding.publication.path,
            "sha256": layout._finalized_snapshot_binding.publication.sha256,
        }
        or snapshot.get("snapshot_mode") != "clean-commit"
        or change is not None
        or bound_snapshot != snapshot
        or run_manifest.get("change_set") is not None
        or run_manifest.get("invocation_argv") != list(invocation_argv)
        or run_manifest.get("expected_suites") != expected
    ):
        raise _error(
            "RUN_MANIFEST_INVALID",
            stage="PLAN",
            run_id=layout.run_id,
        )
    return artifacts


def prepare_source_run(
    layout: RunLayout,
    run_manifest: Any,
    *,
    plans: tuple[SourceSuitePlan, ...],
    invocation_argv: tuple[str, ...],
) -> SourceRunState:
    if (
        not isinstance(layout, RunLayout)
        or not isinstance(plans, tuple)
        or len(plans) != len(SOURCE_SUITE_ORDER)
        or not isinstance(invocation_argv, tuple)
        or len(invocation_argv) != 6
        or invocation_argv[:5]
        != (
            "/usr/bin/python3",
            "-I",
            "test/quality/source_gate/cli.py",
            "run",
            "--output-root",
        )
        or not invocation_argv[5].startswith("/")
        or invocation_argv[5] == "/"
    ):
        raise _error("RUN_MANIFEST_INVALID", stage="PLAN")
    with layout._lock:
        layout._open()
        layout._snapshot_terminal_absent()
        snapshot = layout._read_bound_finalized_snapshot()
        _validate_source_run(
            layout,
            run_manifest,
            snapshot,
            plans=plans,
            invocation_argv=invocation_argv,
        )
        publication = _publish(
            layout,
            "root",
            "run-manifest.json",
            canonical_json_bytes(run_manifest),
            failure=False,
        )
        rebound = layout._read_bound_publication(
            publication,
            expected_area="root",
            expected_leaf="run-manifest.json",
            code="RUN_MANIFEST_INVALID",
        )
        closing_snapshot = layout._read_bound_finalized_snapshot()
        _validate_source_run(
            layout,
            rebound,
            closing_snapshot,
            plans=plans,
            invocation_argv=invocation_argv,
        )
        if rebound != run_manifest or closing_snapshot != snapshot:
            raise _error(
                "RUN_MANIFEST_INVALID",
                stage="PLAN",
                run_id=layout.run_id,
            )
        return SourceRunState(
            layout,
            plans,
            invocation_argv,
            publication,
            rebound,
        )


def publish_source_pair(
    state: SourceRunState,
    observation: Any,
    result: Any,
) -> None:
    layout = state.layout
    with layout._lock:
        layout._open()
        layout._snapshot_terminal_absent()
        index = len(state.observations)
        if (
            state.completion_started
            or index >= len(state.plans)
            or len(state.results) != index
            or len(state.observation_publications) != index
            or len(state.result_publications) != index
        ):
            raise _error(
                "REPLAYED_RESULT",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )
        plan = state.plans[index]
        try:
            _schema("source-observation.v1", observation)
            validate_source_observation(observation)
            _schema("test-result.v1", result)
            validate_result(result)
            expected_result = result_from_observation(
                observation,
                expected_suite_id=plan.suite["id"],
                expected_entrypoint_id=plan.suite["entrypoint_id"],
                expected_test_ids=plan.expected_test_ids,
                approved_skipped_ids=plan.approved_skipped_test_ids,
                approved_ignored_ids=plan.approved_ignored_test_ids,
            )
        except RunStoreError:
            raise
        except Exception as exc:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            ) from exc
        if (
            observation.get("run_id") != layout.run_id
            or observation.get("command_argv_sha256")
            != plan.command_argv_sha256
            or observation.get("environment_sha256")
            != plan.environment_sha256
            or observation.get("tool_identity_sha256")
            != plan.tool_identity_sha256
            or result != expected_result
        ):
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )
        observation_leaf = plan.suite["id"] + ".observation.json"
        observation_publication = _publish(
            layout,
            "results",
            observation_leaf,
            canonical_json_bytes(observation),
            failure=False,
        )
        rebound_observation = layout._read_bound_publication(
            observation_publication,
            expected_area="results",
            expected_leaf=observation_leaf,
            code="RESULT_BINDING_MISMATCH",
        )
        _schema("source-observation.v1", rebound_observation)
        validate_source_observation(rebound_observation)
        if rebound_observation != observation:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )
        result_leaf = plan.suite["id"] + ".json"
        result_publication = _publish(
            layout,
            "results",
            result_leaf,
            canonical_json_bytes(result),
            failure=False,
        )
        rebound_result = layout._read_bound_publication(
            result_publication,
            expected_area="results",
            expected_leaf=result_leaf,
            code="RESULT_BINDING_MISMATCH",
        )
        _schema("test-result.v1", rebound_result)
        validate_result(rebound_result)
        if rebound_result != result:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )
        state.observation_publications.append(observation_publication)
        state.result_publications.append(result_publication)
        state.observations.append(rebound_observation)
        state.results.append(rebound_result)


def _reread_pairs(
    state: SourceRunState,
) -> tuple[list[Any], list[Any]]:
    observations = []
    results = []
    for plan, observation_publication, result_publication in zip(
        state.plans,
        state.observation_publications,
        state.result_publications,
    ):
        observation_leaf = plan.suite["id"] + ".observation.json"
        result_leaf = plan.suite["id"] + ".json"
        observation = state.layout._read_bound_publication(
            observation_publication,
            expected_area="results",
            expected_leaf=observation_leaf,
            code="RESULT_BINDING_MISMATCH",
        )
        result = state.layout._read_bound_publication(
            result_publication,
            expected_area="results",
            expected_leaf=result_leaf,
            code="RESULT_BINDING_MISMATCH",
        )
        _schema("source-observation.v1", observation)
        validate_source_observation(observation)
        _schema("test-result.v1", result)
        validate_result(result)
        expected_result = result_from_observation(
            observation,
            expected_suite_id=plan.suite["id"],
            expected_entrypoint_id=plan.suite["entrypoint_id"],
            expected_test_ids=plan.expected_test_ids,
            approved_skipped_ids=plan.approved_skipped_test_ids,
            approved_ignored_ids=plan.approved_ignored_test_ids,
        )
        if result != expected_result:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=state.layout.run_id,
            )
        observations.append(observation)
        results.append(result)
    return observations, results


def complete_source_run(
    state: SourceRunState,
    *,
    completed_at: str,
    pre_seal_recheck=None,
) -> Any:
    layout = state.layout
    with layout._lock:
        layout._open()
        layout._snapshot_terminal_absent()
        if state.completion_started:
            raise _error(
                "REPLAYED_RESULT",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )
        state.completion_started = True
        if (
            len(state.plans) != len(SOURCE_SUITE_ORDER)
            or len(state.observations) != len(state.plans)
            or len(state.results) != len(state.plans)
            or len(state.observation_publications) != len(state.plans)
            or len(state.result_publications) != len(state.plans)
        ):
            raise _error(
                "PARTIAL_RESULTS",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )
        snapshot = layout._read_bound_finalized_snapshot()
        run = layout._read_bound_publication(
            state.run_publication,
            expected_area="root",
            expected_leaf="run-manifest.json",
            code="RUN_MANIFEST_INVALID",
        )
        artifacts = _validate_source_run(
            state,
            run,
            snapshot,
            plans=state.plans,
            invocation_argv=state.invocation_argv,
        )
        observations, results = _reread_pairs(state)
        if observations != state.observations or results != state.results:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )
        evidence = {
            "schema": "evidence-manifest.v1",
            "run_id": layout.run_id,
            "run_manifest": {
                "path": state.run_publication.path,
                "sha256": state.run_publication.sha256,
            },
            "test_results": [
                {
                    "suite_id": plan.suite["id"],
                    "entrypoint_id": plan.suite["entrypoint_id"],
                    "path": publication.path,
                    "sha256": publication.sha256,
                }
                for plan, publication in zip(
                    state.plans, state.result_publications,
                )
            ],
            "source_observations": [
                {
                    "suite_id": plan.suite["id"],
                    "entrypoint_id": plan.suite["entrypoint_id"],
                    "path": publication.path,
                    "sha256": publication.sha256,
                }
                for plan, publication in zip(
                    state.plans,
                    state.observation_publications,
                )
            ],
        }
        artifacts[state.run_publication.path] = canonical_json_bytes(run)
        for publication, value in zip(
            state.observation_publications, observations,
        ):
            artifacts[publication.path] = canonical_json_bytes(value)
        for publication, value in zip(
            state.result_publications, results,
        ):
            artifacts[publication.path] = canonical_json_bytes(value)
        try:
            _schema("evidence-manifest.v1", evidence)
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
        rebound_evidence = layout._read_bound_publication(
            evidence_publication,
            expected_area="root",
            expected_leaf="evidence-manifest.json",
            code="RESULT_BINDING_MISMATCH",
        )
        artifacts[evidence_publication.path] = canonical_json_bytes(evidence)
        _schema("evidence-manifest.v1", rebound_evidence)
        validate_evidence_manifest(rebound_evidence, run, artifacts)
        if rebound_evidence != evidence:
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="AGGREGATE",
                run_id=layout.run_id,
            )

        # Closing read: every authority-bearing input is rebound under the
        # layout lock immediately before the terminal publication.
        closing_snapshot = layout._read_bound_finalized_snapshot()
        closing_run = layout._read_bound_publication(
            state.run_publication,
            expected_area="root",
            expected_leaf="run-manifest.json",
            code="RUN_MANIFEST_INVALID",
        )
        closing_observations, closing_results = _reread_pairs(state)
        closing_evidence = layout._read_bound_publication(
            evidence_publication,
            expected_area="root",
            expected_leaf="evidence-manifest.json",
            code="RESULT_BINDING_MISMATCH",
        )
        if (
            closing_snapshot != snapshot
            or closing_run != run
            or closing_observations != observations
            or closing_results != results
            or closing_evidence != evidence
        ):
            raise _error(
                "RESULT_BINDING_MISMATCH",
                stage="SEAL",
                run_id=layout.run_id,
            )
        _validate_source_run(
            state,
            closing_run,
            closing_snapshot,
            plans=state.plans,
            invocation_argv=state.invocation_argv,
        )
        decision, runner_exit = aggregate_results(closing_results)
        seal = {
            "schema": "completion-seal.v1",
            "run_id": layout.run_id,
            "run_manifest": {
                "path": state.run_publication.path,
                "sha256": state.run_publication.sha256,
            },
            "source_snapshot_manifest": run["source_snapshot_manifest"],
            "evidence_manifest": {
                "path": evidence_publication.path,
                "sha256": evidence_publication.sha256,
            },
            "input_digest_set_sha256": sha256_hex(
                canonical_json_bytes(run["input_digests"]),
            ),
            "aggregate_decision": decision,
            "runner_exit": runner_exit,
            "completed_at": completed_at,
        }
        _schema("completion-seal.v1", seal)
        validate_completion_seal(
            seal,
            closing_run,
            closing_snapshot,
            closing_evidence,
            artifacts,
        )
        if pre_seal_recheck is not None:
            pre_seal_recheck()
        layout._snapshot_terminal_absent()
        _publish(
            layout,
            "root",
            "completion-seal.json",
            canonical_json_bytes(seal),
            failure=False,
            dedicated_terminal=True,
        )
        return seal
