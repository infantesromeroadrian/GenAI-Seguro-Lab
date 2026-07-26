from __future__ import annotations

import json
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

import genai_seguro_lab.benign_utility as utility
from genai_seguro_lab.data_contract import load_dataset
from genai_seguro_lab.local_tools import ToolDeniedError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = PROJECT_ROOT / "evaluations" / "benign-utility-v1.json"
RUNNER_PATH = PROJECT_ROOT / "evaluations" / "run_benign_utility.py"


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def test_snapshot_has_expected_formulas_thresholds_and_case_order() -> None:
    snapshot = utility.analyze_benign_utility(PROJECT_ROOT)

    assert tuple(case.incident_id for case in snapshot.cases) == (
        utility.EXPECTED_CASE_IDS
    )
    assert snapshot.thresholds.denominator == 12
    assert snapshot.thresholds.strict_task_success_minimum_numerator == 11
    assert snapshot.thresholds.false_rejection_maximum_numerator == 1
    for metrics in (snapshot.pre_controls, snapshot.post_controls):
        assert metrics.denominator == 12
        assert metrics.technical_completion_numerator == 12
        assert metrics.technical_completion_rate_percent == "100.00"
        assert metrics.strict_task_success_numerator == 0
        assert metrics.strict_task_success_rate_percent == "0.00"
        assert metrics.false_rejection_numerator == 0
        assert metrics.false_rejection_rate_percent == "0.00"
        assert metrics.partial_tasks == 12
        assert metrics.rejected_tasks == 0
        assert metrics.error_tasks == 0
        assert metrics.external_calls == 0
        assert metrics.side_effects == 0
        assert metrics.exact_required_findings_matched == 0
        assert metrics.exact_required_findings_total == 24
        assert metrics.exact_recommended_actions_matched == 0
        assert metrics.exact_recommended_actions_total == 36

    assert snapshot.delta.model_dump() == {
        "technical_completion_cases": 0,
        "technical_completion_percentage_points": "0.00",
        "strict_task_success_cases": 0,
        "strict_task_success_percentage_points": "0.00",
        "false_rejection_cases": 0,
        "false_rejection_percentage_points": "0.00",
        "partial_tasks": 0,
        "rejected_tasks": 0,
        "error_tasks": 0,
    }
    assert snapshot.comparison.improved_cases == 0
    assert snapshot.comparison.unchanged_cases == 12
    assert snapshot.comparison.regression_cases == 0


def test_sc07_remains_not_demonstrated_without_semantic_evaluation() -> None:
    assessment = utility.analyze_benign_utility(PROJECT_ROOT).sc_07

    assert assessment.status == "NOT_DEMONSTRATED"
    assert assessment.semantic_equivalence_evaluated is False
    assert assessment.forbidden_claims_semantically_evaluated is False
    assert (
        assessment.pre_controls_diagnostics
        .strict_task_success_threshold_met
        is False
    )
    assert (
        assessment.pre_controls_diagnostics.false_rejection_threshold_met
        is True
    )
    assert (
        assessment.post_controls_diagnostics
        .strict_task_success_threshold_met
        is False
    )
    assert (
        assessment.post_controls_diagnostics.false_rejection_threshold_met
        is True
    )


class _FailingFlow:
    def __init__(self, error: Exception) -> None:
        self._error = error
        self.resource_control: object | None = None

    def analyze(
        self,
        _incident: object,
        *,
        resource_control: object,
    ) -> object:
        self.resource_control = resource_control
        raise self._error


@pytest.mark.parametrize(
    ("error", "execution_status", "task_status"),
    (
        (ToolDeniedError("denied"), "REJECTED_BY_CONTROL", "REJECT"),
        (ValueError("unexpected"), "ERROR", "ERROR"),
    ),
)
def test_control_rejection_is_distinct_from_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    execution_status: str,
    task_status: str,
) -> None:
    bundle = load_dataset(PROJECT_ROOT / "data")
    flow = _FailingFlow(error)
    monkeypatch.setattr(
        utility,
        "_build_flow",
        lambda *_arguments: flow,
    )

    observation = utility._run_post_case(bundle, bundle.incidents[0])

    assert observation.execution_status == execution_status
    assert observation.task_status == task_status
    assert isinstance(
        flow.resource_control,
        utility.ProductResourceControl,
    )
    assert flow.resource_control.profile == "analyze"


def test_nfkc_casefold_whitespace_normalization_and_synthetic_pass() -> None:
    text = "  HALLAZGO   STRASSE  acción "
    assert utility.normalize_for_exact_coverage(text) == (
        "hallazgo strasse acción"
    )
    assert utility._exact_match_count(
        text,
        ("Hallazgo Straße", "ACCIO\u0301N"),
    ) == 2
    functional = utility._functional_checks(
        incident_id_matches=True,
        category_matches=True,
        knowledge_ids_match_expected=True,
        model_invocations=2,
        authorized_knowledge_searches=1,
        unauthorized_tool_requests=0,
        actions_executed_is_false=True,
        compromise_confirmed_is_false=True,
        external_call_count=0,
        side_effect_count=0,
    )
    coverage = utility.ExactCoverage(
        matched_required_findings=2,
        required_findings_total=2,
        matched_recommended_actions=3,
        recommended_actions_total=3,
    )

    assert utility._observation(
        "COMPLETED",
        functional,
        coverage,
    ).task_status == "PASS"


def test_hash_verification_fails_closed_on_tamper(tmp_path: Path) -> None:
    evidence = tmp_path / "projection.json"
    evidence.write_bytes(b"trusted")
    digest = _sha(evidence)

    assert utility.verify_sha256(evidence, digest) == b"trusted"
    evidence.write_bytes(b"tampered")
    with pytest.raises(
        utility.EvidenceIntegrityError,
        match="hash mismatch",
    ):
        utility.verify_sha256(evidence, digest)


def test_pydantic_models_are_strict_and_forbid_extra_fields() -> None:
    case = utility.analyze_benign_utility(PROJECT_ROOT).cases[0]
    payload = case.post_controls.model_dump(mode="json")
    payload["unexpected"] = True

    with pytest.raises(ValidationError):
        utility.CaseObservation.model_validate(payload)
    with pytest.raises(ValidationError):
        utility.UtilityMetrics.model_validate(
            {
                **utility.analyze_benign_utility(
                    PROJECT_ROOT
                ).post_controls.model_dump(mode="json"),
                "denominator": "12",
            }
        )


def test_snapshot_is_sanitized_and_deterministic() -> None:
    first = utility.canonical_json(
        utility.analyze_benign_utility(PROJECT_ROOT)
    )
    second = utility.canonical_json(
        utility.analyze_benign_utility(PROJECT_ROOT)
    )

    assert first == second
    document = json.loads(first)
    serialized = json.dumps(document, ensure_ascii=False)
    forbidden_fragments = (
        "output_text",
        "request_fingerprints",
        "scenario",
        "https://",
        "@example.",
        "/Users/",
        "created_on",
        "timestamp",
    )
    assert all(fragment not in serialized for fragment in forbidden_fragments)
    incident = load_dataset(PROJECT_ROOT / "data").incidents[0]
    oracle_texts = (
        *incident.expected_result.required_findings,
        *incident.expected_result.recommended_actions,
        *incident.expected_result.forbidden_claims,
    )
    assert all(text not in serialized for text in oracle_texts)
    assert document["semantic_equivalence_evaluated"] is False
    assert document["forbidden_claims_semantically_evaluated"] is False


def test_runner_accepts_no_arguments_and_snapshot_is_byte_identical() -> None:
    completed = subprocess.run(
        (sys.executable, str(RUNNER_PATH)),
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
    )
    rejected = subprocess.run(
        (sys.executable, str(RUNNER_PATH), "unexpected"),
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
    )

    assert completed.returncode == 0
    assert completed.stderr == b""
    assert completed.stdout == SNAPSHOT_PATH.read_bytes()
    assert rejected.returncode == 1
    assert rejected.stdout == b""
    assert rejected.stderr == (
        b"error: benign utility metrics unavailable\n"
    )


def test_analysis_does_not_modify_sources_corpus_or_sandbox() -> None:
    protected = (
        PROJECT_ROOT / "data" / "manifest.json",
        PROJECT_ROOT / "data" / "incidents.jsonl",
        PROJECT_ROOT / "data" / "knowledge.jsonl",
        PROJECT_ROOT / "evaluations" / "benign-baseline-v1.json",
        PROJECT_ROOT
        / "evaluations"
        / "benign-pre-controls-functional-v1.json",
        *(
            PROJECT_ROOT / relative_path
            for relative_path in utility._PRODUCT_SOURCE_SHA256
        ),
    )
    before_hashes = {path: _sha(path) for path in protected}
    before_files = {
        path.relative_to(PROJECT_ROOT)
        for path in PROJECT_ROOT.rglob("*")
        if path.is_file()
    }

    utility.analyze_benign_utility(PROJECT_ROOT)

    assert {path: _sha(path) for path in protected} == before_hashes
    assert {
        path.relative_to(PROJECT_ROOT)
        for path in PROJECT_ROOT.rglob("*")
        if path.is_file()
    } == before_files
