"""Pruebas del runner neutral de retest adversario."""

from __future__ import annotations

import json
import platform
import importlib.util
from datetime import datetime, timezone
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path

import pytest
from pydantic import ValidationError

import genai_seguro_lab.adversarial_retest as adversarial_retest
from genai_seguro_lab.adversarial_baseline import _CaseExecution
from genai_seguro_lab.adversarial_retest import (
    CANONICAL_CASE_IDS,
    AdversarialRetestAuthorization,
    AdversarialRetestError,
    CandidateSnapshot,
    RuntimeFileSnapshot,
    RuntimeSnapshot,
    canonical_json,
    canonical_jsonl,
    default_adversarial_retest_authorization,
    run_adversarial_retest,
    write_adversarial_retest_artifacts,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def authorization() -> AdversarialRetestAuthorization:
    return default_adversarial_retest_authorization()


@pytest.fixture
def candidate() -> CandidateSnapshot:
    return CandidateSnapshot(
        commit="1" * 40,
        tree="2" * 40,
        branch="main",
        clean_before_run=True,
        posture="hardened_checkout",
    )


@pytest.fixture
def runtime() -> RuntimeSnapshot:
    uv_lock = ROOT / "uv.lock"
    return RuntimeSnapshot(
        python=platform.python_version(),
        uv="0.6.10",
        pydantic=version("pydantic"),
        platform="darwin",
        uv_lock=RuntimeFileSnapshot(
            path="$REPO/uv.lock",
            sha256=sha256(uv_lock.read_bytes()).hexdigest(),
            bytes=uv_lock.stat().st_size,
        ),
        external_calls=False,
        cost_eur="0.00",
    )


def _run(
    tmp_path: Path,
    *,
    authorization: AdversarialRetestAuthorization,
    candidate: CandidateSnapshot,
    runtime: RuntimeSnapshot,
    candidate_unchanged: bool = True,
) -> tuple[adversarial_retest.AdversarialRetestArtifacts, Path]:
    run_root = tmp_path / "adversarial-retest-v1"
    run_root.mkdir()
    artifacts = run_adversarial_retest(
        repository_root=ROOT,
        run_root=run_root,
        candidate=candidate,
        runtime=runtime,
        run_id="GSL-ADV-RT-20260726-001",
        executed_at_utc=datetime(2026, 7, 26, 12, tzinfo=timezone.utc),
        sanitized_command=(
            "uv",
            "run",
            "--frozen",
            "python",
            "evaluations/run_adversarial_retest.py",
            "--run-root",
            "$TMP/adversarial-retest-v1",
        ),
        authorization=authorization,
        verify_candidate_unchanged=lambda: candidate_unchanged,
    )
    return artifacts, run_root


def test_authorization_is_exact_neutral_and_rejects_broader_scope(
    authorization: AdversarialRetestAuthorization,
) -> None:
    assert authorization.case_ids == CANONICAL_CASE_IDS
    assert len(authorization.case_ids) == 14
    assert authorization.source_profile == "GSL-PROFILE-VULNERABLE-001"
    assert authorization.candidate_posture == "hardened_checkout"
    assert authorization.max_target_processes == 1
    assert authorization.max_effect_files_per_run == 1
    assert authorization.retry_count == 0

    with pytest.raises(ValidationError):
        AdversarialRetestAuthorization.model_validate(
            {
                **authorization.model_dump(),
                "external_network": True,
            }
        )


def test_live_retest_preserves_scope_and_emits_only_neutral_observations(
    tmp_path: Path,
    authorization: AdversarialRetestAuthorization,
    candidate: CandidateSnapshot,
    runtime: RuntimeSnapshot,
) -> None:
    artifacts, run_root = _run(
        tmp_path,
        authorization=authorization,
        candidate=candidate,
        runtime=runtime,
    )

    assert tuple(case.case_id for case in artifacts.results.cases) == (
        CANONICAL_CASE_IDS
    )
    assert artifacts.results.summary.total_cases == 14
    assert artifacts.results.summary.completed_cases == 14
    assert artifacts.results.summary.stopped_cases == 0
    assert artifacts.results.summary.error_cases == 0
    assert artifacts.results.summary.inert_cases_executed == 0
    assert len(artifacts.events) == 16
    assert artifacts.events[0].event == "run_started"
    assert artifacts.events[-1].event == "run_completed"
    assert all(
        case.execution_status == "COMPLETED"
        for case in artifacts.results.cases
    )

    tol005 = next(
        case
        for case in artifacts.results.cases
        if case.case_id == "ADV-TOL-005"
    )
    assert (
        tol005.observed_outcome,
        tol005.observed_tool_decision,
        tol005.observed_effect,
        tol005.oracle_relation,
    ) == ("rejected", "reject", "none", "DIFF")
    assert artifacts.configuration.corpus.oracles_delivered_to_target is False
    assert (
        artifacts.configuration.authorization.source_profile
        == "GSL-PROFILE-VULNERABLE-001"
    )
    assert artifacts.configuration.candidate.posture == "hardened_checkout"
    assert artifacts.configuration.final_retest is False
    assert artifacts.results.final_retest is False

    comparable = (
        artifacts.configuration.corpus.byte_identical_content_files
    )
    assert len(comparable) == 5
    assert all(file.relation == "BYTE_IDENTICAL" for file in comparable)
    manifest = artifacts.configuration.corpus.adversarial_manifest
    assert (
        manifest.historical_version,
        manifest.candidate_version,
        manifest.relation,
    ) == ("1.3.0", "1.4.0", "METADATA_ONLY_DRIFT_DECLARED")
    assert len(manifest.content_identity_scope) == 5
    assert len(artifacts.results.corpus_integrity.files) == 6
    assert all(
        file.before_sha256 == file.after_sha256 and file.unchanged
        for file in artifacts.results.corpus_integrity.files
    )

    serialized = (
        canonical_json(artifacts.configuration)
        + canonical_json(artifacts.results)
        + canonical_jsonl(artifacts.events)
    )
    lowered = serialized.casefold()
    assert str(ROOT).casefold() not in lowered
    assert str(run_root).casefold() not in lowered
    assert "/users/" not in lowered
    for forbidden_field in (
        '"payload',
        '"output',
        '"stdout',
        '"stderr',
        '"traceback',
        '"canary',
        '"credential',
        '"model_invocations"',
        '"tool_requests"',
        '"effect_files"',
    ):
        assert forbidden_field not in lowered
    for evaluative_label in ("PASS", "FAIL", "MITIGATED"):
        assert evaluative_label not in serialized


def test_writer_is_create_only_and_manifest_hashes_the_closed_projection(
    tmp_path: Path,
    authorization: AdversarialRetestAuthorization,
    candidate: CandidateSnapshot,
    runtime: RuntimeSnapshot,
) -> None:
    artifacts, run_root = _run(
        tmp_path,
        authorization=authorization,
        candidate=candidate,
        runtime=runtime,
    )
    output_dir = run_root / "reviewed"
    manifest = write_adversarial_retest_artifacts(
        artifacts=artifacts,
        output_dir=output_dir,
    )

    assert tuple(file.path for file in manifest.files) == (
        "config.json",
        "results.json",
        "events.jsonl",
    )
    assert manifest.reviewed_for_versioning is False
    assert manifest.final_retest is False
    config_bytes = (output_dir / "config.json").read_bytes()
    results = json.loads(
        (output_dir / "results.json").read_text(encoding="utf-8")
    )
    assert results["configuration_sha256"] == sha256(config_bytes).hexdigest()
    for file in manifest.files:
        path = output_dir / file.path
        assert path.stat().st_size == file.bytes
        assert sha256(path.read_bytes()).hexdigest() == file.sha256
    assert all(
        (output_dir / name).stat().st_mode & 0o777 == 0o600
        for name in (
            "config.json",
            "results.json",
            "events.jsonl",
            "manifest.json",
        )
    )

    with pytest.raises(
        AdversarialRetestError,
        match="must not already exist",
    ):
        write_adversarial_retest_artifacts(
            artifacts=artifacts,
            output_dir=output_dir,
        )


def test_case_errors_are_recorded_without_messages_or_oracle_evaluation(
    tmp_path: Path,
    authorization: AdversarialRetestAuthorization,
    candidate: CandidateSnapshot,
    runtime: RuntimeSnapshot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def execute_case(**kwargs: object) -> _CaseExecution:
        record = kwargs["record"]
        if getattr(record, "id") == "ADV-PI-001":
            raise RuntimeError("sensitive content must never be serialized")
        return _CaseExecution(
            observation_type="SyntheticObservation",
            observation={
                "external_calls": False,
                "effect_files_created": 0,
            },
            within_time_budget=getattr(record, "id") != "ADV-PI-002",
        )

    monkeypatch.setattr(adversarial_retest, "_execute_case", execute_case)
    monkeypatch.setattr(
        adversarial_retest,
        "_observed_contract",
        lambda *_: ("rejected", "reject", "none"),
    )
    artifacts, _ = _run(
        tmp_path,
        authorization=authorization,
        candidate=candidate,
        runtime=runtime,
    )

    first = artifacts.results.cases[0]
    assert first.execution_status == "ERROR"
    assert first.oracle_relation == "NOT_EVALUATED"
    assert (
        first.observed_outcome,
        first.observed_tool_decision,
        first.observed_effect,
    ) == ("not_observed", "not_observed", "not_observed")
    assert first.error_category == "execution_error"
    serialized = canonical_json(artifacts.results)
    assert "sensitive content" not in serialized
    assert artifacts.results.summary.error_cases == 1
    assert artifacts.results.summary.stopped_cases == 1
    assert artifacts.results.summary.completed_cases == 12
    assert artifacts.results.summary.status == "ERROR"
    assert artifacts.results.cases[1].execution_status == "STOPPED"
    assert artifacts.events[-1].execution_status == "ERROR"


def test_stopped_case_sets_stopped_run_status_without_oracle_evaluation(
    tmp_path: Path,
    authorization: AdversarialRetestAuthorization,
    candidate: CandidateSnapshot,
    runtime: RuntimeSnapshot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def execute_case(**_: object) -> _CaseExecution:
        nonlocal calls
        calls += 1
        return _CaseExecution(
            observation_type="SyntheticObservation",
            observation={
                "external_calls": False,
                "effect_files_created": 0,
            },
            within_time_budget=calls != 1,
        )

    monkeypatch.setattr(adversarial_retest, "_execute_case", execute_case)
    monkeypatch.setattr(
        adversarial_retest,
        "_observed_contract",
        lambda *_: ("rejected", "reject", "none"),
    )
    artifacts, _ = _run(
        tmp_path,
        authorization=authorization,
        candidate=candidate,
        runtime=runtime,
    )

    assert artifacts.results.summary.status == "STOPPED"
    assert artifacts.results.summary.completed_cases == 13
    assert artifacts.results.summary.stopped_cases == 1
    assert artifacts.results.summary.error_cases == 0
    assert artifacts.results.cases[0].oracle_relation == "NOT_EVALUATED"
    assert artifacts.events[-1].execution_status == "STOPPED"


def test_candidate_drift_is_terminal_after_the_single_case_sequence(
    tmp_path: Path,
    authorization: AdversarialRetestAuthorization,
    candidate: CandidateSnapshot,
    runtime: RuntimeSnapshot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        adversarial_retest,
        "_execute_case",
        lambda **_: _CaseExecution(
            observation_type="SyntheticObservation",
            observation={
                "external_calls": False,
                "effect_files_created": 0,
            },
            within_time_budget=True,
        ),
    )
    monkeypatch.setattr(
        adversarial_retest,
        "_observed_contract",
        lambda *_: ("rejected", "reject", "none"),
    )
    with pytest.raises(
        AdversarialRetestError,
        match="candidate checkout changed",
    ):
        _run(
            tmp_path,
            authorization=authorization,
            candidate=candidate,
            runtime=runtime,
            candidate_unchanged=False,
        )


def test_historical_evidence_manifest_requires_the_pinned_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_regular_file = adversarial_retest._read_regular_file

    def tampered_manifest(path: Path) -> bytes:
        content = read_regular_file(path)
        if (
            path.name == "manifest.json"
            and path.parent.name == "adversarial-baseline-v1"
        ):
            return content + b" "
        return content

    monkeypatch.setattr(
        adversarial_retest,
        "_read_regular_file",
        tampered_manifest,
    )
    with pytest.raises(
        AdversarialRetestError,
        match="does not match its pinned hash",
    ):
        adversarial_retest._verify_historical_baseline(ROOT)


def test_metadata_drift_declaration_requires_the_known_current_manifest_hash() -> None:
    historical = adversarial_retest._verify_historical_baseline(ROOT)
    corpus = adversarial_retest.load_adversarial_corpus(
        ROOT / "data" / "adversarial"
    )
    current_hashes = adversarial_retest._current_corpus_hashes(ROOT)
    current_hashes[adversarial_retest.CURRENT_MANIFEST_PATH] = "0" * 64

    with pytest.raises(
        AdversarialRetestError,
        match="does not expose the declared metadata drift",
    ):
        adversarial_retest._compare_corpus(
            repository_root=ROOT,
            corpus=corpus,
            current_hashes=current_hashes,
            historical=historical,
        )


def test_cli_writes_diagnostic_evidence_before_nonzero_error_exit(
    tmp_path: Path,
    authorization: AdversarialRetestAuthorization,
    candidate: CandidateSnapshot,
    runtime: RuntimeSnapshot,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        adversarial_retest,
        "_execute_case",
        lambda **_: (_ for _ in ()).throw(RuntimeError("not serialized")),
    )
    artifacts, _ = _run(
        tmp_path,
        authorization=authorization,
        candidate=candidate,
        runtime=runtime,
    )
    runner_path = ROOT / "evaluations" / "run_adversarial_retest.py"
    spec = importlib.util.spec_from_file_location(
        "test_run_adversarial_retest",
        runner_path,
    )
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    monkeypatch.setattr(
        runner,
        "_candidate_snapshot",
        lambda **_: candidate,
    )
    monkeypatch.setattr(
        runner,
        "run_adversarial_retest",
        lambda **_: artifacts,
    )
    cli_root = tmp_path / "cli-diagnostic"
    cli_root.mkdir()

    returncode = runner.main(
        (
            "--expected-commit",
            candidate.commit,
            "--expected-tree",
            candidate.tree,
            "--expected-branch",
            candidate.branch,
            "--run-id",
            artifacts.configuration.run_id,
            "--executed-at-utc",
            "2026-07-26T12:00:00Z",
            "--uv-version",
            "0.6.10",
            "--run-root",
            str(cli_root),
        )
    )

    assert returncode == 2
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["status"] == "ERROR"
    assert (cli_root / "reviewed" / "manifest.json").is_file()


def test_historical_runner_and_evidence_remain_byte_identical() -> None:
    expected_hashes = {
        "src/genai_seguro_lab/adversarial_baseline.py": (
            "1e64075c1e6958babe222e9c78de6d5033d4777334247a74c41e9557fdd7996c"
        ),
        "evaluations/run_adversarial_baseline.py": (
            "2fb69dfa924bb5cfa12b27512bcf6e0f4a5800217edd4f016bfedaa8f789cc9f"
        ),
        "evaluations/adversarial-baseline-v1/README.md": (
            "fbd04499b0b2ee601bf56e23c4d66e0b85177dffe6672ac69f514e87a2b25497"
        ),
        "evaluations/adversarial-baseline-v1/config.json": (
            "e570b6c5f6776034036cc118a85c476ea4316055259c43002e23de019c323319"
        ),
        "evaluations/adversarial-baseline-v1/events.jsonl": (
            "b3e0819dd2322ece607c76909037bb11f966c1b2062347f247fd833fd3c8de43"
        ),
        "evaluations/adversarial-baseline-v1/manifest.json": (
            "c7b96d964dc5ba40f5b53895486ef59bf833992c5393a9967449b98ba80eae45"
        ),
        "evaluations/adversarial-baseline-v1/results.json": (
            "8b0401fcd5897ba8985d4e0acf72daa0792acae6e9efcb30966425c3cbc4f760"
        ),
    }
    assert {
        path: sha256((ROOT / path).read_bytes()).hexdigest()
        for path in expected_hashes
    } == expected_hashes
