"""Pruebas del registro estático y su verificador offline."""

from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from genai_seguro_lab.control_findings import (
    REGISTER_PATH,
    SOURCE_IDENTITIES,
    ControlFindingsError,
    ControlFindingsRegister,
    canonical_json,
    verify_control_findings,
)

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "evaluations" / "verify_control_findings.py"


def test_register_has_six_disjoint_findings_and_derived_summary() -> None:
    register = _load_register(ROOT)

    assert tuple(item.finding_id for item in register.findings) == (
        "CF-001",
        "CF-002",
        "CF-003",
        "CF-004",
        "CF-005",
        "CF-006",
    )
    assert register.summary.model_dump() == {
        "total_findings": 6,
        "control_failures": 0,
        "historical_bypasses": 1,
        "current_control_failures_observed_in_measured_scope": 0,
        "current_bypasses_observed_in_measured_scope": 0,
        "negative_results": 2,
        "evidence_gaps": 3,
        "m06_review_candidates": 1,
        "declared_adversarial_cases": 18,
        "measured_adversarial_cases": 14,
        "source_final_retest": False,
    }
    assert len({item.condition_code for item in register.findings}) == 6


def test_policy_does_not_promote_partial_or_missing_evidence_to_failure() -> None:
    register = _load_register(ROOT)
    policy = register.classification_policy

    assert policy.partial_control_is_failure is False
    assert policy.inert_fixture_is_failure is False
    assert policy.not_demonstrated_is_failure is False
    assert policy.not_computable_means_zero is False
    assert policy.overhead_without_threshold_is_defect is False
    assert (
        policy.current_absence_scope
        == "ONLY_THE_14_MEASURED_FIXTURES_IN_THE_INITIAL_RETEST"
    )


def test_historical_bypass_and_m06_candidate_keep_their_limits() -> None:
    register = _load_register(ROOT)
    historical = register.findings[0]
    utility = register.findings[3]
    semantic = register.findings[4]
    operational = register.findings[5]

    assert historical.kind == "HISTORICAL_BYPASS"
    assert historical.lifecycle == "PENDING_FINAL_RETEST"
    assert historical.state == "MITIGATED_IN_INITIAL_RETEST_NOT_FINAL"
    assert historical.treatment.target == "PGS-05-M07"
    assert historical.treatment.correction_candidate_m06 is False

    assert utility.kind == "NEGATIVE_RESULT"
    assert utility.state == "OBSERVED_PRE_AND_POST"
    assert utility.success_criterion_refs == ("SC-07",)
    assert utility.treatment.correction_candidate_m06 is True
    assert semantic.kind == "MEASUREMENT_GAP"
    assert semantic.state == "OPEN"
    assert operational.state == "OBSERVED_WITHOUT_ACCEPTANCE_THRESHOLD"


def test_verifier_checks_all_pinned_sources_and_evidence_assertions() -> None:
    report = verify_control_findings(ROOT)

    assert report.model_dump() == {
        "schema_version": "1.0.0",
        "verification_id": "GSL-CONTROL-FINDINGS-VERIFICATION-001",
        "registry_id": "GSL-CONTROL-FINDINGS-001",
        "source_count": 3,
        "finding_count": 6,
        "evidence_assertion_count": 44,
        "verified": True,
    }
    for identity in SOURCE_IDENTITIES.values():
        path = ROOT / identity["path"]
        assert sha256(path.read_bytes()).hexdigest() == identity["sha256"]


def test_source_tamper_fails_closed(tmp_path: Path) -> None:
    repository = _copy_sources(tmp_path)
    source = repository / SOURCE_IDENTITIES["DAT-21"]["path"]
    source.write_bytes(source.read_bytes() + b" ")

    with pytest.raises(ControlFindingsError, match="source hash mismatch"):
        verify_control_findings(repository)


def test_unresolved_or_divergent_assertion_fails_closed(tmp_path: Path) -> None:
    repository = _copy_sources(tmp_path)
    register_path = repository / REGISTER_PATH
    document = json.loads(register_path.read_text())
    document["findings"][1]["evidence"][0]["expected"] = "0"
    register = ControlFindingsRegister.model_validate_json(json.dumps(document))
    register_path.write_text(canonical_json(register))

    with pytest.raises(ControlFindingsError, match="assertion mismatch"):
        verify_control_findings(repository)

    document = json.loads((ROOT / REGISTER_PATH).read_text())
    document["findings"][1]["evidence"][0]["pointer"] = "/missing/value"
    register = ControlFindingsRegister.model_validate_json(json.dumps(document))
    register_path.write_text(canonical_json(register))
    with pytest.raises(ControlFindingsError, match="pointer is unresolved"):
        verify_control_findings(repository)


def test_schema_is_strict_closed_and_rejects_premature_closure() -> None:
    register = _load_register(ROOT)
    document = register.model_dump(mode="json")
    document["unexpected"] = True
    with pytest.raises(ValidationError):
        ControlFindingsRegister.model_validate(document)

    document = register.model_dump(mode="json")
    document["findings"][0]["lifecycle"] = "CLOSED"
    with pytest.raises(ValidationError):
        ControlFindingsRegister.model_validate(document)


def test_register_is_canonical_sanitized_and_runner_only_reports_validation() -> None:
    register = _load_register(ROOT)
    serialized = canonical_json(register)

    assert serialized == (ROOT / REGISTER_PATH).read_text()
    lowered = serialized.casefold()
    assert str(ROOT).casefold() not in lowered
    for forbidden in (
        "/users/",
        "executed_at",
        "timestamp_utc",
        '"hostname"',
        '"username"',
    ):
        assert forbidden not in lowered

    completed = subprocess.run(
        (sys.executable, str(RUNNER)),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "evidence_assertion_count": 44,
        "finding_count": 6,
        "registry_id": "GSL-CONTROL-FINDINGS-001",
        "schema_version": "1.0.0",
        "source_count": 3,
        "verification_id": "GSL-CONTROL-FINDINGS-VERIFICATION-001",
        "verified": True,
    }


def test_verifier_has_no_target_execution_or_generation_dependencies() -> None:
    module_path = ROOT / "src" / "genai_seguro_lab" / "control_findings.py"
    tree = ast.parse(module_path.read_text())
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert not imported_roots & {
        "socket",
        "subprocess",
        "urllib",
        "requests",
        "evaluation_harness",
        "adversarial_retest",
    }
    assert "generate_control_findings" not in module_path.read_text()


def test_runner_error_is_generic_and_has_no_stdout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    spec = importlib.util.spec_from_file_location(
        "verify_control_findings_test",
        RUNNER,
    )
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    monkeypatch.setattr(
        runner,
        "verify_control_findings",
        lambda _: (_ for _ in ()).throw(ControlFindingsError("detail")),
    )

    assert runner.main(()) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: control findings unavailable\n"


def _load_register(project_root: Path) -> ControlFindingsRegister:
    return ControlFindingsRegister.model_validate_json(
        (project_root / REGISTER_PATH).read_bytes()
    )


def _copy_sources(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    for relative_path in (
        REGISTER_PATH,
        *(Path(identity["path"]) for identity in SOURCE_IDENTITIES.values()),
    ):
        target = repository / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative_path, target)
    return repository
