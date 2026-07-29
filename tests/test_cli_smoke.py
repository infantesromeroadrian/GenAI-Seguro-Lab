"""Smoke tests de proceso completo para la interfaz local."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from genai_seguro_lab.cli import build_parser

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "evaluations" / "benign-baseline-v1.json"
ENTRYPOINT = ROOT / "main.py"


def _environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("OLLAMA_API_KEY", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _run_entrypoint(
    *arguments: str,
    cwd: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, str(ENTRYPOINT), *arguments),
        cwd=cwd,
        env=_environment(),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_entrypoint_analyzes_from_outside_repository(
    tmp_path: Path,
) -> None:
    assert ENTRYPOINT.is_file()

    completed = _run_entrypoint(
        "analyze",
        "--incident",
        "INC-BEN-001",
        cwd=tmp_path,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload["incident_id"] == "INC-BEN-001"
    assert payload["knowledge_ids"] == ["KB-001"]
    assert payload["model_invocations"] == 2
    assert payload["tool_requests"] == 1
    assert payload["external_calls"] is False
    assert payload["cost_eur"] == 0
    assert "Hechos observados" in payload["output_text"]
    assert "Fuentes autorizadas" in payload["output_text"]
    assert "Incertidumbres y datos ausentes" in payload["output_text"]
    assert "Actuación propuesta" in payload["output_text"]
    assert payload["output_text"].count("- Propuesta:") >= 3


def test_correction_candidate_is_reproducible_without_rewriting_baseline() -> None:
    first = _run_entrypoint("baseline")
    second = _run_entrypoint("baseline")

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout
    assert first.stdout != BASELINE.read_text(encoding="utf-8")

    payload = json.loads(first.stdout)
    historical = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert payload["baseline_id"] == (
        "GSL-CORRECTION-CANDIDATE-BENIGN-001"
    )
    assert historical["baseline_id"] == "GSL-BASELINE-BENIGN-001"
    assert payload["summary"] == {
        "cases_failed": 0,
        "cases_passed": 12,
        "cases_total": 12,
        "cost_eur": 0,
        "external_calls": 0,
        "model_invocations": 24,
        "tool_requests": 12,
    }
    assert len(payload["cases"]) == 12
    assert payload["evaluation_scope"] == "benign_flow_functionality"
    assert payload["security_baseline"] is False
    assert payload["semantic_utility_evaluated"] is False


def test_repeated_case_is_byte_identical() -> None:
    first = _run_entrypoint(
        "analyze",
        "--incident",
        "INC-BEN-012",
    )
    second = _run_entrypoint(
        "analyze",
        "--incident",
        "INC-BEN-012",
    )

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout


def test_unknown_incident_fails_without_traceback() -> None:
    completed = _run_entrypoint(
        "analyze",
        "--incident",
        "INC-BEN-999",
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == "error: unknown benign incident identifier\n"
    assert "Traceback" not in completed.stderr


def test_cloud_analyze_is_explicit_and_missing_key_fails_sanitized() -> None:
    completed = _run_entrypoint(
        "analyze",
        "--incident",
        "INC-BEN-001",
        "--provider",
        "ollama",
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == (
        "error: cloud analysis provider is unavailable\n"
    )
    assert "OLLAMA_API_KEY" not in completed.stderr
    assert "Traceback" not in completed.stderr


def test_provider_option_exists_only_for_analyze_and_web() -> None:
    parser = build_parser()

    assert parser.parse_args(
        [
            "analyze",
            "--incident",
            "INC-BEN-001",
            "--provider",
            "ollama",
        ]
    ).provider == "ollama"
    assert parser.parse_args(
        ["web", "--provider", "ollama"]
    ).provider == "ollama"
    with pytest.raises(SystemExit) as captured:
        parser.parse_args(["baseline", "--provider", "ollama"])
    assert captured.value.code == 2


def test_smoke_commands_do_not_create_real_drafts() -> None:
    drafts = ROOT / "sandbox" / "drafts"
    before = sorted(path.name for path in drafts.iterdir())

    completed = _run_entrypoint("baseline")

    assert completed.returncode == 0
    assert sorted(path.name for path in drafts.iterdir()) == before == [
        "README.md"
    ]
