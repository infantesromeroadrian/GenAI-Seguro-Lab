"""Valida GSL-AIA-001 sin ejecutar producto, harness ni evaluadores."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
AIA = ROOT / "docs" / "ai-impact-assessment.md"
SYSTEM_CARD = ROOT / "docs" / "system-card.md"
DOCS_README = ROOT / "docs" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

SOURCE_COMMIT = "648dd9afe9ef696388257ebf8dda4b59ece1aeb5"
CANDIDATE_COMMIT = "77edd64037bb0e41edffa58cae2682ba7d2694d2"
EVALUATOR_COMMIT = "636e1dbb8cac21c8c7bfc0709bf1d88b4b56304e"
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"

EXPECTED_IMPACTS = {f"AIA-IMP-{index:02d}" for index in range(1, 11)}
EXPECTED_RISKS = {f"RR-{index:02d}" for index in range(1, 7)}
EXPECTED_TRIGGERS = {f"AIA-TRG-{index:02d}" for index in range(1, 8)}
EXPECTED_ADR_TRIGGERS = {f"ADR-TRG-{index:02d}" for index in range(1, 8)}
EXPECTED_CONTROLS = {f"CTL-{index:02d}" for index in range(1, 14)}
ALLOWED_CLASSIFICATIONS = {
    "NO_APLICA_ALCANCE_ACTUAL",
    "ACOTADO_ALCANCE_ACTUAL",
    "NO_DEMOSTRADO",
    "POTENCIAL_SI_AMPLIA",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(_read(path))
    assert isinstance(loaded, dict)
    return loaded


def _marked(document: str, name: str) -> str:
    start = f"<!-- {name}:start -->"
    end = f"<!-- {name}:end -->"
    assert document.count(start) == 1
    assert document.count(end) == 1
    return document.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def _table_rows(section: str, prefix: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        if cells and cells[0].startswith(f"`{prefix}"):
            rows.append(cells)
    return rows


def test_aia_pins_scope_sources_and_non_authorizing_outcome() -> None:
    document = _read(AIA)
    for expected in (
        "`GSL-AIA-001`",
        "`1.3.0`",
        "2026-07-29",
        "`COMPLETADA_ALCANCE_ACTUAL`",
        "`CONTINUAR_SOLO_LABORATORIO_ACTUAL`",
        "`NO_AUTORIZA_AMPLIACION`",
        f"`{SOURCE_COMMIT}`",
        f"`{CANDIDATE_COMMIT}`",
        f"`{EVALUATOR_COMMIT}`",
        f"`{DAT25_SHA256}`",
    ):
        assert expected in document

    compact = " ".join(document.split()).casefold()
    for boundary in (
        "no es una evaluación jurídica",
        "un mapa de cumplimiento",
        "una aprobación de producción",
        "una aceptación de riesgo",
        "no habilita datos reales",
    ):
        assert boundary in compact
    assert re.search(r"/(?:users|home)/[^/\s]+", compact) is None


def test_screening_matches_the_current_system_and_affected_parties() -> None:
    screening = _marked(_read(AIA), "aia-screening")
    for fact in (
        "`MOD-01` `deterministic/scripted-v1`",
        "`ACT-01`",
        "`ACT-02`",
        "`ACT-03`",
        "`DAT-01` a `DAT-25`",
        "No hay entrenamiento",
        "No",
        "`TOL-02` es interno y create-only",
        "`IDN-03` es una identidad sintética",
        "`CMP-19`",
        "`127.0.0.1`",
        "no expone prompt libre",
        "cuenta macOS",
        "`PGS-06-M04`",
    ):
        assert fact in screening

    document = _read(AIA)
    for party in (
        "Titulares de datos reales",
        "Visitantes del perfil público",
        "`REV-01`",
    ):
        assert party in document
    assert "AIA-TRG-02` se activó" in document
    assert "./web-threat-model.md" in document


def test_impact_register_is_complete_classified_and_control_linked() -> None:
    section = _marked(_read(AIA), "aia-impact-register")
    rows = _table_rows(section, "AIA-IMP-")
    assert len(rows) == 10
    assert {row[0].strip("`") for row in rows} == EXPECTED_IMPACTS
    assert len({row[0] for row in rows}) == len(rows)

    for row in rows:
        assert len(row) == 6
        assert all(cell for cell in row)
        assert row[-1].strip("`") in ALLOWED_CLASSIFICATIONS

    observed_controls = set(re.findall(r"`(CTL-\d{2})`", section))
    assert observed_controls == EXPECTED_CONTROLS


def test_all_residual_risks_are_handed_off_once_and_remain_pending() -> None:
    section = _marked(_read(AIA), "aia-risk-handoff")
    rows = _table_rows(section, "RR-")
    assert len(rows) == 6
    assert {row[0].strip("`") for row in rows} == EXPECTED_RISKS
    assert len({row[0] for row in rows}) == len(rows)

    for row in rows:
        assert len(row) == 5
        assert row[-1] == "`PENDIENTE_HUMANA`"
        assert "AIA-IMP-" in row[1]
        assert "PGS-" in row[3]

    compact = " ".join(_read(AIA).split()).casefold()
    assert "sin aceptar, repriorizar, cerrar o duplicar los riesgos" in compact


def test_reassessment_triggers_preserve_the_adr_contract() -> None:
    section = _marked(_read(AIA), "aia-triggers")
    rows = _table_rows(section, "AIA-TRG-")
    assert len(rows) == 7
    assert {row[0].strip("`") for row in rows} == EXPECTED_TRIGGERS
    assert len({row[0] for row in rows}) == len(rows)
    assert set(re.findall(r"`(ADR-TRG-\d{2})`", section)) == EXPECTED_ADR_TRIGGERS
    for row in rows:
        assert len(row) == 4
        assert all(cell for cell in row)


def test_aia_reports_dat25_without_rerunning_it() -> None:
    evidence = _load_json(DAT25)
    document = " ".join(_read(AIA).split())
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
    assert evidence["snapshot_id"] == "GSL-FINAL-RETEST-001"
    assert evidence["final_retest"] is True
    assert evidence["candidate"]["commit"] == CANDIDATE_COMMIT
    assert evidence["evaluator"]["commit"] == EVALUATOR_COMMIT

    adversarial = evidence["adversarial"]["metrics"]
    benign = evidence["benign"]["metrics"]
    assert adversarial["completed_cases"] == 14
    assert adversarial["baseline_attack_success_numerator"] == 1
    assert adversarial["final_attack_success_numerator"] == 0
    assert adversarial["baseline_accepted_unauthorized_operations"] == 1
    assert adversarial["final_accepted_unauthorized_operations"] == 0
    assert adversarial["improved_cases"] == 1
    assert adversarial["regression_cases"] == 0
    assert adversarial["inert_records"] == 4
    assert adversarial["inert_records_executed"] == 0
    assert benign["completed_cases"] == 12
    assert benign["false_rejection_cases"] == 0
    assert benign["required_findings_preserved"] == 24
    assert benign["recommended_actions_preserved"] == 36
    assert benign["forbidden_claims_preserved"] == 24

    for expected in (
        "14/14",
        "1/14 a 0/14",
        "12/12",
        "24/24",
        "36/36",
        "cuatro fixtures DOS/SC inertes",
        "no demuestra equivalencia semántica general",
    ):
        assert expected.casefold() in document.casefold()


def test_documentation_links_the_completed_aia_without_architecture_claims() -> None:
    docs_readme = _read(DOCS_README)
    readme = _read(README)
    plan = _read(PLAN)
    system_card = _read(SYSTEM_CARD)

    assert "./ai-impact-assessment.md" in docs_readme
    assert "./docs/ai-impact-assessment.md" in readme
    assert "./docs/ai-impact-assessment.md" in plan
    assert "./ai-impact-assessment.md" in system_card
    assert "- [x] **PGS-06-M02**" in plan
    assert "no modifica el mapa" in _read(AIA)
