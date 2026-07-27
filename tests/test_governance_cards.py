"""Valida las fichas de gobierno de M01 sin ejecutar el laboratorio."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SYSTEM_CARD = ROOT / "docs" / "system-card.md"
DATA_CARD = ROOT / "docs" / "data-card.md"
MODEL_CARD = ROOT / "docs" / "model-card.md"
DOCS_README = ROOT / "docs" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
BENIGN_MANIFEST = ROOT / "data" / "manifest.json"
ADVERSARIAL_MANIFEST = ROOT / "data" / "adversarial" / "manifest.json"
MODEL_ADAPTER = ROOT / "src" / "genai_seguro_lab" / "model_adapter.py"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

SOURCE_COMMIT = "52e039f0c72f96671170e977a761691aa81c525e"
CANDIDATE_COMMIT = "77edd64037bb0e41edffa58cae2682ba7d2694d2"
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"
CARD_STATUS = "DESCRIPTIVA_ALCANCE_ACTUAL"

EXPECTED_CARD_IDS = {
    SYSTEM_CARD: "GSL-SYSTEM-CARD-001",
    DATA_CARD: "GSL-DATA-CARD-001",
    MODEL_CARD: "GSL-MODEL-CARD-001",
}
EXPECTED_BOUNDARIES = {f"TB-{index:02d}" for index in range(1, 7)}
EXPECTED_DATA_ASSETS = {f"DAT-{index:02d}" for index in range(1, 26)}


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


def _compact(document: str) -> str:
    return " ".join(document.split())


def test_cards_pin_identity_scope_and_evidence_without_approval_claims() -> None:
    for path, identifier in EXPECTED_CARD_IDS.items():
        document = _read(path)
        for expected in (
            f"`{identifier}`",
            "`1.0.0`",
            "2026-07-28",
            f"`{CARD_STATUS}`",
            f"`{SOURCE_COMMIT}`",
            f"`{CANDIDATE_COMMIT}`",
            f"`{DAT25_SHA256}`",
        ):
            assert expected in document

        lowered = document.casefold()
        assert "no constituye" in lowered or "no es una" in lowered
        assert "/users/" not in lowered
        assert "adrianinfantes" not in lowered


def test_system_card_covers_boundaries_actors_components_and_pending_risks() -> None:
    document = _read(SYSTEM_CARD)
    boundaries = set(re.findall(r"`(TB-\d{2})`", _marked(document, "system-boundaries")))
    assert boundaries == EXPECTED_BOUNDARIES

    for actor in ("ACT-01", "ACT-02", "ACT-03"):
        assert f"`{actor}`" in document
    for component_index in range(1, 19):
        assert f"`CMP-{component_index:02d}`" in document
    for element in ("MOD-01", "TOL-01", "TOL-02", "IDN-01", "IDN-03", "IDN-04", "IDN-05"):
        assert f"`{element}`" in document
    for risk_index in range(1, 7):
        risk = f"RR-{risk_index:02d}"
        assert document.count(f"`{risk}`") == 1

    compact = _compact(document)
    for expected in (
        "no hay proveedor",
        "servicio web",
        "base de datos",
        "vector store",
        "cloud",
        "Docker",
        "logging persistente",
        "`PENDIENTE_HUMANA`",
        "no demuestra presencia humana",
        "no demuestran equivalencia semántica general",
    ):
        assert expected.casefold() in compact.casefold()


def test_data_card_has_one_row_for_each_inventory_asset() -> None:
    document = _read(DATA_CARD)
    asset_section = _marked(document, "data-assets")
    observed = re.findall(r"`(DAT-\d{2})`", asset_section)

    assert len(observed) == 25
    assert set(observed) == EXPECTED_DATA_ASSETS
    assert len(set(observed)) == len(observed)


def test_data_card_matches_manifests_and_file_hashes() -> None:
    document = _read(DATA_CARD)
    benign = _load_json(BENIGN_MANIFEST)
    adversarial = _load_json(ADVERSARIAL_MANIFEST)

    assert benign["id"] == "GSL-DATASET-001"
    assert benign["version"] == "1.0.0"
    assert benign["synthetic"] is True
    assert benign["sensitivity"] == "synthetic_internal"
    assert benign["expected_result"] == {
        "incident_records": 12,
        "knowledge_records": 8,
        "benign_incident_records": 12,
        "adversarial_records": 0,
    }

    assert adversarial["id"] == "GSL-ADVERSARIAL-CORPUS-001"
    assert adversarial["version"] == "1.4.0"
    assert adversarial["synthetic"] is True
    assert adversarial["sensitivity"] == "synthetic_internal"
    assert adversarial["expected_result"] == {
        "input_records": 18,
        "oracle_records": 18,
        "unique_abuse_cases": 17,
        "threat_families": 6,
        "test_wired_records": 14,
        "inert_records": 4,
        "canonical_evaluation_records": 14,
    }

    for manifest, directory in (
        (benign, BENIGN_MANIFEST.parent),
        (adversarial, ADVERSARIAL_MANIFEST.parent),
    ):
        for entry in manifest["files"]:
            actual_hash = sha256((directory / entry["path"]).read_bytes()).hexdigest()
            assert actual_hash == entry["sha256"]
            assert entry["sha256"] in document
            assert str(entry["records"]) in document

    for manifest in (benign, adversarial):
        assert manifest["id"] in document
        assert manifest["version"] in document


def test_model_card_matches_the_deterministic_adapter_contract() -> None:
    card = _read(MODEL_CARD)
    facts = _marked(card, "model-facts")
    source = _read(MODEL_ADAPTER)

    for expected in (
        "`MOD-01`",
        "`DeterministicModelAdapter`",
        "`deterministic`",
        "`scripted-v1`",
        "`true`",
        "`false`",
        "`UnknownModelRequestError`",
        "Ninguno",
    ):
        assert expected in facts

    for source_contract in (
        'provider: Literal["deterministic"] = "deterministic"',
        'model: Literal["scripted-v1"] = "scripted-v1"',
        "deterministic: Literal[True] = True",
        "external_calls: Literal[False] = False",
        "cost_eur: Literal[0] = 0",
        "class DeterministicModelAdapter:",
        "class UnknownModelRequestError",
        "requests require exactly one leading trusted instruction",
        "requests require explicitly classified user data",
        "requests require explicitly classified untrusted content",
    ):
        assert source_contract in source

    compact = _compact(card).casefold()
    for limitation in (
        "no es un modelo de machine learning",
        "doble determinista",
        "no existe entrenamiento",
        "no autentica",
        "no existe ruta desde `mod-01` hacia `tol-02`",
        "no demuestra equivalencia semántica general",
    ):
        assert limitation in compact


def test_cards_report_dat25_metrics_without_rerunning_it() -> None:
    evidence = _load_json(DAT25)
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
    assert evidence["snapshot_id"] == "GSL-FINAL-RETEST-001"
    assert evidence["schema_version"] == "1.0.0"
    assert evidence["final_retest"] is True
    assert evidence["candidate"]["commit"] == CANDIDATE_COMMIT

    adversarial = evidence["adversarial"]["metrics"]
    assert adversarial["completed_cases"] == 14
    assert adversarial["baseline_attack_success_numerator"] == 1
    assert adversarial["final_attack_success_numerator"] == 0
    assert adversarial["baseline_accepted_unauthorized_operations"] == 1
    assert adversarial["final_accepted_unauthorized_operations"] == 0
    assert adversarial["improved_cases"] == 1
    assert adversarial["regression_cases"] == 0
    assert adversarial["inert_records"] == 4
    assert adversarial["inert_records_executed"] == 0

    benign = evidence["benign"]["metrics"]
    assert benign["completed_cases"] == 12
    assert benign["false_rejection_cases"] == 0
    assert benign["required_findings_preserved"] == 24
    assert benign["recommended_actions_preserved"] == 36
    assert benign["forbidden_claims_preserved"] == 24
    assert benign["unique_output_hashes"] == 12
    assert benign["output_policy_interventions"] == 2

    for card_path in (SYSTEM_CARD, MODEL_CARD):
        compact = _compact(_read(card_path))
        for expected in (
            "14/14",
            "1/14 a 0/14",
            "12/12",
            "24/24",
            "36/36",
            "cuatro fixtures",
        ):
            assert expected in compact


def test_documentation_and_roadmap_reference_completed_m01() -> None:
    docs_readme = _read(DOCS_README)
    readme = _read(README)
    plan = _read(PLAN)

    for link in ("./system-card.md", "./data-card.md", "./model-card.md"):
        assert link in docs_readme
    for link in (
        "./docs/system-card.md",
        "./docs/data-card.md",
        "./docs/model-card.md",
    ):
        assert link in readme

    assert "- [x] **PGS-06-M01**" in plan
    assert "49 de 66 microtareas completadas" in plan
    assert "17 abiertas (**74,2 %**)" in plan
    assert "**PGS-06-M02 — completar la evaluación de impacto de IA.**" in plan

    assert "PGS-06-M01" in readme
    assert "49 de 66 microtareas (74,2 %)" in readme
    assert "con 17 abiertas" in readme
    assert "**PGS-06-M02 — completar la evaluación de impacto de IA.**" in readme
