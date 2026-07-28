"""Valida la política de cambio y reevaluación de PGS-06-M09."""

from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "docs" / "model-change-reevaluation-policy.md"
MODEL_CARD = ROOT / "docs" / "model-card.md"
SYSTEM_CARD = ROOT / "docs" / "system-card.md"
AIA = ROOT / "docs" / "ai-impact-assessment.md"
ADR = ROOT / "docs" / "architecture-decision-record.md"
RISK_REGISTER = ROOT / "docs" / "risk-register.md"
DOCS_README = ROOT / "docs" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

EXPECTED_CLASSES = {f"MCHG-{index:02d}" for index in range(1, 10)}
EXPECTED_PACKAGES = {f"REEVAL-{index:02d}" for index in range(1, 9)}
EXPECTED_ADR_TRIGGERS = {f"ADR-TRG-{index:02d}" for index in range(1, 8)}
EXPECTED_AIA_TRIGGERS = {f"AIA-TRG-{index:02d}" for index in range(1, 8)}
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _marked(document: str, name: str) -> str:
    start = f"<!-- {name}:start -->"
    end = f"<!-- {name}:end -->"
    assert document.count(start) == 1
    assert document.count(end) == 1
    return document.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_policy_has_nine_change_classes_and_eight_evaluation_packages() -> None:
    document = _read(POLICY)
    classes = _marked(document, "model-change-classes")
    catalog = _marked(document, "reevaluation-catalog")

    assert set(re.findall(r"`(MCHG-\d{2})`", classes)) == EXPECTED_CLASSES
    assert set(re.findall(r"`(REEVAL-\d{2})`", catalog)) == EXPECTED_PACKAGES
    assert EXPECTED_PACKAGES <= set(re.findall(r"`(REEVAL-\d{2})`", classes))
    assert set(re.findall(r"`(ADR-TRG-\d{2})`", classes)) == EXPECTED_ADR_TRIGGERS
    assert set(re.findall(r"`(AIA-TRG-\d{2})`", classes)) == EXPECTED_AIA_TRIGGERS


def test_policy_separates_authority_evidence_and_independent_review() -> None:
    compact = " ".join(_read(POLICY).split()).casefold()
    for boundary in (
        "clasificar un cambio no lo autoriza",
        "`necesita_autoridad` antes de diseño o llamada",
        "una corrección no altera el dato que la motivó",
        "no sobrescribir una evidencia anterior",
        "agente del mismo proceso no sustituye",
        "`dat-25` es el único retest final de su candidato y contrato",
        "no se regenera, reejecuta, sobrescribe",
        "ni reescribe `main`",
        "no acepta ni cierra automáticamente `rr-01` a `rr-06`",
    ):
        assert boundary in compact
    assert re.search(r"/(?:users|home)/[^/\s]+", compact) is None


def test_governance_sources_link_the_completed_policy() -> None:
    for path in (MODEL_CARD, SYSTEM_CARD, AIA, ADR, RISK_REGISTER, DOCS_README):
        assert "./model-change-reevaluation-policy.md" in _read(path)
    assert "./docs/model-change-reevaluation-policy.md" in _read(README)
    assert "./docs/model-change-reevaluation-policy.md" in _read(PLAN)
    assert "- [x] **PGS-06-M09**" in _read(PLAN)


def test_dat25_remains_immutable() -> None:
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
