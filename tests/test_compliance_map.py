"""Valida el mapa de cumplimiento acotado de PGS-06-M04."""

from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAP = ROOT / "docs" / "compliance-map.md"
DOCS_README = ROOT / "docs" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

EXPECTED_IDS = {f"CMPMAP-{index:02d}" for index in range(1, 10)}
EXPECTED_NATURES = {
    "OBLIGACION_POTENCIAL",
    "ESTANDAR_VOLUNTARIO",
    "GUIA_VOLUNTARIA",
    "DECISION_INTERNA_VOLUNTARIA",
}
EXPECTED_STATUSES = {
    "POR_CONFIRMAR",
    "NO_ACTIVADA_ALCANCE_ACTUAL",
    "NO_ADOPTADO",
    "APLICADA_PARCIAL",
    "VIGENTE_INTERNA",
}
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _marked(document: str, name: str) -> str:
    start = f"<!-- {name}:start -->"
    end = f"<!-- {name}:end -->"
    assert document.count(start) == 1
    assert document.count(end) == 1
    return document.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def _rows(section: str) -> list[list[str]]:
    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in section.splitlines()
        if line.startswith("| `CMPMAP-")
    ]


def test_map_has_one_complete_classification_per_source() -> None:
    document = _read(MAP)
    rows = _rows(_marked(document, "compliance-map"))

    assert len(rows) == 9
    assert {row[0].strip("`") for row in rows} == EXPECTED_IDS
    assert {row[2].strip("`") for row in rows} == EXPECTED_NATURES
    assert {row[3].strip("`") for row in rows} == EXPECTED_STATUSES
    assert all(len(row) == 7 and all(row) for row in rows)
    assert all("ACT-02" in row[-1] for row in rows)


def test_map_preserves_legal_and_assurance_boundaries() -> None:
    compact = " ".join(_read(MAP).split()).casefold()
    for boundary in (
        "no es asesoramiento jurídico",
        "una declaración de conformidad",
        "una certificación",
        "una autorización de producción",
        "una aceptación de riesgo",
        "no se ha clasificado jurídicamente",
        "datos sintéticos y ningún dato personal",
        "no existe un sistema de gestión de ia auditado",
        "no como certificado",
        "`rev-01` no está asignado",
    ):
        assert boundary in compact

    assert "2026-07-28" in compact
    assert "rr-01` a `rr-06" in compact
    assert re.search(r"/(?:users|home)/[^/\s]+", compact) is None


def test_map_uses_official_sources_and_existing_evidence() -> None:
    document = _read(MAP)
    for host in (
        "digital-strategy.ec.europa.eu",
        "eur-lex.europa.eu",
        "iso.org",
        "nist.gov",
        "genai.owasp.org",
        "atlas.mitre.org",
        "cisa.gov",
    ):
        assert host in document

    for evidence in (
        "GSL-AIA-001",
        "GSL-RACI-001",
        "GSL-RISK-REGISTER-001",
        "GSL-NIST-CONTROLS-001",
        "GSL-THREAT-CROSSWALK-001",
        "GSL-ADR-001",
    ):
        assert evidence in document


def test_documentation_and_roadmap_link_completed_m04() -> None:
    assert "./compliance-map.md" in _read(DOCS_README)
    assert "./docs/compliance-map.md" in _read(README)
    assert "./docs/compliance-map.md" in _read(PLAN)
    assert "- [x] **PGS-06-M04**" in _read(PLAN)


def test_dat25_remains_immutable() -> None:
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
