"""Valida la extensión de ciclo de vida de logs de PGS-06-M05."""

from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "docs" / "security-events-policy.md"
DATA_CARD = ROOT / "docs" / "data-card.md"
DOCS_README = ROOT / "docs" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

EXPECTED_IDS = {f"LOG-{index:02d}" for index in range(1, 9)}
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
        if line.startswith("| `LOG-")
    ]


def test_lifecycle_matrix_covers_each_storage_class_once() -> None:
    policy = _read(POLICY)
    rows = _rows(_marked(policy, "log-lifecycle"))

    assert len(rows) == 8
    assert {row[0].strip("`") for row in rows} == EXPECTED_IDS
    assert all(len(row) == 6 and all(row) for row in rows)
    assert "`1.1.0`" in policy
    assert "`PGS-04-M07` y `PGS-06-M05`" in policy


def test_policy_preserves_minimization_redaction_and_deletion_limits() -> None:
    compact = " ".join(_read(POLICY).split()).casefold()
    for statement in (
        "la regla por defecto es **no recopilar** texto libre",
        "un campo no declarado se rechaza",
        "la redacción posterior no convierte una exposición previa en inexistente",
        "cero retención automática",
        "no purga el historial",
        "`dat-25` no se regenera, sobrescribe ni elimina",
        "no se ha fijado un plazo legal de conservación",
        "no afirmar borrado seguro",
        "rev-01` no está asignado",
    ):
        assert statement in compact
    assert re.search(r"/(?:users|home)/[^/\s]+", compact) is None


def test_existing_runtime_contract_remains_ephemeral_and_closed() -> None:
    policy = _read(POLICY)
    for statement in (
        "El journal vive únicamente en memoria",
        "No existe ningún campo de texto libre",
        "no escribe ficheros",
        "no envía datos por red",
        "no se exporta a un SIEM",
    ):
        assert statement in policy


def test_documentation_and_roadmap_link_completed_m05() -> None:
    assert "./security-events-policy.md" in _read(DATA_CARD)
    assert "./security-events-policy.md" in _read(DOCS_README)
    assert "./docs/security-events-policy.md" in _read(README)
    assert "- [x] **PGS-06-M05**" in _read(PLAN)


def test_dat25_remains_immutable() -> None:
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
