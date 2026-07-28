"""Valida el procedimiento humano de parada y recuperación de PGS-06-M07."""

from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROCEDURE = ROOT / "docs" / "stop-recovery-procedure.md"
POLICY = ROOT / "docs" / "sandbox-recovery-policy.md"
RUNBOOK = ROOT / "docs" / "ai-incident-response-runbook.md"
DOCS_README = ROOT / "docs" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

EXPECTED_LEVELS = {f"STOP-{index:02d}" for index in range(1, 5)}
EXPECTED_STEPS = {f"SR-{index:02d}" for index in range(1, 9)}
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _marked(document: str, name: str) -> str:
    start = f"<!-- {name}:start -->"
    end = f"<!-- {name}:end -->"
    assert document.count(start) == 1
    assert document.count(end) == 1
    return document.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_procedure_has_four_stop_levels_and_eight_steps() -> None:
    document = _read(PROCEDURE)
    levels = set(
        re.findall(r"`(STOP-\d{2})`", _marked(document, "stop-levels"))
    )
    steps = set(
        re.findall(r"`(SR-\d{2})`", _marked(document, "stop-recovery-workflow"))
    )
    assert levels == EXPECTED_LEVELS
    assert steps == EXPECTED_STEPS


def test_procedure_preserves_atomicity_authority_and_manual_limits() -> None:
    compact = " ".join(_read(PROCEDURE).split()).casefold()
    for statement in (
        "no añade handlers de `sigint` o `sigterm`",
        "no deshace un final ya publicado",
        "no editar `.gsl-txn-*`",
        "no reparar, borrar, reintentar",
        "no reutilizar challenge, aprobación o grant",
        "nunca se eliminan manualmente artefactos `.gsl-txn-*`",
        "las cuatro fixtures dos/sc siguen inertes",
        "`dat-25` permanece inmutable y no se reejecuta",
    ):
        assert statement in compact
    assert re.search(r"/(?:users|home)/[^/\s]+", compact) is None


def test_procedure_matches_the_implemented_recovery_contract() -> None:
    procedure = _read(PROCEDURE)
    policy = _read(POLICY)
    for invariant in (
        "create-only",
        "stop()",
        "clean",
        "recovered",
        "O_NOFOLLOW",
        "flock",
        "SIGINT",
        "SIGTERM",
    ):
        assert invariant.casefold() in procedure.casefold()
        assert invariant.casefold() in policy.casefold()
    assert "./ai-incident-response-runbook.md" in procedure
    assert "./stop-recovery-procedure.md" in _read(RUNBOOK)


def test_documentation_and_roadmap_link_completed_m07() -> None:
    assert "./stop-recovery-procedure.md" in _read(DOCS_README)
    assert "./docs/stop-recovery-procedure.md" in _read(README)
    assert "./docs/stop-recovery-procedure.md" in _read(PLAN)
    assert "- [x] **PGS-06-M07**" in _read(PLAN)


def test_dat25_remains_immutable() -> None:
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
