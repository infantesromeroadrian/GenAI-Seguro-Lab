"""Valida el ADR de M09 sin ejecutar producto, harness o evaluadores."""

from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADR = ROOT / "docs" / "architecture-decision-record.md"
README = ROOT / "README.md"
DOCS_README = ROOT / "docs" / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

INVARIANTS_START = "<!-- adr-invariants:start -->"
INVARIANTS_END = "<!-- adr-invariants:end -->"
ALTERNATIVES_START = "<!-- adr-alternatives:start -->"
ALTERNATIVES_END = "<!-- adr-alternatives:end -->"
TRIGGERS_START = "<!-- adr-triggers:start -->"
TRIGGERS_END = "<!-- adr-triggers:end -->"
ROLLBACK_START = "<!-- adr-rollback:start -->"
ROLLBACK_END = "<!-- adr-rollback:end -->"

EXPECTED_INVARIANTS = {f"ADR-INV-{index:02d}" for index in range(1, 11)}
EXPECTED_ALTERNATIVES = {
    "ADR-ALT-01": "RECHAZADA_ALCANCE_ACTUAL",
    "ADR-ALT-02": "DIFERIDA_POR_TRIGGER",
    "ADR-ALT-03": "RECHAZADA_ALCANCE_ACTUAL",
    "ADR-ALT-04": "DIFERIDA_POR_TRIGGER",
    "ADR-ALT-05": "RECHAZADA_ESTRUCTURAL",
    "ADR-ALT-06": "DIFERIDA_POR_TRIGGER",
    "ADR-ALT-07": "RECHAZADA_ALCANCE_ACTUAL",
}
EXPECTED_TRIGGERS = {f"ADR-TRG-{index:02d}" for index in range(1, 8)}
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"

ID_RE = re.compile(r"`(ADR-(?:INV|ALT|TRG)-\d{2})`")
STATUS_RE = re.compile(r"`([A-Z_]+)`")


def _document() -> str:
    return ADR.read_text(encoding="utf-8")


def _marked_content(start: str, end: str) -> str:
    document = _document()
    assert document.count(start) == 1
    assert document.count(end) == 1
    return document.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def _marked_rows(start: str, end: str) -> list[tuple[str, ...]]:
    lines = [
        line.strip()
        for line in _marked_content(start, end).splitlines()
        if line.strip()
    ]
    assert len(lines) >= 3
    assert all(set(cell.strip()) == {"-"} for cell in lines[1].strip("|").split("|"))
    return [
        tuple(cell.strip() for cell in line.strip("|").split("|"))
        for line in lines[2:]
    ]


def test_adr_identity_scope_and_final_evidence_are_pinned() -> None:
    document = _document()

    for expected in (
        "`GSL-ADR-001`",
        "`1.0.0`",
        "`ACEPTADA_ALCANCE_ACTUAL`",
        "2026-07-28",
        "`24626fbf3f4a70765cac1353252168f3a8ad4607`",
        "`77edd64037bb0e41edffa58cae2682ba7d2694d2`",
        "`636e1dbb8cac21c8c7bfc0709bf1d88b4b56304e`",
        f"`{DAT25_SHA256}`",
    ):
        assert expected in document

    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
    compact = " ".join(document.casefold().split())
    assert "no significa que sea la arquitectura final" in compact
    assert "no los acepta ni los puntúa" in compact


def test_invariants_preserve_authority_and_evaluation_boundaries() -> None:
    rows = _marked_rows(INVARIANTS_START, INVARIANTS_END)
    observed = set()
    for row in rows:
        assert len(row) == 3
        match = ID_RE.fullmatch(row[0])
        assert match is not None
        observed.add(match.group(1))

    assert observed == EXPECTED_INVARIANTS

    compact = " ".join(_document().split())
    for expected in (
        "La salida del modelo no crea identidad, grant, permiso o efecto",
        "Perfil vulnerable, harness y evaluadores no son rutas de producto",
        "Oráculos, `expected_result` y `DAT-24` no entran",
        "`adversarial_oracles_delivered_to_target_case:false`",
        "`rubric_delivered_to_target:false`",
        "La evidencia publicada es inmutable",
        "no es una garantía global",
        "no acredita presencia humana real",
    ):
        assert expected in compact


def test_alternatives_are_explicit_and_do_not_select_future_capabilities() -> None:
    rows = _marked_rows(ALTERNATIVES_START, ALTERNATIVES_END)
    observed: dict[str, str] = {}
    for row in rows:
        assert len(row) == 10
        identifier = ID_RE.fullmatch(row[0])
        status = STATUS_RE.fullmatch(row[2])
        assert identifier is not None
        assert status is not None
        assert row[5]
        observed[identifier.group(1)] = status.group(1)

    assert observed == EXPECTED_ALTERNATIVES
    assert all("SELECCIONADA" not in status for status in observed.values())
    assert "| Seguridad y utilidad |" in _marked_content(
        ALTERNATIVES_START,
        ALTERNATIVES_END,
    )

    compact = " ".join(_document().split())
    for alternative in (
        "Prompt o guardrail propiedad del modelo",
        "Modelo real local",
        "Proveedor o modelo alojado",
        "UI, API o usuario remoto",
        "Integrar perfil vulnerable",
        "Aislamiento por proceso",
        "Framework de agentes o guardrails",
    ):
        assert alternative in compact


def test_triggers_and_rollback_are_compensating_and_preserve_history() -> None:
    trigger_rows = _marked_rows(TRIGGERS_START, TRIGGERS_END)
    observed_triggers = {
        match.group(1)
        for row in trigger_rows
        if (match := ID_RE.fullmatch(row[0])) is not None
    }
    assert observed_triggers == EXPECTED_TRIGGERS

    rollback = " ".join(_marked_content(ROLLBACK_START, ROLLBACK_END).split())
    for expected in (
        "Detener la nueva exposición",
        "volver a la CLI determinista sin red",
        "commit compensatorio",
        "checkout limpio",
        "hash de `DAT-25`",
        "evidencia nueva con otro identificador",
        "ADR sucesor",
        "no lo deshace",
    ):
        assert expected in rollback

    lowered = rollback.casefold()
    for destructive in (
        "reset --hard",
        "push --force",
        "borrar dat-25",
        "regenerar dat-25",
    ):
        assert destructive not in lowered

    assert "`RR-01` a `RR-06`" in _document()


def test_documentation_references_the_accepted_adr_and_completed_m09() -> None:
    readme = README.read_text(encoding="utf-8")
    docs_readme = DOCS_README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "./docs/architecture-decision-record.md" in readme
    assert "./architecture-decision-record.md" in docs_readme
    assert "- [x] **PGS-05-M09**" in plan
