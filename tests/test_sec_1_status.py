"""Valida la separación entre cierre interno y gate SEC-1."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / "docs" / "sec-1-status.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
README = ROOT / "README.md"


def test_sec1_remains_open_for_both_observed_dependencies() -> None:
    document = STATUS.read_text(encoding="utf-8")

    assert "| Gate `SEC-1` | `OPEN_NOT_ACHIEVED` |" in document
    assert "| Prerrequisito `BASE` | `PENDING` |" in document
    assert "| Un tercero reproduce al menos una prueba | `NOT_SATISFIED` |" in document
    assert "`P01-M11`: abierta" in document
    assert "`RR-01` a `RR-06` siguen abiertos" in document
    assert "no cierra el gate" in document


def test_status_document_records_internal_accounting_without_closing_the_gate() -> None:
    document = STATUS.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "| Roadmap interno | `RESOLVED_WITH_OMISSION` |" in document
    assert "65 completadas + 1 omitida = 66/66 resueltas; 0 abiertas" in document
    assert "- [x] **PGS-07-M10**" in plan


def test_status_links_resolve_and_claims_are_bounded() -> None:
    document = STATUS.read_text(encoding="utf-8")

    for raw_target in re.findall(r"\]\(([^)]+)\)", document):
        target = raw_target.split("#", 1)[0]
        if not target or target.startswith(("http://", "https://")):
            continue
        assert (STATUS.parent / target).resolve().exists(), raw_target
    assert re.search(r"/(?:Users|home)/[^/\s]+", document) is None
    assert "no es una revisión independiente" in document
    assert "aceptación de riesgo" in document


def test_sec1_status_is_visible_in_readme() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "./docs/sec-1-status.md" in readme
    assert "`SEC-1` permanece `OPEN_NOT_ACHIEVED`" in readme
