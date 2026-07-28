"""Valida los claims y límites de los resúmenes de cierre."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TECHNICAL = ROOT / "docs" / "technical-summary.md"
EXECUTIVE = ROOT / "docs" / "executive-summary.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
README = ROOT / "README.md"


def test_technical_summary_locates_architecture_threats_controls_and_evidence() -> None:
    document = TECHNICAL.read_text(encoding="utf-8")

    for reference in (
        "../architecture/manifest.json",
        "./abuse-cases.md",
        "./control-responsibility-mapping.md",
        "../evaluations/final-retest-v1.json",
        "./risk-register.md",
        "./final-traceability-matrix.md",
    ):
        assert reference in document
    assert "1/14 → 0/14" in document
    assert "12/12 benignos" in document
    assert "327/327 tests" in document
    assert "`DAT-25` es inmutable" in document


def test_both_summaries_preserve_the_real_scope_and_open_gaps() -> None:
    combined = "\n".join(
        (
            TECHNICAL.read_text(encoding="utf-8"),
            EXECUTIVE.read_text(encoding="utf-8"),
        )
    )
    normalized = " ".join(combined.split())

    assert "doble determinista" in normalized
    assert "no conecta un modelo de IA real" in normalized
    assert "revisión humana" in normalized
    assert "`REV-01` sigue sin asignar" in normalized
    assert "`RR-01` a `RR-06` siguen `ABIERTO`" in normalized
    assert "`SEC-1` no debe declararse superado" in normalized
    assert "No debe presentarse como producto listo para producción" in normalized
    assert re.search(r"/(?:Users|home)/[^/\s]+", combined) is None


def test_summary_links_resolve_inside_the_repository() -> None:
    for source in (TECHNICAL, EXECUTIVE):
        document = source.read_text(encoding="utf-8")
        for raw_target in re.findall(r"\]\(([^)]+)\)", document):
            target = raw_target.split("#", 1)[0]
            if not target or target.startswith(("http://", "https://")):
                continue
            assert (source.parent / target).resolve().exists(), raw_target


def test_m07_is_closed_and_both_summaries_are_linked() -> None:
    plan = PLAN.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    assert "- [x] **PGS-07-M07**" in plan
    assert "./docs/technical-summary.md" in readme
    assert "./docs/executive-summary.md" in readme
