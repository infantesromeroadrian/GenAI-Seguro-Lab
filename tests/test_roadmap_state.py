"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "53 de 66 microtareas (80,3 %)" in readme
    assert "con 13 abiertas" in readme
    assert "**PGS-06-M06 — crear el runbook de respuesta a incidentes de IA.**" in readme

    assert "53 de 66 microtareas completadas" in plan
    assert "13 abiertas (**80,3 %**)" in plan
    assert "**PGS-06-M06 — crear el runbook de respuesta a incidentes de IA.**" in plan
