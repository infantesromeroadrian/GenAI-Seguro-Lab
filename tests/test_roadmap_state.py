"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "52 de 66 microtareas (78,8 %)" in readme
    assert "con 14 abiertas" in readme
    assert "**PGS-06-M05 — definir política de logs, redacción, conservación y eliminación.**" in readme

    assert "52 de 66 microtareas completadas" in plan
    assert "14 abiertas (**78,8 %**)" in plan
    assert "**PGS-06-M05 — definir política de logs, redacción, conservación y eliminación.**" in plan
