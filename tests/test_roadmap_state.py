"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "57 de 66 microtareas (86,4 %)" in readme
    assert "con 9 abiertas" in readme
    assert "**PGS-07-M01 — reconstruir el proyecto desde un entorno limpio.**" in readme

    assert "57 de 66 microtareas completadas" in plan
    assert "9 abiertas (**86,4 %**)" in plan
    assert "**PGS-07-M01 — reconstruir el proyecto desde un entorno limpio.**" in plan
