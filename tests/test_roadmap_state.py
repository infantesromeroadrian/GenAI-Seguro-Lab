"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "60 de 66 microtareas (90,9 %)" in readme
    assert "con 6 abiertas" in readme
    assert (
        "**PGS-07-M04 — obtener una revisión humana independiente del threat "
        "model y de una prueba.**"
    ) in readme

    assert "60 de 66 microtareas completadas" in plan
    assert "6 abiertas (**90,9 %**)" in plan
    assert (
        "**PGS-07-M04 — obtener una revisión humana independiente del threat "
        "model y de una prueba.**"
    ) in plan
