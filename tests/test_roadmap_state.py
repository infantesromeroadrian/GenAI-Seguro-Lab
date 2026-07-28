"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "58 de 66 microtareas (87,9 %)" in readme
    assert "con 8 abiertas" in readme
    assert (
        "**PGS-07-M02 — ejecutar tests, corpus benigno y corpus adversario "
        "autorizado.**"
    ) in readme

    assert "58 de 66 microtareas completadas" in plan
    assert "8 abiertas (**87,9 %**)" in plan
    assert (
        "**PGS-07-M02 — ejecutar tests, corpus benigno y corpus adversario "
        "autorizado.**"
    ) in plan
