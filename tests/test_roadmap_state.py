"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "59 de 66 microtareas (89,4 %)" in readme
    assert "con 7 abiertas" in readme
    assert (
        "**PGS-07-M03 — verificar que logs y artefactos no contienen secretos "
        "ni datos reales.**"
    ) in readme

    assert "59 de 66 microtareas completadas" in plan
    assert "7 abiertas (**89,4 %**)" in plan
    assert (
        "**PGS-07-M03 — verificar que logs y artefactos no contienen secretos "
        "ni datos reales.**"
    ) in plan
