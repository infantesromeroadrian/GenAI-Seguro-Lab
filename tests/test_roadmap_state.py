"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "62 completadas + 1 omitida = 63/66 resueltas" in readme
    assert "3 abiertas" in readme
    assert (
        "**PGS-07-M07 — preparar los resúmenes técnico y ejecutivo.**"
    ) in readme

    assert "62 completadas + 1 omitida = 63/66 resueltas" in plan
    assert "3 abiertas" in plan
    assert (
        "**PGS-07-M07 — preparar los resúmenes técnico y ejecutivo.**"
    ) in plan
