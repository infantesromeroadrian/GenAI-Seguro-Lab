"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "63 completadas + 1 omitida = 64/66 resueltas" in readme
    assert "2 abiertas" in readme
    assert (
        "**PGS-07-M09 — revisar P01-M01 y P01-M04–P01-M11 contra sus "
        "criterios vigentes.**"
    ) in readme

    assert "63 completadas + 1 omitida = 64/66 resueltas" in plan
    assert "2 abiertas" in plan
    assert (
        "**PGS-07-M09 — revisar P01-M01 y P01-M04–P01-M11 contra sus "
        "criterios vigentes.**"
    ) in plan
