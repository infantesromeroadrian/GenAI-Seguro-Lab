"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "60 completadas + 1 omitida = 61/66 resueltas" in readme
    assert "5 abiertas" in readme
    assert (
        "**PGS-07-M05 — registrar la ausencia de hallazgos de revisión y la "
        "discrepancia resultante.**"
    ) in readme

    assert "60 completadas + 1 omitida = 61/66 resueltas" in plan
    assert "5 abiertas" in plan
    assert (
        "**PGS-07-M05 — registrar la ausencia de hallazgos de revisión y la "
        "discrepancia resultante.**"
    ) in plan
