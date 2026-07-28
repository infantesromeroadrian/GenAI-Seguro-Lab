"""Único owner de los contadores y del siguiente paso mutable del roadmap."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    assert "64 completadas + 1 omitida = 65/66 resueltas" in readme
    assert "1 abierta" in readme
    assert (
        "**PGS-07-M10 — registrar el estado real de SEC-1 sin cerrarlo.**"
    ) in readme

    assert "64 completadas + 1 omitida = 65/66 resueltas" in plan
    assert "1 abierta" in plan
    assert (
        "**PGS-07-M10 — registrar el estado real de SEC-1 sin cerrarlo.**"
    ) in plan
