"""El plan es el único owner de los contadores y del siguiente paso mutable."""

import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def test_current_project_progress_and_next_microtask_are_consistent() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    expected = "65 completadas + 1 omitida = 66/66 resueltas"
    assert expected in plan
    assert "0 abiertas" in plan
    assert "No quedan microtareas internas abiertas." in plan
    assert "./plan-proyecto-GenAI-Seguro-Lab.md" in readme
    assert expected not in readme
    assert "No queda una siguiente microtarea interna." not in readme
    assert re.search(r"\bPGS-\d{2}-M\d{2}\b", readme) is None

    rows = re.findall(
        r"^- \[([ x-])\] \*\*(PGS-\d{2}-M\d{2})\*\*", plan, re.MULTILINE
    )
    assert len(rows) == 66
    assert Counter(state for state, _ in rows) == {"x": 65, "-": 1}
    assert [identifier for state, identifier in rows if state == "-"] == [
        "PGS-07-M04"
    ]
