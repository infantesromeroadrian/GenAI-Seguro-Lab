"""Valida cobertura y límites de la matriz final de trazabilidad."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "final-traceability-matrix.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def _matrix_body() -> str:
    document = MATRIX.read_text(encoding="utf-8")
    return document.split("<!-- final-traceability:start -->", 1)[1].split(
        "<!-- final-traceability:end -->", 1
    )[0]


def test_matrix_covers_every_rf_rs_ro_and_sc_once() -> None:
    expected = (
        {f"RF-{number:02d}" for number in range(1, 5)}
        | {f"RS-{number:02d}" for number in range(1, 7)}
        | {f"RO-{number:02d}" for number in range(1, 3)}
        | {f"SC-{number:02d}" for number in range(1, 14)}
    )
    observed = re.findall(r"^\| `((?:RF|RS|RO|SC)-\d{2})` \|", _matrix_body(), re.MULTILINE)

    assert len(expected) == 25
    assert set(observed) == expected
    assert all(count == 1 for count in Counter(observed).values())


def test_matrix_uses_closed_states_and_existing_local_references() -> None:
    body = _matrix_body()
    allowed = {
        "DEMONSTRATED",
        "DEMONSTRATED_BOUNDED",
        "PARTIAL",
        "NOT_DEMONSTRATED",
    }
    states = re.findall(r"`([A-Z_]+)`:", body)

    assert len(states) == 25
    assert set(states) <= allowed
    counts = Counter(states)
    document = MATRIX.read_text(encoding="utf-8")
    for status, count in counts.items():
        assert f"`{status}`: {count} requisito" in document
    for raw_target in re.findall(r"\]\(([^)]+)\)", body):
        target = raw_target.split("#", 1)[0]
        if not target or target.startswith(("http://", "https://")):
            continue
        assert (MATRIX.parent / target).resolve().exists(), raw_target


def test_matrix_preserves_review_risk_and_scope_limits() -> None:
    document = MATRIX.read_text(encoding="utf-8")

    assert "| `SC-12` |" in document
    assert "`NOT_DEMONSTRATED`: no hubo persona revisora" in document
    assert "`D-REV-01` permanece abierta" in document
    assert "`RR-01` a `RR-06` permanecen `ABIERTO`" in document
    assert "no demuestra conformidad legal integral" in document
    assert "no certifica el sistema ni acepta riesgos" in document


def test_m06_is_closed_and_the_matrix_is_linked() -> None:
    plan = PLAN.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    assert "- [x] **PGS-07-M06**" in plan
    assert "./docs/final-traceability-matrix.md" in readme
