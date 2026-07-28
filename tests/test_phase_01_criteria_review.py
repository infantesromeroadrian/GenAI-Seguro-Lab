"""Valida la revisión acotada de los criterios padre P01."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "docs" / "phase-01-criteria-review.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"


def _table() -> str:
    document = REVIEW.read_text(encoding="utf-8")
    return document.split("<!-- p01-criteria-review:start -->", 1)[1].split(
        "<!-- p01-criteria-review:end -->", 1
    )[0]


def test_review_covers_the_nine_authorised_parent_microtasks_once() -> None:
    observed = re.findall(r"^\| `(P01-M\d{2})` \|", _table(), re.MULTILINE)
    expected = {"P01-M01", *(f"P01-M{number:02d}" for number in range(4, 12))}

    assert set(observed) == expected
    assert len(observed) == 9
    assert all(count == 1 for count in Counter(observed).values())
    assert "P01-M02` y `P01-M03`, gestionadas" in REVIEW.read_text(
        encoding="utf-8"
    )


def test_review_distinguishes_satisfied_tasks_from_the_open_review() -> None:
    table = _table()
    statuses = re.findall(r"`(SATISFIED|NOT_SATISFIED)`:", table)

    assert Counter(statuses) == {"SATISFIED": 8, "NOT_SATISFIED": 1}
    assert "| `P01-M11` |" in table
    assert "`NOT_SATISFIED`: no hubo revisión humana" in table
    assert "`P01-M11` permanece abierta" in REVIEW.read_text(encoding="utf-8")
    assert "`SEC-1` permanecen abiertas" in REVIEW.read_text(encoding="utf-8")


def test_review_links_resolve_and_contains_no_personal_route() -> None:
    document = REVIEW.read_text(encoding="utf-8")

    for raw_target in re.findall(r"\]\(([^)]+)\)", document):
        target = raw_target.split("#", 1)[0]
        if not target or target.startswith(("http://", "https://")):
            continue
        assert (REVIEW.parent / target).resolve().exists(), raw_target
    assert re.search(r"/(?:Users|home)/[^/\s]+", document) is None


def test_m09_is_closed_and_parent_result_is_recorded_in_review() -> None:
    plan = PLAN.read_text(encoding="utf-8")
    normalized = " ".join(REVIEW.read_text(encoding="utf-8").split())

    assert "- [x] **PGS-07-M09**" in plan
    assert (
        "`P01-M01` y `P01-M04` a `P01-M10` pueden registrarse como "
        "completadas por criterio"
    ) in normalized
    assert "`P01-M11` permanece abierta" in normalized
