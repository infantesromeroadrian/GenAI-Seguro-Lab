"""Valida el snapshot documental M08 sin ejecutar evaluadores ni runners."""

from __future__ import annotations

import re
from collections import Counter
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "docs" / "residual-risk-and-tradeoffs.md"

SOURCE_START = "<!-- residual-risk-sources:start -->"
SOURCE_END = "<!-- residual-risk-sources:end -->"
RISK_START = "<!-- residual-risk-register:start -->"
RISK_END = "<!-- residual-risk-register:end -->"

EXPECTED_CASES_BY_RISK = {
    "RR-01": ("AC-DOS-01",),
    "RR-02": ("AC-DOS-02", "AC-DOS-03"),
    "RR-03": ("AC-SC-01",),
    "RR-04": ("AC-TOL-05",),
    "RR-05": ("AC-TOL-03", "AC-TOL-04"),
    "RR-06": (
        "AC-PI-01",
        "AC-PI-02",
        "AC-PI-03",
        "AC-JB-01",
        "AC-JB-02",
        "AC-EX-01",
        "AC-EX-02",
        "AC-EX-03",
        "AC-TOL-01",
        "AC-TOL-02",
    ),
}
INERT_CASES = {"AC-DOS-01", "AC-DOS-02", "AC-DOS-03", "AC-SC-01"}
EXPECTED_SOURCE_ROLES = {
    "DAT-20": "HISTORICAL_ONLY",
    "DAT-21": "HISTORICAL_ONLY",
    "DAT-22": "HISTORICAL_ONLY",
    "DAT-23": "HISTORICAL_ONLY",
    "DAT-24": "CLOSED_RUBRIC",
    "DAT-25": "FINAL",
}
EVIDENCE_SHA256 = {
    "evaluations/adversarial-metrics-v1.json": (
        "2d4302018cc849e54507e4bf58b0d5ab98822a5b602ec5289d4874a2335ffb85"
    ),
    "evaluations/benign-pre-controls-functional-v1.json": (
        "004642ce949e829f507c918c88dc12078a1800e597c986eee3e15cf70fc8817e"
    ),
    "evaluations/benign-utility-v1.json": (
        "af77c91c3505ef22e8ee0f4b0047de6c9b44bfe5a2127dd25d39b86077f451da"
    ),
    "evaluations/operational-metrics-v1.json": (
        "cea6d0dceff86d7b2c16c3f6fc44425f6f76e9cb2f53b021f109b070597410c3"
    ),
    "evaluations/control-findings-v1.json": (
        "7336dd284f05b11f9e1dd31a0bf0e36d8cfcf0e4c5c03012a639ce3ade6e3cc8"
    ),
    "evaluations/final-retest-rubric-v1.json": (
        "8fa18ee4d2f87e183156610e6b2d88db25c7fcaf35c7f5184424b2863884c375"
    ),
    "evaluations/final-retest-v1.json": (
        "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"
    ),
}

CASE_RE = re.compile(r"\bAC-[A-Z]+-\d{2}\b")
RISK_RE = re.compile(r"`(RR-\d{2})`")
SOURCE_RE = re.compile(r"`(DAT-\d{2})`")
ROLE_RE = re.compile(r"`([A-Z_]+)`")


def _document() -> str:
    return SNAPSHOT.read_text(encoding="utf-8")


def _marked_rows(start: str, end: str) -> list[tuple[str, ...]]:
    document = _document()
    assert document.count(start) == 1
    assert document.count(end) == 1
    marked = document.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]
    lines = [line.strip() for line in marked.splitlines() if line.strip()]
    assert len(lines) >= 3
    assert all(set(cell.strip()) == {"-"} for cell in lines[1].strip("|").split("|"))
    return [
        tuple(cell.strip() for cell in line.strip("|").split("|"))
        for line in lines[2:]
    ]


def test_snapshot_identity_source_roles_and_evidence_are_pinned() -> None:
    document = _document()

    for expected in (
        "`GSL-RESIDUAL-RISK-001`",
        "`1.0.0`",
        "2026-07-27",
        "`77edd64037bb0e41edffa58cae2682ba7d2694d2`",
        "`bc09b78f7f3d85f94241f9955e79abb264bd89de`",
        "`636e1dbb8cac21c8c7bfc0709bf1d88b4b56304e`",
        "`05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d`",
    ):
        assert expected in document

    observed_roles: dict[str, str] = {}
    for source, role, _use in _marked_rows(SOURCE_START, SOURCE_END):
        source_match = SOURCE_RE.fullmatch(source)
        role_match = ROLE_RE.fullmatch(role)
        assert source_match is not None
        assert role_match is not None
        observed_roles[source_match.group(1)] = role_match.group(1)
    assert observed_roles == EXPECTED_SOURCE_ROLES

    observed_hashes = {
        relative: sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in EVIDENCE_SHA256
    }
    assert observed_hashes == EVIDENCE_SHA256


def test_six_primary_risks_cover_each_abuse_case_exactly_once() -> None:
    rows = _marked_rows(RISK_START, RISK_END)
    assert len(rows) == 6

    observed: dict[str, tuple[str, ...]] = {}
    all_cases: list[str] = []
    for row in rows:
        assert len(row) == 9
        risk_cell, *_middle, decision = row
        risk_match = RISK_RE.search(risk_cell)
        assert risk_match is not None
        risk_id = risk_match.group(1)
        cases = tuple(CASE_RE.findall(risk_cell))
        observed[risk_id] = cases
        all_cases.extend(cases)
        assert decision.startswith("`PENDIENTE_HUMANA`")

        if set(cases) <= INERT_CASES:
            state = row[2]
            assert "`INERT`" in state
            assert "`OUTSIDE_DENOMINATOR`" in state
            assert "0 ejecutadas" in state

    assert observed == EXPECTED_CASES_BY_RISK
    assert Counter(all_cases) == Counter(
        case
        for cases in EXPECTED_CASES_BY_RISK.values()
        for case in cases
    )
    assert set(all_cases) == {
        "AC-PI-01",
        "AC-PI-02",
        "AC-PI-03",
        "AC-JB-01",
        "AC-JB-02",
        "AC-EX-01",
        "AC-EX-02",
        "AC-EX-03",
        "AC-TOL-01",
        "AC-TOL-02",
        "AC-TOL-03",
        "AC-TOL-04",
        "AC-TOL-05",
        "AC-DOS-01",
        "AC-DOS-02",
        "AC-DOS-03",
        "AC-SC-01",
    }


def test_metrics_tradeoffs_and_limits_remain_bounded() -> None:
    compact = " ".join(_document().split())

    for expected in (
        "14/14 casos adversarios completados",
        "1/14 → 0/14",
        "1 → 0",
        "1 caso mejorado",
        "0 regresiones",
        "12/12 casos benignos completados",
        "0/12 falsos rechazos",
        "24/24 hallazgos",
        "36/36 acciones recomendadas",
        "24/24 prohibiciones",
        "0/24 hallazgos",
        "0/36 acciones",
        "0/24 cláusulas",
        "`CF-002` permanece `NOT_COMPUTABLE`",
        "`df13683` → `ba600ca`",
        "189693584 ns",
        "259169250 ns",
        "+67387688 ns",
        "167383000 ns",
        "223382500 ns",
        "+60542500 ns",
        "36315136 B",
        "41172992 B",
        "+4907008 B",
        "30 pares, un único host y una única sesión",
        "M08 no califica estos cambios como aceptables",
    ):
        assert expected in compact

    for limit in (
        "modelo GenAI real",
        "prompt libre",
        "equivalencia semántica general",
        "ataques desconocidos",
        "producción",
        "umbral operacional",
        "significación",
        "energía",
        "TCO",
        "concurrencia",
        "carga sostenida",
    ):
        assert limit in compact

    for unsafe_claim in (
        "100% utilidad",
        "100 % utilidad",
        "cobertura semántica",
        "0/18",
        "18/18",
    ):
        assert unsafe_claim not in compact.casefold()

    assert "no acepta ningún riesgo" in compact
    assert "M08 únicamente documenta el corte" in compact
