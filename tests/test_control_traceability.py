"""Valida la trazabilidad documental de controles, no su eficacia defensiva."""

from __future__ import annotations

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROL_MAP = ROOT / "docs" / "control-responsibility-mapping.md"
START_MARKER = "<!-- control-traceability:start -->"
END_MARKER = "<!-- control-traceability:end -->"

EXPECTED_CONTROLS = tuple(f"CTL-{number:02d}" for number in range(1, 14))
EXPECTED_THREATS = {
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
KNOWN_ROLES = {"ACT-01", "ACT-02", "ACT-03", "REV-01"}
EXPECTED_HEADER = (
    "ID",
    "Control",
    "Estado",
    "Responsable",
    "Amenazas",
    "Evidencia actual",
    "Pruebas actuales",
    "Limitación",
    "Próxima evidencia prevista",
)

CONTROL_RE = re.compile(r"`(CTL-\d{2})`")
THREAT_RE = re.compile(r"\bAC-[A-Z]+-\d+\b")
ROLE_RE = re.compile(r"\b(?:ACT|REV)-\d+\b")
CODE_RE = re.compile(r"`([^`]+)`")
SELECTOR_RE = re.compile(
    r"tests/[A-Za-z0-9_./-]+\.py::test_[A-Za-z0-9_]+"
)


def _marked_table() -> list[tuple[str, ...]]:
    document = CONTROL_MAP.read_text(encoding="utf-8")
    assert document.count(START_MARKER) == 1
    assert document.count(END_MARKER) == 1

    table = document.split(START_MARKER, maxsplit=1)[1].split(
        END_MARKER, maxsplit=1
    )[0]
    lines = [line.strip() for line in table.splitlines() if line.strip()]
    assert len(lines) >= 3

    rows = [
        tuple(cell.strip() for cell in line.removeprefix("|").removesuffix("|").split("|"))
        for line in lines
    ]
    assert rows[0] == EXPECTED_HEADER
    assert all(set(cell) == {"-"} for cell in rows[1])
    assert all(len(row) == len(EXPECTED_HEADER) for row in rows[2:])
    return rows[2:]


def _test_functions(relative_path: str) -> set[str]:
    test_path = (ROOT / relative_path).resolve()
    tests_root = (ROOT / "tests").resolve()
    assert test_path.is_relative_to(tests_root)
    assert test_path.is_file()

    tree = ast.parse(test_path.read_text(encoding="utf-8"), filename=str(test_path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_control_traceability_matrix_is_complete_and_well_formed() -> None:
    """Comprueba el contrato de documentación, no la eficacia de los controles."""

    rows = _marked_table()
    assert len(rows) == len(EXPECTED_CONTROLS)

    observed_controls: list[str] = []
    covered_threats: set[str] = set()

    for (
        control_id,
        control,
        state,
        responsible,
        threats,
        evidence,
        tests,
        limitation,
        next_evidence,
    ) in rows:
        control_match = CONTROL_RE.fullmatch(control_id)
        assert control_match is not None
        observed_controls.append(control_match.group(1))

        assert control
        assert state
        assert evidence
        assert limitation and limitation not in {"-", "—", "N/A", "n/a"}
        assert next_evidence

        role_ids = ROLE_RE.findall(responsible)
        assert role_ids
        assert set(role_ids) <= KNOWN_ROLES

        threat_ids = THREAT_RE.findall(threats)
        assert threat_ids
        assert len(threat_ids) == len(set(threat_ids))
        assert set(threat_ids) <= EXPECTED_THREATS
        covered_threats.update(threat_ids)

        selectors = CODE_RE.findall(tests)
        assert selectors
        assert len(selectors) == len(set(selectors))
        assert all(SELECTOR_RE.fullmatch(selector) for selector in selectors)
        for selector in selectors:
            relative_path, function_name = selector.split("::", maxsplit=1)
            assert function_name in _test_functions(relative_path)

    assert tuple(observed_controls) == EXPECTED_CONTROLS
    assert len(observed_controls) == len(set(observed_controls))
    assert covered_threats == EXPECTED_THREATS
