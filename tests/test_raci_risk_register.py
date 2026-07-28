"""Valida la RACI y el registro formal de riesgos de PGS-06-M03."""

from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RACI = ROOT / "docs" / "raci.md"
RISK_REGISTER = ROOT / "docs" / "risk-register.md"
CONTROL_MAP = ROOT / "docs" / "control-responsibility-mapping.md"
SYSTEM_CARD = ROOT / "docs" / "system-card.md"
DOCS_README = ROOT / "docs" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

SOURCE_COMMIT = "648dd9afe9ef696388257ebf8dda4b59ece1aeb5"
CANDIDATE_COMMIT = "77edd64037bb0e41edffa58cae2682ba7d2694d2"
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"
ACTORS = ("ACT-02", "ACT-01", "ACT-03", "REV-01")
EXPECTED_RACI_IDS = {f"RACI-{index:02d}" for index in range(1, 13)}
EXPECTED_RISK_CASES = {
    "RR-01": {"AC-DOS-01"},
    "RR-02": {"AC-DOS-02", "AC-DOS-03"},
    "RR-03": {"AC-SC-01"},
    "RR-04": {"AC-TOL-05"},
    "RR-05": {"AC-TOL-03", "AC-TOL-04"},
    "RR-06": {
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
    },
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _marked(document: str, name: str) -> str:
    start = f"<!-- {name}:start -->"
    end = f"<!-- {name}:end -->"
    assert document.count(start) == 1
    assert document.count(end) == 1
    return document.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def _table(document: str, marker: str) -> tuple[list[str], list[list[str]]]:
    lines = [
        line.strip()
        for line in _marked(document, marker).splitlines()
        if line.strip().startswith("|")
    ]
    assert len(lines) >= 3
    headers = [cell.strip() for cell in lines[0].strip("|").split("|")]
    assert all(set(cell.replace(":", "").replace("-", "")) == set() for cell in lines[1].strip("|").split("|"))
    rows = [
        [cell.strip() for cell in line.strip("|").split("|")]
        for line in lines[2:]
    ]
    assert all(len(row) == len(headers) for row in rows)
    return headers, rows


def _identifier(cell: str, prefix: str) -> str:
    match = re.search(rf"`({prefix}-\d{{2}})`", cell)
    assert match is not None
    return match.group(1)


def _raci_tokens(cell: str) -> set[str]:
    value = cell.replace("`", "").strip()
    if value == "—":
        return {value}
    return set(value.split("/"))


def test_raci_has_one_current_accountable_per_activity() -> None:
    document = _read(RACI)
    headers, rows = _table(document, "raci-matrix")

    assert "`GSL-RACI-001`" in document
    assert "`1.0.0`" in document
    assert "`VIGENTE_ALCANCE_ACTUAL`" in document
    assert f"`{SOURCE_COMMIT}`" in document
    assert headers[2:6] == [f"`{actor}`" for actor in ACTORS]
    assert {_identifier(row[0], "RACI") for row in rows} == EXPECTED_RACI_IDS
    assert len(rows) == 12

    allowed = {"A", "R", "C", "I", "P-R", "P-C", "P-I", "—"}
    for row in rows:
        actor_tokens = [_raci_tokens(cell) for cell in row[2:6]]
        assert all(tokens <= allowed for tokens in actor_tokens)
        assert sum("A" in tokens for tokens in actor_tokens) == 1
        assert "A" in actor_tokens[0]

        raci_id = _identifier(row[0], "RACI")
        if raci_id == "RACI-11":
            assert "P-R" in actor_tokens[3]
        else:
            assert any("R" in tokens for tokens in actor_tokens)


def test_raci_keeps_synthetic_confirmation_and_review_planned() -> None:
    document = _read(RACI)
    _, rows = _table(document, "raci-matrix")
    by_id = {_identifier(row[0], "RACI"): row for row in rows}

    assert _raci_tokens(by_id["RACI-06"][4]) == {"R"}
    assert all(
        "R" not in _raci_tokens(row[4])
        for risk_id, row in by_id.items()
        if risk_id != "RACI-06"
    )
    assert all(
        all(token.startswith("P-") or token == "—" for token in _raci_tokens(row[5]))
        for row in rows
    )
    compact = " ".join(document.split()).casefold()
    for expected in (
        "planificado y sin asignar",
        "no demuestra presencia",
        "no permiten afirmar",
        "único accountable actual",
    ):
        assert expected in compact


def test_formal_risk_register_preserves_scope_ownership_and_pending_decisions() -> None:
    document = _read(RISK_REGISTER)
    _, rows = _table(document, "formal-risk-register")

    assert "`GSL-RISK-REGISTER-001`" in document
    assert "`1.0.0`" in document
    assert "`ABIERTO_ALCANCE_ACTUAL`" in document
    assert f"`{SOURCE_COMMIT}`" in document
    assert f"`{CANDIDATE_COMMIT}`" in document
    assert f"`{DAT25_SHA256}`" in document
    assert len(rows) == 6

    observed: dict[str, set[str]] = {}
    for row in rows:
        risk_id = _identifier(row[0], "RR")
        observed[risk_id] = set(re.findall(r"`(AC-[A-Z]+-\d{2})`", row[0]))
        assert row[2] == "`ACT-02`"
        assert "`ABIERTO`" in row[3]
        assert "`PROPUESTO_NO_APROBADO`" in row[6]
        assert re.findall(r"`PGS-\d{2}-M\d{2}`", row[7])
        assert row[8] == "`PENDIENTE_HUMANA`"
        assert row[9]

    assert observed == EXPECTED_RISK_CASES
    all_cases = [case for cases in observed.values() for case in cases]
    assert len(all_cases) == 17
    assert len(set(all_cases)) == 17


def test_decision_queue_has_six_unselected_human_handoffs() -> None:
    document = _read(RISK_REGISTER)
    headers, rows = _table(document, "risk-decision-queue")

    assert "`ACT-02`" in headers[2]
    assert len(rows) == 6
    assert {_identifier(row[0], "RDEC") for row in rows} == {
        f"RDEC-{index:02d}" for index in range(1, 7)
    }
    assert {_identifier(row[1], "RR") for row in rows} == set(EXPECTED_RISK_CASES)
    for row in rows:
        assert row[2]
        assert row[3]
        assert row[4]
        assert row[5] == "`PENDIENTE_HUMANA`"

    compact = " ".join(document.split())
    assert "No hay una opción seleccionada" in compact
    assert "`CERRADO`" in document
    assert "decisión humana explícita" in document


def test_m03_is_integrated_without_duplicate_raci_or_architecture_claims() -> None:
    control_map = _read(CONTROL_MAP)
    system_card = _read(SYSTEM_CARD)
    docs_readme = _read(DOCS_README)
    readme = _read(README)
    plan = _read(PLAN)

    assert "raci-matrix:start" not in control_map
    for link in ("./raci.md", "./risk-register.md"):
        assert link in control_map
        assert link in system_card
        assert link in docs_readme
    for link in ("./docs/raci.md", "./docs/risk-register.md"):
        assert link in readme

    assert "- [x] **PGS-06-M03**" in plan
    assert "**PGS-06-M04 — crear el mapa de cumplimiento" in plan
    assert "arquitectura" not in _marked(_read(RACI), "raci-matrix").casefold()


def test_governance_documents_pin_dat25_without_reexecuting_it() -> None:
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
    for path in (RACI, RISK_REGISTER):
        document = _read(path)
        assert re.search(r"/(?:users|home)/[^/\s]+", document.casefold()) is None
        assert "run_final_retest.py" not in document
