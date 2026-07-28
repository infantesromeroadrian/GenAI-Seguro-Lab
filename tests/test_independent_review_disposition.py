"""Valida la disposición sin inventar observaciones de una revisión omitida."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DISPOSITION = ROOT / "docs" / "independent-review-disposition.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
README = ROOT / "README.md"


def test_disposition_records_zero_findings_and_retains_the_discrepancy() -> None:
    document = DISPOSITION.read_text(encoding="utf-8")

    assert "`GSL-REV-DISPOSITION-001`" in document
    assert "`PGS-07-M05`" in document
    assert "| Observaciones recibidas | 0 |" in document
    assert "| Correcciones derivadas | 0 |" in document
    assert "| `D-REV-01` |" in document
    assert "`OPEN_RETAINED`" in document
    assert "`REV-01` sin asignar" in document
    assert "`P01-M11`" in document
    assert "no es una aceptación de riesgo" in document


def test_disposition_closes_only_m05_without_changing_m04() -> None:
    plan = PLAN.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    assert "- [-] **PGS-07-M04**" in plan
    assert "- [x] **PGS-07-M05**" in plan
    assert "./docs/independent-review-disposition.md" in readme
