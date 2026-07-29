"""Trazabilidad estática de la extensión Ollama sin ejecutar red."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "ollama-cloud-experimental.md"
ADR = ROOT / "docs" / "ollama-cloud-adr.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"
BASELINE_SOURCE = ROOT / "src" / "genai_seguro_lab" / "baseline.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_example_environment_is_intentionally_empty() -> None:
    example = _read(ROOT / ".env.example")

    assert example == ""


def test_experimental_contract_is_linked_and_declares_honest_limits() -> None:
    document = " ".join(_read(DOC).split())
    readme = _read(ROOT / "README.md")
    docs_index = _read(ROOT / "docs" / "README.md")

    for expected in (
        "`GSL-OLLAMA-001`",
        "POST https://ollama.com/api/chat",
        "`gpt-oss:120b`",
        "`stream=false`",
        "`think=low`",
        "`temperature=0`",
        "exactamente dos llamadas",
        "60 s por llamada",
        "cero reintentos",
        "coste",
        "desconocido",
        "`deterministic=false`",
        "`external_calls=true`",
        "`PASSED_BOUNDED_REAL_SMOKE`",
        "2026-07-28",
        "2026-07-29",
        "408 casos superados",
        "dos POST",
        "`operation_completed`",
        "dos fallos previos",
        "transporte falso",
        "baseline",
        "`DAT-25`",
    ):
        assert expected.casefold() in document.casefold()
    assert "./docs/ollama-cloud-experimental.md" in readme
    assert "./ollama-cloud-experimental.md" in docs_index
    for usage_document in (document, readme):
        assert "read -r -s OLLAMA_API_KEY" in usage_document
        assert "export OLLAMA_API_KEY='" not in usage_document


def test_governance_surfaces_distinguish_extension_from_historical_evidence() -> None:
    expected_by_path = {
        ROOT / "docs" / "rules-of-engagement.md": (
            "`3.0.0`",
            "`GSL-OLLAMA-001`",
            "baseline/evaluaciones",
        ),
        ROOT / "docs" / "system-inventory.md": (
            "`MOD-02`",
            "`CMP-20`",
            "`CMP-21`",
        ),
        ROOT / "docs" / "system-card.md": (
            "`GSL-OLLAMA-001`",
            "coste desconocido",
            "transporte falso",
        ),
        ROOT / "docs" / "model-card.md": (
            "Anexo posterior — `MOD-02`",
            "`deterministic=false`",
            "`external_calls=true`",
        ),
        ROOT / "docs" / "data-card.md": (
            "Egress sintético opt-in",
            "`OLLAMA_API_KEY`",
            "no crea un nuevo dataset",
        ),
        ROOT / "docs" / "ai-impact-assessment.md": (
            "Reevaluación de la extensión `GSL-OLLAMA-001`",
            "`AIA-TRG-01`",
            "`AIA-TRG-04`",
            "está sincronizado",
            "`TB-08`",
            "`CMP-20`",
            "`CMP-21`",
            "`MOD-02`",
        ),
        ROOT / "docs" / "risk-register.md": (
            "Extensión alojada",
            "comportamiento general del modelo",
            "nunca una reinterpretación de `DAT-25`",
        ),
        ADR: (
            "`GSL-ADR-002`",
            "`ACEPTADA_EXPERIMENTAL`",
            "No existe fallback automático",
        ),
    }

    for path, expected_values in expected_by_path.items():
        document = " ".join(_read(path).split())
        for expected in expected_values:
            assert expected.casefold() in document.casefold()


def test_protected_baseline_and_dat25_hashes_remain_unchanged() -> None:
    assert sha256(BASELINE_SOURCE.read_bytes()).hexdigest() == (
        "3ff79527a7ebe5789d04b5eace38c821479fc1df2e19d3efb454bac2d6ae02a2"
    )
    assert sha256(DAT25.read_bytes()).hexdigest() == (
        "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"
    )
