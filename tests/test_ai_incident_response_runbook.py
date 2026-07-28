"""Valida el runbook acotado de respuesta a incidentes de IA."""

from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "ai-incident-response-runbook.md"
EVENT_POLICY = ROOT / "docs" / "security-events-policy.md"
DOCS_README = ROOT / "docs" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

EXPECTED_SEVERITIES = {f"IR-SEV-{index}" for index in range(4)}
EXPECTED_WORKFLOW = {f"IR-{index:02d}" for index in range(1, 9)}
EXPECTED_PLAYBOOKS = {f"IR-PB-{index:02d}" for index in range(1, 9)}
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _marked(document: str, name: str) -> str:
    start = f"<!-- {name}:start -->"
    end = f"<!-- {name}:end -->"
    assert document.count(start) == 1
    assert document.count(end) == 1
    return document.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def _ids(section: str, prefix: str) -> set[str]:
    return set(re.findall(rf"`({re.escape(prefix)}[A-Z0-9-]+)`", section))


def test_runbook_has_complete_severity_workflow_and_playbooks() -> None:
    document = _read(RUNBOOK)
    severity = _ids(_marked(document, "incident-severity"), "IR-SEV-")
    workflow = _ids(_marked(document, "incident-workflow"), "IR-")
    playbooks = _ids(_marked(document, "incident-playbooks"), "IR-PB-")

    assert severity == EXPECTED_SEVERITIES
    assert workflow == EXPECTED_WORKFLOW
    assert playbooks == EXPECTED_PLAYBOOKS


def test_signal_is_not_treated_as_proof_or_automatic_authority() -> None:
    compact = " ".join(_read(RUNBOOK).split()).casefold()
    for boundary in (
        "no demuestra por sí sola un ataque",
        "no añade un siem",
        "respuesta automática",
        "sigue sin asignar",
        "no acepta riesgo automáticamente",
        "ni se atribuye independencia",
        "no reescribir evidencia histórica",
        "ejecutar las cuatro fixtures dos/sc inertes sin autorización",
        "no autoriza producción",
    ):
        assert boundary in compact
    assert re.search(r"/(?:users|home)/[^/\s]+", compact) is None


def test_runbook_covers_current_signals_and_response_families() -> None:
    runbook = _read(RUNBOOK)
    policy = _read(EVENT_POLICY)
    for signal in (
        "unknown_model_request",
        "tool_denied",
        "output_policy_intervention",
        "resource_limit_exceeded",
        "lock_conflict",
        "authorization_replay_or_context_mismatch",
        "sandbox_violation",
        "data_integrity_violation",
    ):
        assert signal in policy
        assert signal in runbook

    for phase in (
        "Detectar",
        "Triaje",
        "Contener",
        "Preservar",
        "Erradicar o corregir",
        "Recuperar",
        "Comunicar",
        "Aprender",
    ):
        assert phase in runbook


def test_documentation_and_roadmap_link_completed_m06() -> None:
    assert "./ai-incident-response-runbook.md" in _read(DOCS_README)
    assert "./docs/ai-incident-response-runbook.md" in _read(README)
    assert "./docs/ai-incident-response-runbook.md" in _read(PLAN)
    assert "- [x] **PGS-06-M06**" in _read(PLAN)


def test_dat25_remains_immutable() -> None:
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
