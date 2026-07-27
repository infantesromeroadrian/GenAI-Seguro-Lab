"""Pruebas focales de la corrección funcional benigna de M06."""

from __future__ import annotations

from pathlib import Path

from genai_seguro_lab.baseline import _build_flow
from genai_seguro_lab.benign_flow import BenignAnalysisFlow
from genai_seguro_lab.data_contract import (
    IncidentExpectedResult,
    load_dataset,
)
from genai_seguro_lab.local_tools import KnowledgeCatalog
from genai_seguro_lab.resource_control import MAX_FINAL_SUMMARY_BYTES

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
ORACLE_CANARY = "M06_ORACLE_CANARY_MUST_NOT_REACH_TARGET"


def test_all_cases_have_structured_case_specific_safe_content() -> None:
    bundle = load_dataset(DATA_DIR)
    knowledge_by_id = {item.id: item for item in bundle.knowledge}
    flow = _build_flow(
        bundle.incidents,
        KnowledgeCatalog(bundle.knowledge),
        bundle.knowledge,
    )
    outputs: list[str] = []

    for incident in bundle.incidents:
        result = flow.analyze(incident)
        summary = result.output.summary
        outputs.append(summary)

        assert "Hechos observados" in summary
        assert "Fuentes autorizadas" in summary
        assert "Incertidumbres y datos ausentes" in summary
        assert "Actuación propuesta" in summary
        assert "Justificación" in summary
        assert "Riesgos y límites" in summary
        assert summary.count("- Propuesta:") >= 3
        assert len(summary.encode("utf-8")) <= MAX_FINAL_SUMMARY_BYTES
        assert result.output.actions_executed is False
        assert result.output.compromise_confirmed is False
        assert len(result.invocations) == 2
        assert sum(
            invocation.tool_request_count
            for invocation in result.invocations
        ) == 1
        assert all(
            invocation.descriptor.external_calls is False
            for invocation in result.invocations
        )

        expected_procedures = tuple(
            procedure
            for knowledge_id in incident.knowledge_refs
            for procedure in knowledge_by_id[knowledge_id].procedures
        )
        assert all(
            f"- Propuesta: {procedure}" in summary
            for procedure in expected_procedures
        )

    assert len(outputs) == len(set(outputs)) == 12


def test_expected_result_mutation_does_not_reach_request_or_output() -> None:
    bundle = load_dataset(DATA_DIR)
    original = bundle.incidents[0]
    mutated = original.model_copy(
        update={
            "expected_result": IncidentExpectedResult(
                required_findings=(ORACLE_CANARY,),
                recommended_actions=(ORACLE_CANARY,),
                forbidden_claims=(ORACLE_CANARY,),
                allowed_tool_requests=("knowledge_search",),
            )
        }
    )

    assert BenignAnalysisFlow.build_initial_request(original) == (
        BenignAnalysisFlow.build_initial_request(mutated)
    )

    original_result = _build_flow(
        (original,),
        KnowledgeCatalog(bundle.knowledge),
        bundle.knowledge,
    ).analyze(original)
    mutated_result = _build_flow(
        (mutated,),
        KnowledgeCatalog(bundle.knowledge),
        bundle.knowledge,
    ).analyze(mutated)

    assert original_result.output == mutated_result.output
    assert ORACLE_CANARY not in original_result.output.summary
    assert ORACLE_CANARY not in mutated_result.output.summary
