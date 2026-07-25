"""Pruebas de la política M02 para entradas, salidas y herramientas."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from genai_seguro_lab.benign_flow import (
    BenignAnalysisFlow,
    BenignFinalOutput,
    BenignFlowError,
    BenignIncidentInput,
    BenignTaskInput,
    canonical_flow_json,
)
from genai_seguro_lab.data_contract import IncidentRecord, load_dataset
from genai_seguro_lab.local_tools import (
    KnowledgeCatalog,
    ToolExecutionGrant,
    ToolPolicyError,
)
from genai_seguro_lab.model_adapter import (
    DeterministicModelAdapter,
    ModelResponse,
    ModelToolRequest,
    ScriptedExchange,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(scope="module")
def incident() -> IncidentRecord:
    return load_dataset(DATA_DIR).incidents[0]


@pytest.fixture(scope="module")
def knowledge_catalog() -> KnowledgeCatalog:
    return KnowledgeCatalog(load_dataset(DATA_DIR).knowledge)


def _flow_with_final_output(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
    output_text: str,
) -> BenignAnalysisFlow:
    initial = BenignAnalysisFlow.build_initial_request(incident)
    tool_request = ModelToolRequest(
        request_id="CALL-VALIDATION-001",
        name="knowledge_search",
        arguments_json=json.dumps(
            {
                "knowledge_ids": list(incident.knowledge_refs),
                "limit": 1,
                "query": incident.category,
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
    )
    knowledge_tool = knowledge_catalog.for_incident(
        incident,
        principal="benign-flow",
        scope=f"incident:{incident.id}",
    )
    knowledge = knowledge_tool.search(
        tool_request,
        grant=knowledge_tool.execution_grant,
    )
    followup = BenignAnalysisFlow.build_followup_request(
        initial,
        tool_request,
        knowledge,
    )
    adapter = DeterministicModelAdapter(
        (
            ScriptedExchange(
                request=initial,
                response=ModelResponse(
                    finish_reason="tool_request",
                    tool_requests=(tool_request,),
                ),
            ),
            ScriptedExchange(
                request=followup,
                response=ModelResponse(
                    finish_reason="stop",
                    output_text=output_text,
                ),
            ),
        )
    )
    return BenignAnalysisFlow(adapter, knowledge_catalog)


def test_benign_input_envelopes_are_strict_and_omit_oracles(
    incident: IncidentRecord,
) -> None:
    request = BenignAnalysisFlow.build_initial_request(incident)
    task = BenignTaskInput.model_validate_json(request.messages[1].content)
    payload = BenignIncidentInput.model_validate_json(
        request.messages[2].content
    )

    assert task.incident_id == incident.id
    assert set(payload.model_dump()) == {
        "category",
        "id",
        "indicators",
        "knowledge_refs",
        "scenario",
        "title",
    }
    assert not {
        "expected_result",
        "provenance",
        "synthetic",
    }.intersection(payload.model_dump())

    with pytest.raises(ValidationError, match="Extra inputs"):
        BenignTaskInput.model_validate(
            {
                "operation": "analyze_synthetic_incident",
                "incident_id": incident.id,
                "unexpected": "denied",
            }
        )


def test_execution_grant_cannot_be_fabricated_from_model_data() -> None:
    with pytest.raises(ToolPolicyError, match="issued by the application"):
        ToolExecutionGrant(
            principal="benign-flow",
            scope="incident:INC-BEN-001",
            tool="knowledge_search",
            allowed_knowledge_ids=("KB-001",),
        )


@pytest.mark.parametrize(
    "invalid_values",
    (
        {"actions_executed": True},
        {"compromise_confirmed": True},
        {"unexpected": "denied"},
    ),
)
def test_final_output_schema_rejects_forbidden_claims_and_fields(
    incident: IncidentRecord,
    invalid_values: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "incident_id": incident.id,
        "summary": "Análisis sintético.",
        "knowledge_ids": incident.knowledge_refs,
        "actions_executed": False,
        "compromise_confirmed": False,
    }
    values.update(invalid_values)

    with pytest.raises(ValidationError):
        BenignFinalOutput.model_validate(values)


def test_flow_rejects_unstructured_final_output(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
) -> None:
    flow = _flow_with_final_output(
        incident,
        knowledge_catalog,
        "texto libre no validado",
    )

    with pytest.raises(BenignFlowError, match="schema validation"):
        flow.analyze(incident)


def test_flow_rejects_final_output_for_another_incident(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
) -> None:
    output = BenignFinalOutput(
        incident_id="INC-BEN-002",
        summary="Análisis sintético.",
        knowledge_ids=incident.knowledge_refs,
        actions_executed=False,
        compromise_confirmed=False,
    )
    flow = _flow_with_final_output(
        incident,
        knowledge_catalog,
        canonical_flow_json(output),
    )

    with pytest.raises(BenignFlowError, match="another incident"):
        flow.analyze(incident)


def test_flow_rejects_final_output_with_unauthorized_knowledge(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
) -> None:
    output = BenignFinalOutput(
        incident_id=incident.id,
        summary="Análisis sintético.",
        knowledge_ids=("KB-002",),
        actions_executed=False,
        compromise_confirmed=False,
    )
    flow = _flow_with_final_output(
        incident,
        knowledge_catalog,
        canonical_flow_json(output),
    )

    with pytest.raises(BenignFlowError, match="authorized knowledge"):
        flow.analyze(incident)
