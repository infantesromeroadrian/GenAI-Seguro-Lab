"""Pruebas de integración del flujo benigno mínimo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from genai_seguro_lab.benign_flow import (
    BenignAnalysisFlow,
    BenignFinalOutput,
    BenignFlowError,
    canonical_flow_json,
)
from genai_seguro_lab.data_contract import IncidentRecord, load_dataset
from genai_seguro_lab.local_tools import (
    KnowledgeSearchTool,
    ToolDeniedError,
    ToolExecutionPolicy,
)
from genai_seguro_lab.model_adapter import (
    DeterministicModelAdapter,
    ModelResponse,
    ModelToolRequest,
    ScriptedExchange,
    UnknownModelRequestError,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(scope="module")
def incident() -> IncidentRecord:
    return load_dataset(DATA_DIR).incidents[0]


@pytest.fixture(scope="module")
def knowledge_tool() -> KnowledgeSearchTool:
    return KnowledgeSearchTool(load_dataset(DATA_DIR).knowledge)


def _search_request(incident: IncidentRecord) -> ModelToolRequest:
    return ModelToolRequest(
        request_id="CALL-KNOWLEDGE-001",
        name="knowledge_search",
        arguments_json=json.dumps(
            {
                "query": incident.category,
                "knowledge_ids": list(incident.knowledge_refs),
                "limit": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _configured_flow(
    incident: IncidentRecord,
    knowledge_tool: KnowledgeSearchTool,
) -> BenignAnalysisFlow:
    initial = BenignAnalysisFlow.build_initial_request(incident)
    tool_request = _search_request(incident)
    first_response = ModelResponse(
        finish_reason="tool_request",
        tool_requests=(tool_request,),
    )
    knowledge = knowledge_tool.search(
        tool_request,
        policy=ToolExecutionPolicy(
            allowed_tools=initial.available_tools,
            allowed_knowledge_ids=incident.knowledge_refs,
        ),
    )
    followup = BenignAnalysisFlow.build_followup_request(
        initial,
        tool_request,
        knowledge,
    )
    final_response = ModelResponse(
        finish_reason="stop",
        output_text=canonical_flow_json(
            BenignFinalOutput(
                incident_id=incident.id,
                summary=(
                    "El mensaje contiene indicadores sintéticos de phishing; "
                    "no consta compromiso."
                ),
                knowledge_ids=tuple(hit.id for hit in knowledge.hits),
                actions_executed=False,
                compromise_confirmed=False,
            )
        ),
    )
    adapter = DeterministicModelAdapter(
        (
            ScriptedExchange(request=initial, response=first_response),
            ScriptedExchange(request=followup, response=final_response),
        )
    )
    return BenignAnalysisFlow(adapter, knowledge_tool)


def test_benign_flow_searches_once_and_returns_final_text(
    incident: IncidentRecord,
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    flow = _configured_flow(incident, knowledge_tool)

    first = flow.analyze(incident)
    second = flow.analyze(incident)

    assert first == second
    assert first.incident_id == incident.id
    assert [hit.id for hit in first.knowledge.hits] == ["KB-001"]
    assert len(first.invocations) == 2
    assert all(
        invocation.descriptor.external_calls is False
        for invocation in first.invocations
    )
    assert "no consta compromiso" in first.output_text


def test_flow_fails_if_model_skips_required_search(
    incident: IncidentRecord,
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    initial = BenignAnalysisFlow.build_initial_request(incident)
    adapter = DeterministicModelAdapter(
        (
            ScriptedExchange(
                request=initial,
                response=ModelResponse(
                    finish_reason="stop",
                    output_text="Respuesta sin consultar conocimiento.",
                ),
            ),
        )
    )
    flow = BenignAnalysisFlow(adapter, knowledge_tool)

    with pytest.raises(BenignFlowError, match="exactly one tool"):
        flow.analyze(incident)


def test_flow_denies_a_non_knowledge_tool(
    incident: IncidentRecord,
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    initial = BenignAnalysisFlow.build_initial_request(incident)
    adapter = DeterministicModelAdapter(
        (
            ScriptedExchange(
                request=initial,
                response=ModelResponse(
                    finish_reason="tool_request",
                    tool_requests=(
                        ModelToolRequest(
                            request_id="CALL-DRAFT-001",
                            name="draft_create",
                            arguments_json='{"filename":"not-authorized.md"}',
                        ),
                    ),
                ),
            ),
        )
    )
    flow = BenignAnalysisFlow(adapter, knowledge_tool)

    with pytest.raises(ToolDeniedError, match="not allowed"):
        flow.analyze(incident)


def test_flow_fails_closed_when_search_has_no_hits(
    incident: IncidentRecord,
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    initial = BenignAnalysisFlow.build_initial_request(incident)
    tool_request = ModelToolRequest(
        request_id="CALL-KNOWLEDGE-EMPTY",
        name="knowledge_search",
        arguments_json=json.dumps(
            {
                "query": "termino-inexistente",
                "knowledge_ids": list(incident.knowledge_refs),
                "limit": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
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
        )
    )
    flow = BenignAnalysisFlow(adapter, knowledge_tool)

    with pytest.raises(BenignFlowError, match="no authorized hits"):
        flow.analyze(incident)


def test_flow_does_not_generalize_to_an_unscripted_incident(
    incident: IncidentRecord,
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    flow = _configured_flow(incident, knowledge_tool)
    other_incident = load_dataset(DATA_DIR).incidents[1]

    with pytest.raises(UnknownModelRequestError):
        flow.analyze(other_incident)
