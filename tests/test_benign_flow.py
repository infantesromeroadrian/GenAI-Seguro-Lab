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
    KnowledgeCatalog,
    ToolDeniedError,
)
from genai_seguro_lab.model_adapter import (
    DeterministicModelAdapter,
    ModelResponse,
    ModelToolRequest,
    ScriptedExchange,
    UnknownModelRequestError,
)
from genai_seguro_lab.output_policy import OutputPolicy
from genai_seguro_lab.output_policy import OutputPolicyRejectedError

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(scope="module")
def incident() -> IncidentRecord:
    return load_dataset(DATA_DIR).incidents[0]


@pytest.fixture(scope="module")
def knowledge_catalog() -> KnowledgeCatalog:
    return KnowledgeCatalog(load_dataset(DATA_DIR).knowledge)


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
    knowledge_catalog: KnowledgeCatalog,
    *,
    summary: str | None = None,
) -> BenignAnalysisFlow:
    initial = BenignAnalysisFlow.build_initial_request(incident)
    tool_request = _search_request(incident)
    first_response = ModelResponse(
        finish_reason="tool_request",
        tool_requests=(tool_request,),
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
    final_response = ModelResponse(
        finish_reason="stop",
        output_text=canonical_flow_json(
            BenignFinalOutput(
                incident_id=incident.id,
                summary=summary or (
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
    return BenignAnalysisFlow(
        adapter,
        knowledge_catalog,
        output_policy=OutputPolicy(),
    )


def test_benign_flow_searches_once_and_returns_final_text(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
) -> None:
    flow = _configured_flow(incident, knowledge_catalog)

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
    serialized_invocations = tuple(
        invocation.model_dump(mode="json")
        for invocation in first.invocations
    )
    assert all("response" not in item for item in serialized_invocations)
    assert all("output_text" not in item for item in serialized_invocations)
    assert first.invocations[0].tool_request_count == 1
    assert first.invocations[1].tool_request_count == 0
    assert first.output_policy.decision == "allow"


def test_benign_flow_redacts_before_returning_safe_result(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
) -> None:
    raw = "Contacta con analyst@example.test en /Users/operator/report.txt."
    result = _configured_flow(
        incident,
        knowledge_catalog,
        summary=raw,
    ).analyze(incident)

    assert result.output_text == (
        "Contacta con [REDACTED_EMAIL] en [REDACTED_LOCAL_PATH]"
    )
    assert result.output_policy.decision == "redact"
    assert result.output_policy.redaction_categories == (
        "email",
        "local_path",
    )
    assert raw not in repr(result)
    assert raw not in str(result.model_dump(mode="json"))


def test_benign_flow_rejects_without_retaining_raw_output(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
) -> None:
    raw = "CANARY_GSL_EX_003"
    flow = _configured_flow(
        incident,
        knowledge_catalog,
        summary=raw,
    )

    with pytest.raises(OutputPolicyRejectedError) as captured:
        flow.analyze(incident)

    assert raw not in str(captured.value)
    assert raw not in repr(captured.value)


def test_flow_fails_if_model_skips_required_search(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
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
    flow = BenignAnalysisFlow(
        adapter,
        knowledge_catalog,
        output_policy=OutputPolicy(),
    )

    with pytest.raises(BenignFlowError, match="exactly one tool"):
        flow.analyze(incident)


def test_flow_denies_a_non_knowledge_tool(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
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
    flow = BenignAnalysisFlow(
        adapter,
        knowledge_catalog,
        output_policy=OutputPolicy(),
    )

    with pytest.raises(ToolDeniedError, match="not allowed"):
        flow.analyze(incident)


def test_flow_denies_a_query_not_bound_to_the_incident(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
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
    flow = BenignAnalysisFlow(
        adapter,
        knowledge_catalog,
        output_policy=OutputPolicy(),
    )

    with pytest.raises(
        ToolDeniedError,
        match="does not match the validated incident",
    ):
        flow.analyze(incident)


def test_flow_does_not_generalize_to_an_unscripted_incident(
    incident: IncidentRecord,
    knowledge_catalog: KnowledgeCatalog,
) -> None:
    flow = _configured_flow(incident, knowledge_catalog)
    other_incident = load_dataset(DATA_DIR).incidents[1]

    with pytest.raises(UnknownModelRequestError):
        flow.analyze(other_incident)
