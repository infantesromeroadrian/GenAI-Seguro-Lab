"""Pruebas del límite de confianza entre instrucciones y datos."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from genai_seguro_lab.benign_flow import BenignAnalysisFlow
from genai_seguro_lab.data_contract import IncidentRecord, load_dataset
from genai_seguro_lab.local_tools import KnowledgeSearchTool
from genai_seguro_lab.model_adapter import (
    ModelMessage,
    ModelRequest,
    ModelToolRequest,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(scope="module")
def incident() -> IncidentRecord:
    return load_dataset(DATA_DIR).incidents[0]


def test_initial_request_separates_every_trust_domain(
    incident: IncidentRecord,
) -> None:
    request = BenignAnalysisFlow.build_initial_request(incident)

    assert request.instruction_boundary == "separated"
    assert [
        (message.role, message.trust_class) for message in request.messages
    ] == [
        ("system", "trusted_instruction"),
        ("user", "user_data"),
        ("user", "untrusted_content"),
    ]
    user_data = json.loads(request.messages[1].content)
    untrusted_content = json.loads(request.messages[2].content)
    assert user_data == {
        "incident_id": incident.id,
        "operation": "analyze_synthetic_incident",
    }
    assert untrusted_content["scenario"] == incident.scenario
    assert incident.scenario not in request.messages[0].content
    assert incident.scenario not in request.messages[1].content


def test_followup_preserves_boundary_and_marks_model_and_tool_data(
    incident: IncidentRecord,
) -> None:
    initial = BenignAnalysisFlow.build_initial_request(incident)
    tool_request = ModelToolRequest(
        request_id="CALL-BOUNDARY-001",
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
    knowledge = KnowledgeSearchTool(
        load_dataset(DATA_DIR).knowledge
    ).search(
        tool_request,
        allowed_ids=incident.knowledge_refs,
    )

    followup = BenignAnalysisFlow.build_followup_request(
        initial,
        tool_request,
        knowledge,
    )

    assert followup.instruction_boundary == "separated"
    assert followup.messages[-2].trust_class == "model_output"
    assert followup.messages[-1].role == "tool"
    assert followup.messages[-1].trust_class == "untrusted_content"


@pytest.mark.parametrize(
    ("role", "trust_class"),
    (
        ("system", "untrusted_content"),
        ("user", "trusted_instruction"),
        ("assistant", "user_data"),
        ("tool", "model_output"),
    ),
)
def test_message_roles_reject_incompatible_trust_classes(
    role: str,
    trust_class: str,
) -> None:
    with pytest.raises(ValidationError, match="cannot be classified"):
        ModelMessage.model_validate(
            {
                "role": role,
                "trust_class": trust_class,
                "content": "contenido",
            }
        )


def test_request_requires_one_leading_trusted_instruction() -> None:
    messages = (
        ModelMessage(
            role="user",
            trust_class="user_data",
            content='{"operation":"analyze"}',
        ),
        ModelMessage(
            role="user",
            trust_class="untrusted_content",
            content='{"scenario":"synthetic"}',
        ),
        ModelMessage(
            role="system",
            trust_class="trusted_instruction",
            content="Instrucción tardía.",
        ),
    )

    with pytest.raises(ValidationError, match="leading trusted instruction"):
        ModelRequest(
            request_id="REQ-BOUNDARY-LATE",
            instruction_boundary="separated",
            messages=messages,
        )


@pytest.mark.parametrize(
    ("omitted_trust_class", "error"),
    (
        ("user_data", "explicitly classified user data"),
        ("untrusted_content", "explicitly classified untrusted content"),
    ),
)
def test_request_requires_user_and_untrusted_data_domains(
    omitted_trust_class: str,
    error: str,
) -> None:
    messages = (
        ModelMessage(
            role="system",
            trust_class="trusted_instruction",
            content="Instrucción.",
        ),
        ModelMessage(
            role="user",
            trust_class=(
                "untrusted_content"
                if omitted_trust_class == "user_data"
                else "user_data"
            ),
            content='{"value":"synthetic"}',
        ),
    )

    with pytest.raises(ValidationError, match=error):
        ModelRequest(
            request_id="REQ-BOUNDARY-MISSING",
            instruction_boundary="separated",
            messages=messages,
        )
