"""Pruebas del adaptador determinista de modelo."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from genai_seguro_lab.model_adapter import (
    DeterministicModelAdapter,
    ModelAdapter,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelToolRequest,
    ScriptedExchange,
    UnknownModelRequestError,
    request_fingerprint,
)


@pytest.fixture
def model_request() -> ModelRequest:
    return ModelRequest(
        request_id="REQ-BEN-001",
        instruction_boundary="separated",
        messages=(
            ModelMessage(
                role="system",
                trust_class="trusted_instruction",
                content="Analiza únicamente el incidente sintético.",
            ),
            ModelMessage(
                role="user",
                trust_class="user_data",
                content='{"operation":"summarize"}',
            ),
            ModelMessage(
                role="user",
                trust_class="untrusted_content",
                content='{"observation":"mensaje sintético"}',
            ),
        ),
        available_tools=("knowledge_search",),
    )


@pytest.fixture
def response() -> ModelResponse:
    return ModelResponse(
        finish_reason="stop",
        output_text="El mensaje contiene indicadores sospechosos sintéticos.",
    )


@pytest.fixture
def adapter(
    model_request: ModelRequest,
    response: ModelResponse,
) -> DeterministicModelAdapter:
    return DeterministicModelAdapter(
        (ScriptedExchange(request=model_request, response=response),)
    )


def test_adapter_matches_protocol_and_has_no_external_effects(
    adapter: DeterministicModelAdapter,
) -> None:
    assert isinstance(adapter, ModelAdapter)
    assert adapter.descriptor.provider == "deterministic"
    assert adapter.descriptor.deterministic is True
    assert adapter.descriptor.external_calls is False
    assert adapter.descriptor.cost_eur == 0


def test_exact_request_is_reproducible(
    adapter: DeterministicModelAdapter,
    model_request: ModelRequest,
    response: ModelResponse,
) -> None:
    first = adapter.generate(model_request)
    second = adapter.generate(model_request)

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert first.request_fingerprint == request_fingerprint(model_request)
    assert first.response == response


def test_changed_request_fails_closed_without_echoing_content(
    adapter: DeterministicModelAdapter,
) -> None:
    changed = ModelRequest(
        request_id="REQ-BEN-001",
        instruction_boundary="separated",
        messages=(
            ModelMessage(
                role="system",
                trust_class="trusted_instruction",
                content="Analiza únicamente el incidente sintético.",
            ),
            ModelMessage(
                role="user",
                trust_class="user_data",
                content='{"operation":"summarize"}',
            ),
            ModelMessage(
                role="user",
                trust_class="untrusted_content",
                content="contenido-que-no-debe-aparecer-en-el-error",
            ),
        ),
        available_tools=("knowledge_search",),
    )

    with pytest.raises(UnknownModelRequestError) as exc_info:
        adapter.generate(changed)

    message = str(exc_info.value)
    assert "REQ-BEN-001" in message
    assert "contenido-que-no-debe-aparecer-en-el-error" not in message


def test_duplicate_or_empty_scripts_are_rejected(
    model_request: ModelRequest,
    response: ModelResponse,
) -> None:
    script = ScriptedExchange(request=model_request, response=response)

    with pytest.raises(ValueError, match="at least one scripted exchange"):
        DeterministicModelAdapter(())

    with pytest.raises(ValueError, match="duplicate scripted model request"):
        DeterministicModelAdapter((script, script))


def test_stop_response_must_be_final_text_without_tool_requests() -> None:
    tool_request = ModelToolRequest(
        request_id="CALL-001",
        name="knowledge_search",
        arguments_json='{"query":"phishing"}',
    )

    with pytest.raises(ValidationError, match="require output text"):
        ModelResponse(finish_reason="stop")

    with pytest.raises(ValidationError, match="cannot contain tool requests"):
        ModelResponse(
            finish_reason="stop",
            output_text="Texto final.",
            tool_requests=(tool_request,),
        )


def test_tool_response_requires_requests_with_unique_ids() -> None:
    tool_request = ModelToolRequest(
        request_id="CALL-001",
        name="knowledge_search",
        arguments_json='{"query":"phishing"}',
    )

    with pytest.raises(ValidationError, match="require at least one request"):
        ModelResponse(finish_reason="tool_request")

    with pytest.raises(ValidationError, match="identifiers must be unique"):
        ModelResponse(
            finish_reason="tool_request",
            tool_requests=(tool_request, tool_request),
        )


def test_tool_arguments_must_be_a_json_object() -> None:
    with pytest.raises(ValidationError, match="valid JSON"):
        ModelToolRequest(
            request_id="CALL-001",
            name="knowledge_search",
            arguments_json="{not-json}",
        )

    with pytest.raises(ValidationError, match="JSON object"):
        ModelToolRequest(
            request_id="CALL-001",
            name="knowledge_search",
            arguments_json='["not", "an", "object"]',
        )


def test_tool_request_is_transported_but_not_authorized(
    model_request: ModelRequest,
) -> None:
    response = ModelResponse(
        finish_reason="tool_request",
        tool_requests=(
            ModelToolRequest(
                request_id="CALL-UNAPPROVED-001",
                name="unapproved_tool",
                arguments_json='{"target":"sandbox"}',
            ),
        ),
    )
    adapter = DeterministicModelAdapter(
        (ScriptedExchange(request=model_request, response=response),)
    )

    result = adapter.generate(model_request)

    assert result.response.tool_requests[0].name == "unapproved_tool"
    assert "authorized" not in result.response.model_dump()


def test_request_rejects_unknown_advertised_tools(
    model_request: ModelRequest,
) -> None:
    with pytest.raises(ValidationError, match="literal_error"):
        ModelRequest(
            request_id=model_request.request_id,
            instruction_boundary=model_request.instruction_boundary,
            messages=model_request.messages,
            available_tools=("unapproved_tool",),
        )
