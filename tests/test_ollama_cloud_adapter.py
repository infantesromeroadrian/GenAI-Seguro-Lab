"""Pruebas sin red del adaptador opt-in de Ollama Cloud."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.error import HTTPError

import pytest

from genai_seguro_lab.model_adapter import (
    ModelMessage,
    ModelRequest,
    ModelToolRequest,
)
from genai_seguro_lab.ollama_cloud_adapter import (
    MAX_OLLAMA_RESPONSE_BYTES,
    OLLAMA_CHAT_ENDPOINT,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT_SECONDS,
    OllamaCloudAdapter,
    OllamaCloudConfigurationError,
    OllamaCloudResponseError,
    OllamaCloudTransportError,
    UrllibOllamaCloudTransport,
)

_TEST_KEY = "test-only-placeholder"
_EXPECTED_AUTH_SHA256 = hashlib.sha256(
    f"Bearer {_TEST_KEY}".encode()
).hexdigest()


@dataclass(frozen=True)
class CapturedCall:
    url: str
    header_names: frozenset[str]
    authorization_matches: bool
    document: dict[str, object]
    timeout_seconds: float
    max_response_bytes: int


class FakeTransport:
    """Conserva solo un booleano sobre Authorization, nunca su valor."""

    def __init__(self, responses: tuple[bytes | Exception, ...]) -> None:
        self._responses = list(responses)
        self.calls: list[CapturedCall] = []

    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> bytes:
        authorization_sha256 = hashlib.sha256(
            headers.get("Authorization", "").encode()
        ).hexdigest()
        document = json.loads(body)
        assert isinstance(document, dict)
        self.calls.append(
            CapturedCall(
                url=url,
                header_names=frozenset(headers),
                authorization_matches=hmac.compare_digest(
                    authorization_sha256,
                    _EXPECTED_AUTH_SHA256,
                ),
                document=document,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        )
        if not self._responses:
            raise AssertionError("unexpected transport call")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _initial_request() -> ModelRequest:
    return ModelRequest(
        request_id="REQ-BEN-001-INITIAL",
        instruction_boundary="separated",
        messages=(
            ModelMessage(
                role="system",
                trust_class="trusted_instruction",
                content="Sigue solo la operación autorizada.",
            ),
            ModelMessage(
                role="user",
                trust_class="user_data",
                content=(
                    '{"incident_id":"INC-BEN-001",'
                    '"operation":"analyze_synthetic_incident"}'
                ),
            ),
            ModelMessage(
                role="user",
                trust_class="untrusted_content",
                content=(
                    '{"category":"phishing","id":"INC-BEN-001",'
                    '"knowledge_refs":["KB-001"]}'
                ),
            ),
        ),
        available_tools=("knowledge_search",),
    )


def _first_remote_response(
    *,
    name: str = "knowledge_search",
    arguments: object | None = None,
    thinking: str = "THINKING_MUST_NOT_SURVIVE",
) -> bytes:
    if arguments is None:
        arguments = {
            "knowledge_ids": ["KB-001"],
            "limit": 1,
            "query": "phishing",
        }
    return json.dumps(
        {
            "done": True,
            "message": {
                "role": "assistant",
                "content": "",
                "thinking": thinking,
                "tool_calls": [
                    {
                        "type": "function",
                        "function": {
                            "index": 0,
                            "name": name,
                            "arguments": arguments,
                        },
                    }
                ],
            },
            "provider_debug": "REMOTE_BODY_MUST_NOT_SURVIVE",
        }
    ).encode()


def _followup_request(
    initial: ModelRequest,
    tool_request: ModelToolRequest,
) -> ModelRequest:
    request_json = json.dumps(
        tool_request.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return ModelRequest(
        request_id="REQ-BEN-001-FINAL",
        instruction_boundary="separated",
        messages=(
            *initial.messages,
            ModelMessage(
                role="assistant",
                trust_class="model_output",
                content=f"Solicitud de herramienta: {request_json}",
            ),
            ModelMessage(
                role="tool",
                trust_class="untrusted_content",
                content=(
                    '{"hits":[{"content":"Evidencia sintética.",'
                    '"id":"KB-001","procedures":["Validar"],'
                    '"title":"Phishing","topic":"phishing"}],'
                    '"query":"phishing"}'
                ),
            ),
        ),
    )


def _final_remote_response(
    content: str | None = None,
    *,
    tool_calls: object | None = None,
) -> bytes:
    message: dict[str, object] = {
        "role": "assistant",
        "content": content
        or (
            '{"actions_executed":false,'
            '"compromise_confirmed":false,'
            '"incident_id":"INC-BEN-001",'
            '"knowledge_ids":["KB-001"],'
            '"summary":"No se confirma compromiso."}'
        ),
        "thinking": "FINAL_THINKING_MUST_NOT_SURVIVE",
    }
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return json.dumps(
        {
            "done": True,
            "message": message,
            "raw_provider_field": "REMOTE_BODY_MUST_NOT_SURVIVE",
        }
    ).encode()


def _adapter(transport: FakeTransport) -> OllamaCloudAdapter:
    return OllamaCloudAdapter(
        transport=transport,
        api_key_loader=lambda: _TEST_KEY,
    )


def test_two_call_protocol_uses_fixed_cloud_contract_without_oracles() -> None:
    transport = FakeTransport(
        (_first_remote_response(), _final_remote_response())
    )
    adapter = _adapter(transport)
    initial = _initial_request()

    first = adapter.generate(initial)
    followup = _followup_request(
        initial,
        first.response.tool_requests[0],
    )
    second = adapter.generate(followup)

    assert len(transport.calls) == 2
    assert all(call.url == OLLAMA_CHAT_ENDPOINT for call in transport.calls)
    assert all(
        call.timeout_seconds == OLLAMA_TIMEOUT_SECONDS
        for call in transport.calls
    )
    assert all(
        call.max_response_bytes == MAX_OLLAMA_RESPONSE_BYTES
        for call in transport.calls
    )
    assert all(call.authorization_matches for call in transport.calls)
    assert all(
        call.header_names
        == frozenset({"Accept", "Authorization", "Content-Type"})
        for call in transport.calls
    )

    first_document, second_document = (
        call.document for call in transport.calls
    )
    for document in (first_document, second_document):
        assert document["model"] == OLLAMA_MODEL
        assert document["stream"] is False
        assert document["think"] == "low"
        assert document["options"] == {"temperature": 0}
        serialized = json.dumps(document, sort_keys=True).casefold()
        assert "expected_result" not in serialized
        assert "oracle" not in serialized
        assert "rubric" not in serialized

    assert len(first_document["tools"]) == 1
    assert (
        first_document["tools"][0]["function"]["name"]
        == "knowledge_search"
    )
    assert "tools" not in second_document
    assert second_document["messages"][-2]["tool_calls"][0]["function"][
        "name"
    ] == "knowledge_search"
    assert second_document["messages"][-1]["tool_name"] == "knowledge_search"

    assert first.descriptor.provider == "ollama"
    assert first.descriptor.model == "gpt-oss:120b"
    assert first.descriptor.deterministic is False
    assert first.descriptor.external_calls is True
    assert first.descriptor.cost_eur is None
    assert first.response.finish_reason == "tool_request"
    assert len(first.response.tool_requests) == 1
    assert second.response.finish_reason == "stop"
    assert "THINKING_MUST_NOT_SURVIVE" not in repr(first)
    assert "REMOTE_BODY_MUST_NOT_SURVIVE" not in repr(first)
    assert "FINAL_THINKING_MUST_NOT_SURVIVE" not in repr(second)
    assert "REMOTE_BODY_MUST_NOT_SURVIVE" not in repr(second)
    assert _TEST_KEY not in repr(first)
    assert _TEST_KEY not in repr(second)


def test_initial_contract_maps_incident_fields_to_bounded_tool_arguments() -> None:
    transport = FakeTransport((_first_remote_response(),))

    _adapter(transport).generate(_initial_request())

    document = transport.calls[0].document
    system_instruction = document["messages"][0]["content"]
    assert isinstance(system_instruction, str)
    assert (
        "query debe copiar exactamente el valor no vacío de category"
        in system_instruction
    )
    assert (
        "knowledge_ids debe copiar exactamente su array knowledge_refs"
        in system_instruction
    )
    assert "limit debe ser 1" in system_instruction

    parameters = document["tools"][0]["function"]["parameters"]
    assert parameters["properties"]["query"] == {
        "type": "string",
        "minLength": 1,
        "maxLength": 200,
        "pattern": r"^[^\r\n]*\S[^\r\n]*$",
        "description": (
            "Copia exactamente el valor no vacío de category del incidente."
        ),
    }
    assert (
        parameters["properties"]["knowledge_ids"]["description"]
        == "Copia exactamente el array knowledge_refs del incidente."
    )
    assert (
        parameters["properties"]["limit"]["description"]
        == "Usa 1 para este único incidente."
    )


def test_tool_name_remains_untrusted_for_application_validation() -> None:
    transport = FakeTransport(
        (_first_remote_response(name="draft_create"),)
    )

    result = _adapter(transport).generate(_initial_request())

    assert result.response.tool_requests[0].name == "draft_create"
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "tool_calls",
    (
        [],
        [
            {
                "function": {
                    "name": "knowledge_search",
                    "arguments": {
                        "query": "phishing",
                        "knowledge_ids": ["KB-001"],
                        "limit": 1,
                    },
                }
            },
            {
                "function": {
                    "name": "knowledge_search",
                    "arguments": {
                        "query": "phishing",
                        "knowledge_ids": ["KB-001"],
                        "limit": 1,
                    },
                }
            },
        ],
    ),
)
def test_initial_response_requires_exactly_one_tool_call(
    tool_calls: object,
) -> None:
    remote = json.dumps(
        {
            "done": True,
            "message": {
                "role": "assistant",
                "content": "ignored",
                "tool_calls": tool_calls,
            },
        }
    ).encode()
    transport = FakeTransport((remote,))

    with pytest.raises(
        OllamaCloudResponseError,
        match="response was rejected",
    ) as captured:
        _adapter(transport).generate(_initial_request())

    assert len(transport.calls) == 1
    assert "ignored" not in str(captured.value)


@pytest.mark.parametrize(
    "arguments",
    (
        '["not","an","object"]',
        ["not", "an", "object"],
    ),
)
def test_tool_arguments_must_be_a_bounded_json_object(
    arguments: object,
) -> None:
    transport = FakeTransport(
        (_first_remote_response(arguments=arguments),)
    )

    with pytest.raises(OllamaCloudResponseError):
        _adapter(transport).generate(_initial_request())

    assert len(transport.calls) == 1


def test_oversized_remote_tool_arguments_fail_as_sanitized_response() -> None:
    transport = FakeTransport(
        (
            _first_remote_response(
                arguments={
                    "knowledge_ids": ["KB-001"],
                    "limit": 1,
                    "query": "x" * 4096,
                }
            ),
        )
    )

    with pytest.raises(
        OllamaCloudResponseError,
        match="response was rejected",
    ) as captured:
        _adapter(transport).generate(_initial_request())

    assert len(transport.calls) == 1
    assert "x" * 64 not in str(captured.value)


def test_second_response_rejects_unannounced_tool_calls() -> None:
    transport = FakeTransport(
        (
            _first_remote_response(),
            _final_remote_response(
                tool_calls=[
                    {
                        "function": {
                            "name": "knowledge_search",
                            "arguments": {},
                        }
                    }
                ]
            ),
        )
    )
    adapter = _adapter(transport)
    initial = _initial_request()
    first = adapter.generate(initial)

    with pytest.raises(OllamaCloudResponseError):
        adapter.generate(
            _followup_request(
                initial,
                first.response.tool_requests[0],
            )
        )

    assert "tools" not in transport.calls[1].document
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    "response",
    (
        b"not-json",
        b"[]",
        b"x" * (MAX_OLLAMA_RESPONSE_BYTES + 1),
    ),
)
def test_invalid_or_oversized_remote_body_fails_sanitized(
    response: bytes,
) -> None:
    transport = FakeTransport((response,))

    with pytest.raises(
        OllamaCloudResponseError,
        match="response was rejected",
    ) as captured:
        _adapter(transport).generate(_initial_request())

    assert "not-json" not in str(captured.value)
    assert len(transport.calls) == 1


def test_missing_key_fails_before_transport_without_secret_details() -> None:
    transport = FakeTransport((_first_remote_response(),))
    adapter = OllamaCloudAdapter(
        transport=transport,
        api_key_loader=lambda: "",
    )

    with pytest.raises(
        OllamaCloudConfigurationError,
        match="credentials are unavailable",
    ) as captured:
        adapter.generate(_initial_request())

    assert str(captured.value) == "ollama cloud credentials are unavailable"
    assert transport.calls == []


def test_transport_failure_has_no_retry_or_raw_exception_details() -> None:
    transport = FakeTransport(
        (TimeoutError("REMOTE_TIMEOUT_CANARY"),)
    )

    with pytest.raises(
        OllamaCloudTransportError,
        match="provider is unavailable",
    ) as captured:
        _adapter(transport).generate(_initial_request())

    assert len(transport.calls) == 1
    assert "REMOTE_TIMEOUT_CANARY" not in str(captured.value)
    assert _TEST_KEY not in str(captured.value)


class _FakeHTTPResponse:
    def __init__(
        self,
        content: bytes,
        *,
        status: int = 200,
        content_length: str | None = None,
    ) -> None:
        self.status = status
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self._content = content

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, maximum: int) -> bytes:
        return self._content[:maximum]


class _FakeOpener:
    def __init__(self, outcome: _FakeHTTPResponse | Exception) -> None:
        self.outcome = outcome
        self.calls = 0

    def open(self, request: object, *, timeout: float) -> _FakeHTTPResponse:
        self.calls += 1
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.mark.parametrize(
    "outcome",
    (
        HTTPError(
            OLLAMA_CHAT_ENDPOINT,
            302,
            "REMOTE_REDIRECT_CANARY",
            hdrs=None,
            fp=None,
        ),
        HTTPError(
            OLLAMA_CHAT_ENDPOINT,
            503,
            "REMOTE_STATUS_CANARY",
            hdrs=None,
            fp=None,
        ),
        TimeoutError("REMOTE_TIMEOUT_CANARY"),
    ),
)
def test_stdlib_transport_rejects_redirect_status_and_timeout_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    outcome: Exception,
) -> None:
    opener = _FakeOpener(outcome)
    monkeypatch.setattr(
        "genai_seguro_lab.ollama_cloud_adapter.build_opener",
        lambda *handlers: opener,
    )

    with pytest.raises(
        OllamaCloudTransportError,
        match="provider is unavailable",
    ) as captured:
        UrllibOllamaCloudTransport().post(
            url=OLLAMA_CHAT_ENDPOINT,
            headers={
                "Authorization": "Bearer test-only-placeholder",
                "Content-Type": "application/json",
            },
            body=b"{}",
            timeout_seconds=OLLAMA_TIMEOUT_SECONDS,
            max_response_bytes=MAX_OLLAMA_RESPONSE_BYTES,
        )

    assert opener.calls == 1
    assert "CANARY" not in str(captured.value)


@pytest.mark.parametrize(
    "response",
    (
        _FakeHTTPResponse(
            b"{}",
            content_length=str(MAX_OLLAMA_RESPONSE_BYTES + 1),
        ),
        _FakeHTTPResponse(b"x" * (MAX_OLLAMA_RESPONSE_BYTES + 1)),
        _FakeHTTPResponse(b"{}", content_length="not-an-integer"),
    ),
)
def test_stdlib_transport_bounds_remote_body_before_return(
    monkeypatch: pytest.MonkeyPatch,
    response: _FakeHTTPResponse,
) -> None:
    opener = _FakeOpener(response)
    monkeypatch.setattr(
        "genai_seguro_lab.ollama_cloud_adapter.build_opener",
        lambda *handlers: opener,
    )

    with pytest.raises(OllamaCloudTransportError):
        UrllibOllamaCloudTransport().post(
            url=OLLAMA_CHAT_ENDPOINT,
            headers={
                "Authorization": "Bearer test-only-placeholder",
                "Content-Type": "application/json",
            },
            body=b"{}",
            timeout_seconds=OLLAMA_TIMEOUT_SECONDS,
            max_response_bytes=MAX_OLLAMA_RESPONSE_BYTES,
        )

    assert opener.calls == 1
