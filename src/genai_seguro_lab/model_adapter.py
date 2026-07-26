"""Frontera de modelo y doble determinista para pruebas reproducibles."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from hashlib import sha256
from types import MappingProxyType
from typing import Annotated, Literal, Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .resource_control import MAX_TOOL_ARGUMENTS_BYTES, require_utf8_size

Text = Annotated[str, Field(min_length=1)]
RequestId = Annotated[
    str,
    Field(pattern=r"^REQ-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
]
ToolRequestId = Annotated[
    str,
    Field(pattern=r"^CALL-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
InstructionBoundary = Literal["separated", "deliberately_merged"]
KnownToolName = Literal["knowledge_search", "draft_create"]
MessageTrustClass = Literal[
    "trusted_instruction",
    "user_data",
    "untrusted_content",
    "model_output",
]


class AdapterSchema(BaseModel):
    """Base estricta e inmutable para la frontera de modelo."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ModelMessage(AdapterSchema):
    role: Literal["system", "user", "assistant", "tool"]
    trust_class: MessageTrustClass
    content: Text

    @model_validator(mode="after")
    def validate_role_trust_class(self) -> Self:
        allowed_trust_classes: dict[str, set[str]] = {
            "system": {"trusted_instruction"},
            "user": {"user_data", "untrusted_content"},
            "assistant": {"model_output"},
            "tool": {"untrusted_content"},
        }
        if self.trust_class not in allowed_trust_classes[self.role]:
            raise ValueError(
                f"{self.role} messages cannot be classified as "
                f"{self.trust_class}"
            )
        return self


class ModelRequest(AdapterSchema):
    request_id: RequestId
    instruction_boundary: InstructionBoundary
    messages: Annotated[tuple[ModelMessage, ...], Field(min_length=1)]
    available_tools: Annotated[
        tuple[KnownToolName, ...],
        Field(max_length=2),
    ] = ()

    @field_validator("available_tools")
    @classmethod
    def reject_duplicate_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("available tool names must be unique")
        return value

    @model_validator(mode="after")
    def require_explicit_trust_boundaries(self) -> Self:
        system_messages = tuple(
            message
            for message in self.messages
            if message.trust_class == "trusted_instruction"
        )
        if len(system_messages) != 1 or self.messages[0] != system_messages[0]:
            raise ValueError(
                "requests require exactly one leading trusted instruction"
            )
        if not any(
            message.trust_class == "user_data" for message in self.messages
        ):
            raise ValueError("requests require explicitly classified user data")
        if not any(
            message.trust_class == "untrusted_content"
            for message in self.messages
        ):
            raise ValueError(
                "requests require explicitly classified untrusted content"
            )
        return self


class ModelToolRequest(AdapterSchema):
    request_id: ToolRequestId
    name: Text
    arguments_json: Text

    @field_validator("arguments_json")
    @classmethod
    def require_json_object(cls, value: str) -> str:
        require_utf8_size(value, MAX_TOOL_ARGUMENTS_BYTES)
        try:
            arguments = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("tool arguments must be valid JSON") from exc
        if not isinstance(arguments, dict):
            raise ValueError("tool arguments must be a JSON object")
        return value


class ModelResponse(AdapterSchema):
    finish_reason: Literal["stop", "tool_request"]
    output_text: Text | None = None
    tool_requests: tuple[ModelToolRequest, ...] = ()

    @model_validator(mode="after")
    def validate_finish_reason(self) -> Self:
        request_ids = [request.request_id for request in self.tool_requests]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("tool request identifiers must be unique")

        if self.finish_reason == "stop":
            if self.output_text is None:
                raise ValueError("stop responses require output text")
            if self.tool_requests:
                raise ValueError("stop responses cannot contain tool requests")
        elif not self.tool_requests:
            raise ValueError("tool_request responses require at least one request")

        return self


class ModelDescriptor(AdapterSchema):
    provider: Literal["deterministic"] = "deterministic"
    model: Literal["scripted-v1"] = "scripted-v1"
    deterministic: Literal[True] = True
    external_calls: Literal[False] = False
    cost_eur: Literal[0] = 0


class ScriptedExchange(AdapterSchema):
    request: ModelRequest
    response: ModelResponse


class ModelResult(AdapterSchema):
    descriptor: ModelDescriptor
    request_id: RequestId
    request_fingerprint: Sha256
    response: ModelResponse


@runtime_checkable
class ModelAdapter(Protocol):
    """Contrato mínimo que deberán respetar todos los adaptadores."""

    @property
    def descriptor(self) -> ModelDescriptor: ...

    def generate(self, request: ModelRequest) -> ModelResult: ...


class UnknownModelRequestError(LookupError):
    """La petición no tiene una respuesta exacta configurada."""


def request_fingerprint(request: ModelRequest) -> str:
    """Devuelve una huella estable sin exponer el contenido de la petición."""

    if not isinstance(request, ModelRequest):
        raise TypeError("request must be a ModelRequest")

    canonical = json.dumps(
        request.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


class DeterministicModelAdapter:
    """Responde solo a peticiones completas configuradas de antemano."""

    def __init__(self, scripts: Iterable[ScriptedExchange]) -> None:
        responses: dict[str, ModelResponse] = {}
        for script in scripts:
            if not isinstance(script, ScriptedExchange):
                raise TypeError("scripts must contain ScriptedExchange values")

            fingerprint = request_fingerprint(script.request)
            if fingerprint in responses:
                raise ValueError("duplicate scripted model request")
            responses[fingerprint] = script.response

        if not responses:
            raise ValueError("at least one scripted exchange is required")

        self._responses: Mapping[str, ModelResponse] = MappingProxyType(responses)
        self._descriptor = ModelDescriptor()

    @property
    def descriptor(self) -> ModelDescriptor:
        return self._descriptor

    def generate(self, request: ModelRequest) -> ModelResult:
        if not isinstance(request, ModelRequest):
            raise TypeError("request must be a ModelRequest")

        fingerprint = request_fingerprint(request)
        try:
            response = self._responses[fingerprint]
        except KeyError:
            raise UnknownModelRequestError(
                f"no scripted response for {request.request_id} "
                f"({fingerprint[:12]})"
            ) from None

        return ModelResult(
            descriptor=self.descriptor,
            request_id=request.request_id,
            request_fingerprint=fingerprint,
            response=response,
        )
