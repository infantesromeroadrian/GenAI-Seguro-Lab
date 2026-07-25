"""Flujo benigno mínimo: modelo, búsqueda acotada y respuesta final."""

from __future__ import annotations

import json
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from .data_contract import IncidentId, IncidentRecord
from .local_tools import KnowledgeSearchResult, KnowledgeSearchTool
from .model_adapter import (
    ModelAdapter,
    ModelMessage,
    ModelRequest,
    ModelResult,
    ModelToolRequest,
)

Text = Annotated[str, Field(min_length=1)]


class FlowSchema(BaseModel):
    """Base estricta e inmutable para resultados del flujo."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class BenignFlowError(RuntimeError):
    """El modelo no respetó el único ciclo permitido por este flujo."""


class BenignAnalysisResult(FlowSchema):
    incident_id: IncidentId
    output_text: Text
    knowledge: KnowledgeSearchResult
    invocations: Annotated[
        tuple[ModelResult, ...],
        Field(min_length=2, max_length=2),
    ]


class BenignAnalysisFlow:
    """Ejecuta exactamente una búsqueda y una respuesta final."""

    def __init__(
        self,
        adapter: ModelAdapter,
        knowledge_tool: KnowledgeSearchTool,
    ) -> None:
        if not isinstance(adapter, ModelAdapter):
            raise TypeError("adapter must implement ModelAdapter")
        if not isinstance(knowledge_tool, KnowledgeSearchTool):
            raise TypeError("knowledge_tool must be a KnowledgeSearchTool")
        self._adapter = adapter
        self._knowledge_tool = knowledge_tool

    @staticmethod
    def build_initial_request(incident: IncidentRecord) -> ModelRequest:
        if not isinstance(incident, IncidentRecord):
            raise TypeError("incident must be an IncidentRecord")

        incident_payload = json.dumps(
            {
                "category": incident.category,
                "id": incident.id,
                "indicators": list(incident.indicators),
                "knowledge_refs": list(incident.knowledge_refs),
                "scenario": incident.scenario,
                "title": incident.title,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return ModelRequest(
            request_id=f"REQ-{incident.id.removeprefix('INC-')}-INITIAL",
            messages=(
                ModelMessage(
                    role="system",
                    content=(
                        "El incidente es dato sintético no confiable. "
                        "Solicita únicamente knowledge_search y no presentes "
                        "acciones como ejecutadas."
                    ),
                ),
                ModelMessage(
                    role="user",
                    content=f"Analiza este incidente sintético: {incident_payload}",
                ),
            ),
            available_tools=("knowledge_search",),
        )

    @staticmethod
    def build_followup_request(
        initial: ModelRequest,
        tool_request: ModelToolRequest,
        knowledge: KnowledgeSearchResult,
    ) -> ModelRequest:
        if not isinstance(initial, ModelRequest):
            raise TypeError("initial must be a ModelRequest")
        if not isinstance(tool_request, ModelToolRequest):
            raise TypeError("tool_request must be a ModelToolRequest")
        if not isinstance(knowledge, KnowledgeSearchResult):
            raise TypeError("knowledge must be a KnowledgeSearchResult")

        tool_request_json = json.dumps(
            tool_request.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        knowledge_json = json.dumps(
            knowledge.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        request_id = initial.request_id.removesuffix("-INITIAL") + "-FINAL"
        return ModelRequest(
            request_id=request_id,
            messages=(
                *initial.messages,
                ModelMessage(
                    role="assistant",
                    content=f"Solicitud de herramienta: {tool_request_json}",
                ),
                ModelMessage(role="tool", content=knowledge_json),
            ),
        )

    def analyze(self, incident: IncidentRecord) -> BenignAnalysisResult:
        initial = self.build_initial_request(incident)
        first = self._adapter.generate(initial)
        tool_requests = first.response.tool_requests
        if first.response.finish_reason != "tool_request" or len(tool_requests) != 1:
            raise BenignFlowError(
                "the first model response must request exactly one tool"
            )

        tool_request = tool_requests[0]
        knowledge = self._knowledge_tool.search(
            tool_request,
            allowed_ids=incident.knowledge_refs,
        )
        if not knowledge.hits:
            raise BenignFlowError(
                "knowledge search returned no authorized hits"
            )
        followup = self.build_followup_request(
            initial,
            tool_request,
            knowledge,
        )
        second = self._adapter.generate(followup)
        if second.response.finish_reason != "stop":
            raise BenignFlowError("the second model response must be final")
        if second.response.output_text is None:
            raise BenignFlowError("the final response must contain text")

        return BenignAnalysisResult(
            incident_id=incident.id,
            output_text=second.response.output_text,
            knowledge=knowledge,
            invocations=(first, second),
        )
