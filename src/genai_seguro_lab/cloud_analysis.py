"""Runner opt-in para un único incidente sintético con Ollama Cloud."""

from __future__ import annotations

import json
from collections.abc import Callable
from time import monotonic
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .benign_flow import BenignAnalysisFlow
from .data_contract import (
    DatasetBundle,
    IncidentCategory,
    IncidentId,
    KnowledgeId,
)
from .local_tools import KnowledgeCatalog
from .model_adapter import ModelAdapter
from .ollama_cloud_adapter import OllamaCloudAdapter
from .output_policy import OutputPolicy
from .resource_control import ProductResourceControl
from .security_events import SecurityEventJournal

Text = Annotated[str, Field(min_length=1)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class CloudAnalysisSchema(BaseModel):
    """Salida cerrada que no conserva petición ni respuesta remota."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CloudAnalysisResult(CloudAnalysisSchema):
    incident_id: IncidentId
    category: IncidentCategory
    status: Literal["passed"] = "passed"
    output_text: Text
    knowledge_ids: Annotated[
        tuple[KnowledgeId, ...],
        Field(min_length=1, max_length=8),
    ]
    request_fingerprints: Annotated[
        tuple[Sha256, ...],
        Field(min_length=2, max_length=2),
    ]
    model_invocations: Literal[2] = 2
    tool_requests: Literal[1] = 1
    provider: Literal["ollama"] = "ollama"
    model: Literal["gpt-oss:120b"] = "gpt-oss:120b"
    deterministic: Literal[False] = False
    external_calls: Literal[True] = True
    cost_eur: None = None


class UnknownCloudIncidentError(LookupError):
    """El identificador no pertenece al corpus sintético validado."""


def canonical_cloud_analysis_json(result: CloudAnalysisResult) -> str:
    if not isinstance(result, CloudAnalysisResult):
        raise TypeError("result must be a CloudAnalysisResult")
    return (
        json.dumps(
            result.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def run_cloud_incident(
    bundle: DatasetBundle,
    incident_id: str,
    *,
    adapter: ModelAdapter | None = None,
    clock: Callable[[], float] = monotonic,
    security_journal: SecurityEventJournal | None = None,
) -> CloudAnalysisResult:
    """Ejecuta exactamente dos llamadas alojadas para un incidente."""

    if not isinstance(bundle, DatasetBundle):
        raise TypeError("bundle must be a DatasetBundle")
    if not isinstance(incident_id, str):
        raise TypeError("incident_id must be a string")
    selected_adapter = adapter or OllamaCloudAdapter()
    if (
        not isinstance(selected_adapter, ModelAdapter)
        or selected_adapter.descriptor.provider != "ollama"
    ):
        raise TypeError("adapter must be the ollama hosted model adapter")
    journal = security_journal or SecurityEventJournal(
        "cloud_analyze",
        clock=clock,
    )
    if (
        not isinstance(journal, SecurityEventJournal)
        or journal.profile != "cloud_analyze"
    ):
        raise TypeError(
            "security_journal must use the cloud_analyze profile"
        )
    control = ProductResourceControl(
        "cloud_analyze",
        clock=clock,
        security_journal=journal,
    )

    try:
        incident = next(
            (
                candidate
                for candidate in bundle.incidents
                if candidate.id == incident_id
            ),
            None,
        )
        if incident is None:
            journal.signal(
                "unknown_model_request",
                source="flow",
                outcome="denied",
            )
            raise UnknownCloudIncidentError(
                "unknown synthetic incident identifier"
            )

        result = BenignAnalysisFlow(
            selected_adapter,
            KnowledgeCatalog(bundle.knowledge),
            output_policy=OutputPolicy(),
        ).analyze(
            incident,
            resource_control=control,
        )
        cloud_result = CloudAnalysisResult(
            incident_id=incident.id,
            category=incident.category,
            output_text=result.output_text,
            knowledge_ids=tuple(hit.id for hit in result.knowledge.hits),
            request_fingerprints=tuple(
                invocation.request_fingerprint
                for invocation in result.invocations
            ),
            model_invocations=len(result.invocations),
            tool_requests=sum(
                invocation.tool_request_count
                for invocation in result.invocations
            ),
            provider=result.invocations[0].descriptor.provider,
            model=result.invocations[0].descriptor.model,
            deterministic=result.invocations[0].descriptor.deterministic,
            external_calls=any(
                invocation.descriptor.external_calls
                for invocation in result.invocations
            ),
            cost_eur=None,
        )
    except Exception:
        if not journal.is_finished:
            journal.finish(succeeded=False)
        raise
    journal.finish(succeeded=True)
    return cloud_result
