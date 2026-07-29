"""Proyección pública mínima del análisis alojado de un incidente sintético."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from time import monotonic
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .cloud_analysis import CloudAnalysisResult, run_cloud_incident
from .data_contract import IncidentCategory, IncidentId, KnowledgeId, load_dataset
from .ollama_cloud_adapter import (
    OLLAMA_PUBLIC_TIMEOUT_SECONDS,
    OllamaCloudAdapter,
)
from .security_events import (
    SecurityEventKind,
    SecurityEventOutcome,
    SecurityEventReport,
    SecurityEventSource,
    SecuritySignal,
    SecurityEventJournal,
)

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_DATA_DIR = ROOT / "data"

Text = Annotated[str, Field(min_length=1)]


class PublicAnalysisSchema(BaseModel):
    """Contrato cerrado que excluye metadatos internos y cuerpos remotos."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PublicAnalysisResult(PublicAnalysisSchema):
    incident_id: IncidentId
    category: IncidentCategory
    status: Literal["passed"]
    output_text: Text
    knowledge_ids: Annotated[
        tuple[KnowledgeId, ...],
        Field(min_length=1, max_length=8),
    ]
    model_invocations: Literal[2]
    tool_requests: Literal[1]
    deterministic: Literal[False]
    external_calls: Literal[True]
    cost_eur: None


class PublicSecurityEvent(PublicAnalysisSchema):
    sequence: Annotated[int, Field(ge=1)]
    elapsed_ms: Annotated[int, Field(ge=0)]
    kind: SecurityEventKind
    source: SecurityEventSource
    outcome: SecurityEventOutcome
    signal: SecuritySignal | None


class PublicSecurityReport(PublicAnalysisSchema):
    control_id: Literal["GSL-SECURITY-EVENTS-001"]
    version: Literal["1.0.0"]
    profile: Literal["cloud_analyze"]
    events_count: Annotated[int, Field(ge=1)]
    bytes_used: Annotated[int, Field(ge=1)]
    correlations_count: Annotated[int, Field(ge=1)]
    events: Annotated[
        tuple[PublicSecurityEvent, ...],
        Field(min_length=1),
    ]


class PublicAnalysisEnvelope(PublicAnalysisSchema):
    result: PublicAnalysisResult
    security_report: PublicSecurityReport


def project_public_analysis(
    result: CloudAnalysisResult,
    report: SecurityEventReport,
) -> PublicAnalysisEnvelope:
    """Conserva resultado y métricas seguras, no identidad del proveedor."""

    if not isinstance(result, CloudAnalysisResult):
        raise TypeError("result must be a CloudAnalysisResult")
    if not isinstance(report, SecurityEventReport):
        raise TypeError("report must be a SecurityEventReport")
    if report.profile != "cloud_analyze":
        raise ValueError("report must use the cloud_analyze profile")

    return PublicAnalysisEnvelope(
        result=PublicAnalysisResult(
            incident_id=result.incident_id,
            category=result.category,
            status=result.status,
            output_text=result.output_text,
            knowledge_ids=result.knowledge_ids,
            model_invocations=result.model_invocations,
            tool_requests=result.tool_requests,
            deterministic=result.deterministic,
            external_calls=result.external_calls,
            cost_eur=result.cost_eur,
        ),
        security_report=PublicSecurityReport(
            control_id=report.control_id,
            version=report.version,
            profile=report.profile,
            events_count=report.events_count,
            bytes_used=report.bytes_used,
            correlations_count=report.correlations_count,
            events=tuple(
                PublicSecurityEvent(
                    sequence=event.sequence,
                    elapsed_ms=event.elapsed_ms,
                    kind=event.kind,
                    source=event.source,
                    outcome=event.outcome,
                    signal=event.signal,
                )
                for event in report.events
            ),
        ),
    )


def analyze_public_incident(
    incident_id: str,
    *,
    data_dir: Path = PUBLIC_DATA_DIR,
    adapter: OllamaCloudAdapter | None = None,
    clock: Callable[[], float] = monotonic,
) -> PublicAnalysisEnvelope:
    """Ejecuta el flujo existente con un máximo público de 25 s por llamada."""

    if not isinstance(data_dir, Path):
        raise TypeError("data_dir must be a Path")
    selected_adapter = adapter or OllamaCloudAdapter(
        timeout_seconds=OLLAMA_PUBLIC_TIMEOUT_SECONDS
    )
    if not isinstance(selected_adapter, OllamaCloudAdapter):
        raise TypeError("adapter must be an OllamaCloudAdapter")
    if selected_adapter.timeout_seconds > OLLAMA_PUBLIC_TIMEOUT_SECONDS:
        raise ValueError("public adapter timeout exceeds the public limit")

    journal = SecurityEventJournal("cloud_analyze", clock=clock)
    result = run_cloud_incident(
        load_dataset(data_dir),
        incident_id,
        adapter=selected_adapter,
        clock=clock,
        security_journal=journal,
    )
    return project_public_analysis(result, journal.report())
