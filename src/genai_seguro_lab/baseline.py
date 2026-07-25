"""Baseline funcional benigna, determinista y sin llamadas externas."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .benign_flow import (
    BenignAnalysisFlow,
    BenignAnalysisResult,
    BenignFinalOutput,
    canonical_flow_json,
)
from .data_contract import (
    DatasetBundle,
    DatasetId,
    IncidentCategory,
    IncidentId,
    IncidentRecord,
    KnowledgeId,
    load_dataset,
)
from .local_tools import KnowledgeCatalog
from .model_adapter import (
    DeterministicModelAdapter,
    ModelResponse,
    ModelToolRequest,
    ScriptedExchange,
)

Text = Annotated[str, Field(min_length=1)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class BaselineSchema(BaseModel):
    """Base estricta e inmutable para la evidencia de baseline."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class BaselineDataset(BaselineSchema):
    id: DatasetId
    version: Literal["1.0.0"]
    manifest_sha256: Sha256


class FunctionalCaseResult(BaselineSchema):
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
    external_calls: Literal[False] = False
    cost_eur: Literal[0] = 0


class FunctionalBaselineSummary(BaselineSchema):
    cases_total: Annotated[int, Field(ge=1)]
    cases_passed: Annotated[int, Field(ge=1)]
    cases_failed: Literal[0] = 0
    model_invocations: Annotated[int, Field(ge=2)]
    tool_requests: Annotated[int, Field(ge=1)]
    external_calls: Literal[0] = 0
    cost_eur: Literal[0] = 0


class FunctionalBaseline(BaselineSchema):
    baseline_id: Literal["GSL-BASELINE-BENIGN-001"]
    schema_version: Literal["1.0.0"]
    profile: Literal["deterministic_benign"]
    evaluation_scope: Literal["benign_flow_functionality"]
    security_baseline: Literal[False] = False
    semantic_utility_evaluated: Literal[False] = False
    dataset: BaselineDataset
    summary: FunctionalBaselineSummary
    cases: Annotated[tuple[FunctionalCaseResult, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def verify_summary(self) -> Self:
        incident_ids = [case.incident_id for case in self.cases]
        if len(incident_ids) != len(set(incident_ids)):
            raise ValueError("baseline incident identifiers must be unique")

        expected = {
            "cases_total": len(self.cases),
            "cases_passed": len(self.cases),
            "model_invocations": sum(
                case.model_invocations for case in self.cases
            ),
            "tool_requests": sum(case.tool_requests for case in self.cases),
        }
        actual = {
            "cases_total": self.summary.cases_total,
            "cases_passed": self.summary.cases_passed,
            "model_invocations": self.summary.model_invocations,
            "tool_requests": self.summary.tool_requests,
        }
        if actual != expected:
            raise ValueError("baseline summary does not match its cases")
        return self


class UnknownIncidentError(LookupError):
    """El identificador no pertenece al corpus benigno cargado."""


def canonical_json(document: BaselineSchema) -> str:
    """Serializa una evidencia estable, legible y terminada en salto de línea."""

    if not isinstance(document, BaselineSchema):
        raise TypeError("document must be a BaselineSchema")
    return (
        json.dumps(
            document.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _knowledge_request(incident: IncidentRecord) -> ModelToolRequest:
    suffix = incident.id.removeprefix("INC-")
    return ModelToolRequest(
        request_id=f"CALL-{suffix}-KNOWLEDGE",
        name="knowledge_search",
        arguments_json=json.dumps(
            {
                "knowledge_ids": list(incident.knowledge_refs),
                "limit": len(incident.knowledge_refs),
                "query": incident.category,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _output_text(
    incident: IncidentRecord,
    knowledge_ids: tuple[str, ...],
) -> str:
    references = ", ".join(knowledge_ids)
    return (
        f"{incident.id}: {incident.title}. "
        f"Se observaron {len(incident.indicators)} indicadores sintéticos "
        f"de la categoría {incident.category} y se consultó conocimiento "
        f"autorizado ({references}). No se ejecutaron acciones ni se "
        "confirma un compromiso."
    )


def _build_flow(
    incidents: tuple[IncidentRecord, ...],
    knowledge_catalog: KnowledgeCatalog,
) -> BenignAnalysisFlow:
    scripts: list[ScriptedExchange] = []
    for incident in incidents:
        initial = BenignAnalysisFlow.build_initial_request(incident)
        tool_request = _knowledge_request(incident)
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
        if not knowledge.hits:
            raise ValueError("baseline configuration produced no knowledge hits")
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
                    summary=_output_text(
                        incident,
                        tuple(hit.id for hit in knowledge.hits),
                    ),
                    knowledge_ids=tuple(hit.id for hit in knowledge.hits),
                    actions_executed=False,
                    compromise_confirmed=False,
                )
            ),
        )
        scripts.extend(
            (
                ScriptedExchange(
                    request=initial,
                    response=first_response,
                ),
                ScriptedExchange(
                    request=followup,
                    response=final_response,
                ),
            )
        )

    return BenignAnalysisFlow(
        DeterministicModelAdapter(scripts),
        knowledge_catalog,
    )


def _case_result(
    incident: IncidentRecord,
    result: BenignAnalysisResult,
) -> FunctionalCaseResult:
    return FunctionalCaseResult(
        incident_id=result.incident_id,
        category=incident.category,
        output_text=result.output_text,
        knowledge_ids=tuple(hit.id for hit in result.knowledge.hits),
        request_fingerprints=tuple(
            invocation.request_fingerprint for invocation in result.invocations
        ),
        model_invocations=len(result.invocations),
        tool_requests=sum(
            len(invocation.response.tool_requests)
            for invocation in result.invocations
        ),
        external_calls=any(
            invocation.descriptor.external_calls
            for invocation in result.invocations
        ),
        cost_eur=sum(
            invocation.descriptor.cost_eur
            for invocation in result.invocations
        ),
    )


def run_incident(
    bundle: DatasetBundle,
    incident_id: str,
) -> FunctionalCaseResult:
    """Ejecuta un único caso benigno por su identificador exacto."""

    if not isinstance(bundle, DatasetBundle):
        raise TypeError("bundle must be a DatasetBundle")
    if not isinstance(incident_id, str):
        raise TypeError("incident_id must be a string")

    incident = next(
        (
            candidate
            for candidate in bundle.incidents
            if candidate.id == incident_id
        ),
        None,
    )
    if incident is None:
        raise UnknownIncidentError("unknown benign incident identifier")

    knowledge_catalog = KnowledgeCatalog(bundle.knowledge)
    result = _build_flow((incident,), knowledge_catalog).analyze(incident)
    return _case_result(incident, result)


def run_functional_baseline(data_dir: Path) -> FunctionalBaseline:
    """Ejecuta todo el corpus benigno y devuelve evidencia determinista."""

    if not isinstance(data_dir, Path):
        raise TypeError("data_dir must be a Path")
    bundle = load_dataset(data_dir)
    knowledge_catalog = KnowledgeCatalog(bundle.knowledge)
    flow = _build_flow(bundle.incidents, knowledge_catalog)
    cases = tuple(
        _case_result(incident, flow.analyze(incident))
        for incident in bundle.incidents
    )
    return FunctionalBaseline(
        baseline_id="GSL-BASELINE-BENIGN-001",
        schema_version="1.0.0",
        profile="deterministic_benign",
        evaluation_scope="benign_flow_functionality",
        dataset=BaselineDataset(
            id=bundle.manifest.id,
            version=bundle.manifest.version,
            manifest_sha256=sha256(
                (data_dir / "manifest.json").read_bytes()
            ).hexdigest(),
        ),
        summary=FunctionalBaselineSummary(
            cases_total=len(cases),
            cases_passed=len(cases),
            model_invocations=sum(
                case.model_invocations for case in cases
            ),
            tool_requests=sum(case.tool_requests for case in cases),
        ),
        cases=cases,
    )
