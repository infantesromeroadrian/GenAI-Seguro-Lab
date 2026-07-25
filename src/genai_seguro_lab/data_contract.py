"""Contrato y carga verificable del corpus sintético."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

Text = Annotated[str, Field(min_length=1)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
IncidentId = Annotated[str, Field(pattern=r"^INC-BEN-[0-9]{3}$")]
KnowledgeId = Annotated[str, Field(pattern=r"^KB-[0-9]{3}$")]
DatasetId = Annotated[str, Field(pattern=r"^GSL-DATASET-[0-9]{3}$")]

IncidentCategory = Literal[
    "phishing",
    "identity",
    "endpoint",
    "data_protection",
    "availability",
    "cloud_configuration",
    "supply_chain",
    "physical_device",
]
Sensitivity = Literal["synthetic_internal"]
AllowedTool = Literal["knowledge_search"]


class StrictModel(BaseModel):
    """Base inmutable, estricta y cerrada para todos los registros."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Provenance(StrictModel):
    origin: Literal["authored_for_lab"]
    author: Literal["GenAI Seguro Lab"]
    created_on: Annotated[str, Field(pattern=r"^2026-07-25$")]
    references: tuple[str, ...]


class IncidentExpectedResult(StrictModel):
    required_findings: Annotated[tuple[Text, ...], Field(min_length=1)]
    recommended_actions: Annotated[tuple[Text, ...], Field(min_length=1)]
    forbidden_claims: Annotated[tuple[Text, ...], Field(min_length=1)]
    allowed_tool_requests: tuple[AllowedTool, ...]


class IncidentRecord(StrictModel):
    id: IncidentId
    type: Literal["benign_incident"]
    category: IncidentCategory
    title: Text
    scenario: Text
    indicators: Annotated[tuple[Text, ...], Field(min_length=1)]
    knowledge_refs: Annotated[tuple[KnowledgeId, ...], Field(min_length=1)]
    provenance: Provenance
    synthetic: Literal[True]
    sensitivity: Sensitivity
    expected_result: IncidentExpectedResult

    @field_validator("indicators", "knowledge_refs")
    @classmethod
    def reject_duplicates(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate values are not allowed")
        return value


class KnowledgeExpectedResult(StrictModel):
    supported_categories: Annotated[
        tuple[IncidentCategory, ...], Field(min_length=1)
    ]
    allowed_tool_requests: tuple[AllowedTool, ...]


class KnowledgeRecord(StrictModel):
    id: KnowledgeId
    type: Literal["knowledge_document"]
    topic: IncidentCategory
    title: Text
    content: Annotated[str, Field(min_length=80)]
    procedures: Annotated[tuple[Text, ...], Field(min_length=1)]
    provenance: Provenance
    synthetic: Literal[True]
    sensitivity: Sensitivity
    expected_result: KnowledgeExpectedResult

    @field_validator("procedures")
    @classmethod
    def reject_duplicate_procedures(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate procedures are not allowed")
        return value


class ManifestFile(StrictModel):
    path: Literal["incidents.jsonl", "knowledge.jsonl"]
    kind: Literal["incident_jsonl", "knowledge_jsonl"]
    records: Annotated[int, Field(ge=1)]
    sha256: Sha256


class ManifestExpectedResult(StrictModel):
    incident_records: Annotated[int, Field(ge=1)]
    knowledge_records: Annotated[int, Field(ge=1)]
    benign_incident_records: Annotated[int, Field(ge=1)]
    adversarial_records: Annotated[int, Field(ge=0)]


class DatasetManifest(StrictModel):
    id: DatasetId
    version: Literal["1.0.0"]
    type: Literal["dataset_manifest"]
    files: Annotated[tuple[ManifestFile, ...], Field(min_length=2, max_length=2)]
    provenance: Provenance
    synthetic: Literal[True]
    sensitivity: Sensitivity
    expected_result: ManifestExpectedResult


@dataclass(frozen=True)
class DatasetBundle:
    manifest: DatasetManifest
    incidents: tuple[IncidentRecord, ...]
    knowledge: tuple[KnowledgeRecord, ...]


RecordT = TypeVar("RecordT", bound=BaseModel)


def _load_jsonl(path: Path, model: type[RecordT]) -> tuple[RecordT, ...]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise ValueError(f"{path.name} must contain non-empty JSONL records")

    records: list[RecordT] = []
    for line_number, line in enumerate(lines, start=1):
        try:
            records.append(model.model_validate_json(line))
        except ValidationError as exc:
            raise ValueError(
                f"{path.name}:{line_number} violates the data contract"
            ) from exc
    return tuple(records)


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load_dataset(data_dir: Path) -> DatasetBundle:
    """Carga el corpus y comprueba esquema, hashes, conteos y referencias."""

    manifest = DatasetManifest.model_validate_json(
        (data_dir / "manifest.json").read_text(encoding="utf-8")
    )
    incidents = _load_jsonl(data_dir / "incidents.jsonl", IncidentRecord)
    knowledge = _load_jsonl(data_dir / "knowledge.jsonl", KnowledgeRecord)

    incident_ids = [record.id for record in incidents]
    knowledge_ids = [record.id for record in knowledge]
    if len(incident_ids) != len(set(incident_ids)):
        raise ValueError("incident identifiers must be unique")
    if len(knowledge_ids) != len(set(knowledge_ids)):
        raise ValueError("knowledge identifiers must be unique")

    known_ids = set(knowledge_ids)
    missing_refs = {
        reference
        for incident in incidents
        for reference in incident.knowledge_refs
        if reference not in known_ids
    }
    if missing_refs:
        raise ValueError(f"unknown knowledge references: {sorted(missing_refs)}")

    entries = {entry.path: entry for entry in manifest.files}
    expected_paths = {"incidents.jsonl", "knowledge.jsonl"}
    if set(entries) != expected_paths:
        raise ValueError("manifest must enumerate exactly the approved data files")

    expected_kinds = {
        "incidents.jsonl": "incident_jsonl",
        "knowledge.jsonl": "knowledge_jsonl",
    }
    record_counts = {
        "incidents.jsonl": len(incidents),
        "knowledge.jsonl": len(knowledge),
    }
    for relative_path, entry in entries.items():
        path = data_dir / relative_path
        if entry.kind != expected_kinds[relative_path]:
            raise ValueError(f"unexpected kind for {relative_path}")
        if entry.records != record_counts[relative_path]:
            raise ValueError(f"record count mismatch for {relative_path}")
        if entry.sha256 != _digest(path):
            raise ValueError(f"hash mismatch for {relative_path}")

    expected = manifest.expected_result
    if expected.incident_records != len(incidents):
        raise ValueError("manifest incident total does not match")
    if expected.knowledge_records != len(knowledge):
        raise ValueError("manifest knowledge total does not match")
    if expected.benign_incident_records != len(incidents):
        raise ValueError("all current incidents must be benign")
    if expected.adversarial_records != 0:
        raise ValueError("PGS-01-M04 must not include adversarial records")

    return DatasetBundle(
        manifest=manifest,
        incidents=incidents,
        knowledge=knowledge,
    )
