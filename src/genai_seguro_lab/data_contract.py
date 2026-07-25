"""Contratos y carga verificable de los corpus sintéticos."""

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
AdversarialCaseId = Annotated[
    str,
    Field(pattern=r"^ADV-(PI|JB|EX|TOL|DOS|SC)-[0-9]{3}$"),
]
AdversarialCorpusId = Annotated[
    str,
    Field(pattern=r"^GSL-ADVERSARIAL-CORPUS-[0-9]{3}$"),
]

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
AbuseCaseId = Literal[
    "AC-PI-01",
    "AC-PI-02",
    "AC-PI-03",
    "AC-JB-01",
    "AC-JB-02",
    "AC-EX-01",
    "AC-EX-02",
    "AC-EX-03",
    "AC-TOL-01",
    "AC-TOL-02",
    "AC-TOL-03",
    "AC-TOL-04",
    "AC-TOL-05",
    "AC-DOS-01",
    "AC-DOS-02",
    "AC-DOS-03",
    "AC-SC-01",
]
ThreatFamily = Literal[
    "prompt_injection",
    "jailbreak",
    "information_disclosure",
    "tool_abuse",
    "denial_of_service",
    "supply_chain",
]
AttackVehicle = Literal[
    "cli_unknown_argument",
    "temporary_incident_copy",
    "temporary_knowledge_copy",
    "synthetic_model_double",
    "internal_knowledge_search",
    "synthetic_canary",
    "internal_tool_request",
    "internal_draft_api",
    "temporary_sandbox",
    "limited_cli_subprocesses",
    "temporary_dataset_copy",
    "sized_dataset_descriptor",
    "temporary_candidate_copy",
]
AttackTarget = Literal[
    "CMP-01",
    "CMP-02",
    "CMP-03",
    "CMP-06",
    "MOD-01",
    "TOL-01",
    "TOL-02",
    "DAT-01",
    "DAT-02",
    "DAT-03",
    "INF-01",
    "INF-02",
]
RoeStatus = Literal["catalogued", "requires_extension"]
ExpectedOutcome = Literal[
    "rejected",
    "safe_completion",
    "known_residual",
    "controlled_observation",
    "fails_closed",
    "not_authorized",
    "integrity_drift_detected",
]
ExpectedToolDecision = Literal[
    "not_applicable",
    "reject",
    "allow_knowledge_search",
    "allow_one_temporary_draft",
    "stop_before_execution",
]
ExpectedEffect = Literal[
    "none",
    "synthetic_read_only",
    "sanitized_process_output",
    "one_temporary_markdown",
    "temporary_copy_only",
]
CatalogConsequence = Literal["C0", "C1", "C2", "C3"]

EXPECTED_ADVERSARIAL_ABUSE_CASES = frozenset(
    {
        "AC-PI-01",
        "AC-PI-02",
        "AC-PI-03",
        "AC-JB-01",
        "AC-JB-02",
        "AC-EX-01",
        "AC-EX-02",
        "AC-EX-03",
        "AC-TOL-01",
        "AC-TOL-02",
        "AC-TOL-03",
        "AC-TOL-04",
        "AC-TOL-05",
        "AC-DOS-01",
        "AC-DOS-02",
        "AC-DOS-03",
        "AC-SC-01",
    }
)
EXPECTED_ADVERSARIAL_FAMILIES = frozenset(
    {
        "prompt_injection",
        "jailbreak",
        "information_disclosure",
        "tool_abuse",
        "denial_of_service",
        "supply_chain",
    }
)
EXPECTED_ADVERSARIAL_FAMILY_BY_ABUSE_CASE = {
    "AC-PI-01": "prompt_injection",
    "AC-PI-02": "prompt_injection",
    "AC-PI-03": "prompt_injection",
    "AC-JB-01": "jailbreak",
    "AC-JB-02": "jailbreak",
    "AC-EX-01": "information_disclosure",
    "AC-EX-02": "information_disclosure",
    "AC-EX-03": "information_disclosure",
    "AC-TOL-01": "tool_abuse",
    "AC-TOL-02": "tool_abuse",
    "AC-TOL-03": "tool_abuse",
    "AC-TOL-04": "tool_abuse",
    "AC-TOL-05": "tool_abuse",
    "AC-DOS-01": "denial_of_service",
    "AC-DOS-02": "denial_of_service",
    "AC-DOS-03": "denial_of_service",
    "AC-SC-01": "supply_chain",
}
EXPECTED_ADVERSARIAL_PREFIX_BY_FAMILY = {
    "prompt_injection": "PI",
    "jailbreak": "JB",
    "information_disclosure": "EX",
    "tool_abuse": "TOL",
    "denial_of_service": "DOS",
    "supply_chain": "SC",
}


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


class AdversarialParameter(StrictModel):
    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    value: Annotated[str, Field(min_length=1, max_length=512)]


class AdversarialInputRecord(StrictModel):
    id: AdversarialCaseId
    type: Literal["adversarial_input"]
    abuse_case_id: AbuseCaseId
    family: ThreatFamily
    variant: Annotated[
        str,
        Field(pattern=r"^[a-z0-9][a-z0-9_]{0,63}$"),
    ]
    title: Text
    vehicle: AttackVehicle
    target: AttackTarget
    payload_kind: Literal["inert_text", "inert_test_descriptor"]
    payload: Annotated[str, Field(min_length=1, max_length=65_536)]
    parameters: Annotated[
        tuple[AdversarialParameter, ...],
        Field(max_length=8),
    ]
    provenance: Provenance
    synthetic: Literal[True]
    sensitivity: Sensitivity
    scope: Literal["local_lab_only"]
    fixture_state: Literal["inert_not_wired"]
    roe_status: RoeStatus
    external_target: Literal[False]

    @field_validator("parameters")
    @classmethod
    def reject_duplicate_parameter_names(
        cls, value: tuple[AdversarialParameter, ...]
    ) -> tuple[AdversarialParameter, ...]:
        names = [parameter.name for parameter in value]
        if len(names) != len(set(names)):
            raise ValueError(
                "duplicate adversarial parameter names are not allowed"
            )
        return value

    @field_validator("payload")
    @classmethod
    def enforce_payload_byte_budget(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 65_536:
            raise ValueError("adversarial payload exceeds the 64 KiB RoE limit")
        return value


class AdversarialOracleRecord(StrictModel):
    case_id: AdversarialCaseId
    type: Literal["adversarial_oracle"]
    abuse_case_id: AbuseCaseId
    expected_outcome: ExpectedOutcome
    expected_tool_decision: ExpectedToolDecision
    expected_effect: ExpectedEffect
    catalog_consequence: CatalogConsequence
    required_observations: Annotated[tuple[Text, ...], Field(min_length=1)]
    forbidden_observations: tuple[Text, ...]
    fixed_before_execution: Literal[True]
    provenance: Provenance
    synthetic: Literal[True]
    sensitivity: Sensitivity

    @field_validator("required_observations", "forbidden_observations")
    @classmethod
    def reject_duplicate_observations(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate oracle observations are not allowed")
        return value


class AdversarialManifestFile(StrictModel):
    path: Literal["inputs.jsonl", "oracles.jsonl"]
    kind: Literal["adversarial_input_jsonl", "adversarial_oracle_jsonl"]
    records: Literal[18]
    sha256: Sha256


class AdversarialManifestExpectedResult(StrictModel):
    input_records: Literal[18]
    oracle_records: Literal[18]
    unique_abuse_cases: Literal[17]
    threat_families: Literal[6]
    runtime_connections: Literal[0]
    attack_executions: Literal[0]


class AdversarialCorpusManifest(StrictModel):
    id: AdversarialCorpusId
    version: Literal["1.0.0"]
    type: Literal["adversarial_corpus_manifest"]
    rules_of_engagement: Literal["GSL-ROE-001"]
    target_profile: Literal["GSL-PROFILE-VULNERABLE-001"]
    files: Annotated[
        tuple[AdversarialManifestFile, ...],
        Field(min_length=2, max_length=2),
    ]
    provenance: Provenance
    synthetic: Literal[True]
    sensitivity: Sensitivity
    fixture_state: Literal["prepared_not_wired"]
    expected_result: AdversarialManifestExpectedResult


@dataclass(frozen=True)
class DatasetBundle:
    manifest: DatasetManifest
    incidents: tuple[IncidentRecord, ...]
    knowledge: tuple[KnowledgeRecord, ...]


@dataclass(frozen=True)
class AdversarialCorpusBundle:
    manifest: AdversarialCorpusManifest
    inputs: tuple[AdversarialInputRecord, ...]
    oracles: tuple[AdversarialOracleRecord, ...]


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


def load_adversarial_corpus(data_dir: Path) -> AdversarialCorpusBundle:
    """Carga fixtures y oráculos inertes sin conectarlos a ninguna ejecución."""

    input_path = data_dir / "inputs.jsonl"
    input_bytes = input_path.read_bytes()
    if any(len(line) > 65_536 for line in input_bytes.splitlines()):
        raise ValueError("adversarial input record exceeds the 64 KiB RoE limit")
    if len(input_bytes) > 10_485_760:
        raise ValueError("adversarial corpus exceeds the 10 MiB RoE run limit")

    manifest = AdversarialCorpusManifest.model_validate_json(
        (data_dir / "manifest.json").read_text(encoding="utf-8")
    )
    inputs = _load_jsonl(
        input_path,
        AdversarialInputRecord,
    )
    oracles = _load_jsonl(
        data_dir / "oracles.jsonl",
        AdversarialOracleRecord,
    )

    input_ids = [record.id for record in inputs]
    oracle_ids = [record.case_id for record in oracles]
    if len(input_ids) != len(set(input_ids)):
        raise ValueError("adversarial input identifiers must be unique")
    if len(oracle_ids) != len(set(oracle_ids)):
        raise ValueError("adversarial oracle identifiers must be unique")
    if set(input_ids) != set(oracle_ids):
        raise ValueError("every adversarial input must have exactly one oracle")

    inputs_by_id = {record.id: record for record in inputs}
    for oracle in oracles:
        if inputs_by_id[oracle.case_id].abuse_case_id != oracle.abuse_case_id:
            raise ValueError(
                f"oracle abuse case mismatch for {oracle.case_id}"
            )

    abuse_case_ids = [record.abuse_case_id for record in inputs]
    if set(abuse_case_ids) != EXPECTED_ADVERSARIAL_ABUSE_CASES:
        raise ValueError("adversarial corpus must cover all 17 abuse cases")
    if abuse_case_ids.count("AC-JB-01") != 2:
        raise ValueError("AC-JB-01 must have exactly two adversarial variants")
    if any(
        abuse_case_ids.count(case_id) != 1
        for case_id in EXPECTED_ADVERSARIAL_ABUSE_CASES
        if case_id != "AC-JB-01"
    ):
        raise ValueError("every other abuse case must have exactly one fixture")

    families = {record.family for record in inputs}
    if families != EXPECTED_ADVERSARIAL_FAMILIES:
        raise ValueError("adversarial corpus must cover all six threat families")

    for record in inputs:
        if (
            record.family
            != EXPECTED_ADVERSARIAL_FAMILY_BY_ABUSE_CASE[record.abuse_case_id]
        ):
            raise ValueError(
                f"unexpected threat family for {record.abuse_case_id}"
            )
        if (
            record.id.split("-")[1]
            != EXPECTED_ADVERSARIAL_PREFIX_BY_FAMILY[record.family]
        ):
            raise ValueError(f"case identifier family mismatch for {record.id}")
        expected_status = (
            "requires_extension"
            if record.abuse_case_id == "AC-DOS-03"
            else "catalogued"
        )
        if record.roe_status != expected_status:
            raise ValueError(
                f"unexpected RoE status for {record.abuse_case_id}"
            )

    entries = {entry.path: entry for entry in manifest.files}
    expected_paths = {"inputs.jsonl", "oracles.jsonl"}
    if set(entries) != expected_paths:
        raise ValueError(
            "adversarial manifest must enumerate exactly inputs and oracles"
        )

    expected_kinds = {
        "inputs.jsonl": "adversarial_input_jsonl",
        "oracles.jsonl": "adversarial_oracle_jsonl",
    }
    record_counts = {
        "inputs.jsonl": len(inputs),
        "oracles.jsonl": len(oracles),
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
    if expected.input_records != len(inputs):
        raise ValueError("manifest adversarial input total does not match")
    if expected.oracle_records != len(oracles):
        raise ValueError("manifest adversarial oracle total does not match")
    if expected.unique_abuse_cases != len(set(abuse_case_ids)):
        raise ValueError("manifest abuse-case coverage does not match")
    if expected.threat_families != len(families):
        raise ValueError("manifest threat-family coverage does not match")

    return AdversarialCorpusBundle(
        manifest=manifest,
        inputs=inputs,
        oracles=oracles,
    )
