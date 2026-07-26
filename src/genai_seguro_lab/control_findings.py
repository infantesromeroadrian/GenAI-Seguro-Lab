"""Verificación offline del registro revisado de hallazgos de PGS-05-M05."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .adversarial_metrics import AdversarialMetricsSnapshot
from .benign_utility import BenignUtilitySnapshot
from .operational_metrics import OperationalMetricsSnapshot

SOURCE_SNAPSHOT_COMMIT = "15067f37f8cd769bbebd1b7d3f235cea301952a8"
REGISTER_PATH = Path("evaluations/control-findings-v1.json")
SOURCE_IDENTITIES = {
    "DAT-20": {
        "artifact_id": "GSL-METRICS-ADVERSARIAL-001",
        "path": "evaluations/adversarial-metrics-v1.json",
        "sha256": (
            "2d4302018cc849e54507e4bf58b0d5ab98822a5b602ec5289d4874a2335ffb85"
        ),
    },
    "DAT-21": {
        "artifact_id": "GSL-METRICS-BENIGN-UTILITY-001",
        "path": "evaluations/benign-utility-v1.json",
        "sha256": (
            "af77c91c3505ef22e8ee0f4b0047de6c9b44bfe5a2127dd25d39b86077f451da"
        ),
    },
    "DAT-22": {
        "artifact_id": "GSL-METRICS-OPERATIONAL-001",
        "path": "evaluations/operational-metrics-v1.json",
        "sha256": (
            "cea6d0dceff86d7b2c16c3f6fc44425f6f76e9cb2f53b021f109b070597410c3"
        ),
    },
}
EXPECTED_FINDING_IDS = tuple(f"CF-{number:03d}" for number in range(1, 7))
VALID_CONTROL_REFS = frozenset(f"CTL-{number:02d}" for number in range(1, 14))
VALID_ABUSE_CASE_REFS = frozenset(
    (
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
    )
)
VALID_FIXTURE_REFS = frozenset(
    (
        "ADV-TOL-005",
        "ADV-DOS-001",
        "ADV-DOS-002",
        "ADV-DOS-003",
        "ADV-SC-001",
    )
)

Sha256Value = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
JsonPointer = Annotated[
    str,
    Field(pattern=r"^/(?:[^/~]|~[01])+(?:/(?:[^/~]|~[01])+)*$"),
]
Scalar = str | int | bool | None
FindingKind = Literal[
    "CONTROL_FAILURE",
    "HISTORICAL_BYPASS",
    "NEGATIVE_RESULT",
    "MEASUREMENT_GAP",
    "COVERAGE_GAP",
]
FindingState = Literal[
    "MITIGATED_IN_INITIAL_RETEST_NOT_FINAL",
    "OPEN",
    "OUTSIDE_EVALUATED_DENOMINATOR",
    "OBSERVED_PRE_AND_POST",
    "OBSERVED_WITHOUT_ACCEPTANCE_THRESHOLD",
]
Lifecycle = Literal["OPEN", "PENDING_FINAL_RETEST", "DEFERRED"]
TreatmentAction = Literal[
    "FINAL_RETEST",
    "ADD_EVIDENCE",
    "CORRECT_IF_CONTRACT_CONFIRMED",
    "DOCUMENT_RESIDUAL",
]
TreatmentTarget = Literal[
    "PGS-05-M06",
    "PGS-05-M07",
    "PGS-05-M08",
    "FUTURE_AUTHORIZED_EVALUATION",
]


class ControlFindingsError(RuntimeError):
    """El registro o una de sus fuentes no cumple el contrato fijado."""


class ControlFindingsSchema(BaseModel):
    """Base cerrada, estricta e inmutable para el registro y su informe."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SourceReference(ControlFindingsSchema):
    data_id: Literal["DAT-20", "DAT-21", "DAT-22"]
    artifact_id: Literal[
        "GSL-METRICS-ADVERSARIAL-001",
        "GSL-METRICS-BENIGN-UTILITY-001",
        "GSL-METRICS-OPERATIONAL-001",
    ]
    path: Literal[
        "evaluations/adversarial-metrics-v1.json",
        "evaluations/benign-utility-v1.json",
        "evaluations/operational-metrics-v1.json",
    ]
    sha256: Sha256Value


class EvidenceAssertion(ControlFindingsSchema):
    source_data_id: Literal["DAT-20", "DAT-21", "DAT-22"]
    pointer: JsonPointer
    expected: Scalar


class Treatment(ControlFindingsSchema):
    action: TreatmentAction
    target: TreatmentTarget
    correction_candidate_m06: bool
    reconsideration_condition: Annotated[str, Field(min_length=10, max_length=240)]


class ControlFinding(ControlFindingsSchema):
    finding_id: Annotated[str, Field(pattern=r"^CF-[0-9]{3}$")]
    condition_code: Literal[
        "HISTORICAL_LITERAL_CONFIRMATION_BYPASS",
        "TOOL_REQUEST_ATTEMPTS_NOT_COMPUTABLE",
        "ADVERSARIAL_COVERAGE_14_OF_18",
        "STRICT_BENIGN_UTILITY_0_OF_12",
        "SEMANTIC_UTILITY_NOT_EVALUATED",
        "LOCAL_OPERATIONAL_OVERHEAD_WITHOUT_THRESHOLD",
    ]
    kind: FindingKind
    state: FindingState
    lifecycle: Lifecycle
    title: Annotated[str, Field(min_length=8, max_length=120)]
    control_refs: tuple[str, ...]
    abuse_case_refs: tuple[str, ...]
    fixture_refs: tuple[str, ...]
    success_criterion_refs: tuple[Literal["SC-07"], ...]
    evidence: Annotated[
        tuple[EvidenceAssertion, ...],
        Field(min_length=1),
    ]
    interpretation: Annotated[str, Field(min_length=20, max_length=420)]
    treatment: Treatment

    @model_validator(mode="after")
    def verify_references_and_state(self) -> Self:
        _require_sorted_unique(self.control_refs, "control references")
        _require_sorted_unique(self.abuse_case_refs, "abuse case references")
        _require_sorted_unique(self.fixture_refs, "fixture references")
        _require_sorted_unique(
            self.success_criterion_refs,
            "success criterion references",
        )
        if not set(self.control_refs) <= VALID_CONTROL_REFS:
            raise ValueError("unknown control reference")
        if not set(self.abuse_case_refs) <= VALID_ABUSE_CASE_REFS:
            raise ValueError("unknown abuse case reference")
        if not set(self.fixture_refs) <= VALID_FIXTURE_REFS:
            raise ValueError("unknown fixture reference")
        evidence_keys = tuple(
            (item.source_data_id, item.pointer) for item in self.evidence
        )
        if len(evidence_keys) != len(set(evidence_keys)):
            raise ValueError("duplicate evidence assertion")

        allowed_states = {
            "CONTROL_FAILURE": {"OPEN"},
            "HISTORICAL_BYPASS": {
                "MITIGATED_IN_INITIAL_RETEST_NOT_FINAL",
            },
            "NEGATIVE_RESULT": {
                "OBSERVED_PRE_AND_POST",
                "OBSERVED_WITHOUT_ACCEPTANCE_THRESHOLD",
            },
            "MEASUREMENT_GAP": {"OPEN"},
            "COVERAGE_GAP": {"OUTSIDE_EVALUATED_DENOMINATOR"},
        }
        if self.state not in allowed_states[self.kind]:
            raise ValueError("finding kind and state are inconsistent")
        if (
            self.kind == "HISTORICAL_BYPASS"
            and self.lifecycle != "PENDING_FINAL_RETEST"
        ):
            raise ValueError("historical bypass must await the final retest")
        if self.treatment.correction_candidate_m06 != (
            self.treatment.target == "PGS-05-M06"
        ):
            raise ValueError("M06 candidate and treatment target disagree")
        return self


class ClassificationPolicy(ControlFindingsSchema):
    partial_control_is_failure: Literal[False]
    inert_fixture_is_failure: Literal[False]
    not_demonstrated_is_failure: Literal[False]
    not_computable_means_zero: Literal[False]
    overhead_without_threshold_is_defect: Literal[False]
    current_absence_scope: Literal[
        "ONLY_THE_14_MEASURED_FIXTURES_IN_THE_INITIAL_RETEST"
    ]


class SanitizationPolicy(ControlFindingsSchema):
    raw_content_included: Literal[False]
    absolute_paths_included: Literal[False]
    dynamic_timestamps_included: Literal[False]
    personal_data_included: Literal[False]
    allowlisted_values_only: Literal[True]


class FindingsSummary(ControlFindingsSchema):
    total_findings: Annotated[int, Field(ge=0)]
    control_failures: Annotated[int, Field(ge=0)]
    historical_bypasses: Annotated[int, Field(ge=0)]
    current_control_failures_observed_in_measured_scope: Literal[0]
    current_bypasses_observed_in_measured_scope: Literal[0]
    negative_results: Annotated[int, Field(ge=0)]
    evidence_gaps: Annotated[int, Field(ge=0)]
    m06_review_candidates: Annotated[int, Field(ge=0)]
    declared_adversarial_cases: Literal[18]
    measured_adversarial_cases: Literal[14]
    source_final_retest: Literal[False]


class ControlFindingsRegister(ControlFindingsSchema):
    schema_version: Literal["1.0.0"]
    registry_id: Literal["GSL-CONTROL-FINDINGS-001"]
    registry_revision: Literal[1]
    source_snapshot_commit: Literal[
        "15067f37f8cd769bbebd1b7d3f235cea301952a8"
    ]
    sources: Annotated[
        tuple[SourceReference, ...],
        Field(min_length=3, max_length=3),
    ]
    classification_policy: ClassificationPolicy
    sanitization: SanitizationPolicy
    findings: Annotated[
        tuple[ControlFinding, ...],
        Field(min_length=6, max_length=6),
    ]
    summary: FindingsSummary

    @model_validator(mode="after")
    def verify_closed_register(self) -> Self:
        if tuple(source.data_id for source in self.sources) != tuple(
            SOURCE_IDENTITIES
        ):
            raise ValueError("source order is invalid")
        expected_sources = tuple(
            {
                "data_id": data_id,
                **identity,
            }
            for data_id, identity in SOURCE_IDENTITIES.items()
        )
        if tuple(source.model_dump() for source in self.sources) != expected_sources:
            raise ValueError("source identities do not match the pinned cut")
        if tuple(item.finding_id for item in self.findings) != EXPECTED_FINDING_IDS:
            raise ValueError("finding order is invalid")
        conditions = tuple(item.condition_code for item in self.findings)
        if len(conditions) != len(set(conditions)):
            raise ValueError("finding conditions must be unique")
        if self.summary.model_dump() != _derive_summary(self.findings):
            raise ValueError("summary does not match the findings")
        return self


class VerificationReport(ControlFindingsSchema):
    schema_version: Literal["1.0.0"]
    verification_id: Literal["GSL-CONTROL-FINDINGS-VERIFICATION-001"]
    registry_id: Literal["GSL-CONTROL-FINDINGS-001"]
    source_count: Literal[3]
    finding_count: Literal[6]
    evidence_assertion_count: Annotated[int, Field(gt=0)]
    verified: Literal[True]


def canonical_json(document: ControlFindingsSchema) -> str:
    """Serializa un registro o informe validado de forma determinista."""

    if not isinstance(document, ControlFindingsSchema):
        raise TypeError("document must be control findings evidence")
    return (
        json.dumps(
            document.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def verify_control_findings(project_root: Path) -> VerificationReport:
    """Verifica el registro estático y todas sus referencias sin ejecutarlas."""

    register_path = project_root / REGISTER_PATH
    try:
        register_bytes = register_path.read_bytes()
        register = ControlFindingsRegister.model_validate_json(register_bytes)
    except Exception as error:
        raise ControlFindingsError("control findings register is invalid") from error

    if canonical_json(register).encode() != register_bytes:
        raise ControlFindingsError("control findings register is not canonical")

    documents: dict[str, Any] = {}
    for source in register.sources:
        source_path = project_root / source.path
        try:
            source_bytes = source_path.read_bytes()
        except OSError as error:
            raise ControlFindingsError("control findings source is unavailable") from error
        if sha256(source_bytes).hexdigest() != source.sha256:
            raise ControlFindingsError("control findings source hash mismatch")
        documents[source.data_id] = _validate_source(
            source.data_id,
            source_bytes,
            source.artifact_id,
        )

    assertion_count = 0
    for finding in register.findings:
        for assertion in finding.evidence:
            actual = _resolve_json_pointer(
                documents[assertion.source_data_id],
                assertion.pointer,
            )
            if type(actual) is not type(assertion.expected) or actual != (
                assertion.expected
            ):
                raise ControlFindingsError(
                    "control findings evidence assertion mismatch"
                )
            assertion_count += 1

    return VerificationReport(
        schema_version="1.0.0",
        verification_id="GSL-CONTROL-FINDINGS-VERIFICATION-001",
        registry_id=register.registry_id,
        source_count=3,
        finding_count=len(register.findings),
        evidence_assertion_count=assertion_count,
        verified=True,
    )


def _validate_source(
    data_id: str,
    content: bytes,
    expected_artifact_id: str,
) -> dict[str, Any]:
    models = {
        "DAT-20": (AdversarialMetricsSnapshot, "metrics_id"),
        "DAT-21": (BenignUtilitySnapshot, "metrics_id"),
        "DAT-22": (OperationalMetricsSnapshot, "metrics_id"),
    }
    model, identity_field = models[data_id]
    try:
        validated = model.model_validate_json(content)
    except Exception as error:
        raise ControlFindingsError("control findings source schema mismatch") from error
    document = validated.model_dump(mode="json")
    if document[identity_field] != expected_artifact_id:
        raise ControlFindingsError("control findings source identity mismatch")
    return document


def _resolve_json_pointer(document: Any, pointer: str) -> Scalar:
    current = document
    for raw_token in pointer.split("/")[1:]:
        token = _decode_pointer_token(raw_token)
        try:
            if isinstance(current, dict):
                current = current[token]
            elif isinstance(current, list):
                if token != "0" and token.startswith("0"):
                    raise ValueError("non-canonical array index")
                current = current[int(token)]
            else:
                raise TypeError("pointer traverses a scalar")
        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise ControlFindingsError(
                "control findings evidence pointer is unresolved"
            ) from error
    if current is not None and not isinstance(current, (str, int, bool)):
        raise ControlFindingsError(
            "control findings evidence pointer must resolve to a scalar"
        )
    return current


def _decode_pointer_token(token: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(token):
        if token[index] != "~":
            decoded.append(token[index])
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
            raise ControlFindingsError("invalid JSON pointer escape")
        decoded.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(decoded)


def _derive_summary(
    findings: tuple[ControlFinding, ...],
) -> dict[str, int | bool]:
    kinds = tuple(item.kind for item in findings)
    return {
        "total_findings": len(findings),
        "control_failures": kinds.count("CONTROL_FAILURE"),
        "historical_bypasses": kinds.count("HISTORICAL_BYPASS"),
        "current_control_failures_observed_in_measured_scope": 0,
        "current_bypasses_observed_in_measured_scope": 0,
        "negative_results": kinds.count("NEGATIVE_RESULT"),
        "evidence_gaps": (
            kinds.count("MEASUREMENT_GAP") + kinds.count("COVERAGE_GAP")
        ),
        "m06_review_candidates": sum(
            item.treatment.correction_candidate_m06 for item in findings
        ),
        "declared_adversarial_cases": 18,
        "measured_adversarial_cases": 14,
        "source_final_retest": False,
    }


def _require_sorted_unique(values: tuple[str, ...], label: str) -> None:
    if tuple(sorted(values)) != values or len(values) != len(set(values)):
        raise ValueError(f"{label} must be sorted and unique")
