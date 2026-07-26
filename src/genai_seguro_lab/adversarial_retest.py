"""Retest adversario neutral sobre el checkout endurecido exacto."""

from __future__ import annotations

import json
import os
import resource
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from time import monotonic_ns
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .adversarial_baseline import (
    CANONICAL_CASE_IDS,
    AdversarialBaselineResults,
    BaselineConfiguration,
    SanitizedEvent as HistoricalSanitizedEvent,
    _execute_case,
    _jailbreak_authorization,
    _observed_contract,
    _prompt_authorization,
    _tool_authorization,
)
from .data_contract import (
    AdversarialCorpusBundle,
    ExpectedEffect,
    ExpectedOutcome,
    ExpectedToolDecision,
    load_adversarial_corpus,
)
from .evaluation_harness import (
    build_jailbreak_disclosure_plan,
    build_prompt_injection_plan,
    build_tool_abuse_plan,
)

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
GitOid = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
RunId = Annotated[str, Field(pattern=r"^GSL-ADV-RT-[0-9]{8}-[0-9]{3}$")]
ExecutionStatus = Literal["COMPLETED", "STOPPED", "ERROR"]
OracleRelation = Literal["MATCH", "DIFF", "NOT_EVALUATED"]
ObservedOutcome: TypeAlias = ExpectedOutcome | Literal["not_observed"]
ObservedToolDecision: TypeAlias = (
    ExpectedToolDecision | Literal["not_observed"]
)
ObservedEffect: TypeAlias = ExpectedEffect | Literal["not_observed"]

RETEST_ID = "GSL-RETEST-ADVERSARIAL-001"
EVIDENCE_ID = "GSL-EVIDENCE-ADVERSARIAL-RETEST-001"
HISTORICAL_BASELINE_ID = "GSL-BASELINE-ADVERSARIAL-001"
HISTORICAL_CANDIDATE_COMMIT = "93aefa45eac687d219bfed32f03be4e60e4a13ed"
HISTORICAL_EVIDENCE_MANIFEST_SHA256 = (
    "c7b96d964dc5ba40f5b53895486ef59bf833992c5393a9967449b98ba80eae45"
)
CURRENT_ADVERSARIAL_MANIFEST_SHA256 = (
    "99e8b44dbee5b0c52341a3ba496b50885f622ae531fc40b937a549bceaa893c3"
)
HISTORICAL_EVIDENCE_DIRECTORY = (
    "evaluations/adversarial-baseline-v1"
)
CONTENT_COMPARISON_PATHS = (
    "data/incidents.jsonl",
    "data/knowledge.jsonl",
    "data/manifest.json",
    "data/adversarial/inputs.jsonl",
    "data/adversarial/oracles.jsonl",
)
CURRENT_MANIFEST_PATH = "data/adversarial/manifest.json"
CURRENT_CORPUS_PATHS = (*CONTENT_COMPARISON_PATHS, CURRENT_MANIFEST_PATH)


class AdversarialRetestSchema(BaseModel):
    """Base estricta, cerrada e inmutable para el retest y su evidencia."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AdversarialRetestAuthorization(AdversarialRetestSchema):
    """Autoridad exacta y topes de PGS-05-M01."""

    rules_of_engagement: Literal["GSL-ROE-001"]
    source_profile: Literal["GSL-PROFILE-VULNERABLE-001"]
    candidate_posture: Literal["hardened_checkout"]
    case_ids: Annotated[tuple[str, ...], Field(min_length=14, max_length=14)]
    synthetic_data: Literal[True]
    external_network: Literal[False]
    canonical_checkout_mutation: Literal[False]
    raw_evidence_location: Literal["temporary_directory"]
    canonical_write_mode: Literal["manual_after_review"]
    max_run_seconds: Literal[600]
    max_case_seconds: Literal[15]
    max_target_processes: Literal[1]
    max_effect_files_per_case: Literal[1]
    max_effect_files_per_run: Literal[1]
    max_input_bytes_per_run: Literal[10_485_760]
    max_temporary_bytes_per_run: Literal[26_214_400]
    max_rss_bytes: Literal[536_870_912]
    retry_count: Literal[0]


class CandidateSnapshot(AdversarialRetestSchema):
    commit: GitOid
    tree: GitOid
    branch: Literal["main"]
    clean_before_run: Literal[True]
    posture: Literal["hardened_checkout"]


class RuntimeFileSnapshot(AdversarialRetestSchema):
    path: Literal["$REPO/uv.lock"]
    sha256: Sha256
    bytes: Annotated[int, Field(ge=1)]


class RuntimeSnapshot(AdversarialRetestSchema):
    python: Annotated[str, Field(pattern=r"^3\.12\.[0-9]+$")]
    uv: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    pydantic: Annotated[str, Field(pattern=r"^2\.[0-9]+\.[0-9]+$")]
    platform: Literal["darwin", "linux"]
    uv_lock: RuntimeFileSnapshot
    external_calls: Literal[False]
    cost_eur: Literal["0.00"]


class HistoricalEvidenceFile(AdversarialRetestSchema):
    path: Literal["config.json", "results.json", "events.jsonl"]
    sha256: Sha256
    bytes: Annotated[int, Field(ge=1)]


class HistoricalEvidenceManifest(AdversarialRetestSchema):
    schema_version: Literal["1.0.0"]
    evidence_id: Literal["GSL-EVIDENCE-ADVERSARIAL-001"]
    baseline_id: Literal["GSL-BASELINE-ADVERSARIAL-001"]
    run_id: Annotated[str, Field(pattern=r"^GSL-ADV-BL-[0-9]{8}-[0-9]{3}$")]
    candidate_commit: Literal[
        "93aefa45eac687d219bfed32f03be4e60e4a13ed"
    ]
    files: Annotated[
        tuple[HistoricalEvidenceFile, ...],
        Field(min_length=3, max_length=3),
    ]
    total_bytes: Annotated[int, Field(ge=1, le=26_214_400)]
    reviewed_for_versioning: Literal[True]


class HistoricalCorpusFile(AdversarialRetestSchema):
    path: str
    sha256: Sha256
    bytes: Annotated[int, Field(ge=1)]


class HistoricalBaselineReference(AdversarialRetestSchema):
    baseline_id: Literal["GSL-BASELINE-ADVERSARIAL-001"]
    evidence_id: Literal["GSL-EVIDENCE-ADVERSARIAL-001"]
    evidence_directory: Literal[
        "$REPO/evaluations/adversarial-baseline-v1"
    ]
    candidate_commit: Literal[
        "93aefa45eac687d219bfed32f03be4e60e4a13ed"
    ]
    manifest_sha256: Sha256
    evidence_files: Annotated[
        tuple[HistoricalEvidenceFile, ...],
        Field(min_length=3, max_length=3),
    ]
    configuration_hash_verified_from_results: Literal[True]
    evidence_hashes_verified: Literal[True]
    reviewed_for_versioning: Literal[True]
    corpus_version: Literal["1.3.0"]
    corpus_files: Annotated[
        tuple[HistoricalCorpusFile, ...],
        Field(min_length=6, max_length=6),
    ]


class ComparableContentFile(AdversarialRetestSchema):
    path: str
    historical_sha256: Sha256
    candidate_before_sha256: Sha256
    historical_bytes: Annotated[int, Field(ge=1)]
    candidate_before_bytes: Annotated[int, Field(ge=1)]
    relation: Literal["BYTE_IDENTICAL"]


class AdversarialManifestComparison(AdversarialRetestSchema):
    path: Literal["data/adversarial/manifest.json"]
    historical_version: Literal["1.3.0"]
    candidate_version: Literal["1.4.0"]
    historical_sha256: Sha256
    candidate_before_sha256: Sha256
    relation: Literal["METADATA_ONLY_DRIFT_DECLARED"]
    content_identity_scope: Annotated[
        tuple[str, ...],
        Field(min_length=5, max_length=5),
    ]


class CorpusComparison(AdversarialRetestSchema):
    corpus_id: Literal["GSL-ADVERSARIAL-CORPUS-001"]
    selected_records: Literal[14]
    inert_records: Literal[4]
    case_ids: Annotated[tuple[str, ...], Field(min_length=14, max_length=14)]
    oracles_delivered_to_target: Literal[False]
    byte_identical_content_files: Annotated[
        tuple[ComparableContentFile, ...],
        Field(min_length=5, max_length=5),
    ]
    adversarial_manifest: AdversarialManifestComparison


class RetestConfiguration(AdversarialRetestSchema):
    schema_version: Literal["1.0.0"]
    retest_id: Literal["GSL-RETEST-ADVERSARIAL-001"]
    run_id: RunId
    executed_at_utc: datetime
    request_authority: Literal["user_go_for_pgs_05_m01"]
    operator: Literal["ACT-02"]
    candidate: CandidateSnapshot
    runtime: RuntimeSnapshot
    historical_baseline: HistoricalBaselineReference
    corpus: CorpusComparison
    authorization: AdversarialRetestAuthorization
    command: tuple[str, ...]
    temporary_root: Literal["$TMP/adversarial-retest-v1"]
    evidence_directory: Literal["$TMP/adversarial-retest-v1/reviewed"]
    stop_conditions: tuple[
        Literal["network_attempt"],
        Literal["non_synthetic_data"],
        Literal["out_of_scope_write"],
        Literal["unapproved_tool"],
        Literal["budget_exceeded"],
        Literal["candidate_or_corpus_drift"],
        Literal["historical_evidence_drift"],
        Literal["user_interrupt"],
    ]
    evidence_policy: tuple[
        Literal["closed_field_projection"],
        Literal["paths_tokenized"],
        Literal["content_minimized"],
        Literal["temporary_first"],
    ]
    cleanup_policy: tuple[
        Literal["manual_review_before_versioning"],
        Literal["version_only_reviewed_projection"],
        Literal["no_automatic_retry"],
    ]
    final_retest: Literal[False]


class AdversarialCaseResult(AdversarialRetestSchema):
    case_id: str
    abuse_case_id: str
    family: str
    execution_status: ExecutionStatus
    observed_outcome: ObservedOutcome
    observed_tool_decision: ObservedToolDecision
    observed_effect: ObservedEffect
    oracle_relation: OracleRelation
    duration_ms: Annotated[int, Field(ge=0, le=15_000)]
    observation_recorded: bool
    stop_reason: Literal["case_time_budget"] | None = None
    error_category: Literal["execution_error"] | None = None


class CorpusIntegrityFile(AdversarialRetestSchema):
    path: str
    before_sha256: Sha256
    after_sha256: Sha256
    before_bytes: Annotated[int, Field(ge=1)]
    after_bytes: Annotated[int, Field(ge=1)]
    unchanged: Literal[True]


class CorpusIntegrity(AdversarialRetestSchema):
    files: Annotated[
        tuple[CorpusIntegrityFile, ...],
        Field(min_length=6, max_length=6),
    ]
    all_unchanged: Literal[True]


class RetestSummary(AdversarialRetestSchema):
    status: ExecutionStatus
    total_cases: Literal[14]
    completed_cases: Annotated[int, Field(ge=0, le=14)]
    stopped_cases: Annotated[int, Field(ge=0, le=14)]
    error_cases: Annotated[int, Field(ge=0, le=14)]
    unique_case_ids: Literal[True]
    canonical_case_order: Literal[True]
    inert_cases_executed: Literal[0]
    total_duration_ms: Annotated[int, Field(ge=0, le=600_000)]
    raw_temporary_bytes: Annotated[int, Field(ge=0, le=26_214_400)]
    peak_rss_bytes: Annotated[int, Field(ge=1, le=536_870_912)]
    checkout_clean_after_run: Literal[True]
    candidate_unchanged: Literal[True]
    corpus_unchanged: Literal[True]
    historical_evidence_unchanged: Literal[True]
    within_operational_budget: Literal[True]
    external_calls: Literal[0]
    cost_eur: Literal["0.00"]


class RetestResults(AdversarialRetestSchema):
    schema_version: Literal["1.0.0"]
    retest_id: Literal["GSL-RETEST-ADVERSARIAL-001"]
    run_id: RunId
    candidate_commit: GitOid
    candidate_tree: GitOid
    configuration_sha256: Sha256
    summary: RetestSummary
    corpus_integrity: CorpusIntegrity
    cases: Annotated[
        tuple[AdversarialCaseResult, ...],
        Field(min_length=14, max_length=14),
    ]
    final_retest: Literal[False]


class SanitizedEvent(AdversarialRetestSchema):
    schema_version: Literal["1.0.0"]
    run_id: RunId
    observed_at_utc: datetime
    event: Literal["run_started", "case_observed", "run_completed"]
    case_id: str | None = None
    execution_status: ExecutionStatus | None = None
    observed_outcome: ObservedOutcome | None = None
    observed_tool_decision: ObservedToolDecision | None = None
    observed_effect: ObservedEffect | None = None
    oracle_relation: OracleRelation | None = None
    duration_ms: Annotated[int, Field(ge=0, le=600_000)] | None = None
    external_calls: Literal[0] = 0


class EvidenceFile(AdversarialRetestSchema):
    path: Literal["config.json", "results.json", "events.jsonl"]
    sha256: Sha256
    bytes: Annotated[int, Field(ge=1)]


class EvidenceManifest(AdversarialRetestSchema):
    schema_version: Literal["1.0.0"]
    evidence_id: Literal["GSL-EVIDENCE-ADVERSARIAL-RETEST-001"]
    retest_id: Literal["GSL-RETEST-ADVERSARIAL-001"]
    run_id: RunId
    candidate_commit: GitOid
    candidate_tree: GitOid
    files: Annotated[
        tuple[EvidenceFile, ...],
        Field(min_length=3, max_length=3),
    ]
    total_bytes: Annotated[int, Field(ge=1, le=26_214_400)]
    reviewed_for_versioning: bool
    final_retest: Literal[False]


@dataclass(frozen=True, slots=True)
class AdversarialRetestArtifacts:
    configuration: RetestConfiguration
    results: RetestResults
    events: tuple[SanitizedEvent, ...]


@dataclass(frozen=True, slots=True)
class _HistoricalBaseline:
    reference: HistoricalBaselineReference
    configuration: BaselineConfiguration


class AdversarialRetestError(RuntimeError):
    """El retest no satisface el contrato acotado de PGS-05-M01."""


def default_adversarial_retest_authorization() -> (
    AdversarialRetestAuthorization
):
    """Construye la autoridad única del retest M01."""

    return AdversarialRetestAuthorization(
        rules_of_engagement="GSL-ROE-001",
        source_profile="GSL-PROFILE-VULNERABLE-001",
        candidate_posture="hardened_checkout",
        case_ids=CANONICAL_CASE_IDS,
        synthetic_data=True,
        external_network=False,
        canonical_checkout_mutation=False,
        raw_evidence_location="temporary_directory",
        canonical_write_mode="manual_after_review",
        max_run_seconds=600,
        max_case_seconds=15,
        max_target_processes=1,
        max_effect_files_per_case=1,
        max_effect_files_per_run=1,
        max_input_bytes_per_run=10_485_760,
        max_temporary_bytes_per_run=26_214_400,
        max_rss_bytes=536_870_912,
        retry_count=0,
    )


def canonical_json(document: AdversarialRetestSchema) -> str:
    """Serializa JSON estricto con orden y salto final estables."""

    return json.dumps(
        document.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def canonical_jsonl(events: tuple[SanitizedEvent, ...]) -> str:
    """Serializa únicamente eventos de campos cerrados."""

    return "".join(
        json.dumps(
            event.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
        for event in events
    )


def run_adversarial_retest(
    *,
    repository_root: Path,
    run_root: Path,
    candidate: CandidateSnapshot,
    runtime: RuntimeSnapshot,
    run_id: str,
    executed_at_utc: datetime,
    sanitized_command: tuple[str, ...],
    authorization: AdversarialRetestAuthorization,
    verify_candidate_unchanged: Callable[[], bool],
) -> AdversarialRetestArtifacts:
    """Ejecuta una vez los 14 casos y conserva una proyección neutral."""

    repository_root = repository_root.resolve(strict=True)
    run_root = _validated_run_root(run_root, repository_root)
    if not isinstance(candidate, CandidateSnapshot):
        raise TypeError("candidate must be a CandidateSnapshot")
    if not isinstance(runtime, RuntimeSnapshot):
        raise TypeError("runtime must be a RuntimeSnapshot")
    if not isinstance(authorization, AdversarialRetestAuthorization):
        raise TypeError(
            "authorization must be an AdversarialRetestAuthorization"
        )
    if authorization.case_ids != CANONICAL_CASE_IDS:
        raise AdversarialRetestError(
            "retest must select the canonical 14 cases in canonical order"
        )
    if (
        executed_at_utc.tzinfo is None
        or executed_at_utc.utcoffset()
        != timezone.utc.utcoffset(executed_at_utc)
    ):
        raise AdversarialRetestError(
            "executed_at_utc must be timezone-aware UTC"
        )

    historical_before = _verify_historical_baseline(repository_root)
    data_dir = repository_root / "data"
    adversarial_dir = data_dir / "adversarial"
    corpus = load_adversarial_corpus(adversarial_dir)
    _validate_corpus(corpus, authorization)
    hashes_before = _current_corpus_hashes(repository_root)
    corpus_comparison = _compare_corpus(
        repository_root=repository_root,
        corpus=corpus,
        current_hashes=hashes_before,
        historical=historical_before,
    )
    configuration = RetestConfiguration(
        schema_version="1.0.0",
        retest_id=RETEST_ID,
        run_id=run_id,
        executed_at_utc=executed_at_utc,
        request_authority="user_go_for_pgs_05_m01",
        operator="ACT-02",
        candidate=candidate,
        runtime=runtime,
        historical_baseline=historical_before.reference,
        corpus=corpus_comparison,
        authorization=authorization,
        command=sanitized_command,
        temporary_root="$TMP/adversarial-retest-v1",
        evidence_directory="$TMP/adversarial-retest-v1/reviewed",
        stop_conditions=(
            "network_attempt",
            "non_synthetic_data",
            "out_of_scope_write",
            "unapproved_tool",
            "budget_exceeded",
            "candidate_or_corpus_drift",
            "historical_evidence_drift",
            "user_interrupt",
        ),
        evidence_policy=(
            "closed_field_projection",
            "paths_tokenized",
            "content_minimized",
            "temporary_first",
        ),
        cleanup_policy=(
            "manual_review_before_versioning",
            "version_only_reviewed_projection",
            "no_automatic_retry",
        ),
        final_retest=False,
    )
    configuration_sha = _text_sha256(canonical_json(configuration))

    pi_authorization = _prompt_authorization()
    jb_authorization = _jailbreak_authorization()
    tol_authorization = _tool_authorization()
    pi_plan = build_prompt_injection_plan(corpus, pi_authorization)
    jb_plan = build_jailbreak_disclosure_plan(corpus, jb_authorization)
    tol_plan = build_tool_abuse_plan(corpus, tol_authorization)
    records = {record.id: record for record in corpus.inputs}
    oracles = {oracle.case_id: oracle for oracle in corpus.oracles}

    run_started = _utc_now()
    started_ns = monotonic_ns()
    events: list[SanitizedEvent] = [
        SanitizedEvent(
            schema_version="1.0.0",
            run_id=run_id,
            observed_at_utc=run_started,
            event="run_started",
        )
    ]
    case_results: list[AdversarialCaseResult] = []
    observed_effect_files = 0
    for case_id in authorization.case_ids:
        case_root = run_root / "cases" / case_id.lower()
        case_root.mkdir(parents=True, exist_ok=False)
        case_started_ns = monotonic_ns()
        try:
            execution = _execute_case(
                repository_root=repository_root,
                data_dir=data_dir,
                entrypoint=repository_root / "main.py",
                case_root=case_root,
                record=records[case_id],
                pi_plan=pi_plan,
                jb_plan=jb_plan,
                tol_plan=tol_plan,
                pi_authorization=pi_authorization,
                jb_authorization=jb_authorization,
                tol_authorization=tol_authorization,
            )
            duration_ms = _elapsed_ms(case_started_ns)
            if execution.observation.get("external_calls") is not False:
                raise AdversarialRetestError(
                    "a case reported an external call"
                )
            observed = _observed_contract(case_id, execution)
            effect_files = _observed_effect_files(
                execution.observation,
                observed_effect=observed[2],
            )
            if effect_files > authorization.max_effect_files_per_case:
                raise AdversarialRetestError(
                    "a case exceeded the effect-file budget"
                )
            observed_effect_files += effect_files
            if (
                observed_effect_files
                > authorization.max_effect_files_per_run
            ):
                raise AdversarialRetestError(
                    "the run exceeded the effect-file budget"
                )
            if execution.within_time_budget:
                execution_status: ExecutionStatus = "COMPLETED"
                oracle = oracles[case_id]
                oracle_relation: OracleRelation = (
                    "MATCH"
                    if observed
                    == (
                        oracle.expected_outcome,
                        oracle.expected_tool_decision,
                        oracle.expected_effect,
                    )
                    else "DIFF"
                )
                stop_reason = None
                observation_recorded = True
            else:
                execution_status = "STOPPED"
                oracle_relation = "NOT_EVALUATED"
                stop_reason = "case_time_budget"
                observation_recorded = True
            result = AdversarialCaseResult(
                case_id=case_id,
                abuse_case_id=records[case_id].abuse_case_id,
                family=records[case_id].family,
                execution_status=execution_status,
                observed_outcome=observed[0],
                observed_tool_decision=observed[1],
                observed_effect=observed[2],
                oracle_relation=oracle_relation,
                duration_ms=duration_ms,
                observation_recorded=observation_recorded,
                stop_reason=stop_reason,
                error_category=None,
            )
        except AdversarialRetestError:
            raise
        except Exception:
            duration_ms = min(
                _elapsed_ms(case_started_ns),
                authorization.max_case_seconds * 1000,
            )
            result = AdversarialCaseResult(
                case_id=case_id,
                abuse_case_id=records[case_id].abuse_case_id,
                family=records[case_id].family,
                execution_status="ERROR",
                observed_outcome="not_observed",
                observed_tool_decision="not_observed",
                observed_effect="not_observed",
                oracle_relation="NOT_EVALUATED",
                duration_ms=duration_ms,
                observation_recorded=False,
                stop_reason=None,
                error_category="execution_error",
            )
        case_results.append(result)
        events.append(
            SanitizedEvent(
                schema_version="1.0.0",
                run_id=run_id,
                observed_at_utc=_utc_now(),
                event="case_observed",
                case_id=case_id,
                execution_status=result.execution_status,
                observed_outcome=result.observed_outcome,
                observed_tool_decision=result.observed_tool_decision,
                observed_effect=result.observed_effect,
                oracle_relation=result.oracle_relation,
                duration_ms=result.duration_ms,
            )
        )

    total_duration_ms = _elapsed_ms(started_ns)
    if total_duration_ms > authorization.max_run_seconds * 1000:
        raise AdversarialRetestError("retest exceeded its run-time budget")
    if tuple(result.case_id for result in case_results) != CANONICAL_CASE_IDS:
        raise AdversarialRetestError(
            "retest did not preserve canonical case cardinality and order"
        )

    hashes_after = _current_corpus_hashes(repository_root)
    corpus_integrity = _corpus_integrity(
        repository_root=repository_root,
        before=hashes_before,
        after=hashes_after,
    )
    if not verify_candidate_unchanged():
        raise AdversarialRetestError(
            "candidate checkout changed during the retest"
        )
    historical_after = _verify_historical_baseline(repository_root)
    if historical_after.reference != historical_before.reference:
        raise AdversarialRetestError(
            "historical baseline evidence changed during the retest"
        )
    raw_temporary_bytes = _directory_bytes(run_root)
    if raw_temporary_bytes > authorization.max_temporary_bytes_per_run:
        raise AdversarialRetestError(
            "temporary data exceeded the byte budget"
        )
    peak_rss_bytes = _peak_rss_bytes()
    if peak_rss_bytes > authorization.max_rss_bytes:
        raise AdversarialRetestError("retest exceeded the RSS budget")

    completed_cases = sum(
        result.execution_status == "COMPLETED"
        for result in case_results
    )
    stopped_cases = sum(
        result.execution_status == "STOPPED" for result in case_results
    )
    error_cases = sum(
        result.execution_status == "ERROR" for result in case_results
    )
    if error_cases:
        run_status: ExecutionStatus = "ERROR"
    elif stopped_cases:
        run_status = "STOPPED"
    else:
        run_status = "COMPLETED"
    summary = RetestSummary(
        status=run_status,
        total_cases=14,
        completed_cases=completed_cases,
        stopped_cases=stopped_cases,
        error_cases=error_cases,
        unique_case_ids=True,
        canonical_case_order=True,
        inert_cases_executed=0,
        total_duration_ms=total_duration_ms,
        raw_temporary_bytes=raw_temporary_bytes,
        peak_rss_bytes=peak_rss_bytes,
        checkout_clean_after_run=True,
        candidate_unchanged=True,
        corpus_unchanged=True,
        historical_evidence_unchanged=True,
        within_operational_budget=True,
        external_calls=0,
        cost_eur="0.00",
    )
    events.append(
        SanitizedEvent(
            schema_version="1.0.0",
            run_id=run_id,
            observed_at_utc=_utc_now(),
            event="run_completed",
            execution_status=run_status,
            duration_ms=total_duration_ms,
        )
    )
    results = RetestResults(
        schema_version="1.0.0",
        retest_id=RETEST_ID,
        run_id=run_id,
        candidate_commit=candidate.commit,
        candidate_tree=candidate.tree,
        configuration_sha256=configuration_sha,
        summary=summary,
        corpus_integrity=corpus_integrity,
        cases=tuple(case_results),
        final_retest=False,
    )
    artifacts = AdversarialRetestArtifacts(
        configuration=configuration,
        results=results,
        events=tuple(events),
    )
    _assert_projection_is_sanitized(artifacts, repository_root, run_root)
    return artifacts


def write_adversarial_retest_artifacts(
    *,
    artifacts: AdversarialRetestArtifacts,
    output_dir: Path,
) -> EvidenceManifest:
    """Escribe una sola proyección saneada sin sobrescribir ningún archivo."""

    if not isinstance(artifacts, AdversarialRetestArtifacts):
        raise TypeError("artifacts must be AdversarialRetestArtifacts")
    output_dir = output_dir.resolve(strict=False)
    temp_root = _system_temporary_root()
    if output_dir == temp_root or not output_dir.is_relative_to(temp_root):
        raise AdversarialRetestError(
            "evidence output must remain below the system temporary directory"
        )
    if output_dir.exists() or output_dir.is_symlink():
        raise AdversarialRetestError(
            "evidence output directory must not already exist"
        )
    output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    documents = (
        ("config.json", canonical_json(artifacts.configuration)),
        ("results.json", canonical_json(artifacts.results)),
        ("events.jsonl", canonical_jsonl(artifacts.events)),
    )
    files: list[EvidenceFile] = []
    for filename, content in documents:
        path = output_dir / filename
        _write_new_file(path, content.encode("utf-8"))
        files.append(
            EvidenceFile(
                path=filename,
                sha256=_file_sha256(path),
                bytes=path.stat().st_size,
            )
        )
    manifest = EvidenceManifest(
        schema_version="1.0.0",
        evidence_id=EVIDENCE_ID,
        retest_id=RETEST_ID,
        run_id=artifacts.configuration.run_id,
        candidate_commit=artifacts.configuration.candidate.commit,
        candidate_tree=artifacts.configuration.candidate.tree,
        files=tuple(files),
        total_bytes=sum(file.bytes for file in files),
        reviewed_for_versioning=False,
        final_retest=False,
    )
    _write_new_file(
        output_dir / "manifest.json",
        canonical_json(manifest).encode("utf-8"),
    )
    maximum = (
        artifacts.configuration.authorization.max_temporary_bytes_per_run
    )
    if _directory_bytes(output_dir.parent) > maximum:
        raise AdversarialRetestError(
            "sanitized evidence exceeded the temporary byte budget"
        )
    return manifest


def _verify_historical_baseline(repository_root: Path) -> _HistoricalBaseline:
    directory = repository_root / HISTORICAL_EVIDENCE_DIRECTORY
    manifest_bytes = _read_regular_file(directory / "manifest.json")
    manifest_sha256 = sha256(manifest_bytes).hexdigest()
    if manifest_sha256 != HISTORICAL_EVIDENCE_MANIFEST_SHA256:
        raise AdversarialRetestError(
            "historical evidence manifest does not match its pinned hash"
        )
    manifest = HistoricalEvidenceManifest.model_validate_json(manifest_bytes)
    expected_paths = ("config.json", "results.json", "events.jsonl")
    if tuple(file.path for file in manifest.files) != expected_paths:
        raise AdversarialRetestError(
            "historical evidence manifest has an unexpected file list"
        )
    contents: dict[str, bytes] = {}
    for file in manifest.files:
        content = _read_regular_file(directory / file.path)
        if (
            len(content) != file.bytes
            or sha256(content).hexdigest() != file.sha256
        ):
            raise AdversarialRetestError(
                "historical evidence does not match its manifest"
            )
        contents[file.path] = content
    if manifest.total_bytes != sum(len(content) for content in contents.values()):
        raise AdversarialRetestError(
            "historical evidence byte total does not match its manifest"
        )

    configuration = BaselineConfiguration.model_validate_json(
        contents["config.json"]
    )
    results = AdversarialBaselineResults.model_validate_json(
        contents["results.json"]
    )
    historical_events = tuple(
        HistoricalSanitizedEvent.model_validate_json(line)
        for line in contents["events.jsonl"].splitlines()
        if line
    )
    if (
        configuration.baseline_id != HISTORICAL_BASELINE_ID
        or configuration.candidate.commit != HISTORICAL_CANDIDATE_COMMIT
        or results.candidate_commit != HISTORICAL_CANDIDATE_COMMIT
        or manifest.candidate_commit != HISTORICAL_CANDIDATE_COMMIT
        or results.configuration_sha256
        != sha256(contents["config.json"]).hexdigest()
        or len(historical_events) != 16
        or any(
            event.run_id != configuration.run_id
            for event in historical_events
        )
    ):
        raise AdversarialRetestError(
            "historical baseline references are internally inconsistent"
        )
    corpus_files = tuple(
        HistoricalCorpusFile(
            path=file.path,
            sha256=file.sha256,
            bytes=file.bytes,
        )
        for file in configuration.corpus.files
    )
    if (
        configuration.corpus.corpus_version != "1.3.0"
        or tuple(file.path for file in corpus_files) != CURRENT_CORPUS_PATHS
    ):
        raise AdversarialRetestError(
            "historical corpus snapshot is not the expected v1.3 scope"
        )
    reference = HistoricalBaselineReference(
        baseline_id=HISTORICAL_BASELINE_ID,
        evidence_id=manifest.evidence_id,
        evidence_directory="$REPO/evaluations/adversarial-baseline-v1",
        candidate_commit=manifest.candidate_commit,
        manifest_sha256=manifest_sha256,
        evidence_files=manifest.files,
        configuration_hash_verified_from_results=True,
        evidence_hashes_verified=True,
        reviewed_for_versioning=True,
        corpus_version="1.3.0",
        corpus_files=corpus_files,
    )
    return _HistoricalBaseline(
        reference=reference,
        configuration=configuration,
    )


def _validate_corpus(
    corpus: AdversarialCorpusBundle,
    authorization: AdversarialRetestAuthorization,
) -> None:
    if (
        corpus.manifest.id != "GSL-ADVERSARIAL-CORPUS-001"
        or corpus.manifest.version != "1.4.0"
        or corpus.manifest.rules_of_engagement
        != authorization.rules_of_engagement
        or corpus.manifest.target_profile != authorization.source_profile
    ):
        raise AdversarialRetestError(
            "candidate corpus manifest does not match the retest contract"
        )
    wired_ids = tuple(
        record.id
        for record in corpus.inputs
        if record.fixture_state == "test_wired"
    )
    inert_ids = tuple(
        record.id
        for record in corpus.inputs
        if record.fixture_state == "inert_not_wired"
    )
    if wired_ids != authorization.case_ids or len(inert_ids) != 4:
        raise AdversarialRetestError(
            "candidate corpus does not preserve 14 wired and 4 inert cases"
        )
    if any(
        not oracle.fixed_before_execution
        for oracle in corpus.oracles
        if oracle.case_id in authorization.case_ids
    ):
        raise AdversarialRetestError(
            "selected oracles must be fixed before execution"
        )


def _compare_corpus(
    *,
    repository_root: Path,
    corpus: AdversarialCorpusBundle,
    current_hashes: Mapping[str, str],
    historical: _HistoricalBaseline,
) -> CorpusComparison:
    historical_files = {
        file.path: file
        for file in historical.reference.corpus_files
    }
    comparable: list[ComparableContentFile] = []
    total_bytes = 0
    for path in CONTENT_COMPARISON_PATHS:
        historical_file = historical_files[path]
        current_bytes = (repository_root / path).stat().st_size
        total_bytes += current_bytes
        if (
            current_hashes[path] != historical_file.sha256
            or current_bytes != historical_file.bytes
        ):
            raise AdversarialRetestError(
                "candidate content differs from the historical baseline"
            )
        comparable.append(
            ComparableContentFile(
                path=path,
                historical_sha256=historical_file.sha256,
                candidate_before_sha256=current_hashes[path],
                historical_bytes=historical_file.bytes,
                candidate_before_bytes=current_bytes,
                relation="BYTE_IDENTICAL",
            )
        )
    current_manifest_bytes = (
        repository_root / CURRENT_MANIFEST_PATH
    ).stat().st_size
    total_bytes += current_manifest_bytes
    if total_bytes > 10_485_760:
        raise AdversarialRetestError("input data exceeded the run byte budget")
    historical_manifest = historical_files[CURRENT_MANIFEST_PATH]
    if (
        current_hashes[CURRENT_MANIFEST_PATH]
        != CURRENT_ADVERSARIAL_MANIFEST_SHA256
        or current_hashes[CURRENT_MANIFEST_PATH]
        == historical_manifest.sha256
        or corpus.manifest.version != "1.4.0"
        or historical.configuration.corpus.corpus_version != "1.3.0"
    ):
        raise AdversarialRetestError(
            "adversarial manifest does not expose the declared metadata drift"
        )
    return CorpusComparison(
        corpus_id=corpus.manifest.id,
        selected_records=14,
        inert_records=4,
        case_ids=CANONICAL_CASE_IDS,
        oracles_delivered_to_target=False,
        byte_identical_content_files=tuple(comparable),
        adversarial_manifest=AdversarialManifestComparison(
            path=CURRENT_MANIFEST_PATH,
            historical_version="1.3.0",
            candidate_version="1.4.0",
            historical_sha256=historical_manifest.sha256,
            candidate_before_sha256=current_hashes[CURRENT_MANIFEST_PATH],
            relation="METADATA_ONLY_DRIFT_DECLARED",
            content_identity_scope=CONTENT_COMPARISON_PATHS,
        ),
    )


def _corpus_integrity(
    *,
    repository_root: Path,
    before: Mapping[str, str],
    after: Mapping[str, str],
) -> CorpusIntegrity:
    files: list[CorpusIntegrityFile] = []
    for path in CURRENT_CORPUS_PATHS:
        current_size = (repository_root / path).stat().st_size
        if before[path] != after[path]:
            raise AdversarialRetestError(
                "candidate corpus changed during the retest"
            )
        files.append(
            CorpusIntegrityFile(
                path=path,
                before_sha256=before[path],
                after_sha256=after[path],
                before_bytes=current_size,
                after_bytes=current_size,
                unchanged=True,
            )
        )
    return CorpusIntegrity(files=tuple(files), all_unchanged=True)


def _observed_effect_files(
    observation: Mapping[str, JsonValue],
    *,
    observed_effect: ExpectedEffect,
) -> int:
    for key in (
        "effect_files_created",
        "attack_files_created",
        "replay_additional_files",
    ):
        value = observation.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            if value < 0:
                raise AdversarialRetestError(
                    "an observed effect count was invalid"
                )
            if value:
                return value
    draft_files = observation.get("draft_files")
    if isinstance(draft_files, list) and draft_files:
        return len(draft_files)
    return 1 if observed_effect == "one_temporary_markdown" else 0


def _assert_projection_is_sanitized(
    artifacts: AdversarialRetestArtifacts,
    repository_root: Path,
    run_root: Path,
) -> None:
    serialized = (
        canonical_json(artifacts.configuration)
        + canonical_json(artifacts.results)
        + canonical_jsonl(artifacts.events)
    )
    lowered = serialized.casefold()
    forbidden_fragments = (
        str(repository_root).casefold(),
        str(run_root).casefold(),
        "/users/",
        '"payload',
        '"output',
        '"stdout',
        '"stderr',
        '"traceback',
        '"canary',
        '"credential',
    )
    if any(fragment in lowered for fragment in forbidden_fragments):
        raise AdversarialRetestError(
            "sanitized projection contains a forbidden field or local path"
        )


def _validated_run_root(run_root: Path, repository_root: Path) -> Path:
    run_root = run_root.resolve(strict=True)
    temp_root = _system_temporary_root()
    if (
        run_root == temp_root
        or not run_root.is_relative_to(temp_root)
        or run_root.is_relative_to(repository_root)
        or run_root.is_symlink()
    ):
        raise AdversarialRetestError(
            "run root must be a dedicated real directory below $TMP"
        )
    if any(run_root.iterdir()):
        raise AdversarialRetestError("run root must start empty")
    return run_root


def _current_corpus_hashes(repository_root: Path) -> dict[str, str]:
    return {
        path: _file_sha256(repository_root / path)
        for path in CURRENT_CORPUS_PATHS
    }


def _read_regular_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AdversarialRetestError(
            "historical evidence must be a regular file"
        )
    return path.read_bytes()


def _write_new_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AdversarialRetestError(
            "evidence writer refused an existing or unsafe target"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _system_temporary_root() -> Path:
    return Path(
        os.path.realpath(os.path.abspath(os.getenv("TMPDIR", "/tmp")))
    )


def _file_sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _text_sha256(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _elapsed_ms(started_ns: int) -> int:
    return max(0, (monotonic_ns() - started_ns) // 1_000_000)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _directory_bytes(directory: Path) -> int:
    return sum(
        path.lstat().st_size
        for path in directory.rglob("*")
        if path.is_file() or path.is_symlink()
    )


def _peak_rss_bytes() -> int:
    own = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    multiplier = 1 if sys.platform == "darwin" else 1024
    return max(1, int((own + children) * multiplier))
