"""Contrato focal del journal y sus integraciones de seguridad."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

from genai_seguro_lab.baseline import run_functional_baseline
from genai_seguro_lab.benign_flow import BenignAnalysisFlow, BenignFlowError
from genai_seguro_lab.data_contract import load_dataset
from genai_seguro_lab.local_tools import (
    DraftApprovalAuthority,
    DraftApprovalError,
    DraftWriterTool,
    KnowledgeCatalog,
    SandboxViolationError,
    ToolDeniedError,
)
from genai_seguro_lab.model_adapter import (
    DeterministicModelAdapter,
    ModelDescriptor,
    ModelRequest,
    ModelResponse,
    ModelToolRequest,
    ScriptedExchange,
    UnknownModelRequestError,
)
from genai_seguro_lab.output_policy import (
    OutputPolicy,
    OutputPolicyRejectedError,
)
from genai_seguro_lab.resource_control import (
    ProductResourceControl,
    ResourceLimitError,
    ResourceLockError,
    exclusive_process_lock,
)
from genai_seguro_lab.security_events import (
    MAX_SECURITY_EVENT_BYTES,
    SECURITY_EVENTS_ID,
    SECURITY_EVENTS_VERSION,
    SecurityEvent,
    SecurityEventJournal,
    SecurityEventLimitError,
    SecurityEventReport,
    canonical_security_event_json,
    canonical_security_report_json,
    verify_security_event_chain,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
ENTRYPOINT = ROOT / "main.py"
BASELINE = ROOT / "evaluations" / "benign-baseline-v1.json"
IDENTITY = "synthetic-approver"
CREDENTIAL = "synthetic-credential"
CANARIES = (
    "CANARY_GSL_SECURITY_EVENT",
    "synthetic-secret@example.invalid",
    "/Users/synthetic/private.txt",
    "Authorization: Bearer synthetic-token",
)


def _constant_token(value: int):
    return lambda size: bytes([value]) * size


def _draft_request(
    *,
    filename: str = "security-event-test.md",
    title: str = "Resumen",
    body: str = "Contenido sintético.",
) -> ModelToolRequest:
    return ModelToolRequest(
        request_id="CALL-SECURITY-EVENT-DRAFT",
        name="draft_create",
        arguments_json=json.dumps(
            {
                "body": body,
                "filename": filename,
                "references": ["KB-001"],
                "title": title,
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _draft_components(
    tmp_path: Path,
) -> tuple[DraftApprovalAuthority, DraftWriterTool]:
    drafts = tmp_path / "sandbox" / "drafts"
    drafts.mkdir(parents=True)
    control = ProductResourceControl("draft", clock=lambda: 0.0)
    authority = DraftApprovalAuthority(
        configured_identity=IDENTITY,
        credential=CREDENTIAL,
        clock=lambda: 0.0,
    )
    writer = DraftWriterTool(
        drafts.resolve(),
        principal="security-event-test",
        scope="draft:security-event-test",
        approval_authority=authority,
        output_policy=OutputPolicy(),
        allowed_knowledge_ids=("KB-001",),
        resource_control=control,
    )
    return authority, writer


def _signals(report: SecurityEventReport) -> list[str]:
    return [
        event.signal
        for event in report.events
        if event.signal is not None
    ]


def _run_entrypoint(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        (sys.executable, str(ENTRYPOINT), *arguments),
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_event_and_report_are_closed_frozen_and_canonically_chained() -> None:
    journal = SecurityEventJournal(
        "analyze",
        clock=lambda: 10.0,
        token_bytes=_constant_token(1),
    )
    journal.observe(
        kind="model_request",
        source="model_adapter",
        outcome="observed",
    )
    journal.finish(succeeded=True)
    report = journal.report()

    assert report.control_id == SECURITY_EVENTS_ID
    assert report.version == SECURITY_EVENTS_VERSION
    assert tuple(event.sequence for event in report.events) == (1, 2, 3)
    assert all(
        len(canonical_security_event_json(event).encode("utf-8"))
        <= MAX_SECURITY_EVENT_BYTES
        for event in report.events
    )
    verify_security_event_chain(report.events)
    assert SecurityEventReport.model_validate_json(
        canonical_security_report_json(report)
    ) == report

    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(
            {
                **report.events[0].model_dump(),
                "prompt": "forbidden",
            }
        )
    with pytest.raises(ValidationError):
        report.events[0].outcome = "failed"  # type: ignore[misc]


def test_global_sequence_and_hash_chain_remain_contiguous_under_concurrency() -> None:
    journal = SecurityEventJournal(
        "baseline",
        clock=lambda: 0.0,
        token_bytes=_constant_token(2),
    )

    def append(_: int) -> None:
        journal.observe(
            kind="model_request",
            source="model_adapter",
            outcome="observed",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        tuple(executor.map(append, range(100)))
    journal.finish(succeeded=True)

    report = journal.report()
    assert tuple(event.sequence for event in report.events) == tuple(
        range(1, 103)
    )
    verify_security_event_chain(report.events)


def test_event_count_limit_accepts_exact_boundary_and_rejects_plus_one() -> None:
    journal = SecurityEventJournal(
        "analyze",
        clock=lambda: 0.0,
        token_bytes=_constant_token(3),
    )
    for _ in range(30):
        journal.observe(
            kind="model_request",
            source="model_adapter",
            outcome="observed",
        )

    with pytest.raises(SecurityEventLimitError):
        journal.observe(
            kind="model_request",
            source="model_adapter",
            outcome="observed",
        )

    journal.finish(succeeded=True)
    assert journal.report().events_count == 32


def test_authentication_failures_are_correlated_and_signal_exactly_third() -> None:
    tokens = iter((bytes([4]) * 16, bytes([5]) * 16))
    journal = SecurityEventJournal(
        "draft",
        clock=lambda: 0.0,
        token_bytes=lambda size: next(tokens),
    )
    other = journal.new_correlation()

    assert journal.authentication_failed() is None
    assert journal.authentication_failed() is None
    assert journal.authentication_failed(correlation=other) is None
    assert journal.authentication_failed() is not None
    assert journal.authentication_failed() is None
    assert journal.authentication_failed(correlation=other) is None
    assert journal.authentication_failed(correlation=other) is not None

    events = [
        event
        for event in journal.events
        if event.signal == "authentication_failures_repeated"
    ]
    assert len(events) == 2
    assert events[0].correlation_id != events[1].correlation_id


def test_resource_and_lock_failures_emit_sanitized_signals(
    tmp_path: Path,
) -> None:
    resource_journal = SecurityEventJournal(
        "analyze",
        clock=lambda: 0.0,
        token_bytes=_constant_token(6),
    )
    control = ProductResourceControl(
        "analyze",
        clock=lambda: 0.0,
        security_journal=resource_journal,
    )
    control.begin_case()
    with pytest.raises(ResourceLimitError):
        control.begin_case()
    assert "resource_limit_exceeded" in _signals(resource_journal.report())

    target = tmp_path / "manifest.json"
    target.write_text("{}", encoding="utf-8")
    lock_journal = SecurityEventJournal(
        "analyze",
        clock=lambda: 0.0,
        token_bytes=_constant_token(7),
    )
    with target.open() as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ResourceLockError):
            with exclusive_process_lock(
                target,
                security_journal=lock_journal,
            ):
                raise AssertionError("conflicting lock must not be acquired")
    assert "lock_conflict" in _signals(lock_journal.report())


def test_knowledge_denial_emits_signal_without_request_content() -> None:
    bundle = load_dataset(DATA_DIR)
    journal = SecurityEventJournal(
        "analyze",
        clock=lambda: 0.0,
        token_bytes=_constant_token(8),
    )
    incident = bundle.incidents[0]
    tool = KnowledgeCatalog(bundle.knowledge).for_incident(
        incident,
        principal="security-event-test",
        scope=f"incident:{incident.id}",
        security_journal=journal,
    )
    request = ModelToolRequest(
        request_id="CALL-DENIED",
        name="draft_create",
        arguments_json=json.dumps(
            {
                "body": CANARIES[0],
                "filename": "denied.md",
                "references": [],
                "title": "Denied",
            }
        ),
    )

    with pytest.raises(ToolDeniedError):
        tool.search(request, grant=tool.execution_grant)

    serialized = canonical_security_report_json(journal.report())
    assert "tool_denied" in serialized
    assert CANARIES[0] not in serialized


def test_flow_derives_sequence_and_unknown_request_signals() -> None:
    bundle = load_dataset(DATA_DIR)
    incident = bundle.incidents[0]
    initial = BenignAnalysisFlow.build_initial_request(incident)
    sequence_journal = SecurityEventJournal(
        "analyze",
        clock=lambda: 0.0,
        token_bytes=_constant_token(10),
    )
    sequence_flow = BenignAnalysisFlow(
        DeterministicModelAdapter(
            (
                ScriptedExchange(
                    request=initial,
                    response=ModelResponse(
                        finish_reason="stop",
                        output_text="Secuencia sintética no permitida.",
                    ),
                ),
            )
        ),
        KnowledgeCatalog(bundle.knowledge),
        output_policy=OutputPolicy(),
    )
    with pytest.raises(BenignFlowError):
        sequence_flow.analyze(
            incident,
            resource_control=ProductResourceControl(
                "analyze",
                clock=lambda: 0.0,
                security_journal=sequence_journal,
            ),
        )
    assert "unexpected_flow_sequence" in _signals(
        sequence_journal.report()
    )

    class UnknownAdapter:
        descriptor = ModelDescriptor()

        def generate(self, request: ModelRequest):
            raise UnknownModelRequestError("synthetic miss")

    unknown_journal = SecurityEventJournal(
        "analyze",
        clock=lambda: 0.0,
        token_bytes=_constant_token(11),
    )
    unknown_flow = BenignAnalysisFlow(
        UnknownAdapter(),
        KnowledgeCatalog(bundle.knowledge),
        output_policy=OutputPolicy(),
    )
    with pytest.raises(UnknownModelRequestError):
        unknown_flow.analyze(
            incident,
            resource_control=ProductResourceControl(
                "analyze",
                clock=lambda: 0.0,
                security_journal=unknown_journal,
            ),
        )
    assert "unknown_model_request" in _signals(unknown_journal.report())
    assert "synthetic miss" not in canonical_security_report_json(
        unknown_journal.report()
    )


def test_output_policy_and_auth_replay_signals_contain_no_canaries(
    tmp_path: Path,
) -> None:
    authority, writer = _draft_components(tmp_path)
    try:
        with pytest.raises(OutputPolicyRejectedError):
            writer.prepare(
                _draft_request(body="CANARY_GSL_EX_003"),
                grant=writer.prepare_grant,
            )

        proposal = writer.prepare(
            _draft_request(filename="approved.md"),
            grant=writer.prepare_grant,
        )
        challenge = writer.issue_approval_challenge(proposal)
        for _ in range(3):
            with pytest.raises(DraftApprovalError):
                authority.approve(
                    challenge,
                    identity=IDENTITY,
                    credential="wrong-credential",
                )

        report = writer.resource_control.security_journal.report()
        assert _signals(report).count("output_policy_intervention") == 1
        assert _signals(report).count(
            "authentication_failures_repeated"
        ) == 1
        serialized = canonical_security_report_json(report)
        assert "CANARY_GSL_EX_003" not in serialized
        assert "wrong-credential" not in serialized
        assert IDENTITY not in serialized
    finally:
        writer.close()
        authority.close()


def test_authorization_replay_is_signalled_without_identity(
    tmp_path: Path,
) -> None:
    authority, writer = _draft_components(tmp_path)
    try:
        proposal = writer.prepare(
            _draft_request(filename="replay.md"),
            grant=writer.prepare_grant,
        )
        challenge = writer.issue_approval_challenge(proposal)
        authority.approve(
            challenge,
            identity=IDENTITY,
            credential=CREDENTIAL,
        )

        with pytest.raises(DraftApprovalError):
            authority.approve(
                challenge,
                identity=IDENTITY,
                credential=CREDENTIAL,
            )

        serialized = canonical_security_report_json(
            writer.resource_control.security_journal.report()
        )
        assert "authorization_replay_or_context_mismatch" in serialized
        assert IDENTITY not in serialized
        assert CREDENTIAL not in serialized
    finally:
        writer.close()
        authority.close()


def test_sandbox_violation_is_signalled_without_local_path(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    target = tmp_path / "outside"
    sandbox.mkdir()
    target.mkdir()
    drafts = sandbox / "drafts"
    drafts.symlink_to(target, target_is_directory=True)
    control = ProductResourceControl("draft", clock=lambda: 0.0)
    authority = DraftApprovalAuthority(
        configured_identity=IDENTITY,
        credential=CREDENTIAL,
    )
    try:
        with pytest.raises(SandboxViolationError):
            DraftWriterTool(
                drafts.absolute(),
                principal="security-event-test",
                scope="draft:security-event-test",
                approval_authority=authority,
                output_policy=OutputPolicy(),
                resource_control=control,
            )
        serialized = canonical_security_report_json(
            control.security_journal.report()
        )
        assert "sandbox_violation" in serialized
        assert str(tmp_path) not in serialized
    finally:
        authority.close()


def test_draft_event_pair_is_reserved_before_io_and_fails_closed(
    tmp_path: Path,
) -> None:
    authority, writer = _draft_components(tmp_path)
    target = tmp_path / "sandbox" / "drafts" / "no-effect.md"
    try:
        proposal = writer.prepare(
            _draft_request(filename=target.name),
            grant=writer.prepare_grant,
        )
        challenge = writer.issue_approval_challenge(proposal)
        approval = authority.approve(
            challenge,
            identity=IDENTITY,
            credential=CREDENTIAL,
        )
        effect_grant = writer.authorize_effect(proposal, approval)
        journal = writer.resource_control.security_journal
        while len(journal.events) < 30:
            journal.observe(
                kind="model_request",
                source="model_adapter",
                outcome="observed",
            )

        with pytest.raises(SecurityEventLimitError):
            writer.create(proposal, effect_grant)

        assert not target.exists()
        assert writer.resource_control.usage.draft_files == 0
        assert all(
            event.kind not in {"effect_attempted", "effect_succeeded"}
            for event in journal.events
        )
    finally:
        writer.close()
        authority.close()


def test_successful_draft_records_attempt_and_result_before_return(
    tmp_path: Path,
) -> None:
    authority, writer = _draft_components(tmp_path)
    try:
        proposal = writer.prepare(
            _draft_request(filename="created.md"),
            grant=writer.prepare_grant,
        )
        challenge = writer.issue_approval_challenge(proposal)
        approval = authority.approve(
            challenge,
            identity=IDENTITY,
            credential=CREDENTIAL,
        )
        effect_grant = writer.authorize_effect(proposal, approval)

        result = writer.create(proposal, effect_grant)

        assert result.created is True
        assert [event.kind for event in writer.resource_control.security_journal.events][
            -2:
        ] == ["effect_attempted", "effect_succeeded"]
    finally:
        writer.close()
        authority.close()


def test_data_integrity_failure_is_signalled_without_path_or_exception(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    shutil.copytree(DATA_DIR, data_dir)
    (data_dir / "manifest.json").write_text("{", encoding="utf-8")
    journal = SecurityEventJournal(
        "baseline",
        clock=lambda: 0.0,
        token_bytes=_constant_token(9),
    )

    with pytest.raises(ValueError):
        run_functional_baseline(
            data_dir,
            clock=lambda: 0.0,
            security_journal=journal,
        )

    serialized = canonical_security_report_json(journal.report())
    assert "data_integrity_violation" in serialized
    assert str(data_dir) not in serialized
    assert "JSON" not in serialized


def test_baseline_uses_one_opaque_child_correlation_per_case() -> None:
    token_counter = 0

    def next_token(size: int) -> bytes:
        nonlocal token_counter
        token_counter += 1
        return token_counter.to_bytes(size, "big")

    journal = SecurityEventJournal(
        "baseline",
        clock=lambda: 0.0,
        token_bytes=next_token,
    )

    run_functional_baseline(
        DATA_DIR,
        clock=lambda: 0.0,
        security_journal=journal,
    )

    report = journal.report()
    primary = report.events[0].correlation_id
    assert report.events_count == 88
    assert report.correlations_count == 13
    assert [
        event.kind
        for event in report.events
        if event.correlation_id == primary
    ] == ["operation_started", "operation_completed"]

    child_blocks: list[tuple[str, tuple[int, ...]]] = []
    for correlation_id in dict.fromkeys(
        event.correlation_id for event in report.events
    ):
        if correlation_id == primary:
            continue
        sequences = tuple(
            event.sequence
            for event in report.events
            if event.correlation_id == correlation_id
        )
        child_blocks.append((correlation_id, sequences))

    assert len(child_blocks) == 12
    assert len({correlation for correlation, _ in child_blocks}) == 12
    assert sorted(len(sequences) for _, sequences in child_blocks) == [
        *([7] * 10),
        8,
        8,
    ]
    assert all(
        sequences
        == tuple(range(sequences[0], sequences[0] + len(sequences)))
        for _, sequences in child_blocks
    )
    assert all(
        set(left_sequences).isdisjoint(right_sequences)
        for index, (_, left_sequences) in enumerate(child_blocks)
        for _, right_sequences in child_blocks[index + 1 :]
    )
    interventions = tuple(
        event for event in report.events if event.kind == "security_signal"
    )
    assert len(interventions) == 2
    assert all(
        event.source == "output_policy"
        and event.outcome == "intervened"
        and event.signal == "output_policy_intervention"
        for event in interventions
    )
    serialized = canonical_security_report_json(report)
    bundle = load_dataset(DATA_DIR)
    assert all(incident.id not in serialized for incident in bundle.incidents)


def test_cli_default_is_byte_identical_and_opt_in_is_sanitized_envelope() -> None:
    default = _run_entrypoint("baseline")
    opt_in = _run_entrypoint("baseline", "--security-report")

    assert default.returncode == opt_in.returncode == 0
    assert default.stderr == opt_in.stderr == ""
    assert default.stdout != BASELINE.read_text(encoding="utf-8")
    assert json.loads(default.stdout)["baseline_id"] == (
        "GSL-CORRECTION-CANDIDATE-BENIGN-001"
    )
    assert json.loads(BASELINE.read_text(encoding="utf-8"))[
        "baseline_id"
    ] == "GSL-BASELINE-BENIGN-001"

    envelope = json.loads(opt_in.stdout)
    assert set(envelope) == {"result", "security_report"}
    assert envelope["result"] == json.loads(default.stdout)
    report = SecurityEventReport.model_validate_json(
        json.dumps(envelope["security_report"])
    )
    assert report.profile == "baseline"
    assert report.events_count == 88
    assert report.correlations_count == 13
    assert report.events[-1].kind == "operation_completed"
    assert all(canary not in opt_in.stdout for canary in CANARIES)

    analyze = _run_entrypoint(
        "analyze",
        "--incident",
        "INC-BEN-001",
        "--security-report",
    )
    analyze_report = SecurityEventReport.model_validate_json(
        json.dumps(json.loads(analyze.stdout)["security_report"])
    )
    assert analyze.returncode == 0
    assert analyze_report.correlations_count == 1
