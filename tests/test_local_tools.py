"""Pruebas de mínimo privilegio de las herramientas locales."""

from __future__ import annotations

import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

import genai_seguro_lab.local_tools as local_tools
from genai_seguro_lab.data_contract import (
    DatasetBundle,
    IncidentRecord,
    load_dataset,
)
from genai_seguro_lab.local_tools import (
    DraftApproval,
    DraftApprovalAuthority,
    DraftApprovalChallenge,
    DraftApprovalError,
    DraftAlreadyExistsError,
    DraftEffectGrant,
    DraftProposal,
    DraftProposalError,
    DraftWriterTool,
    KnowledgeCatalog,
    KnowledgeSearchTool,
    SandboxViolationError,
    ToolArgumentsError,
    ToolDeniedError,
    ToolExecutionGrant,
    ToolPolicyError,
)
from genai_seguro_lab.model_adapter import ModelToolRequest

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
SYNTHETIC_IDENTITY = "synthetic-operator"
SYNTHETIC_CREDENTIAL = "synthetic-test-credential-not-a-real-secret"


@pytest.fixture(scope="module")
def dataset() -> DatasetBundle:
    return load_dataset(DATA_DIR)


@pytest.fixture(scope="module")
def incident(dataset: DatasetBundle) -> IncidentRecord:
    return dataset.incidents[0]


@pytest.fixture
def knowledge_tool(
    dataset: DatasetBundle,
    incident: IncidentRecord,
) -> KnowledgeSearchTool:
    return KnowledgeCatalog(dataset.knowledge).for_incident(
        incident,
        principal="benign-flow",
        scope=f"incident:{incident.id}",
    )


@pytest.fixture
def drafts_dir(tmp_path: Path) -> Path:
    path = tmp_path / "sandbox" / "drafts"
    path.mkdir(parents=True)
    return path


def _tool_request(
    *,
    name: str,
    arguments: dict[str, object],
    request_id: str = "CALL-001",
) -> ModelToolRequest:
    return ModelToolRequest(
        request_id=request_id,
        name=name,
        arguments_json=json.dumps(
            arguments,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _draft_request(
    *,
    filename: str = "resumen-incidente.md",
    body: str = "Borrador sintético sin acciones ejecutadas.",
    extra: dict[str, object] | None = None,
) -> ModelToolRequest:
    arguments: dict[str, object] = {
        "filename": filename,
        "title": "Resumen de incidente",
        "body": body,
        "references": ["KB-001"],
    }
    if extra:
        arguments.update(extra)
    return _tool_request(name="draft_create", arguments=arguments)


def _authority(
    *,
    ttl: float = 30.0,
    clock: object | None = None,
) -> DraftApprovalAuthority:
    arguments: dict[str, object] = {
        "configured_identity": SYNTHETIC_IDENTITY,
        "credential": SYNTHETIC_CREDENTIAL,
        "approval_ttl_seconds": ttl,
    }
    if clock is not None:
        arguments["clock"] = clock
    return DraftApprovalAuthority(**arguments)  # type: ignore[arg-type]


def _writer(
    drafts_dir: Path,
    *,
    scope: str = "draft:test",
    principal: str = "draft-caller",
    authority: DraftApprovalAuthority | None = None,
) -> DraftWriterTool:
    return DraftWriterTool(
        drafts_dir,
        principal=principal,
        scope=scope,
        approval_authority=authority or _authority(),
        allowed_knowledge_ids=("KB-001",),
    )


def _prepare(writer: DraftWriterTool, request: ModelToolRequest) -> DraftProposal:
    return writer.prepare(request, grant=writer.prepare_grant)


def _effect_grant(
    writer: DraftWriterTool,
    proposal: DraftProposal,
) -> DraftEffectGrant:
    challenge = writer.issue_approval_challenge(proposal)
    approval = writer._approval_authority.approve(
        challenge,
        identity=SYNTHETIC_IDENTITY,
        credential=SYNTHETIC_CREDENTIAL,
    )
    return writer.authorize_effect(proposal, approval)


def test_knowledge_tool_physically_retains_only_incident_records(
    knowledge_tool: KnowledgeSearchTool,
    incident: IncidentRecord,
    dataset: DatasetBundle,
) -> None:
    assert knowledge_tool.retained_knowledge_ids == incident.knowledge_refs
    assert len(knowledge_tool.retained_knowledge_ids) < len(dataset.knowledge)
    assert knowledge_tool.execution_grant.tool == "knowledge_search"
    assert knowledge_tool.execution_grant.allowed_knowledge_ids == (
        incident.knowledge_refs
    )


def test_knowledge_search_only_returns_incident_records(
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    request = _tool_request(
        name="knowledge_search",
        arguments={
            "query": "phishing",
            "knowledge_ids": ["KB-001"],
            "limit": 1,
        },
    )

    result = knowledge_tool.search(
        request,
        grant=knowledge_tool.execution_grant,
    )

    assert [hit.id for hit in result.hits] == ["KB-001"]
    assert all(hit.topic == "phishing" for hit in result.hits)


def test_model_request_cannot_expand_the_knowledge_grant(
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    announced_catalog = ("knowledge_search", "draft_create")
    other_tool = _tool_request(
        name="draft_create",
        arguments={"filename": "announced-but-not-authorized.md"},
    )
    assert other_tool.name in announced_catalog
    with pytest.raises(ToolDeniedError, match="not allowed"):
        knowledge_tool.search(
            other_tool,
            grant=knowledge_tool.execution_grant,
        )

    out_of_scope = _tool_request(
        name="knowledge_search",
        arguments={
            "query": "identity",
            "knowledge_ids": ["KB-002"],
        },
    )
    with pytest.raises(ToolDeniedError, match="exceeds the incident scope"):
        knowledge_tool.search(
            out_of_scope,
            grant=knowledge_tool.execution_grant,
        )


def test_fabricated_and_foreign_grants_are_rejected(
    dataset: DatasetBundle,
    incident: IncidentRecord,
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    with pytest.raises(ToolPolicyError, match="issued by the application"):
        ToolExecutionGrant(
            principal="benign-flow",
            scope=f"incident:{incident.id}",
            tool="knowledge_search",
            allowed_knowledge_ids=incident.knowledge_refs,
        )

    foreign_principal = KnowledgeCatalog(dataset.knowledge).for_incident(
        incident,
        principal="evaluation-harness",
        scope=f"incident:{incident.id}",
    )
    request = _tool_request(
        name="knowledge_search",
        arguments={
            "query": incident.category,
            "knowledge_ids": list(incident.knowledge_refs),
        },
    )
    with pytest.raises(ToolDeniedError, match="principal and scope"):
        knowledge_tool.search(
            request,
            grant=foreign_principal.execution_grant,
        )

    other_incident = dataset.incidents[1]
    foreign_scope = KnowledgeCatalog(dataset.knowledge).for_incident(
        other_incident,
        principal="benign-flow",
        scope=f"incident:{other_incident.id}",
    )
    with pytest.raises(ToolDeniedError, match="principal and scope"):
        knowledge_tool.search(
            request,
            grant=foreign_scope.execution_grant,
        )


def test_catalog_rejects_a_scope_not_bound_to_the_validated_incident(
    dataset: DatasetBundle,
    incident: IncidentRecord,
) -> None:
    with pytest.raises(ToolPolicyError, match="validated incident"):
        KnowledgeCatalog(dataset.knowledge).for_incident(
            incident,
            principal="benign-flow",
            scope="incident:INC-999",
        )


def test_knowledge_search_rejects_invalid_arguments(
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    request = _tool_request(
        name="knowledge_search",
        arguments={
            "query": "phishing",
            "knowledge_ids": ["KB-001"],
            "limit": 99,
        },
    )

    with pytest.raises(ToolArgumentsError, match="were rejected"):
        knowledge_tool.search(
            request,
            grant=knowledge_tool.execution_grant,
        )


def test_model_can_only_prepare_a_draft_without_effect(
    drafts_dir: Path,
) -> None:
    writer = _writer(drafts_dir)
    proposal = _prepare(writer, _draft_request())

    assert proposal.filename == "resumen-incidente.md"
    assert writer.prepare_grant.tool == "draft_create"
    assert list(drafts_dir.iterdir()) == []

    self_confirmed = _draft_request(extra={"confirmed_by_user": True})
    with pytest.raises(ToolArgumentsError, match="were rejected"):
        _prepare(writer, self_confirmed)
    assert list(drafts_dir.iterdir()) == []


def test_draft_writer_rejects_references_outside_grant(
    drafts_dir: Path,
) -> None:
    writer = DraftWriterTool(
        drafts_dir,
        principal="draft-caller",
        scope="draft:test",
        approval_authority=_authority(),
        allowed_knowledge_ids=("KB-002",),
    )

    with pytest.raises(ToolDeniedError, match="authorized scope"):
        _prepare(writer, _draft_request())


def test_explicit_effect_grant_creates_once_with_owner_only_mode(
    drafts_dir: Path,
) -> None:
    writer = _writer(drafts_dir)
    proposal = _prepare(writer, _draft_request())

    challenge = writer.issue_approval_challenge(proposal)
    with pytest.raises(DraftApprovalError, match="credentials were rejected"):
        writer._approval_authority.approve(
            challenge,
            identity=SYNTHETIC_IDENTITY,
            credential="wrong-synthetic-credential",
        )
    with pytest.raises(DraftApprovalError, match="credentials were rejected"):
        writer._approval_authority.approve(
            challenge,
            identity="synthetic-intruder",
            credential=SYNTHETIC_CREDENTIAL,
        )
    assert list(drafts_dir.iterdir()) == []

    approval = writer._approval_authority.approve(
        challenge,
        identity=SYNTHETIC_IDENTITY,
        credential=SYNTHETIC_CREDENTIAL,
    )
    with pytest.raises(DraftApprovalError, match="challenge was already consumed"):
        writer._approval_authority.approve(
            challenge,
            identity=SYNTHETIC_IDENTITY,
            credential=SYNTHETIC_CREDENTIAL,
        )
    effect_grant = writer.authorize_effect(proposal, approval)
    assert effect_grant.effect == "create"
    assert effect_grant.tool == "draft_create"
    assert effect_grant.approval_identity == SYNTHETIC_IDENTITY
    assert effect_grant.approval_identity_authenticated is True
    assert effect_grant.human_interaction_verified is False
    assert effect_grant.identity_assurance == "synthetic_local_credential"
    assert effect_grant.approval_control == "PGS-04-M04"

    replay_target = _prepare(
        writer,
        _draft_request(filename="approval-replay.md"),
    )
    with pytest.raises(DraftApprovalError, match="approval was already consumed"):
        writer.authorize_effect(replay_target, approval)

    result = writer.create(proposal, effect_grant)
    target = drafts_dir / proposal.filename
    assert result.relative_path == "sandbox/drafts/resumen-incidente.md"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text(encoding="utf-8").startswith(
        "# Resumen de incidente\n\n"
    )

    with pytest.raises(DraftApprovalError, match="already consumed"):
        writer.create(proposal, effect_grant)

    changed = _prepare(
        writer,
        _draft_request(body="Contenido distinto para el mismo destino."),
    )
    with pytest.raises(DraftAlreadyExistsError, match="overwrite is forbidden"):
        writer.create(changed, _effect_grant(writer, changed))
    assert tuple(path.name for path in drafts_dir.iterdir()) == (
        "resumen-incidente.md",
    )


def test_model_literals_cannot_approve_or_reach_io(
    drafts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _writer(drafts_dir)
    proposal = _prepare(writer, _draft_request())

    def unexpected_io() -> None:
        raise AssertionError("literal approval rejection must precede I/O")

    monkeypatch.setattr(writer, "_assert_root_unchanged", unexpected_io)
    fabricated_values: tuple[object, ...] = (
        True,
        {
            "proposal_fingerprint": proposal.proposal_fingerprint,
            "confirmed_by_user": True,
        },
    )
    for fabricated in fabricated_values:
        with pytest.raises(DraftApprovalError, match="opaque authority object"):
            writer.authorize_effect(
                proposal,
                fabricated,  # type: ignore[arg-type]
            )
    assert list(drafts_dir.iterdir()) == []


def test_credential_is_absent_from_opaque_repr_and_serialization(
    drafts_dir: Path,
) -> None:
    authority = _authority()
    writer = _writer(drafts_dir, authority=authority)
    proposal = _prepare(writer, _draft_request())
    challenge = writer.issue_approval_challenge(proposal)
    approval = authority.approve(
        challenge,
        identity=SYNTHETIC_IDENTITY,
        credential=SYNTHETIC_CREDENTIAL,
    )
    effect_grant = writer.authorize_effect(proposal, approval)

    rendered = "\n".join(
        repr(value)
        for value in (authority, challenge, approval, effect_grant)
    )
    assert SYNTHETIC_CREDENTIAL not in rendered
    with pytest.raises(TypeError):
        vars(authority)
    with pytest.raises(TypeError):
        json.dumps(challenge)
    with pytest.raises(TypeError):
        json.dumps(approval)
    serialized_grant_metadata = json.dumps(
        {
            "approval_identity": effect_grant.approval_identity,
            "principal": effect_grant.principal,
            "scope": effect_grant.scope,
            "tool": effect_grant.tool,
            "effect": effect_grant.effect,
        },
        sort_keys=True,
    )
    assert SYNTHETIC_CREDENTIAL not in serialized_grant_metadata


def test_approval_is_bound_to_proposal_writer_root_scope_and_sessions(
    drafts_dir: Path,
    tmp_path: Path,
) -> None:
    authority = _authority()
    writer = _writer(
        drafts_dir,
        scope="draft:bound",
        principal="draft-caller",
        authority=authority,
    )
    proposal = _prepare(writer, _draft_request())
    other_proposal = _prepare(
        writer,
        _draft_request(
            filename="other-proposal.md",
            body="Una propuesta sintética diferente.",
        ),
    )
    challenge = writer.issue_approval_challenge(proposal)
    approval = authority.approve(
        challenge,
        identity=SYNTHETIC_IDENTITY,
        credential=SYNTHETIC_CREDENTIAL,
    )

    with pytest.raises(DraftApprovalError, match="exact effect context"):
        writer.authorize_effect(other_proposal, approval)

    same_context_writer = _writer(
        drafts_dir,
        scope="draft:bound",
        principal="draft-caller",
        authority=authority,
    )
    same_context_proposal = _prepare(
        same_context_writer,
        _draft_request(filename="same-context.md"),
    )
    with pytest.raises(DraftApprovalError, match="exact effect context"):
        same_context_writer.authorize_effect(same_context_proposal, approval)

    foreign_scope_writer = _writer(
        drafts_dir,
        scope="draft:foreign",
        principal="draft-caller",
        authority=authority,
    )
    foreign_scope_proposal = _prepare(
        foreign_scope_writer,
        _draft_request(filename="foreign-scope.md"),
    )
    with pytest.raises(DraftApprovalError, match="exact effect context"):
        foreign_scope_writer.authorize_effect(
            foreign_scope_proposal,
            approval,
        )

    foreign_principal_writer = _writer(
        drafts_dir,
        scope="draft:bound",
        principal="other-caller",
        authority=authority,
    )
    foreign_principal_proposal = _prepare(
        foreign_principal_writer,
        _draft_request(filename="foreign-principal.md"),
    )
    with pytest.raises(DraftApprovalError, match="exact effect context"):
        foreign_principal_writer.authorize_effect(
            foreign_principal_proposal,
            approval,
        )

    other_root = tmp_path / "other" / "sandbox" / "drafts"
    other_root.mkdir(parents=True)
    foreign_root_writer = _writer(
        other_root,
        scope="draft:bound",
        principal="draft-caller",
        authority=authority,
    )
    foreign_root_proposal = _prepare(
        foreign_root_writer,
        _draft_request(filename="foreign-root.md"),
    )
    with pytest.raises(DraftApprovalError, match="exact effect context"):
        foreign_root_writer.authorize_effect(
            foreign_root_proposal,
            approval,
        )

    foreign_authority = _authority()
    with pytest.raises(DraftApprovalError, match="authority session"):
        foreign_authority.approve(
            challenge,
            identity=SYNTHETIC_IDENTITY,
            credential=SYNTHETIC_CREDENTIAL,
        )

    effect_grant = writer.authorize_effect(proposal, approval)
    assert effect_grant._proposal is proposal
    assert effect_grant.proposal_fingerprint == proposal.proposal_fingerprint
    assert list(drafts_dir.iterdir()) == []
    assert list(other_root.iterdir()) == []


def test_challenge_approval_and_grant_expiry_fail_before_io(
    drafts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    authority = _authority(ttl=1.0, clock=lambda: now[0])
    writer = _writer(drafts_dir, authority=authority)

    expired_challenge_proposal = _prepare(
        writer,
        _draft_request(filename="expired-challenge.md"),
    )
    expired_challenge = writer.issue_approval_challenge(
        expired_challenge_proposal
    )
    now[0] = 1.0
    with pytest.raises(DraftApprovalError, match="challenge expired"):
        authority.approve(
            expired_challenge,
            identity=SYNTHETIC_IDENTITY,
            credential=SYNTHETIC_CREDENTIAL,
        )

    expired_approval_proposal = _prepare(
        writer,
        _draft_request(filename="expired-approval.md"),
    )
    approval_challenge = writer.issue_approval_challenge(
        expired_approval_proposal
    )
    approval = authority.approve(
        approval_challenge,
        identity=SYNTHETIC_IDENTITY,
        credential=SYNTHETIC_CREDENTIAL,
    )
    now[0] = 2.0
    with pytest.raises(DraftApprovalError, match="approval expired"):
        writer.authorize_effect(expired_approval_proposal, approval)

    expired_grant_proposal = _prepare(
        writer,
        _draft_request(filename="expired-grant.md"),
    )
    effect_grant = _effect_grant(writer, expired_grant_proposal)
    now[0] = 3.0

    def unexpected_io() -> None:
        raise AssertionError("expiry rejection must precede I/O")

    monkeypatch.setattr(writer, "_assert_root_unchanged", unexpected_io)
    with pytest.raises(DraftApprovalError, match="effect grant expired"):
        writer.create(expired_grant_proposal, effect_grant)
    assert list(drafts_dir.iterdir()) == []


def test_effect_grant_is_consumed_before_io_and_not_restored(
    drafts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _writer(drafts_dir)
    proposal = _prepare(writer, _draft_request())
    effect_grant = _effect_grant(writer, proposal)

    def unavailable_root() -> None:
        raise SandboxViolationError("synthetic root failure")

    monkeypatch.setattr(writer, "_assert_root_unchanged", unavailable_root)
    with pytest.raises(SandboxViolationError, match="synthetic root failure"):
        writer.create(proposal, effect_grant)
    with pytest.raises(DraftApprovalError, match="already consumed"):
        writer.create(proposal, effect_grant)
    assert list(drafts_dir.iterdir()) == []


def test_concurrent_consumers_create_at_most_one_effect(
    drafts_dir: Path,
) -> None:
    writer = _writer(drafts_dir)
    proposal = _prepare(writer, _draft_request())
    effect_grant = _effect_grant(writer, proposal)
    barrier = Barrier(2)

    def consume() -> str:
        barrier.wait(timeout=5)
        try:
            writer.create(proposal, effect_grant)
        except DraftApprovalError:
            return "rejected"
        return "created"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: consume(), range(2)))

    assert sorted(outcomes) == ["created", "rejected"]
    assert tuple(path.name for path in drafts_dir.iterdir()) == (
        "resumen-incidente.md",
    )


def test_close_and_restart_invalidate_pending_authority_objects(
    drafts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _authority()
    writer = _writer(drafts_dir, authority=authority)
    proposal = _prepare(writer, _draft_request())
    grant = _effect_grant(writer, proposal)
    pending_proposal = _prepare(
        writer,
        _draft_request(filename="pending.md"),
    )
    pending_challenge = writer.issue_approval_challenge(pending_proposal)
    pending_approval_proposal = _prepare(
        writer,
        _draft_request(filename="pending-approval.md"),
    )
    pending_approval_challenge = writer.issue_approval_challenge(
        pending_approval_proposal
    )
    pending_approval = authority.approve(
        pending_approval_challenge,
        identity=SYNTHETIC_IDENTITY,
        credential=SYNTHETIC_CREDENTIAL,
    )
    writer.close()

    def unexpected_io() -> None:
        raise AssertionError("closed sessions must fail before I/O")

    monkeypatch.setattr(writer, "_assert_root_unchanged", unexpected_io)
    with pytest.raises(DraftApprovalError, match="writer is closed"):
        writer.create(proposal, grant)
    with pytest.raises(DraftApprovalError, match="already consumed"):
        authority.approve(
            pending_challenge,
            identity=SYNTHETIC_IDENTITY,
            credential=SYNTHETIC_CREDENTIAL,
        )
    replacement_writer = _writer(drafts_dir, authority=authority)
    replacement_proposal = _prepare(
        replacement_writer,
        _draft_request(filename="replacement.md"),
    )
    with pytest.raises(DraftApprovalError, match="already consumed"):
        replacement_writer.authorize_effect(
            replacement_proposal,
            pending_approval,
        )
    replacement_writer.close()

    restarted_authority = _authority()
    with pytest.raises(DraftApprovalError, match="authority session"):
        restarted_authority.approve(
            pending_challenge,
            identity=SYNTHETIC_IDENTITY,
            credential=SYNTHETIC_CREDENTIAL,
        )

    restarted_writer = _writer(
        drafts_dir,
        authority=restarted_authority,
    )
    restarted_proposal = _prepare(
        restarted_writer,
        _draft_request(filename="restart.md"),
    )
    restarted_grant = _effect_grant(
        restarted_writer,
        restarted_proposal,
    )
    restarted_authority.close()
    monkeypatch.setattr(
        restarted_writer,
        "_assert_root_unchanged",
        unexpected_io,
    )
    with pytest.raises(DraftApprovalError, match="authority is closed"):
        restarted_writer.create(restarted_proposal, restarted_grant)
    assert list(drafts_dir.iterdir()) == []


def test_fabricated_proposal_and_effect_grant_fail_before_io(
    drafts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _writer(drafts_dir)
    legitimate = _prepare(writer, _draft_request())
    legitimate_effect = _effect_grant(writer, legitimate)
    fabricated = DraftProposal.model_validate(
        legitimate.model_dump(mode="python")
    )

    def unexpected_io(*_: object, **__: object) -> None:
        raise AssertionError("proposal rejection must happen before I/O")

    monkeypatch.setattr(writer, "_assert_root_unchanged", unexpected_io)
    with pytest.raises(DraftProposalError, match="not prepared"):
        writer.create(fabricated, legitimate_effect)
    assert list(drafts_dir.iterdir()) == []

    with pytest.raises(DraftApprovalError, match="issued by the authority"):
        DraftApprovalChallenge()
    with pytest.raises(DraftApprovalError, match="issued by the authority"):
        DraftApproval()
    with pytest.raises(
        ToolPolicyError,
        match="issued by the approval authority",
    ):
        DraftEffectGrant(
            approval_identity=SYNTHETIC_IDENTITY,
            principal="draft-caller",
            scope="draft:test",
            proposal_fingerprint=legitimate.proposal_fingerprint,
        )


@pytest.mark.parametrize("different_root", [False, True])
def test_proposal_from_another_instance_or_root_fails_before_io(
    drafts_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    different_root: bool,
) -> None:
    first = _writer(drafts_dir, scope="draft:first")
    proposal = _prepare(first, _draft_request())
    effect_grant = _effect_grant(first, proposal)

    if different_root:
        other_root = tmp_path / "other" / "sandbox" / "drafts"
        other_root.mkdir(parents=True)
    else:
        other_root = drafts_dir
    second = _writer(other_root, scope="draft:second")

    def unexpected_io() -> None:
        raise AssertionError("cross-instance rejection must happen before I/O")

    monkeypatch.setattr(second, "_assert_root_unchanged", unexpected_io)
    with pytest.raises(DraftProposalError, match="instance and root"):
        second.create(proposal, effect_grant)
    assert list(other_root.iterdir()) == []


def test_draft_writer_rejects_traversal_and_symlink_root(
    drafts_dir: Path,
    tmp_path: Path,
) -> None:
    writer = _writer(drafts_dir)
    traversal = _draft_request(filename="../escape.md")

    with pytest.raises(ToolArgumentsError, match="were rejected"):
        _prepare(writer, traversal)
    assert not (drafts_dir.parent.parent / "escape.md").exists()

    linked_parent = tmp_path / "linked" / "sandbox"
    linked_parent.mkdir(parents=True)
    link = linked_parent / "drafts"
    link.symlink_to(drafts_dir, target_is_directory=True)
    with pytest.raises(SandboxViolationError, match="cannot be symlinks"):
        _writer(link)


def test_draft_writer_does_not_follow_destination_symlink(
    drafts_dir: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("contenido original\n", encoding="utf-8")
    target = drafts_dir / "resumen-incidente.md"
    target.symlink_to(outside)
    writer = _writer(drafts_dir)
    proposal = _prepare(writer, _draft_request())

    with pytest.raises(DraftAlreadyExistsError, match="overwrite is forbidden"):
        writer.create(proposal, _effect_grant(writer, proposal))

    assert outside.read_text(encoding="utf-8") == "contenido original\n"


def test_directory_descriptor_prevents_path_replacement_diversion(
    drafts_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _writer(drafts_dir)
    proposal = _prepare(writer, _draft_request())
    effect_grant = _effect_grant(writer, proposal)
    real_open = os.open
    moved_sandbox = tmp_path / "anchored-sandbox"
    replacement_target = drafts_dir / proposal.filename
    raced = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal raced
        if dir_fd == writer._root_fd and path == proposal.filename:
            drafts_dir.parent.rename(moved_sandbox)
            drafts_dir.mkdir(parents=True)
            raced = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(local_tools.os, "open", racing_open)
    writer.create(proposal, effect_grant)

    assert raced is True
    assert not replacement_target.exists()
    anchored_target = moved_sandbox / "drafts" / proposal.filename
    assert anchored_target.is_file()
    assert stat.S_IMODE(anchored_target.stat().st_mode) == 0o600
