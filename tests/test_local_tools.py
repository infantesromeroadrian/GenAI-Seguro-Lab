"""Pruebas de mínimo privilegio de las herramientas locales."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

import genai_seguro_lab.local_tools as local_tools
from genai_seguro_lab.data_contract import (
    DatasetBundle,
    IncidentRecord,
    load_dataset,
)
from genai_seguro_lab.local_tools import (
    DraftAlreadyExistsError,
    DraftConfirmation,
    DraftConfirmationError,
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


def _writer(drafts_dir: Path, *, scope: str = "draft:test") -> DraftWriterTool:
    return DraftWriterTool(
        drafts_dir,
        principal="draft-caller",
        scope=scope,
        allowed_knowledge_ids=("KB-001",),
    )


def _prepare(writer: DraftWriterTool, request: ModelToolRequest) -> DraftProposal:
    return writer.prepare(request, grant=writer.prepare_grant)


def _effect_grant(
    writer: DraftWriterTool,
    proposal: DraftProposal,
) -> DraftEffectGrant:
    return writer.authorize_effect(
        proposal,
        DraftConfirmation(
            proposal_fingerprint=proposal.proposal_fingerprint,
            confirmed_by_user=True,
        ),
    )


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
        allowed_knowledge_ids=("KB-002",),
    )

    with pytest.raises(ToolDeniedError, match="authorized scope"):
        _prepare(writer, _draft_request())


def test_explicit_effect_grant_creates_once_with_owner_only_mode(
    drafts_dir: Path,
) -> None:
    writer = _writer(drafts_dir)
    proposal = _prepare(writer, _draft_request())

    wrong = DraftConfirmation(
        proposal_fingerprint="0" * 64,
        confirmed_by_user=True,
    )
    with pytest.raises(DraftConfirmationError, match="does not match"):
        writer.authorize_effect(proposal, wrong)
    assert list(drafts_dir.iterdir()) == []

    effect_grant = _effect_grant(writer, proposal)
    assert effect_grant.effect == "create"
    assert effect_grant.tool == "draft_create"
    assert effect_grant.human_identity_authenticated is False
    assert effect_grant.residual_control == "PGS-04-M04"

    result = writer.create(proposal, effect_grant)
    target = drafts_dir / proposal.filename
    assert result.relative_path == "sandbox/drafts/resumen-incidente.md"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text(encoding="utf-8").startswith(
        "# Resumen de incidente\n\n"
    )

    with pytest.raises(DraftConfirmationError, match="already consumed"):
        writer.create(proposal, effect_grant)

    changed = _prepare(
        writer,
        _draft_request(body="Contenido distinto para el mismo destino."),
    )
    with pytest.raises(DraftAlreadyExistsError, match="overwrite is forbidden"):
        writer.create(changed, _effect_grant(writer, changed))


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

    with pytest.raises(ToolPolicyError, match="issued by the writer"):
        DraftEffectGrant(
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
