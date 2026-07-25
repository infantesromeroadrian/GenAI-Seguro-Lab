"""Pruebas de alcance y autoridad de las herramientas locales."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from genai_seguro_lab.data_contract import load_dataset
from genai_seguro_lab.local_tools import (
    DraftAlreadyExistsError,
    DraftConfirmation,
    DraftConfirmationError,
    DraftWriterTool,
    KnowledgeSearchTool,
    SandboxViolationError,
    ToolArgumentsError,
    ToolDeniedError,
)
from genai_seguro_lab.model_adapter import ModelToolRequest

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(scope="module")
def knowledge_tool() -> KnowledgeSearchTool:
    return KnowledgeSearchTool(load_dataset(DATA_DIR).knowledge)


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


def test_knowledge_search_only_returns_allowed_documents(
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

    result = knowledge_tool.search(request, allowed_ids=("KB-001",))

    assert [hit.id for hit in result.hits] == ["KB-001"]
    assert all(hit.topic == "phishing" for hit in result.hits)


def test_knowledge_search_denies_other_tools_and_out_of_scope_ids(
    knowledge_tool: KnowledgeSearchTool,
) -> None:
    other_tool = _tool_request(name="shell", arguments={"command": "whoami"})
    with pytest.raises(ToolDeniedError, match="not allowed"):
        knowledge_tool.search(other_tool, allowed_ids=("KB-001",))

    out_of_scope = _tool_request(
        name="knowledge_search",
        arguments={
            "query": "identity",
            "knowledge_ids": ["KB-002"],
        },
    )
    with pytest.raises(ToolDeniedError, match="exceeds the incident scope"):
        knowledge_tool.search(out_of_scope, allowed_ids=("KB-001",))


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
        knowledge_tool.search(request, allowed_ids=("KB-001",))


def test_model_can_only_prepare_a_draft(
    drafts_dir: Path,
) -> None:
    writer = DraftWriterTool(drafts_dir)
    proposal = writer.prepare(_draft_request())

    assert proposal.filename == "resumen-incidente.md"
    assert list(drafts_dir.iterdir()) == []

    self_confirmed = _draft_request(extra={"confirmed_by_user": True})
    with pytest.raises(ToolArgumentsError, match="were rejected"):
        writer.prepare(self_confirmed)
    assert list(drafts_dir.iterdir()) == []


def test_exact_confirmation_creates_once_without_overwrite(
    drafts_dir: Path,
) -> None:
    writer = DraftWriterTool(drafts_dir)
    proposal = writer.prepare(_draft_request())

    wrong = DraftConfirmation(
        proposal_fingerprint="0" * 64,
        confirmed_by_user=True,
    )
    with pytest.raises(DraftConfirmationError, match="does not match"):
        writer.create(proposal, wrong)
    assert list(drafts_dir.iterdir()) == []

    confirmation = DraftConfirmation(
        proposal_fingerprint=proposal.proposal_fingerprint,
        confirmed_by_user=True,
    )
    result = writer.create(proposal, confirmation)
    target = drafts_dir / proposal.filename

    assert result.relative_path == "sandbox/drafts/resumen-incidente.md"
    assert target.read_text(encoding="utf-8").startswith(
        "# Resumen de incidente\n\n"
    )
    assert "KB-001" in target.read_text(encoding="utf-8")

    with pytest.raises(DraftConfirmationError, match="already consumed"):
        writer.create(proposal, confirmation)

    changed = writer.prepare(
        _draft_request(body="Contenido distinto para el mismo destino.")
    )
    changed_confirmation = DraftConfirmation(
        proposal_fingerprint=changed.proposal_fingerprint,
        confirmed_by_user=True,
    )
    with pytest.raises(DraftAlreadyExistsError, match="overwrite is forbidden"):
        writer.create(changed, changed_confirmation)


def test_draft_writer_rejects_traversal_and_symlink_root(
    drafts_dir: Path,
    tmp_path: Path,
) -> None:
    writer = DraftWriterTool(drafts_dir)
    traversal = _draft_request(filename="../escape.md")

    with pytest.raises(ToolArgumentsError, match="were rejected"):
        writer.prepare(traversal)
    assert not (drafts_dir.parent.parent / "escape.md").exists()

    linked_parent = tmp_path / "linked" / "sandbox"
    linked_parent.mkdir(parents=True)
    link = linked_parent / "drafts"
    link.symlink_to(drafts_dir, target_is_directory=True)
    with pytest.raises(SandboxViolationError, match="cannot be symlinks"):
        DraftWriterTool(link)


def test_draft_writer_does_not_follow_destination_symlink(
    drafts_dir: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("contenido original\n", encoding="utf-8")
    target = drafts_dir / "resumen-incidente.md"
    target.symlink_to(outside)
    writer = DraftWriterTool(drafts_dir)
    proposal = writer.prepare(_draft_request())
    confirmation = DraftConfirmation(
        proposal_fingerprint=proposal.proposal_fingerprint,
        confirmed_by_user=True,
    )

    with pytest.raises(DraftAlreadyExistsError, match="overwrite is forbidden"):
        writer.create(proposal, confirmation)

    assert outside.read_text(encoding="utf-8") == "contenido original\n"
