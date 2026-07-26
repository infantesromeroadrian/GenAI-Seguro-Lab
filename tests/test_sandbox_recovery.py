"""Pruebas del punto único de publicación y recuperación del sandbox."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

import genai_seguro_lab.local_tools as local_tools
import genai_seguro_lab.sandbox_recovery as sandbox_recovery
from genai_seguro_lab.local_tools import (
    DraftApprovalAuthority,
    DraftApprovalError,
    DraftAlreadyExistsError,
    DraftProposal,
    DraftWriterTool,
)
from genai_seguro_lab.model_adapter import ModelToolRequest
from genai_seguro_lab.output_policy import OutputPolicy
from genai_seguro_lab.resource_control import ProductResourceControl
from genai_seguro_lab.sandbox_recovery import (
    SANDBOX_RECOVERY_ID,
    SANDBOX_RECOVERY_VERSION,
    SandboxRecoveryError,
    SandboxRecoveryLockError,
    SandboxRecoveryReport,
    SandboxTransactionError,
    TransactionMarker,
    canonical_transaction_marker,
)

IDENTITY = "synthetic-operator"
CREDENTIAL = "synthetic-test-credential-not-a-real-secret"
TRANSACTION_ID = "1" * 32
CANARIES = (
    "CANARY_GSL_RECOVERY_PROMPT",
    "synthetic-test-credential-not-a-real-secret",
    "synthetic-operator",
)


@pytest.fixture
def drafts_dir(tmp_path: Path) -> Path:
    path = tmp_path / "sandbox" / "drafts"
    path.mkdir(parents=True)
    return path


def _authority() -> DraftApprovalAuthority:
    return DraftApprovalAuthority(
        configured_identity=IDENTITY,
        credential=CREDENTIAL,
    )


def _writer(
    drafts_dir: Path,
    *,
    authority: DraftApprovalAuthority | None = None,
    control: ProductResourceControl | None = None,
) -> DraftWriterTool:
    return DraftWriterTool(
        drafts_dir.absolute(),
        principal="sandbox-recovery-test",
        scope="draft:sandbox-recovery-test",
        approval_authority=authority or _authority(),
        output_policy=OutputPolicy(),
        allowed_knowledge_ids=("KB-001",),
        resource_control=control,
    )


def _request(
    *,
    filename: str = "recovery-test.md",
    body: str = "Contenido sintético para validar la recuperación.",
) -> ModelToolRequest:
    return ModelToolRequest(
        request_id="CALL-RECOVERY-001",
        name="draft_create",
        arguments_json=json.dumps(
            {
                "filename": filename,
                "title": "Prueba de recuperación",
                "body": body,
                "references": ["KB-001"],
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _prepare_and_authorize(
    writer: DraftWriterTool,
    *,
    filename: str = "recovery-test.md",
) -> tuple[DraftProposal, object]:
    proposal = writer.prepare(
        _request(filename=filename),
        grant=writer.prepare_grant,
    )
    challenge = writer.issue_approval_challenge(proposal)
    approval = writer._approval_authority.approve(
        challenge,
        identity=IDENTITY,
        credential=CREDENTIAL,
    )
    return proposal, writer.authorize_effect(proposal, approval)


def _rendered_bytes(proposal: DraftProposal) -> bytes:
    return DraftWriterTool._render(proposal).encode("utf-8")


def _internal_names(drafts_dir: Path) -> tuple[str, ...]:
    return tuple(
        sorted(
            path.name
            for path in drafts_dir.iterdir()
            if path.name.startswith(".gsl-txn-")
        )
    )


def _write_regular(path: Path, content: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        os.write(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _transaction_artifacts(
    drafts_dir: Path,
    *,
    final_name: str = "recovery-test.md",
    content: bytes = b"synthetic staged content\n",
    transaction_id: str = TRANSACTION_ID,
) -> tuple[Path, Path, TransactionMarker]:
    marker = TransactionMarker(
        control_id=SANDBOX_RECOVERY_ID,
        version=SANDBOX_RECOVERY_VERSION,
        transaction_id=transaction_id,
        final_name=final_name,
        bytes=len(content),
        sha256=sandbox_recovery.sha256(content).hexdigest(),
    )
    marker_path = drafts_dir / f".gsl-txn-{transaction_id}.json"
    stage_path = drafts_dir / f".gsl-txn-{transaction_id}.stage"
    _write_regular(marker_path, canonical_transaction_marker(marker))
    _write_regular(stage_path, content)
    return marker_path, stage_path, marker


def _entry_snapshot(drafts_dir: Path) -> dict[str, tuple[int, int, int, int]]:
    return {
        path.name: (
            path.lstat().st_dev,
            path.lstat().st_ino,
            path.lstat().st_mode,
            path.lstat().st_size,
        )
        for path in drafts_dir.iterdir()
    }


def test_create_is_atomic_owner_only_and_leaves_no_internal_artifacts(
    drafts_dir: Path,
) -> None:
    authority = _authority()
    writer = _writer(drafts_dir, authority=authority)
    proposal, grant = _prepare_and_authorize(writer)

    result = writer.create(proposal, grant)  # type: ignore[arg-type]

    final = drafts_dir / proposal.filename
    assert final.read_bytes() == _rendered_bytes(proposal)
    assert stat.S_IMODE(final.stat().st_mode) == 0o600
    assert final.stat().st_nlink == 1
    assert result.content_sha256 == sandbox_recovery.sha256(
        final.read_bytes()
    ).hexdigest()
    assert result.bytes_written == len(final.read_bytes())
    assert result.recovery_pending is False
    assert _internal_names(drafts_dir) == ()
    assert writer.recovery_report == SandboxRecoveryReport(
        control_id=SANDBOX_RECOVERY_ID,
        version=SANDBOX_RECOVERY_VERSION,
        status="clean",
        no_effect_transactions=0,
        preserved_finals=0,
        internal_artifacts_removed=0,
    )
    writer.stop()
    authority.close()


def test_two_independent_writers_can_publish_only_one_concurrent_effect(
    drafts_dir: Path,
) -> None:
    first = _writer(drafts_dir)
    second = _writer(drafts_dir)
    first_proposal, first_grant = _prepare_and_authorize(first)
    second_proposal, second_grant = _prepare_and_authorize(second)
    barrier = Barrier(2)

    def publish(writer: DraftWriterTool, proposal: object, grant: object) -> str:
        barrier.wait(timeout=5)
        try:
            writer.create(proposal, grant)  # type: ignore[arg-type]
        except (
            DraftAlreadyExistsError,
            SandboxRecoveryLockError,
        ):
            return "rejected"
        return "created"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(
            pool.map(
                lambda values: publish(*values),
                (
                    (first, first_proposal, first_grant),
                    (second, second_proposal, second_grant),
                ),
            )
        )

    assert sorted(outcomes) == ["created", "rejected"]
    final = drafts_dir / "recovery-test.md"
    assert final.read_bytes() == _rendered_bytes(first_proposal)
    assert stat.S_IMODE(final.stat().st_mode) == 0o600
    assert _internal_names(drafts_dir) == ()


def test_prepublication_fault_has_no_effect_and_cleans_once(
    drafts_dir: Path,
) -> None:
    writer = _writer(drafts_dir)
    proposal, grant = _prepare_and_authorize(writer)

    def fail_after_stage(point: str) -> None:
        if point == "after_stage_durable":
            raise RuntimeError("CANARY_GSL_RECOVERY_PROMPT")

    writer._transaction_controller._fault_hook = fail_after_stage
    with pytest.raises(
        SandboxTransactionError,
        match="failed before publication",
    ) as captured:
        writer.create(proposal, grant)  # type: ignore[arg-type]

    assert "CANARY" not in str(captured.value)
    assert not (drafts_dir / proposal.filename).exists()
    assert _internal_names(drafts_dir) == ()
    assert writer.resource_control.usage.draft_files == 1
    assert writer.resource_control.security_journal.events[-1].kind == (
        "operation_failed"
    )


def test_postpublication_fault_preserves_final_and_restart_cleans_metadata(
    drafts_dir: Path,
) -> None:
    writer = _writer(drafts_dir)
    proposal, grant = _prepare_and_authorize(writer)

    def fail_after_publish(point: str) -> None:
        if point == "after_publish":
            raise RuntimeError("synthetic post-publication failure")

    writer._transaction_controller._fault_hook = fail_after_publish
    result = writer.create(proposal, grant)  # type: ignore[arg-type]
    expected = _rendered_bytes(proposal)
    final = drafts_dir / proposal.filename

    assert result.created is True
    assert result.recovery_pending is True
    assert final.read_bytes() == expected
    assert len(_internal_names(drafts_dir)) == 2
    marker_path = next(drafts_dir.glob(".gsl-txn-*.json"))
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))
    assert set(marker_payload) == {
        "bytes",
        "control_id",
        "final_name",
        "sha256",
        "transaction_id",
        "version",
    }
    marker_serialized = marker_path.read_text(encoding="utf-8")
    assert proposal.body not in marker_serialized
    assert str(drafts_dir) not in marker_serialized
    assert all(canary not in marker_serialized for canary in CANARIES)
    assert writer.resource_control.security_journal.events[-1].kind == (
        "operation_completed"
    )
    with pytest.raises(DraftApprovalError, match="writer is closed"):
        writer.prepare(_request(), grant=writer.prepare_grant)

    restarted = _writer(drafts_dir)
    assert restarted.recovery_report.status == "recovered"
    assert restarted.recovery_report.no_effect_transactions == 0
    assert restarted.recovery_report.preserved_finals == 1
    assert restarted.recovery_report.internal_artifacts_removed == 2
    assert final.read_bytes() == expected
    assert _internal_names(drafts_dir) == ()


def test_restart_discards_valid_unpublished_marker_and_stage(
    drafts_dir: Path,
) -> None:
    marker, stage, _ = _transaction_artifacts(drafts_dir)

    writer = _writer(drafts_dir)

    assert writer.recovery_report.status == "recovered"
    assert writer.recovery_report.no_effect_transactions == 1
    assert writer.recovery_report.preserved_finals == 0
    assert writer.recovery_report.internal_artifacts_removed == 2
    assert not marker.exists()
    assert not stage.exists()
    assert not (drafts_dir / "recovery-test.md").exists()


@pytest.mark.parametrize(
    "corruption",
    (
        "marker-json",
        "marker-symlink",
        "marker-fifo",
        "marker-mode",
        "stage-symlink",
        "stage-fifo",
        "stage-mode",
        "stage-hash",
        "stage-links",
    ),
)
def test_ambiguous_internal_state_fails_closed_without_mutation(
    drafts_dir: Path,
    tmp_path: Path,
    corruption: str,
) -> None:
    marker, stage, _ = _transaction_artifacts(drafts_dir)
    if corruption == "marker-json":
        marker.write_bytes(b"{}\n")
        marker.chmod(0o600)
    elif corruption == "marker-symlink":
        marker.unlink()
        marker.symlink_to(tmp_path / "outside-marker")
    elif corruption == "marker-fifo":
        marker.unlink()
        os.mkfifo(marker, 0o600)
    elif corruption == "marker-mode":
        marker.chmod(0o640)
    elif corruption == "stage-symlink":
        stage.unlink()
        stage.symlink_to(tmp_path / "outside-stage")
    elif corruption == "stage-fifo":
        stage.unlink()
        os.mkfifo(stage, 0o600)
    elif corruption == "stage-mode":
        stage.chmod(0o640)
    elif corruption == "stage-hash":
        stage.write_bytes(b"different staged bytes\n")
        stage.chmod(0o600)
    elif corruption == "stage-links":
        os.link(stage, drafts_dir / "unrelated.bin")

    before = _entry_snapshot(drafts_dir)
    control = ProductResourceControl("draft", clock=lambda: 0.0)
    with pytest.raises(SandboxRecoveryError):
        _writer(drafts_dir, control=control)

    assert _entry_snapshot(drafts_dir) == before
    assert control.security_journal.events[-1].kind == "operation_failed"
    serialized = control.security_journal.report().model_dump_json()
    assert "data_integrity_violation" in serialized
    assert str(tmp_path) not in serialized
    assert all(canary not in serialized for canary in CANARIES)


def test_recovery_rejects_wrong_owner_without_mutation(
    drafts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _transaction_artifacts(drafts_dir)
    before = _entry_snapshot(drafts_dir)
    real_owner = os.geteuid()
    monkeypatch.setattr(
        sandbox_recovery.os,
        "geteuid",
        lambda: real_owner + 1,
    )

    with pytest.raises(SandboxRecoveryError):
        _writer(drafts_dir)

    assert _entry_snapshot(drafts_dir) == before


def test_missing_link_nofollow_support_fails_before_authority_registration(
    drafts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _authority()
    control = ProductResourceControl("draft", clock=lambda: 0.0)
    supported = set(os.supports_follow_symlinks)
    supported.discard(os.link)
    monkeypatch.setattr(
        sandbox_recovery.os,
        "supports_follow_symlinks",
        supported,
    )

    def unexpected_authority(*_: object, **__: object) -> object:
        raise AssertionError("authority must not be registered")

    monkeypatch.setattr(
        local_tools,
        "_issue_tool_grant",
        unexpected_authority,
    )
    monkeypatch.setattr(
        DraftApprovalAuthority,
        "_register_writer",
        unexpected_authority,
    )

    with pytest.raises(SandboxRecoveryError):
        _writer(drafts_dir, authority=authority, control=control)

    assert list(drafts_dir.iterdir()) == []
    assert control.security_journal.events[-1].kind == "operation_failed"


def test_directory_fsync_failure_fails_before_authority_registration(
    drafts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _authority()
    control = ProductResourceControl("draft", clock=lambda: 0.0)
    real_fsync = os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(errno.EIO, "synthetic directory fsync failure")
        real_fsync(descriptor)

    def unexpected_authority(*_: object, **__: object) -> object:
        raise AssertionError("authority must not be registered")

    monkeypatch.setattr(sandbox_recovery.os, "fsync", fail_directory_fsync)
    monkeypatch.setattr(
        local_tools,
        "_issue_tool_grant",
        unexpected_authority,
    )
    monkeypatch.setattr(
        DraftApprovalAuthority,
        "_register_writer",
        unexpected_authority,
    )

    with pytest.raises(SandboxRecoveryError):
        _writer(drafts_dir, authority=authority, control=control)

    assert list(drafts_dir.iterdir()) == []
    assert control.security_journal.events[-1].kind == "operation_failed"


def test_ambiguous_final_is_preserved_and_internal_state_is_not_mutated(
    drafts_dir: Path,
) -> None:
    content = b"synthetic staged content\n"
    marker, stage, _ = _transaction_artifacts(
        drafts_dir,
        content=content,
    )
    final = drafts_dir / "recovery-test.md"
    _write_regular(final, content)
    before = _entry_snapshot(drafts_dir)

    with pytest.raises(SandboxRecoveryError):
        _writer(drafts_dir)

    assert _entry_snapshot(drafts_dir) == before
    assert final.read_bytes() == content
    assert marker.exists() and stage.exists()


def test_same_inode_same_size_mutation_is_rehashed_before_any_cleanup(
    drafts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"synthetic staged content\n"
    marker, stage, descriptor = _transaction_artifacts(
        drafts_dir,
        content=content,
    )
    final = drafts_dir / descriptor.final_name
    os.link(stage, final)
    assert stage.stat().st_ino == final.stat().st_ino
    assert stage.stat().st_nlink == final.stat().st_nlink == 2
    replacement = b"X" * len(content)
    real_build_plan = (
        sandbox_recovery.SandboxTransactionController._build_recovery_plan
    )

    def mutate_after_plan(
        controller: object,
        transaction_id: str,
        entries: dict[str, str],
    ) -> object:
        plan = real_build_plan(
            controller,  # type: ignore[arg-type]
            transaction_id,
            entries,
        )
        stage_name = plan.stage.name  # type: ignore[union-attr]
        stage_fd = os.open(
            stage_name,
            os.O_WRONLY | os.O_NOFOLLOW,
            dir_fd=controller._root_fd,  # type: ignore[attr-defined]
        )
        try:
            assert os.write(stage_fd, replacement) == len(replacement)
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        return plan

    monkeypatch.setattr(
        sandbox_recovery.SandboxTransactionController,
        "_build_recovery_plan",
        mutate_after_plan,
    )

    with pytest.raises(SandboxRecoveryError):
        _writer(drafts_dir)

    assert marker.exists()
    assert stage.exists()
    assert final.exists()
    assert stage.stat().st_ino == final.stat().st_ino
    assert stage.stat().st_nlink == final.stat().st_nlink == 2
    assert stage.read_bytes() == final.read_bytes() == replacement


def test_recovery_lock_conflict_fails_before_authority_or_mutation(
    drafts_dir: Path,
) -> None:
    marker, stage, _ = _transaction_artifacts(drafts_dir)
    before = _entry_snapshot(drafts_dir)
    descriptor = os.open(
        drafts_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    control = ProductResourceControl("draft", clock=lambda: 0.0)
    try:
        with pytest.raises(SandboxRecoveryLockError):
            _writer(drafts_dir, control=control)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    assert _entry_snapshot(drafts_dir) == before
    assert marker.exists() and stage.exists()
    assert control.security_journal.events[-1].kind == "operation_failed"
    assert "lock_conflict" in control.security_journal.report().model_dump_json()


def test_create_lock_conflict_has_no_effect_and_stops_the_writer(
    drafts_dir: Path,
) -> None:
    writer = _writer(drafts_dir)
    proposal, grant = _prepare_and_authorize(writer)
    descriptor = os.open(
        drafts_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(SandboxRecoveryLockError):
            writer.create(proposal, grant)  # type: ignore[arg-type]
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    assert not (drafts_dir / proposal.filename).exists()
    assert _internal_names(drafts_dir) == ()
    assert writer.resource_control.usage.draft_files == 1
    assert writer.resource_control.security_journal.events[-1].kind == (
        "operation_failed"
    )
    assert (
        "lock_conflict"
        in writer.resource_control.security_journal.report().model_dump_json()
    )


def test_stop_is_idempotent_revokes_authority_and_context_failure_is_terminal(
    drafts_dir: Path,
) -> None:
    authority = _authority()
    writer = _writer(drafts_dir, authority=authority)
    proposal, grant = _prepare_and_authorize(writer)
    root_fd = writer._root_fd
    writer.stop()
    writer.stop()

    with pytest.raises(OSError):
        os.fstat(root_fd)
    with pytest.raises(DraftApprovalError, match="writer is closed"):
        writer.create(proposal, grant)  # type: ignore[arg-type]
    assert list(drafts_dir.iterdir()) == []
    assert writer.resource_control.security_journal.events[-1].kind == (
        "operation_completed"
    )

    failing = _writer(drafts_dir)
    with pytest.raises(RuntimeError, match="synthetic context failure"):
        with failing:
            raise RuntimeError("synthetic context failure")
    assert failing.resource_control.security_journal.events[-1].kind == (
        "operation_failed"
    )


def test_context_exception_after_published_effect_keeps_coherent_terminal(
    drafts_dir: Path,
) -> None:
    writer = _writer(drafts_dir)
    proposal, grant = _prepare_and_authorize(writer)

    with pytest.raises(RuntimeError, match="failure after effect"):
        with writer:
            writer.create(proposal, grant)  # type: ignore[arg-type]
            raise RuntimeError("failure after effect")

    assert (drafts_dir / proposal.filename).read_bytes() == _rendered_bytes(
        proposal
    )
    assert writer.resource_control.security_journal.events[-1].kind == (
        "operation_completed"
    )
