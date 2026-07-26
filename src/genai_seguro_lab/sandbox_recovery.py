"""Publicación transaccional y recuperación acotada del sandbox de borradores."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

SANDBOX_RECOVERY_ID = "GSL-SANDBOX-RECOVERY-001"
SANDBOX_RECOVERY_VERSION = "1.0.0"

MAX_SANDBOX_ROOT_ENTRIES = 256
MAX_SANDBOX_INTERNAL_ARTIFACTS = 16
MAX_SANDBOX_RECOVERY_TRANSACTIONS = 8
MAX_TRANSACTION_MARKER_BYTES = 1024
MAX_TRANSACTION_STAGE_BYTES = 16 * 1024

TRANSACTION_MARKER_SUFFIX = ".json"
TRANSACTION_STAGE_SUFFIX = ".stage"

_TRANSACTION_PREFIX = ".gsl-txn-"
_TRANSACTION_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_INTERNAL_NAME_PATTERN = re.compile(
    r"^\.gsl-txn-([0-9a-f]{32})\.(json|stage)$"
)
_DRAFT_NAME_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9_-]{0,58}[a-z0-9])?\.md$"
)
_CONTROL_ERROR = "draft sandbox transaction control is unavailable"
_LOCK_ERROR = "draft sandbox transaction control is already in use"
_TRANSACTION_ERROR = "draft transaction failed before publication"
_CONFLICT_ERROR = "draft target already exists"

TransactionId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
DraftName = Annotated[
    str,
    Field(
        max_length=64,
        pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,58}[a-z0-9])?\.md$",
    ),
]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class SandboxRecoveryError(RuntimeError):
    """El control no puede determinar un estado seguro sin ambigüedad."""


class SandboxRecoveryLockError(SandboxRecoveryError):
    """Otra operación cooperante mantiene el bloqueo del sandbox."""


class SandboxTransactionError(RuntimeError):
    """La transacción terminó antes de publicar un efecto."""


class SandboxPublicationConflict(SandboxTransactionError):
    """El nombre final ya existe y la política prohíbe sobrescribirlo."""


class _StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class TransactionMarker(_StrictSchema):
    """Descriptor canónico mínimo de una transacción local."""

    control_id: Literal["GSL-SANDBOX-RECOVERY-001"]
    version: Literal["1.0.0"]
    transaction_id: TransactionId
    final_name: DraftName
    bytes: Annotated[int, Field(ge=1, le=MAX_TRANSACTION_STAGE_BYTES)]
    sha256: Sha256


class SandboxRecoveryReport(_StrictSchema):
    """Resultado saneado de la única reconciliación de arranque."""

    control_id: Literal["GSL-SANDBOX-RECOVERY-001"]
    version: Literal["1.0.0"]
    status: Literal["clean", "recovered"]
    no_effect_transactions: Annotated[
        int,
        Field(ge=0, le=MAX_SANDBOX_RECOVERY_TRANSACTIONS),
    ]
    preserved_finals: Annotated[
        int,
        Field(ge=0, le=MAX_SANDBOX_RECOVERY_TRANSACTIONS),
    ]
    internal_artifacts_removed: Annotated[
        int,
        Field(ge=0, le=MAX_SANDBOX_INTERNAL_ARTIFACTS),
    ]


class SandboxPublicationResult(_StrictSchema):
    """Condición observable del control después del punto de publicación."""

    content_sha256: Sha256
    bytes_written: Annotated[int, Field(ge=1, le=MAX_TRANSACTION_STAGE_BYTES)]
    recovery_pending: bool


@dataclass(frozen=True, slots=True)
class _ValidatedFile:
    name: str
    device: int
    inode: int
    mode: int
    owner: int
    links: int
    size: int
    content_sha256: str


@dataclass(frozen=True, slots=True)
class _RecoveryPlan:
    final_name: str
    marker: _ValidatedFile
    stage: _ValidatedFile | None
    final: _ValidatedFile | None


def canonical_transaction_marker(marker: TransactionMarker) -> bytes:
    """Serializa el marker sin contenido ni contexto de autoridad."""

    if not isinstance(marker, TransactionMarker):
        raise TypeError("marker must be a TransactionMarker")
    return (
        json.dumps(
            marker.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


class SandboxTransactionController:
    """Controla una raíz ya anclada mediante descriptor, sin seguir enlaces."""

    def __init__(
        self,
        root_fd: int,
        root_identity: tuple[int, int],
        *,
        maximum_payload_bytes: int = MAX_TRANSACTION_STAGE_BYTES,
        token_hex: Callable[[int], str],
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if isinstance(root_fd, bool) or not isinstance(root_fd, int):
            raise TypeError("root_fd must be an integer descriptor")
        if (
            not isinstance(root_identity, tuple)
            or len(root_identity) != 2
            or any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in root_identity
            )
        ):
            raise TypeError("root_identity must contain device and inode")
        if (
            isinstance(maximum_payload_bytes, bool)
            or not isinstance(maximum_payload_bytes, int)
            or not 1 <= maximum_payload_bytes <= MAX_TRANSACTION_STAGE_BYTES
        ):
            raise ValueError("maximum_payload_bytes is outside control bounds")
        if not callable(token_hex):
            raise TypeError("token_hex must be callable")
        if fault_hook is not None and not callable(fault_hook):
            raise TypeError("fault_hook must be callable")

        self._root_fd = root_fd
        self._root_identity = root_identity
        self._maximum_payload_bytes = maximum_payload_bytes
        self._token_hex = token_hex
        self._fault_hook = fault_hook
        self._owner = os.geteuid()
        self._require_primitives()
        self._assert_root_descriptor()
        self._recovery_report = self._recover_once()

    @property
    def recovery_report(self) -> SandboxRecoveryReport:
        return self._recovery_report

    def publish(
        self,
        final_name: str,
        content: bytes,
    ) -> SandboxPublicationResult:
        """Publica create-only; nunca devuelve un resultado de efecto incierto."""

        if (
            not isinstance(final_name, str)
            or _DRAFT_NAME_PATTERN.fullmatch(final_name) is None
        ):
            raise SandboxTransactionError(_TRANSACTION_ERROR)
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        if not 1 <= len(content) <= self._maximum_payload_bytes:
            raise SandboxTransactionError(_TRANSACTION_ERROR)

        content_hash = sha256(content).hexdigest()
        with self._exclusive_lock():
            self._assert_root_descriptor()
            if self._scan_internal_names():
                raise SandboxRecoveryError(_CONTROL_ERROR)
            self._require_final_absent(final_name)

            transaction_id = self._token_hex(16)
            if (
                not isinstance(transaction_id, str)
                or _TRANSACTION_ID_PATTERN.fullmatch(transaction_id) is None
            ):
                raise SandboxTransactionError(_TRANSACTION_ERROR)
            marker_name = (
                f"{_TRANSACTION_PREFIX}{transaction_id}"
                f"{TRANSACTION_MARKER_SUFFIX}"
            )
            stage_name = (
                f"{_TRANSACTION_PREFIX}{transaction_id}"
                f"{TRANSACTION_STAGE_SUFFIX}"
            )
            if (
                self._lstat_optional(marker_name) is not None
                or self._lstat_optional(stage_name) is not None
            ):
                raise SandboxTransactionError(_TRANSACTION_ERROR)

            marker = TransactionMarker(
                control_id=SANDBOX_RECOVERY_ID,
                version=SANDBOX_RECOVERY_VERSION,
                transaction_id=transaction_id,
                final_name=final_name,
                bytes=len(content),
                sha256=content_hash,
            )
            published = False
            marker_created = False
            stage_created = False
            try:
                self._create_durable_internal(
                    marker_name,
                    canonical_transaction_marker(marker),
                    MAX_TRANSACTION_MARKER_BYTES,
                )
                marker_created = True
                self._fsync_root()
                self._fault("after_marker_durable")

                self._create_durable_internal(
                    stage_name,
                    content,
                    self._maximum_payload_bytes,
                )
                stage_created = True
                self._fsync_root()
                self._fault("after_stage_durable")

                try:
                    os.link(
                        stage_name,
                        final_name,
                        src_dir_fd=self._root_fd,
                        dst_dir_fd=self._root_fd,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    if exc.errno in {errno.EEXIST, errno.ELOOP}:
                        raise SandboxPublicationConflict(
                            _CONFLICT_ERROR
                        ) from None
                    raise SandboxTransactionError(
                        _TRANSACTION_ERROR
                    ) from exc
                published = True
                self._fsync_root()
                self._fault("after_publish")

                self._unlink_internal(stage_name)
                stage_created = False
                self._fault("after_stage_removed")
                self._unlink_internal(marker_name)
                marker_created = False
                self._fsync_root()
            except Exception as exc:
                if published:
                    return SandboxPublicationResult(
                        content_sha256=content_hash,
                        bytes_written=len(content),
                        recovery_pending=True,
                    )
                self._cleanup_internal_once(
                    marker_name if marker_created else None,
                    stage_name if stage_created else None,
                )
                if isinstance(
                    exc,
                    (
                        SandboxPublicationConflict,
                        SandboxRecoveryError,
                        SandboxTransactionError,
                    ),
                ):
                    raise
                raise SandboxTransactionError(
                    _TRANSACTION_ERROR
                ) from exc

            return SandboxPublicationResult(
                content_sha256=content_hash,
                bytes_written=len(content),
                recovery_pending=False,
            )

    def _recover_once(self) -> SandboxRecoveryReport:
        with self._exclusive_lock():
            self._assert_root_descriptor()
            self._fsync_root()
            internal_names = self._scan_internal_names()
            if not internal_names:
                return SandboxRecoveryReport(
                    control_id=SANDBOX_RECOVERY_ID,
                    version=SANDBOX_RECOVERY_VERSION,
                    status="clean",
                    no_effect_transactions=0,
                    preserved_finals=0,
                    internal_artifacts_removed=0,
                )

            grouped: dict[str, dict[str, str]] = {}
            for name in internal_names:
                match = _INTERNAL_NAME_PATTERN.fullmatch(name)
                if match is None:
                    raise SandboxRecoveryError(_CONTROL_ERROR)
                transaction_id, suffix = match.groups()
                grouped.setdefault(transaction_id, {})[suffix] = name
            if len(grouped) > MAX_SANDBOX_RECOVERY_TRANSACTIONS:
                raise SandboxRecoveryError(_CONTROL_ERROR)

            plans = tuple(
                self._build_recovery_plan(transaction_id, entries)
                for transaction_id, entries in sorted(grouped.items())
            )
            if len({plan.final_name for plan in plans}) != len(plans):
                raise SandboxRecoveryError(_CONTROL_ERROR)
            for plan in plans:
                self._revalidate_plan(plan)

            removed = 0
            for plan in plans:
                self._revalidate_plan(plan)
                if plan.stage is not None:
                    self._unlink_validated_internal(plan.stage)
                    removed += 1
                self._unlink_validated_internal(plan.marker)
                removed += 1
            self._fsync_root()

            return SandboxRecoveryReport(
                control_id=SANDBOX_RECOVERY_ID,
                version=SANDBOX_RECOVERY_VERSION,
                status="recovered",
                no_effect_transactions=sum(
                    plan.final is None for plan in plans
                ),
                preserved_finals=sum(
                    plan.final is not None for plan in plans
                ),
                internal_artifacts_removed=removed,
            )

    def _build_recovery_plan(
        self,
        transaction_id: str,
        entries: dict[str, str],
    ) -> _RecoveryPlan:
        marker_name = entries.get("json")
        if marker_name is None:
            raise SandboxRecoveryError(_CONTROL_ERROR)
        marker_file, marker_content = self._read_validated_regular(
            marker_name,
            maximum=MAX_TRANSACTION_MARKER_BYTES,
            allowed_links={1},
        )
        try:
            marker = TransactionMarker.model_validate_json(marker_content)
        except ValidationError as exc:
            raise SandboxRecoveryError(_CONTROL_ERROR) from exc
        if (
            marker.transaction_id != transaction_id
            or marker.bytes > self._maximum_payload_bytes
            or marker_content != canonical_transaction_marker(marker)
        ):
            raise SandboxRecoveryError(_CONTROL_ERROR)

        stage: _ValidatedFile | None = None
        stage_name = entries.get("stage")
        if stage_name is not None:
            stage, _ = self._read_validated_regular(
                stage_name,
                maximum=self._maximum_payload_bytes,
                allowed_links={1, 2},
                expected_size=marker.bytes,
                expected_sha256=marker.sha256,
            )

        final: _ValidatedFile | None = None
        if self._lstat_optional(marker.final_name) is not None:
            final, _ = self._read_validated_regular(
                marker.final_name,
                maximum=self._maximum_payload_bytes,
                allowed_links={1, 2},
                expected_size=marker.bytes,
                expected_sha256=marker.sha256,
            )

        if stage is not None and final is not None:
            if (
                (stage.device, stage.inode) != (final.device, final.inode)
                or stage.links != 2
                or final.links != 2
            ):
                raise SandboxRecoveryError(_CONTROL_ERROR)
        elif stage is not None and stage.links != 1:
            raise SandboxRecoveryError(_CONTROL_ERROR)
        elif final is not None and final.links != 1:
            raise SandboxRecoveryError(_CONTROL_ERROR)

        return _RecoveryPlan(
            final_name=marker.final_name,
            marker=marker_file,
            stage=stage,
            final=final,
        )

    def _scan_internal_names(self) -> tuple[str, ...]:
        internal: list[str] = []
        entries_seen = 0
        try:
            with os.scandir(self._root_fd) as iterator:
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen > MAX_SANDBOX_ROOT_ENTRIES:
                        raise SandboxRecoveryError(_CONTROL_ERROR)
                    name = entry.name
                    if name.startswith(_TRANSACTION_PREFIX):
                        internal.append(name)
                        if (
                            len(internal)
                            > MAX_SANDBOX_INTERNAL_ARTIFACTS
                        ):
                            raise SandboxRecoveryError(_CONTROL_ERROR)
        except SandboxRecoveryError:
            raise
        except OSError as exc:
            raise SandboxRecoveryError(_CONTROL_ERROR) from exc
        return tuple(sorted(internal))

    def _create_durable_internal(
        self,
        name: str,
        content: bytes,
        maximum: int,
    ) -> None:
        if not 1 <= len(content) <= maximum:
            raise SandboxTransactionError(_TRANSACTION_ERROR)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = -1
        created = False
        try:
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=self._root_fd,
            )
            created = True
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != self._owner
                or metadata.st_nlink != 1
            ):
                raise SandboxTransactionError(_TRANSACTION_ERROR)
            written = 0
            while written < len(content):
                count = os.write(descriptor, content[written:])
                if count <= 0:
                    raise SandboxTransactionError(_TRANSACTION_ERROR)
                written += count
            os.fsync(descriptor)
        except SandboxTransactionError:
            if descriptor >= 0:
                os.close(descriptor)
                descriptor = -1
            if created:
                try:
                    os.unlink(name, dir_fd=self._root_fd)
                except OSError:
                    pass
            raise
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
                descriptor = -1
            if created:
                try:
                    os.unlink(name, dir_fd=self._root_fd)
                except OSError:
                    pass
            raise SandboxTransactionError(_TRANSACTION_ERROR) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _read_validated_regular(
        self,
        name: str,
        *,
        maximum: int,
        allowed_links: set[int],
        expected_size: int | None = None,
        expected_sha256: str | None = None,
    ) -> tuple[_ValidatedFile, bytes]:
        before = self._lstat_optional(name)
        if before is None:
            raise SandboxRecoveryError(_CONTROL_ERROR)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != self._owner
            or before.st_nlink not in allowed_links
            or before.st_size < 1
            or before.st_size > maximum
            or (
                expected_size is not None
                and before.st_size != expected_size
            )
        ):
            raise SandboxRecoveryError(_CONTROL_ERROR)

        flags = (
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=self._root_fd)
            current = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino)
                != (current.st_dev, current.st_ino)
                or current.st_mode != before.st_mode
                or current.st_uid != before.st_uid
                or current.st_nlink != before.st_nlink
                or current.st_size != before.st_size
            ):
                raise SandboxRecoveryError(_CONTROL_ERROR)
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 8 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
        except SandboxRecoveryError:
            raise
        except OSError as exc:
            raise SandboxRecoveryError(_CONTROL_ERROR) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        digest = sha256(content).hexdigest()
        if (
            len(content) != before.st_size
            or len(content) > maximum
            or (
                expected_sha256 is not None
                and digest != expected_sha256
            )
        ):
            raise SandboxRecoveryError(_CONTROL_ERROR)
        return (
            _ValidatedFile(
                name=name,
                device=before.st_dev,
                inode=before.st_ino,
                mode=before.st_mode,
                owner=before.st_uid,
                links=before.st_nlink,
                size=before.st_size,
                content_sha256=digest,
            ),
            content,
        )

    def _revalidate_plan(self, plan: _RecoveryPlan) -> None:
        self._revalidate_file(plan.marker)
        if plan.stage is not None:
            self._revalidate_file(plan.stage)
        if plan.final is not None:
            self._revalidate_file(plan.final)

    def _revalidate_file(self, expected: _ValidatedFile) -> None:
        maximum = (
            MAX_TRANSACTION_MARKER_BYTES
            if expected.name.endswith(TRANSACTION_MARKER_SUFFIX)
            else self._maximum_payload_bytes
        )
        current, _ = self._read_validated_regular(
            expected.name,
            maximum=maximum,
            allowed_links={expected.links},
            expected_size=expected.size,
            expected_sha256=expected.content_sha256,
        )
        if (
            (current.device, current.inode)
            != (expected.device, expected.inode)
            or current.mode != expected.mode
            or current.owner != expected.owner
            or current.links != expected.links
            or current.size != expected.size
            or current.content_sha256 != expected.content_sha256
        ):
            raise SandboxRecoveryError(_CONTROL_ERROR)

    def _unlink_validated_internal(
        self,
        expected: _ValidatedFile,
    ) -> None:
        self._revalidate_file(expected)
        self._unlink_internal(expected.name)

    def _unlink_internal(self, name: str) -> None:
        if _INTERNAL_NAME_PATTERN.fullmatch(name) is None:
            raise SandboxRecoveryError(_CONTROL_ERROR)
        try:
            os.unlink(name, dir_fd=self._root_fd)
        except OSError as exc:
            raise SandboxRecoveryError(_CONTROL_ERROR) from exc

    def _cleanup_internal_once(
        self,
        marker_name: str | None,
        stage_name: str | None,
    ) -> None:
        for name in (stage_name, marker_name):
            if name is None:
                continue
            try:
                if self._lstat_optional(name) is not None:
                    self._unlink_internal(name)
            except (OSError, SandboxRecoveryError):
                continue
        try:
            self._fsync_root()
        except (OSError, SandboxRecoveryError):
            return

    def _lstat_optional(self, name: str) -> os.stat_result | None:
        try:
            return os.stat(
                name,
                dir_fd=self._root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SandboxRecoveryError(_CONTROL_ERROR) from exc

    def _require_final_absent(self, name: str) -> None:
        descriptor = -1
        flags = (
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(name, flags, dir_fd=self._root_fd)
        except FileNotFoundError:
            return
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EISDIR}:
                raise SandboxPublicationConflict(_CONFLICT_ERROR) from None
            raise SandboxRecoveryError(_CONTROL_ERROR) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        raise SandboxPublicationConflict(_CONFLICT_ERROR)

    def _assert_root_descriptor(self) -> None:
        try:
            metadata = os.fstat(self._root_fd)
        except OSError as exc:
            raise SandboxRecoveryError(_CONTROL_ERROR) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != self._root_identity
        ):
            raise SandboxRecoveryError(_CONTROL_ERROR)

    def _fsync_root(self) -> None:
        try:
            os.fsync(self._root_fd)
        except OSError as exc:
            raise SandboxRecoveryError(_CONTROL_ERROR) from exc

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        try:
            fcntl.flock(
                self._root_fd,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except (BlockingIOError, OSError) as exc:
            raise SandboxRecoveryLockError(_LOCK_ERROR) from exc
        try:
            yield
        finally:
            try:
                fcntl.flock(self._root_fd, fcntl.LOCK_UN)
            except OSError:
                pass

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    @staticmethod
    def _require_primitives() -> None:
        required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
        if any(not hasattr(os, name) for name in required_flags):
            raise SandboxRecoveryError(_CONTROL_ERROR)
        required_dir_fd = (os.open, os.stat, os.unlink, os.link)
        if any(function not in os.supports_dir_fd for function in required_dir_fd):
            raise SandboxRecoveryError(_CONTROL_ERROR)
        required_follow_symlinks = (os.stat, os.link)
        if any(
            function not in os.supports_follow_symlinks
            for function in required_follow_symlinks
        ):
            raise SandboxRecoveryError(_CONTROL_ERROR)
        if not hasattr(os, "geteuid"):
            raise SandboxRecoveryError(_CONTROL_ERROR)
