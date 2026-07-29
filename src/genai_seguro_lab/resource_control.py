"""Control preventivo y fail-closed de recursos del producto endurecido."""

from __future__ import annotations

import fcntl
import math
import os
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Literal

from pydantic import BaseModel

from .security_events import SecurityCorrelation, SecurityEventJournal

RESOURCE_CONTROL_ID = "GSL-RESOURCE-POLICY-001"
RESOURCE_CONTROL_VERSION = "1.0.0"

MAX_BENIGN_CORPUS_BYTES = 64 * 1024
MAX_JSONL_RECORD_BYTES = 8 * 1024
MAX_INCIDENT_RECORDS = 32
MAX_KNOWLEDGE_RECORDS = 32
MAX_MODEL_REQUEST_BYTES = 8 * 1024
MAX_MODEL_RESPONSE_BYTES = 8 * 1024
MAX_TOOL_ARGUMENTS_BYTES = 4 * 1024
MAX_KNOWLEDGE_RESULT_BYTES = 4 * 1024
MAX_FINAL_SUMMARY_BYTES = 4 * 1024
MAX_DRAFT_MARKDOWN_BYTES = 16 * 1024

_LIMIT_MESSAGE = "product resource limit exceeded"
_LOCK_MESSAGE = "product resource is already in use"

ResourceProfile = Literal["analyze", "cloud_analyze", "baseline", "draft"]


class ResourceLimitError(RuntimeError):
    """Un límite preventivo impidió continuar sin conservar el contenido."""


class ResourceLockError(ResourceLimitError):
    """Otro proceso cooperante mantiene el recurso de producto."""


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    cases: int
    model_invocations: int
    tool_requests: int
    tool_executions: int
    elapsed_seconds: float | None
    draft_proposals: int
    draft_challenges: int
    authentication_attempts: int
    draft_grants: int
    draft_files: int


@dataclass(frozen=True, slots=True)
class ResourceUsage:
    cases: int
    model_invocations: int
    tool_requests: int
    tool_executions: int
    draft_proposals: int
    draft_challenges: int
    authentication_attempts: int
    draft_grants: int
    draft_files: int
    elapsed_seconds: float


_PROFILE_LIMITS: dict[ResourceProfile, ResourceLimits] = {
    "analyze": ResourceLimits(
        cases=1,
        model_invocations=2,
        tool_requests=1,
        tool_executions=1,
        elapsed_seconds=1.0,
        draft_proposals=0,
        draft_challenges=0,
        authentication_attempts=0,
        draft_grants=0,
        draft_files=0,
    ),
    "cloud_analyze": ResourceLimits(
        cases=1,
        model_invocations=2,
        tool_requests=1,
        tool_executions=1,
        elapsed_seconds=125.0,
        draft_proposals=0,
        draft_challenges=0,
        authentication_attempts=0,
        draft_grants=0,
        draft_files=0,
    ),
    "baseline": ResourceLimits(
        cases=12,
        model_invocations=24,
        tool_requests=12,
        tool_executions=12,
        elapsed_seconds=5.0,
        draft_proposals=0,
        draft_challenges=0,
        authentication_attempts=0,
        draft_grants=0,
        draft_files=0,
    ),
    "draft": ResourceLimits(
        cases=0,
        model_invocations=0,
        tool_requests=0,
        tool_executions=0,
        elapsed_seconds=None,
        draft_proposals=1,
        draft_challenges=1,
        authentication_attempts=3,
        draft_grants=1,
        draft_files=1,
    ),
}


def require_utf8_size(value: str, maximum: int) -> None:
    """Rechaza texto que excede ``maximum`` bytes sin incluirlo en el error."""

    if not isinstance(value, str):
        raise TypeError("value must be a string")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
        raise TypeError("maximum must be a non-negative integer")
    if len(value.encode("utf-8")) > maximum:
        raise ResourceLimitError(_LIMIT_MESSAGE)


def require_serialized_size(document: BaseModel, maximum: int) -> None:
    """Acota la representación JSON UTF-8 de un modelo validado."""

    if not isinstance(document, BaseModel):
        raise TypeError("document must be a pydantic model")
    encoded = document.model_dump_json().encode("utf-8")
    if len(encoded) > maximum:
        raise ResourceLimitError(_LIMIT_MESSAGE)


def read_bounded_regular_file(path: Path, maximum: int) -> bytes:
    """Lee como máximo ``maximum + 1`` bytes desde un descriptor anclado."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
        raise TypeError("maximum must be a non-negative integer")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ResourceLimitError(_LIMIT_MESSAGE) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ResourceLimitError(_LIMIT_MESSAGE)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
    except OSError as exc:
        raise ResourceLimitError(_LIMIT_MESSAGE) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > maximum:
        raise ResourceLimitError(_LIMIT_MESSAGE)
    return content


@contextmanager
def exclusive_process_lock(
    resource: Path,
    *,
    security_journal: SecurityEventJournal | None = None,
) -> Iterator[None]:
    """Bloquea sin espera un recurso existente durante una ejecución CLI."""

    if not isinstance(resource, Path):
        raise TypeError("resource must be a Path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if security_journal is not None and not isinstance(
        security_journal,
        SecurityEventJournal,
    ):
        raise TypeError("security_journal must be a SecurityEventJournal")
    try:
        descriptor = os.open(resource, flags)
    except OSError as exc:
        if security_journal is not None and not security_journal.is_finished:
            security_journal.signal(
                "lock_conflict",
                source="cli_lock",
                outcome="conflict",
            )
        raise ResourceLockError(_LOCK_MESSAGE) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            if (
                security_journal is not None
                and not security_journal.is_finished
            ):
                security_journal.signal(
                    "lock_conflict",
                    source="cli_lock",
                    outcome="conflict",
                )
            raise ResourceLockError(_LOCK_MESSAGE)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            if (
                security_journal is not None
                and not security_journal.is_finished
            ):
                security_journal.signal(
                    "lock_conflict",
                    source="cli_lock",
                    outcome="conflict",
                )
            raise ResourceLockError(_LOCK_MESSAGE) from exc
        yield
    finally:
        os.close(descriptor)


class ProductResourceControl:
    """Presupuesto acotado y observable para una única operación o sesión."""

    def __init__(
        self,
        profile: ResourceProfile,
        *,
        clock: Callable[[], float] = monotonic,
        security_journal: SecurityEventJournal | None = None,
    ) -> None:
        if profile not in _PROFILE_LIMITS:
            raise ValueError("unknown resource profile")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if security_journal is None:
            security_journal = SecurityEventJournal(profile, clock=clock)
        if (
            not isinstance(security_journal, SecurityEventJournal)
            or security_journal.profile != profile
        ):
            raise TypeError(
                "security_journal must match the resource profile"
            )
        self._profile = profile
        self._limits = _PROFILE_LIMITS[profile]
        self._clock = clock
        self._security_journal = security_journal
        self._lock = threading.RLock()
        self._started_at = self._read_clock()
        self._last_checkpoint = self._started_at
        self._cases = 0
        self._model_invocations = 0
        self._tool_requests = 0
        self._tool_executions = 0
        self._draft_proposals = 0
        self._draft_challenges = 0
        self._authentication_attempts = 0
        self._draft_grants = 0
        self._draft_files = 0

    @property
    def control_id(self) -> str:
        return RESOURCE_CONTROL_ID

    @property
    def profile(self) -> ResourceProfile:
        return self._profile

    @property
    def version(self) -> str:
        return RESOURCE_CONTROL_VERSION

    @property
    def limits(self) -> ResourceLimits:
        return self._limits

    @property
    def security_journal(self) -> SecurityEventJournal:
        return self._security_journal

    @property
    def usage(self) -> ResourceUsage:
        with self._lock:
            return ResourceUsage(
                cases=self._cases,
                model_invocations=self._model_invocations,
                tool_requests=self._tool_requests,
                tool_executions=self._tool_executions,
                draft_proposals=self._draft_proposals,
                draft_challenges=self._draft_challenges,
                authentication_attempts=self._authentication_attempts,
                draft_grants=self._draft_grants,
                draft_files=self._draft_files,
                elapsed_seconds=self._last_checkpoint - self._started_at,
            )

    def checkpoint(
        self,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        with self._lock:
            self._checkpoint_locked(correlation)

    def begin_case(
        self,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        self._consume("_cases", self._limits.cases, correlation)

    def before_model_call(
        self,
        request: BaseModel,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        try:
            require_serialized_size(request, MAX_MODEL_REQUEST_BYTES)
        except ResourceLimitError:
            self._signal_resource_limit(correlation)
            raise
        self._consume(
            "_model_invocations",
            self._limits.model_invocations,
            correlation,
        )

    def after_model_call(
        self,
        response: BaseModel,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        self.checkpoint(correlation=correlation)
        try:
            require_serialized_size(response, MAX_MODEL_RESPONSE_BYTES)
        except ResourceLimitError:
            self._signal_resource_limit(correlation)
            raise

    def accept_tool_request(
        self,
        arguments_json: str,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        try:
            require_utf8_size(arguments_json, MAX_TOOL_ARGUMENTS_BYTES)
        except ResourceLimitError:
            self._signal_resource_limit(correlation)
            raise
        self._consume(
            "_tool_requests",
            self._limits.tool_requests,
            correlation,
        )

    def before_tool_execution(
        self,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        self._consume(
            "_tool_executions",
            self._limits.tool_executions,
            correlation,
        )

    def after_tool_execution(
        self,
        result: BaseModel,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        self.checkpoint(correlation=correlation)
        try:
            require_serialized_size(result, MAX_KNOWLEDGE_RESULT_BYTES)
        except ResourceLimitError:
            self._signal_resource_limit(correlation)
            raise

    def accept_final_summary(
        self,
        summary: str,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        self.checkpoint(correlation=correlation)
        try:
            require_utf8_size(summary, MAX_FINAL_SUMMARY_BYTES)
        except ResourceLimitError:
            self._signal_resource_limit(correlation)
            raise

    def reserve_draft_proposal(self) -> None:
        self._consume("_draft_proposals", self._limits.draft_proposals)

    def reserve_draft_challenge(self) -> None:
        self._consume("_draft_challenges", self._limits.draft_challenges)

    def reserve_authentication_attempt(self) -> None:
        self._consume(
            "_authentication_attempts",
            self._limits.authentication_attempts,
        )

    def reserve_draft_grant(self) -> None:
        self._consume("_draft_grants", self._limits.draft_grants)

    def reserve_draft_file(self) -> None:
        self._consume("_draft_files", self._limits.draft_files)

    def _consume(
        self,
        attribute: str,
        maximum: int,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        with self._lock:
            self._checkpoint_locked(correlation)
            current = getattr(self, attribute)
            if current >= maximum:
                self._signal_resource_limit(correlation)
                raise ResourceLimitError(_LIMIT_MESSAGE)
            setattr(self, attribute, current + 1)

    def _checkpoint_locked(
        self,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        now = self._read_clock()
        if now < self._started_at:
            self._signal_resource_limit(correlation)
            raise ResourceLimitError(_LIMIT_MESSAGE)
        self._last_checkpoint = now
        maximum = self._limits.elapsed_seconds
        if maximum is not None and now - self._started_at > maximum:
            self._signal_resource_limit(correlation)
            raise ResourceLimitError(_LIMIT_MESSAGE)

    def _signal_resource_limit(
        self,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        if not self._security_journal.is_finished:
            self._security_journal.signal(
                "resource_limit_exceeded",
                source="resource_control",
                outcome="limited",
                correlation=correlation,
            )

    def _read_clock(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ResourceLimitError(_LIMIT_MESSAGE)
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ResourceLimitError(_LIMIT_MESSAGE)
        return numeric
