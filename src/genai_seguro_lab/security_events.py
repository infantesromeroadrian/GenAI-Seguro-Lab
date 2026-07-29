"""Eventos de seguridad saneados, correlacionados y acotados en memoria."""

from __future__ import annotations

import json
import math
import secrets
import threading
from collections.abc import Callable
from hashlib import sha256
from time import monotonic
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

SECURITY_EVENTS_ID = "GSL-SECURITY-EVENTS-001"
SECURITY_EVENTS_VERSION = "1.0.0"

MAX_SECURITY_EVENT_BYTES = 2 * 1024
MAX_SECURITY_EVENT_ELAPSED_MS = 24 * 60 * 60 * 1000

SecurityEventProfile = Literal[
    "analyze",
    "cloud_analyze",
    "baseline",
    "draft",
]
SecurityEventKind = Literal[
    "operation_started",
    "operation_completed",
    "operation_failed",
    "model_request",
    "model_response",
    "tool_request",
    "tool_result",
    "policy_decision",
    "effect_attempted",
    "effect_succeeded",
    "effect_failed",
    "security_signal",
]
SecurityEventSource = Literal[
    "flow",
    "model_adapter",
    "knowledge_search",
    "output_policy",
    "resource_control",
    "cli_lock",
    "data_contract",
    "draft_approval",
    "draft_writer",
]
SecurityEventOutcome = Literal[
    "observed",
    "allowed",
    "denied",
    "intervened",
    "succeeded",
    "failed",
    "limited",
    "conflict",
    "completed",
]
SecuritySignal = Literal[
    "unexpected_flow_sequence",
    "unknown_model_request",
    "tool_denied",
    "output_policy_intervention",
    "resource_limit_exceeded",
    "lock_conflict",
    "authentication_failures_repeated",
    "authorization_replay_or_context_mismatch",
    "sandbox_violation",
    "data_integrity_violation",
    "provider_error",
]

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
CorrelationId = Annotated[str, Field(pattern=r"^corr_[0-9a-f]{32}$")]

_GENESIS_HASH = "0" * 64
_CORRELATION_ISSUER = object()
_RESERVATION_ISSUER = object()
_LIMIT_MESSAGE = "security event journal limit exceeded"
_STATE_MESSAGE = "security event journal state is invalid"


class SecurityEventError(RuntimeError):
    """Error base del journal sin incorporar contenido observado."""


class SecurityEventLimitError(SecurityEventError):
    """El journal no puede aceptar más evidencia de forma segura."""


class SecurityEventStateError(SecurityEventError):
    """La operación no respeta el ciclo de vida cerrado del journal."""


class _SecuritySchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SecurityEvent(_SecuritySchema):
    """Evento cerrado: solo metadatos enumerados y hashes canónicos."""

    control_id: Literal["GSL-SECURITY-EVENTS-001"]
    version: Literal["1.0.0"]
    sequence: Annotated[int, Field(ge=1)]
    correlation_id: CorrelationId
    elapsed_ms: Annotated[int, Field(ge=0, le=MAX_SECURITY_EVENT_ELAPSED_MS)]
    kind: SecurityEventKind
    source: SecurityEventSource
    outcome: SecurityEventOutcome
    signal: SecuritySignal | None
    previous_event_sha256: Sha256
    event_sha256: Sha256

    @model_validator(mode="after")
    def validate_signal_shape(self) -> Self:
        if (self.kind == "security_signal") != (self.signal is not None):
            raise ValueError("security signal shape is invalid")
        return self


class SecurityEventReport(_SecuritySchema):
    """Snapshot inmutable y verificable del journal en memoria."""

    control_id: Literal["GSL-SECURITY-EVENTS-001"]
    version: Literal["1.0.0"]
    profile: SecurityEventProfile
    events_count: Annotated[int, Field(ge=1)]
    bytes_used: Annotated[int, Field(ge=1)]
    correlations_count: Annotated[int, Field(ge=1)]
    chain_head_sha256: Sha256
    events: Annotated[tuple[SecurityEvent, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        limits = _PROFILE_LIMITS[self.profile]
        if self.events_count != len(self.events):
            raise ValueError("security event count does not match")
        encoded_sizes = tuple(
            len(canonical_security_event_json(event).encode("utf-8"))
            for event in self.events
        )
        if any(size > MAX_SECURITY_EVENT_BYTES for size in encoded_sizes):
            raise ValueError("security event exceeds its byte limit")
        if self.bytes_used != sum(encoded_sizes):
            raise ValueError("security event byte count does not match")
        if (
            self.events_count > limits.events
            or self.bytes_used > limits.bytes
        ):
            raise ValueError("security event report exceeds its profile limit")
        if self.correlations_count != len(
            {event.correlation_id for event in self.events}
        ):
            raise ValueError("security correlation count does not match")
        if self.chain_head_sha256 != self.events[-1].event_sha256:
            raise ValueError("security event chain head does not match")
        verify_security_event_chain(self.events)
        return self


class SecurityCorrelation:
    """Identificador opaco emitido aleatoriamente por un journal concreto."""

    __slots__ = ("_identifier", "_journal", "_marker")

    def __init__(
        self,
        identifier: str,
        *,
        _issuer_token: object | None = None,
        _journal: SecurityEventJournal | None = None,
    ) -> None:
        if _issuer_token is not _CORRELATION_ISSUER or _journal is None:
            raise SecurityEventStateError(_STATE_MESSAGE)
        self._identifier = identifier
        self._journal = _journal
        self._marker = object()

    @property
    def identifier(self) -> str:
        return self._identifier

    def __repr__(self) -> str:
        return "SecurityCorrelation(<opaque>)"


class _DraftEffectReservation:
    """Reserva opaca de intento y resultado antes de cualquier efecto."""

    __slots__ = (
        "_completed",
        "_correlation",
        "_journal",
        "_marker",
        "_started",
    )

    def __init__(
        self,
        correlation: SecurityCorrelation,
        *,
        _issuer_token: object | None = None,
        _journal: SecurityEventJournal | None = None,
    ) -> None:
        if _issuer_token is not _RESERVATION_ISSUER or _journal is None:
            raise SecurityEventStateError(_STATE_MESSAGE)
        self._correlation = correlation
        self._journal = _journal
        self._marker = object()
        self._started = False
        self._completed = False

    def __repr__(self) -> str:
        return "DraftEffectEventReservation(<opaque>)"


class _ProfileLimits(_SecuritySchema):
    events: Annotated[int, Field(ge=2)]
    bytes: Annotated[int, Field(ge=2 * MAX_SECURITY_EVENT_BYTES)]


_PROFILE_LIMITS: dict[SecurityEventProfile, _ProfileLimits] = {
    "analyze": _ProfileLimits(events=32, bytes=32 * 1024),
    "cloud_analyze": _ProfileLimits(events=32, bytes=32 * 1024),
    "baseline": _ProfileLimits(events=256, bytes=256 * 1024),
    "draft": _ProfileLimits(events=32, bytes=32 * 1024),
}


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_security_event_json(event: SecurityEvent) -> str:
    if not isinstance(event, SecurityEvent):
        raise TypeError("event must be a SecurityEvent")
    return _canonical_json(event.model_dump(mode="json"))


def canonical_security_report_json(report: SecurityEventReport) -> str:
    if not isinstance(report, SecurityEventReport):
        raise TypeError("report must be a SecurityEventReport")
    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def verify_security_event_chain(events: tuple[SecurityEvent, ...]) -> None:
    """Verifica secuencia global, tiempo monotónico y cadena SHA-256."""

    if not isinstance(events, tuple):
        raise TypeError("events must be a tuple")
    previous_hash = _GENESIS_HASH
    previous_elapsed = 0
    for expected_sequence, event in enumerate(events, start=1):
        if not isinstance(event, SecurityEvent):
            raise TypeError("events must contain SecurityEvent values")
        if event.sequence != expected_sequence:
            raise ValueError("security event sequence is not contiguous")
        if event.elapsed_ms < previous_elapsed:
            raise ValueError("security event elapsed time is not monotonic")
        if event.previous_event_sha256 != previous_hash:
            raise ValueError("security event chain link does not match")
        body = event.model_dump(mode="json", exclude={"event_sha256"})
        expected_hash = sha256(
            _canonical_json(body).encode("utf-8")
        ).hexdigest()
        if event.event_sha256 != expected_hash:
            raise ValueError("security event hash does not match")
        previous_hash = event.event_sha256
        previous_elapsed = event.elapsed_ms


class SecurityEventJournal:
    """Journal en memoria con append atómico y snapshots inmutables."""

    control_id: Literal["GSL-SECURITY-EVENTS-001"] = SECURITY_EVENTS_ID
    version: Literal["1.0.0"] = SECURITY_EVENTS_VERSION

    def __init__(
        self,
        profile: SecurityEventProfile,
        *,
        clock: Callable[[], float] = monotonic,
        token_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if profile not in _PROFILE_LIMITS:
            raise ValueError("unknown security event profile")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not callable(token_bytes):
            raise TypeError("token_bytes must be callable")
        self._profile = profile
        self._limits = _PROFILE_LIMITS[profile]
        self._clock = clock
        self._token_bytes = token_bytes
        self._lock = threading.RLock()
        self._started_at = self._read_clock()
        self._last_elapsed_ms = 0
        self._events: list[SecurityEvent] = []
        self._bytes_used = 0
        self._correlations: dict[str, SecurityCorrelation] = {}
        self._authentication_failures: dict[str, int] = {}
        self._reserved_events = 0
        self._reserved_bytes = 0
        self._terminal = False
        self._primary_correlation = self.new_correlation()
        self.observe(
            kind="operation_started",
            source="flow",
            outcome="observed",
        )

    @classmethod
    def create(
        cls,
        profile: SecurityEventProfile,
        *,
        clock: Callable[[], float] = monotonic,
        token_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> SecurityEventJournal:
        return cls(profile, clock=clock, token_bytes=token_bytes)

    @property
    def profile(self) -> SecurityEventProfile:
        return self._profile

    @property
    def primary_correlation(self) -> SecurityCorrelation:
        return self._primary_correlation

    @property
    def events(self) -> tuple[SecurityEvent, ...]:
        with self._lock:
            return tuple(self._events)

    @property
    def bytes_used(self) -> int:
        with self._lock:
            return self._bytes_used

    @property
    def is_finished(self) -> bool:
        with self._lock:
            return self._terminal

    @property
    def limits(self) -> tuple[int, int]:
        return self._limits.events, self._limits.bytes

    def new_correlation(self) -> SecurityCorrelation:
        with self._lock:
            raw = self._token_bytes(16)
            if not isinstance(raw, bytes) or len(raw) != 16:
                raise SecurityEventStateError(_STATE_MESSAGE)
            identifier = f"corr_{raw.hex()}"
            if identifier in self._correlations:
                raise SecurityEventStateError(_STATE_MESSAGE)
            correlation = SecurityCorrelation(
                identifier,
                _issuer_token=_CORRELATION_ISSUER,
                _journal=self,
            )
            self._correlations[identifier] = correlation
            return correlation

    def observe(
        self,
        *,
        kind: SecurityEventKind,
        source: SecurityEventSource,
        outcome: SecurityEventOutcome,
        correlation: SecurityCorrelation | None = None,
    ) -> SecurityEvent:
        if kind in {
            "security_signal",
            "operation_completed",
            "operation_failed",
            "effect_attempted",
            "effect_succeeded",
            "effect_failed",
        }:
            raise SecurityEventStateError(_STATE_MESSAGE)
        with self._lock:
            return self._append_unreserved(
                kind=kind,
                source=source,
                outcome=outcome,
                signal=None,
                correlation=self._require_correlation(correlation),
            )

    def signal(
        self,
        signal: SecuritySignal,
        *,
        source: SecurityEventSource,
        outcome: SecurityEventOutcome,
        correlation: SecurityCorrelation | None = None,
    ) -> SecurityEvent:
        with self._lock:
            return self._append_unreserved(
                kind="security_signal",
                source=source,
                outcome=outcome,
                signal=signal,
                correlation=self._require_correlation(correlation),
            )

    def authentication_failed(
        self,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> SecurityEvent | None:
        with self._lock:
            selected = self._require_correlation(correlation)
            failures = self._authentication_failures.get(
                selected.identifier,
                0,
            )
            if failures >= 3:
                return None
            failures += 1
            self._authentication_failures[selected.identifier] = failures
            if failures != 3:
                return None
            return self._append_unreserved(
                kind="security_signal",
                source="draft_approval",
                outcome="denied",
                signal="authentication_failures_repeated",
                correlation=selected,
            )

    def authentication_succeeded(
        self,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> None:
        with self._lock:
            selected = self._require_correlation(correlation)
            self._authentication_failures.pop(selected.identifier, None)

    def reserve_draft_effect(
        self,
        *,
        correlation: SecurityCorrelation | None = None,
    ) -> _DraftEffectReservation:
        with self._lock:
            if self._profile != "draft" or self._terminal:
                raise SecurityEventStateError(_STATE_MESSAGE)
            selected = self._require_correlation(correlation)
            self._require_capacity(
                event_count=2,
                byte_count=2 * MAX_SECURITY_EVENT_BYTES,
                preserve_terminal=True,
            )
            self._reserved_events += 2
            self._reserved_bytes += 2 * MAX_SECURITY_EVENT_BYTES
            return _DraftEffectReservation(
                selected,
                _issuer_token=_RESERVATION_ISSUER,
                _journal=self,
            )

    def begin_draft_effect(
        self,
        reservation: _DraftEffectReservation,
    ) -> SecurityEvent:
        with self._lock:
            self._require_reservation(reservation)
            if reservation._started or reservation._completed:
                raise SecurityEventStateError(_STATE_MESSAGE)
            event = self._append_reserved(
                kind="effect_attempted",
                source="draft_writer",
                outcome="observed",
                correlation=reservation._correlation,
            )
            reservation._started = True
            return event

    def cancel_draft_effect(
        self,
        reservation: _DraftEffectReservation,
    ) -> None:
        """Libera una reserva que aún no llegó al límite de I/O."""

        with self._lock:
            self._require_reservation(reservation)
            if reservation._started or reservation._completed:
                raise SecurityEventStateError(_STATE_MESSAGE)
            if (
                self._reserved_events < 2
                or self._reserved_bytes < 2 * MAX_SECURITY_EVENT_BYTES
            ):
                raise SecurityEventStateError(_STATE_MESSAGE)
            self._reserved_events -= 2
            self._reserved_bytes -= 2 * MAX_SECURITY_EVENT_BYTES
            reservation._completed = True

    def complete_draft_effect(
        self,
        reservation: _DraftEffectReservation,
        *,
        succeeded: bool,
    ) -> SecurityEvent:
        if not isinstance(succeeded, bool):
            raise TypeError("succeeded must be a bool")
        with self._lock:
            self._require_reservation(reservation)
            if not reservation._started or reservation._completed:
                raise SecurityEventStateError(_STATE_MESSAGE)
            event = self._append_reserved(
                kind="effect_succeeded" if succeeded else "effect_failed",
                source="draft_writer",
                outcome="succeeded" if succeeded else "failed",
                correlation=reservation._correlation,
            )
            reservation._completed = True
            return event

    def finish(
        self,
        *,
        succeeded: bool,
        correlation: SecurityCorrelation | None = None,
    ) -> SecurityEvent:
        if not isinstance(succeeded, bool):
            raise TypeError("succeeded must be a bool")
        with self._lock:
            if self._terminal:
                raise SecurityEventStateError(_STATE_MESSAGE)
            if self._reserved_events or self._reserved_bytes:
                raise SecurityEventStateError(_STATE_MESSAGE)
            selected = self._require_correlation(correlation)
            event = self._build_event(
                kind="operation_completed" if succeeded else "operation_failed",
                source="flow",
                outcome="completed" if succeeded else "failed",
                signal=None,
                correlation=selected,
            )
            encoded = canonical_security_event_json(event).encode("utf-8")
            if len(encoded) > MAX_SECURITY_EVENT_BYTES:
                raise SecurityEventLimitError(_LIMIT_MESSAGE)
            if (
                len(self._events) + 1 > self._limits.events
                or self._bytes_used + len(encoded) > self._limits.bytes
            ):
                raise SecurityEventLimitError(_LIMIT_MESSAGE)
            self._events.append(event)
            self._bytes_used += len(encoded)
            self._terminal = True
            return event

    def report(self) -> SecurityEventReport:
        with self._lock:
            events = tuple(self._events)
            return SecurityEventReport(
                control_id=self.control_id,
                version=self.version,
                profile=self._profile,
                events_count=len(events),
                bytes_used=self._bytes_used,
                correlations_count=len(
                    {event.correlation_id for event in events}
                ),
                chain_head_sha256=events[-1].event_sha256,
                events=events,
            )

    def _append_unreserved(
        self,
        *,
        kind: SecurityEventKind,
        source: SecurityEventSource,
        outcome: SecurityEventOutcome,
        signal: SecuritySignal | None,
        correlation: SecurityCorrelation,
    ) -> SecurityEvent:
        if self._terminal:
            raise SecurityEventStateError(_STATE_MESSAGE)
        event = self._build_event(
            kind=kind,
            source=source,
            outcome=outcome,
            signal=signal,
            correlation=correlation,
        )
        encoded = canonical_security_event_json(event).encode("utf-8")
        if len(encoded) > MAX_SECURITY_EVENT_BYTES:
            raise SecurityEventLimitError(_LIMIT_MESSAGE)
        self._require_capacity(
            event_count=1,
            byte_count=len(encoded),
            preserve_terminal=True,
        )
        self._events.append(event)
        self._bytes_used += len(encoded)
        return event

    def _append_reserved(
        self,
        *,
        kind: SecurityEventKind,
        source: SecurityEventSource,
        outcome: SecurityEventOutcome,
        correlation: SecurityCorrelation,
    ) -> SecurityEvent:
        event = self._build_event(
            kind=kind,
            source=source,
            outcome=outcome,
            signal=None,
            correlation=correlation,
        )
        encoded = canonical_security_event_json(event).encode("utf-8")
        if len(encoded) > MAX_SECURITY_EVENT_BYTES:
            raise SecurityEventLimitError(_LIMIT_MESSAGE)
        if (
            self._reserved_events < 1
            or self._reserved_bytes < MAX_SECURITY_EVENT_BYTES
        ):
            raise SecurityEventStateError(_STATE_MESSAGE)
        self._reserved_events -= 1
        self._reserved_bytes -= MAX_SECURITY_EVENT_BYTES
        self._events.append(event)
        self._bytes_used += len(encoded)
        return event

    def _build_event(
        self,
        *,
        kind: SecurityEventKind,
        source: SecurityEventSource,
        outcome: SecurityEventOutcome,
        signal: SecuritySignal | None,
        correlation: SecurityCorrelation,
    ) -> SecurityEvent:
        sequence = len(self._events) + 1
        elapsed_ms = self._read_elapsed_ms()
        previous_hash = (
            self._events[-1].event_sha256
            if self._events
            else _GENESIS_HASH
        )
        body = {
            "control_id": self.control_id,
            "version": self.version,
            "sequence": sequence,
            "correlation_id": correlation.identifier,
            "elapsed_ms": elapsed_ms,
            "kind": kind,
            "source": source,
            "outcome": outcome,
            "signal": signal,
            "previous_event_sha256": previous_hash,
        }
        event_hash = sha256(
            _canonical_json(body).encode("utf-8")
        ).hexdigest()
        return SecurityEvent(**body, event_sha256=event_hash)

    def _require_capacity(
        self,
        *,
        event_count: int,
        byte_count: int,
        preserve_terminal: bool,
    ) -> None:
        terminal_events = 1 if preserve_terminal else 0
        terminal_bytes = (
            MAX_SECURITY_EVENT_BYTES if preserve_terminal else 0
        )
        if (
            len(self._events)
            + self._reserved_events
            + event_count
            + terminal_events
            > self._limits.events
            or self._bytes_used
            + self._reserved_bytes
            + byte_count
            + terminal_bytes
            > self._limits.bytes
        ):
            raise SecurityEventLimitError(_LIMIT_MESSAGE)

    def _require_correlation(
        self,
        correlation: SecurityCorrelation | None,
    ) -> SecurityCorrelation:
        selected = correlation or self._primary_correlation
        if (
            not isinstance(selected, SecurityCorrelation)
            or selected._journal is not self
            or self._correlations.get(selected.identifier) is not selected
        ):
            raise SecurityEventStateError(_STATE_MESSAGE)
        return selected

    def _require_reservation(
        self,
        reservation: _DraftEffectReservation,
    ) -> None:
        if (
            not isinstance(reservation, _DraftEffectReservation)
            or reservation._journal is not self
            or reservation._correlation._journal is not self
        ):
            raise SecurityEventStateError(_STATE_MESSAGE)

    def _read_elapsed_ms(self) -> int:
        now = self._read_clock()
        elapsed = now - self._started_at
        if elapsed < 0:
            raise SecurityEventStateError(_STATE_MESSAGE)
        elapsed_ms = int(elapsed * 1000)
        if (
            elapsed_ms < self._last_elapsed_ms
            or elapsed_ms > MAX_SECURITY_EVENT_ELAPSED_MS
        ):
            raise SecurityEventStateError(_STATE_MESSAGE)
        self._last_elapsed_ms = elapsed_ms
        return elapsed_ms

    def _read_clock(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SecurityEventStateError(_STATE_MESSAGE)
        numeric = float(value)
        if not math.isfinite(numeric):
            raise SecurityEventStateError(_STATE_MESSAGE)
        return numeric
