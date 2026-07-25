"""Política de salida determinista y propiedad de la aplicación."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

OutputChannel = Literal["final_summary", "draft_title", "draft_body"]
PolicyDecision = Literal["allow", "redact"]
RedactionCategory = Literal["email", "local_path"]

POLICY_ID = "GSL-OUTPUT-POLICY-001"
POLICY_VERSION = "1.0.0"

_CHECKED_TEXT_ISSUER = object()
_CHANNELS = frozenset(("final_summary", "draft_title", "draft_body"))
_DRAFT_CHANNELS = frozenset(("draft_title", "draft_body"))

_EMAIL = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}"
    r"(?![\w.-])",
    re.IGNORECASE,
)
_MACOS_ABSOLUTE_PATH = re.compile(
    r"(?<![\w:])/(?:Users|Applications|Volumes|Library|System|private|tmp|"
    r"var|opt|usr|etc)(?:/[^\s<>\"'`]+)+"
)
_WINDOWS_DRIVE_PATH = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z]:\\)(?:[^\\\r\n<>:\"|?*]+\\)*"
    r"[^\\\r\n<>:\"|?*\s]+"
)
_WINDOWS_UNC_PATH = re.compile(
    r"(?<!\\)\\\\[^\\\s<>:\"|?*]+\\[^\\\s<>:\"|?*]+"
    r"(?:\\[^\\\r\n<>:\"|?*]+)*"
)

_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9][A-Z0-9 ]* )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_AUTHORIZATION_BEARER = re.compile(
    r"\bAuthorization\s*:\s*Bearer\s+\S+",
    re.IGNORECASE,
)
_EXPLICIT_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?<!\w)[\"']?(?:credential|password|passwd|pwd|api[_-]?key|"
    r"client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"secret[_-]?key|token|secret)[\"']?\s*(?:=|:)\s*"
    r"[\"']?[^\s\"'`,;]{4,}",
    re.IGNORECASE,
)
_HIDDEN_CONTROL = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    "\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)
_ACTIVE_DRAFT_CONTENT = re.compile(
    r"(?:"
    r"<\s*(?:script|iframe|object|embed|form|input|button|svg|math)\b|"
    r"javascript\s*:|"
    r"data\s*:\s*text/html|"
    r"!\[\[[^\]]+\]\]|"
    r"!?\[[^\]]*\]\(\s*https?://|"
    r"<\s*https?://|"
    r"https?://"
    r")",
    re.IGNORECASE,
)

_FORBIDDEN_CLAIMS = (
    re.compile(
        r"(?:^|[\n.!?;:]\s*)(?:el\s+)?compromiso"
        r"(?:\s+está|\s+ha\s+sido)?\s+confirmado\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\n.!?;:]\s*)(?:el\s+)?equipo\s+ya\s+"
        r"(?:est[aá]\s+)?aislado\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\n.!?;:]\s*)(?:las\s+)?credenciales\s+ya\s+"
        r"(?:est[aá]n\s+|han\s+sido\s+)?revocadas\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\n.!?;:]\s*)(?:the\s+)?compromise"
        r"(?:\s+is|\s+has\s+been)?\s+confirmed\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\n.!?;:]\s*)(?:the\s+)?"
        r"(?:host|machine|endpoint|system|device|computer)"
        r"\s+(?:(?:is\s+)?already|has\s+already\s+been)\s+isolated\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\n.!?;:]\s*)(?:the\s+)?credentials\s+"
        r"(?:(?:are\s+)?already|have\s+already\s+been)\s+revoked\b",
        re.IGNORECASE,
    ),
)


class OutputPolicyError(PermissionError):
    """Base de errores cerrados de la política de salida."""


class OutputPolicyRejectedError(OutputPolicyError):
    """El texto contiene una categoría que la política debe rechazar."""


class PolicyCheckedTextError(OutputPolicyError):
    """El sello no pertenece a esta política y canal."""


@dataclass(frozen=True, slots=True)
class RedactionCount:
    """Conteo seguro por categoría, sin conservar valores."""

    category: RedactionCategory
    count: int


@dataclass(frozen=True, slots=True)
class PolicyDecisionMetadata:
    """Evidencia segura de una decisión de política."""

    policy_id: Literal["GSL-OUTPUT-POLICY-001"]
    policy_version: Literal["1.0.0"]
    channel: OutputChannel
    decision: PolicyDecision
    redaction_categories: tuple[RedactionCategory, ...]
    redaction_counts: tuple[RedactionCount, ...]


@dataclass(frozen=True, slots=True, init=False, eq=False)
class PolicyCheckedText:
    """Sello opaco emitido por una instancia concreta de la política."""

    _marker: object
    _metadata: PolicyDecisionMetadata

    def __init__(
        self,
        metadata: PolicyDecisionMetadata,
        *,
        _issuer_token: object | None = None,
    ) -> None:
        if _issuer_token is not _CHECKED_TEXT_ISSUER:
            raise PolicyCheckedTextError(
                "checked output was not issued by the application policy"
            )
        object.__setattr__(self, "_marker", object())
        object.__setattr__(self, "_metadata", metadata)

    @property
    def metadata(self) -> PolicyDecisionMetadata:
        return self._metadata

    def __repr__(self) -> str:
        return (
            "PolicyCheckedText("
            f"policy_id={self._metadata.policy_id!r}, "
            f"version={self._metadata.policy_version!r}, "
            f"channel={self._metadata.channel!r}, "
            f"decision={self._metadata.decision!r}, "
            f"redactions={sum(item.count for item in self._metadata.redaction_counts)}, "
            "text=<opaque>)"
        )


@dataclass(frozen=True, slots=True)
class _IssuedText:
    channel: OutputChannel
    text: str


class OutputPolicy:
    """Aplica una política cerrada de rechazo, redacción o permiso."""

    __slots__ = ("_issued",)

    policy_id: Literal["GSL-OUTPUT-POLICY-001"] = POLICY_ID
    version: Literal["1.0.0"] = POLICY_VERSION

    def __init__(self) -> None:
        self._issued: dict[PolicyCheckedText, _IssuedText] = {}

    def check(
        self,
        text: str,
        *,
        channel: OutputChannel,
    ) -> PolicyCheckedText:
        """Comprueba un texto con precedencia rechazo, redacción y permiso."""

        if not isinstance(text, str):
            raise TypeError("output text must be a string")
        self._require_channel(channel)
        self._reject_if_required(text, channel)

        sanitized = text
        counts: list[RedactionCount] = []
        sanitized, email_count = _EMAIL.subn("[REDACTED_EMAIL]", sanitized)
        if email_count:
            counts.append(RedactionCount(category="email", count=email_count))

        local_path_count = 0
        for pattern in (
            _MACOS_ABSOLUTE_PATH,
            _WINDOWS_DRIVE_PATH,
            _WINDOWS_UNC_PATH,
        ):
            sanitized, count = pattern.subn(
                "[REDACTED_LOCAL_PATH]",
                sanitized,
            )
            local_path_count += count
        if local_path_count:
            counts.append(
                RedactionCount(
                    category="local_path",
                    count=local_path_count,
                )
            )

        self._reject_if_required(sanitized, channel)
        metadata = PolicyDecisionMetadata(
            policy_id=self.policy_id,
            policy_version=self.version,
            channel=channel,
            decision="redact" if counts else "allow",
            redaction_categories=tuple(item.category for item in counts),
            redaction_counts=tuple(counts),
        )
        checked = PolicyCheckedText(
            metadata,
            _issuer_token=_CHECKED_TEXT_ISSUER,
        )
        self._issued[checked] = _IssuedText(channel=channel, text=sanitized)
        return checked

    def unwrap(
        self,
        checked: PolicyCheckedText,
        *,
        channel: OutputChannel,
    ) -> str:
        """Devuelve únicamente texto emitido por esta instancia y canal."""

        self._require_channel(channel)
        if not isinstance(checked, PolicyCheckedText):
            raise PolicyCheckedTextError(
                "checked output is invalid for this policy and channel"
            )
        issued = self._issued.get(checked)
        if issued is None or issued.channel != channel:
            raise PolicyCheckedTextError(
                "checked output is invalid for this policy and channel"
            )
        return issued.text

    @staticmethod
    def _require_channel(channel: str) -> None:
        if channel not in _CHANNELS:
            raise ValueError("output channel is not supported")

    @staticmethod
    def _reject_if_required(text: str, channel: OutputChannel) -> None:
        reject = (
            "CANARY_GSL_EX_003" in text
            or _PEM_PRIVATE_KEY.search(text) is not None
            or _AUTHORIZATION_BEARER.search(text) is not None
            or _EXPLICIT_CREDENTIAL_ASSIGNMENT.search(text) is not None
            or _HIDDEN_CONTROL.search(text) is not None
            or any(
                pattern.search(text) is not None
                for pattern in _FORBIDDEN_CLAIMS
            )
            or (
                channel in _DRAFT_CHANNELS
                and _ACTIVE_DRAFT_CONTENT.search(text) is not None
            )
        )
        if reject:
            raise OutputPolicyRejectedError(
                "output rejected by application policy"
            )
