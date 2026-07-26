"""Herramientas locales con autoridad de aplicación y datos acotados."""

from __future__ import annotations

import errno
import hmac
import json
import os
import re
import secrets
import stat
import threading
import weakref
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from hashlib import pbkdf2_hmac, sha256
from pathlib import Path
from time import monotonic
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .data_contract import (
    IncidentCategory,
    IncidentRecord,
    KnowledgeId,
    KnowledgeRecord,
)
from .model_adapter import KnownToolName, ModelToolRequest
from .output_policy import OutputPolicy
from .resource_control import (
    MAX_DRAFT_MARKDOWN_BYTES,
    MAX_KNOWLEDGE_RESULT_BYTES,
    MAX_TOOL_ARGUMENTS_BYTES,
    ProductResourceControl,
    require_serialized_size,
    require_utf8_size,
)

Text = Annotated[str, Field(min_length=1)]
Query = Annotated[
    str,
    Field(
        min_length=1,
        max_length=200,
        pattern=r"^[^\r\n]*\S[^\r\n]*$",
    ),
]
DraftFilename = Annotated[
    str,
    Field(
        max_length=64,
        pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,58}[a-z0-9])?\.md$",
    ),
]
DraftTitle = Annotated[
    str,
    Field(min_length=1, max_length=120, pattern=r"^[^\r\n]+$"),
]
DraftBody = Annotated[str, Field(min_length=1, max_length=10_000)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
OperationPrincipal = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]*$",
    ),
]
OperationScope = Annotated[
    str,
    Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]*$",
    ),
]

AUTHENTICATED_APPROVAL_CONTROL = "PGS-04-M04"
_CREDENTIAL_KDF_ITERATIONS = 120_000
_GRANT_ISSUER_TOKEN = object()
_KNOWLEDGE_TOOL_FACTORY_TOKEN = object()
_DRAFT_APPROVAL_ISSUER_TOKEN = object()
_DRAFT_EFFECT_ISSUER_TOKEN = object()
_DRAFT_AUTHORITY_CHANNEL_TOKEN = object()


class ToolSchema(BaseModel):
    """Base estricta e inmutable para entradas y resultados de herramientas."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ToolDeniedError(PermissionError):
    """La solicitud no pertenece al alcance autorizado."""


class ToolArgumentsError(ValueError):
    """Los argumentos no cumplen el esquema de la herramienta."""


class ToolPolicyError(ValueError):
    """La autoridad de ejecución no es válida para una herramienta."""


class DraftProposalError(PermissionError):
    """La propuesta no fue preparada por esta instancia de escritura."""


class DraftApprovalError(PermissionError):
    """La aprobación no autoriza esta propuesta y efecto exactos."""


class DraftAlreadyExistsError(FileExistsError):
    """La política create-only impide escribir el destino."""


class SandboxViolationError(PermissionError):
    """El destino ya no cumple el límite físico del sandbox."""


class _GrantContract(ToolSchema):
    principal: OperationPrincipal
    scope: OperationScope
    tool: KnownToolName
    allowed_knowledge_ids: Annotated[
        tuple[KnowledgeId, ...],
        Field(max_length=8),
    ] = ()

    @field_validator("allowed_knowledge_ids")
    @classmethod
    def reject_duplicate_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("grant knowledge identifiers must be unique")
        return value


@dataclass(frozen=True, slots=True, init=False)
class ToolExecutionGrant:
    """Grant opaco emitido por la aplicación para una sola herramienta."""

    principal: str
    scope: str
    tool: KnownToolName
    allowed_knowledge_ids: tuple[str, ...]
    _binding: object = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        principal: str,
        scope: str,
        tool: KnownToolName,
        allowed_knowledge_ids: tuple[str, ...] = (),
        _issuer_token: object | None = None,
        _binding: object | None = None,
    ) -> None:
        if (
            _issuer_token is not _GRANT_ISSUER_TOKEN
            or _binding is None
        ):
            raise ToolPolicyError(
                "tool grants must be issued by the application"
            )
        try:
            contract = _GrantContract(
                principal=principal,
                scope=scope,
                tool=tool,
                allowed_knowledge_ids=allowed_knowledge_ids,
            )
        except ValidationError as exc:
            raise ToolPolicyError("tool grant contract is invalid") from exc
        object.__setattr__(self, "principal", contract.principal)
        object.__setattr__(self, "scope", contract.scope)
        object.__setattr__(self, "tool", contract.tool)
        object.__setattr__(
            self,
            "allowed_knowledge_ids",
            contract.allowed_knowledge_ids,
        )
        object.__setattr__(self, "_binding", _binding)


def _issue_tool_grant(
    *,
    principal: str,
    scope: str,
    tool: KnownToolName,
    binding: object,
    allowed_knowledge_ids: tuple[str, ...] = (),
) -> ToolExecutionGrant:
    return ToolExecutionGrant(
        principal=principal,
        scope=scope,
        tool=tool,
        allowed_knowledge_ids=allowed_knowledge_ids,
        _issuer_token=_GRANT_ISSUER_TOKEN,
        _binding=binding,
    )


class KnowledgeSearchArguments(ToolSchema):
    query: Query
    knowledge_ids: Annotated[
        tuple[KnowledgeId, ...],
        Field(min_length=1, max_length=8),
    ]
    limit: Annotated[int, Field(ge=1, le=5)] = 3

    @field_validator("knowledge_ids")
    @classmethod
    def reject_duplicate_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("knowledge identifiers must be unique")
        return value


class KnowledgeHit(ToolSchema):
    id: KnowledgeId
    topic: IncidentCategory
    title: Text
    content: Text
    procedures: Annotated[tuple[Text, ...], Field(min_length=1)]


class KnowledgeSearchResult(ToolSchema):
    query: Query
    hits: tuple[KnowledgeHit, ...]


class KnowledgeCatalog:
    """Catálogo de aplicación que entrega vistas físicas por incidente."""

    def __init__(self, documents: Iterable[KnowledgeRecord]) -> None:
        indexed: dict[str, KnowledgeRecord] = {}
        for document in documents:
            if not isinstance(document, KnowledgeRecord):
                raise TypeError(
                    "documents must contain KnowledgeRecord values"
                )
            if document.id in indexed:
                raise ValueError(
                    "knowledge document identifiers must be unique"
                )
            indexed[document.id] = document
        if not indexed:
            raise ValueError("at least one knowledge document is required")
        self._documents = indexed

    def for_incident(
        self,
        incident: IncidentRecord,
        *,
        principal: str,
        scope: str,
    ) -> KnowledgeSearchTool:
        if not isinstance(incident, IncidentRecord):
            raise TypeError("incident must be an IncidentRecord")
        expected_scope = f"incident:{incident.id}"
        if scope != expected_scope:
            raise ToolPolicyError(
                "knowledge scope must match the validated incident"
            )
        try:
            selected = tuple(
                self._documents[knowledge_id]
                for knowledge_id in incident.knowledge_refs
            )
        except KeyError as exc:
            raise ToolPolicyError(
                "validated incident references unavailable knowledge"
            ) from exc
        return KnowledgeSearchTool(
            incident=incident,
            documents=selected,
            principal=principal,
            scope=scope,
            _factory_token=_KNOWLEDGE_TOOL_FACTORY_TOKEN,
        )


class KnowledgeSearchTool:
    """Busca en la vista física exacta ligada a un incidente validado."""

    def __init__(
        self,
        *,
        incident: IncidentRecord,
        documents: tuple[KnowledgeRecord, ...],
        principal: str,
        scope: str,
        _factory_token: object | None = None,
    ) -> None:
        if _factory_token is not _KNOWLEDGE_TOOL_FACTORY_TOKEN:
            raise ToolPolicyError(
                "knowledge tools must be scoped by the application catalog"
            )
        indexed = {document.id: document for document in documents}
        if (
            len(indexed) != len(documents)
            or tuple(indexed) != incident.knowledge_refs
        ):
            raise ToolPolicyError(
                "knowledge tool requires the exact incident record subset"
            )
        self._documents = indexed
        self._principal = principal
        self._scope = scope
        self._binding = object()
        self._execution_grant = _issue_tool_grant(
            principal=principal,
            scope=scope,
            tool="knowledge_search",
            binding=self._binding,
            allowed_knowledge_ids=incident.knowledge_refs,
        )

    @property
    def execution_grant(self) -> ToolExecutionGrant:
        return self._execution_grant

    @property
    def retained_knowledge_ids(self) -> tuple[str, ...]:
        return tuple(self._documents)

    def search(
        self,
        request: ModelToolRequest,
        *,
        grant: ToolExecutionGrant,
    ) -> KnowledgeSearchResult:
        if not isinstance(request, ModelToolRequest):
            raise TypeError("request must be a ModelToolRequest")
        self._require_grant(grant)
        if request.name != "knowledge_search":
            raise ToolDeniedError("requested tool is not allowed in this flow")

        require_utf8_size(request.arguments_json, MAX_TOOL_ARGUMENTS_BYTES)
        try:
            arguments = KnowledgeSearchArguments.model_validate_json(
                request.arguments_json
            )
        except ValidationError as exc:
            raise ToolArgumentsError(
                "knowledge_search arguments were rejected"
            ) from exc

        requested = set(arguments.knowledge_ids)
        retained = set(self._documents)
        if not requested.issubset(retained):
            raise ToolDeniedError(
                "knowledge request exceeds the incident scope"
            )

        terms = set(re.findall(r"\w+", arguments.query.casefold()))
        if not terms:
            raise ToolArgumentsError("knowledge query has no searchable terms")

        scored: list[tuple[int, KnowledgeRecord]] = []
        for knowledge_id in arguments.knowledge_ids:
            document = self._documents[knowledge_id]
            searchable = " ".join(
                (
                    document.topic,
                    document.title,
                    document.content,
                    *document.procedures,
                )
            ).casefold()
            score = sum(searchable.count(term) for term in terms)
            if score:
                scored.append((score, document))

        scored.sort(key=lambda item: (-item[0], item[1].id))
        hits = tuple(
            KnowledgeHit(
                id=document.id,
                topic=document.topic,
                title=document.title,
                content=document.content,
                procedures=document.procedures,
            )
            for _, document in scored[: arguments.limit]
        )
        result = KnowledgeSearchResult(query=arguments.query, hits=hits)
        require_serialized_size(result, MAX_KNOWLEDGE_RESULT_BYTES)
        return result

    def _require_grant(self, grant: ToolExecutionGrant) -> None:
        if not isinstance(grant, ToolExecutionGrant):
            raise TypeError("grant must be a ToolExecutionGrant")
        if (
            grant is not self._execution_grant
            or grant._binding is not self._binding
            or grant.principal != self._principal
            or grant.scope != self._scope
            or grant.tool != "knowledge_search"
            or grant.allowed_knowledge_ids != tuple(self._documents)
        ):
            raise ToolDeniedError(
                "tool grant does not belong to this principal and scope"
            )


class DraftContent(ToolSchema):
    filename: DraftFilename
    title: DraftTitle
    body: DraftBody
    references: Annotated[
        tuple[KnowledgeId, ...],
        Field(max_length=8),
    ] = ()

    @field_validator("references")
    @classmethod
    def reject_duplicate_references(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("draft references must be unique")
        return value


class DraftCreateArguments(DraftContent):
    pass


def _draft_fingerprint(content: DraftContent) -> str:
    canonical = json.dumps(
        content.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


class DraftProposal(DraftContent):
    proposal_fingerprint: Sha256

    @classmethod
    def from_arguments(cls, arguments: DraftCreateArguments) -> DraftProposal:
        values = arguments.model_dump()
        return cls(
            **values,
            proposal_fingerprint=_draft_fingerprint(arguments),
        )

    @model_validator(mode="after")
    def verify_fingerprint(self) -> Self:
        content = DraftContent(
            filename=self.filename,
            title=self.title,
            body=self.body,
            references=self.references,
        )
        if self.proposal_fingerprint != _draft_fingerprint(content):
            raise ValueError("proposal fingerprint does not match its content")
        return self


class DraftApprovalChallenge:
    """Challenge opaco emitido para una propuesta exacta."""

    __slots__ = ("_marker",)

    def __init__(self, *, _issuer_token: object | None = None) -> None:
        if _issuer_token is not _DRAFT_APPROVAL_ISSUER_TOKEN:
            raise DraftApprovalError(
                "approval challenges must be issued by the authority"
            )
        self._marker = object()

    def __repr__(self) -> str:
        return "DraftApprovalChallenge(<opaque>)"


class DraftApproval:
    """Aprobación opaca autenticada por una autoridad local."""

    __slots__ = ("_marker",)

    def __init__(self, *, _issuer_token: object | None = None) -> None:
        if _issuer_token is not _DRAFT_APPROVAL_ISSUER_TOKEN:
            raise DraftApprovalError(
                "draft approvals must be issued by the authority"
            )
        self._marker = object()

    def __repr__(self) -> str:
        return "DraftApproval(<opaque>)"


class _DraftEffectContract(ToolSchema):
    approval_identity: OperationPrincipal
    principal: OperationPrincipal
    scope: OperationScope
    tool: Literal["draft_create"]
    proposal_fingerprint: Sha256
    effect: Literal["create"]
    approval_identity_authenticated: Literal[True]
    human_interaction_verified: Literal[False]
    identity_assurance: Literal["synthetic_local_credential"]
    approval_control: Literal["PGS-04-M04"]


@dataclass(frozen=True, slots=True, init=False, eq=False)
class DraftEffectGrant:
    """Grant de creación ligado a aprobación, propuesta y sesiones exactas."""

    approval_identity: str
    principal: str
    scope: str
    tool: Literal["draft_create"]
    proposal_fingerprint: str
    effect: Literal["create"]
    approval_identity_authenticated: Literal[True]
    human_interaction_verified: Literal[False]
    identity_assurance: Literal["synthetic_local_credential"]
    approval_control: Literal["PGS-04-M04"]
    _writer_binding: object = field(repr=False, compare=False)
    _writer_session: object = field(repr=False, compare=False)
    _root_identity: tuple[int, int] = field(repr=False, compare=False)
    _authority_session: object = field(repr=False, compare=False)
    _proposal: DraftProposal = field(repr=False, compare=False)
    _expires_at: float = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        approval_identity: str,
        principal: str,
        scope: str,
        proposal_fingerprint: str,
        _issuer_token: object | None = None,
        _writer_binding: object | None = None,
        _writer_session: object | None = None,
        _root_identity: tuple[int, int] | None = None,
        _authority_session: object | None = None,
        _proposal: DraftProposal | None = None,
        _expires_at: float | None = None,
    ) -> None:
        if (
            _issuer_token is not _DRAFT_EFFECT_ISSUER_TOKEN
            or _writer_binding is None
            or _writer_session is None
            or _root_identity is None
            or _authority_session is None
            or _proposal is None
            or _expires_at is None
        ):
            raise ToolPolicyError(
                "draft effect grants must be issued by the approval authority"
            )
        try:
            contract = _DraftEffectContract(
                approval_identity=approval_identity,
                principal=principal,
                scope=scope,
                tool="draft_create",
                proposal_fingerprint=proposal_fingerprint,
                effect="create",
                approval_identity_authenticated=True,
                human_interaction_verified=False,
                identity_assurance="synthetic_local_credential",
                approval_control=AUTHENTICATED_APPROVAL_CONTROL,
            )
        except ValidationError as exc:
            raise ToolPolicyError(
                "draft effect grant contract is invalid"
            ) from exc
        object.__setattr__(
            self,
            "approval_identity",
            contract.approval_identity,
        )
        object.__setattr__(self, "principal", contract.principal)
        object.__setattr__(self, "scope", contract.scope)
        object.__setattr__(self, "tool", contract.tool)
        object.__setattr__(
            self,
            "proposal_fingerprint",
            contract.proposal_fingerprint,
        )
        object.__setattr__(self, "effect", contract.effect)
        object.__setattr__(
            self,
            "approval_identity_authenticated",
            contract.approval_identity_authenticated,
        )
        object.__setattr__(
            self,
            "human_interaction_verified",
            contract.human_interaction_verified,
        )
        object.__setattr__(
            self,
            "identity_assurance",
            contract.identity_assurance,
        )
        object.__setattr__(
            self,
            "approval_control",
            contract.approval_control,
        )
        object.__setattr__(self, "_writer_binding", _writer_binding)
        object.__setattr__(self, "_writer_session", _writer_session)
        object.__setattr__(self, "_root_identity", _root_identity)
        object.__setattr__(self, "_authority_session", _authority_session)
        object.__setattr__(self, "_proposal", _proposal)
        object.__setattr__(self, "_expires_at", _expires_at)


class _ApprovalAuthorityContract(ToolSchema):
    configured_identity: OperationPrincipal
    approval_ttl_seconds: Annotated[float, Field(gt=0, le=300)]


@dataclass(frozen=True, slots=True)
class _WriterAuthorityContext:
    writer_binding: object
    writer_session: object
    root_identity: tuple[int, int]
    principal: str
    scope: str
    resource_control: ProductResourceControl


@dataclass(frozen=True, slots=True)
class _DraftAuthorizationContext:
    configured_identity: str
    principal: str
    scope: str
    tool: Literal["draft_create"]
    effect: Literal["create"]
    proposal: DraftProposal
    proposal_fingerprint: str
    writer_binding: object
    writer_session: object
    root_identity: tuple[int, int]
    authority_session: object
    resource_control: ProductResourceControl


@dataclass(frozen=True, slots=True)
class _TimedAuthorizationRecord:
    context: _DraftAuthorizationContext
    expires_at: float


def _same_authorization_context(
    left: _DraftAuthorizationContext,
    right: _DraftAuthorizationContext,
) -> bool:
    return (
        left.configured_identity == right.configured_identity
        and left.principal == right.principal
        and left.scope == right.scope
        and left.tool == right.tool
        and left.effect == right.effect
        and left.proposal is right.proposal
        and left.proposal_fingerprint == right.proposal_fingerprint
        and left.writer_binding is right.writer_binding
        and left.writer_session is right.writer_session
        and left.root_identity == right.root_identity
        and left.authority_session is right.authority_session
        and left.resource_control is right.resource_control
    )


class DraftApprovalAuthority:
    """Autoridad local y efímera para autenticar aprobaciones sintéticas."""

    __slots__ = (
        "_approval_ttl_seconds",
        "_approvals",
        "_challenges",
        "_clock",
        "_closed",
        "_configured_identity",
        "_consumed_approvals",
        "_consumed_challenges",
        "_consumed_effect_grants",
        "_credential_digest",
        "_credential_salt",
        "_effect_grants",
        "_lock",
        "_session",
        "_writers",
    )

    def __init__(
        self,
        *,
        configured_identity: str,
        credential: str,
        approval_ttl_seconds: float = 30.0,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if not isinstance(credential, str):
            raise TypeError("credential must be a string")
        credential_bytes = credential.encode("utf-8")
        if not credential_bytes or len(credential_bytes) > 1024:
            raise ValueError("credential must contain between 1 and 1024 bytes")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if isinstance(approval_ttl_seconds, bool) or not isinstance(
            approval_ttl_seconds,
            (int, float),
        ):
            raise TypeError("approval_ttl_seconds must be numeric")
        try:
            contract = _ApprovalAuthorityContract(
                configured_identity=configured_identity,
                approval_ttl_seconds=float(approval_ttl_seconds),
            )
        except ValidationError as exc:
            raise ToolPolicyError(
                "draft approval authority configuration is invalid"
            ) from exc

        self._configured_identity = contract.configured_identity
        self._approval_ttl_seconds = contract.approval_ttl_seconds
        self._clock = clock
        self._credential_salt = secrets.token_bytes(32)
        self._credential_digest = self._digest_credential(credential_bytes)
        self._session = object()
        self._lock = threading.RLock()
        self._closed = False
        self._writers: dict[object, _WriterAuthorityContext] = {}
        self._challenges: dict[
            DraftApprovalChallenge,
            _TimedAuthorizationRecord,
        ] = {}
        self._approvals: dict[
            DraftApproval,
            _TimedAuthorizationRecord,
        ] = {}
        self._effect_grants: dict[
            DraftEffectGrant,
            _TimedAuthorizationRecord,
        ] = {}
        self._consumed_challenges: set[DraftApprovalChallenge] = set()
        self._consumed_approvals: set[DraftApproval] = set()
        self._consumed_effect_grants: set[DraftEffectGrant] = set()

    @property
    def configured_identity(self) -> str:
        return self._configured_identity

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return (
            "DraftApprovalAuthority("
            f"configured_identity={self._configured_identity!r}, "
            f"state={state!r})"
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._writers.clear()
            self._challenges.clear()
            self._approvals.clear()
            self._effect_grants.clear()
            self._consumed_challenges.clear()
            self._consumed_approvals.clear()
            self._consumed_effect_grants.clear()
            self._credential_salt = b""
            self._credential_digest = b""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def approve(
        self,
        challenge: DraftApprovalChallenge,
        *,
        identity: str,
        credential: str,
    ) -> DraftApproval:
        """Autentica la identidad configurada y consume un challenge válido."""

        if not isinstance(challenge, DraftApprovalChallenge):
            raise DraftApprovalError(
                "approval challenge must be an opaque authority object"
            )
        with self._lock:
            self._require_open()
            record = self._challenges.get(challenge)
            if record is None:
                if challenge in self._consumed_challenges:
                    raise DraftApprovalError(
                        "approval challenge was already consumed"
                    )
                raise DraftApprovalError(
                    "approval challenge was not issued by this authority session"
                )
            record.context.resource_control.reserve_authentication_attempt()
            if not isinstance(identity, str) or not isinstance(credential, str):
                raise DraftApprovalError("approval credentials were rejected")
            identity_bytes = identity.encode("utf-8")
            credential_bytes = credential.encode("utf-8")
            if (
                not identity_bytes
                or len(identity_bytes) > 64
                or not credential_bytes
                or len(credential_bytes) > 1024
            ):
                raise DraftApprovalError("approval credentials were rejected")
            now = self._clock()
            if now >= record.expires_at:
                self._challenges.pop(challenge, None)
                self._consumed_challenges.add(challenge)
                raise DraftApprovalError("approval challenge expired")
            self._require_context_writer(record.context)
            supplied = self._digest_credential(credential_bytes)
            identity_matches = hmac.compare_digest(
                identity_bytes,
                self._configured_identity.encode("utf-8"),
            )
            credential_matches = hmac.compare_digest(
                supplied,
                self._credential_digest,
            )
            if not (identity_matches and credential_matches):
                raise DraftApprovalError("approval credentials were rejected")

            self._challenges.pop(challenge)
            self._consumed_challenges.add(challenge)
            approval = DraftApproval(
                _issuer_token=_DRAFT_APPROVAL_ISSUER_TOKEN
            )
            self._approvals[approval] = _TimedAuthorizationRecord(
                context=record.context,
                expires_at=now + self._approval_ttl_seconds,
            )
            return approval

    def _digest_credential(self, credential: bytes) -> bytes:
        return pbkdf2_hmac(
            "sha256",
            credential,
            self._credential_salt,
            _CREDENTIAL_KDF_ITERATIONS,
        )

    def _register_writer(
        self,
        *,
        writer_binding: object,
        root_identity: tuple[int, int],
        principal: str,
        scope: str,
        resource_control: ProductResourceControl,
        _channel_token: object | None,
    ) -> object:
        self._require_channel(_channel_token)
        if (
            not isinstance(resource_control, ProductResourceControl)
            or resource_control.profile != "draft"
        ):
            raise ToolPolicyError(
                "writer resource control must use the draft profile"
            )
        with self._lock:
            self._require_open()
            writer_session = object()
            self._writers[writer_session] = _WriterAuthorityContext(
                writer_binding=writer_binding,
                writer_session=writer_session,
                root_identity=root_identity,
                principal=principal,
                scope=scope,
                resource_control=resource_control,
            )
            return writer_session

    def _assert_writer_active(
        self,
        *,
        writer_binding: object,
        writer_session: object,
        root_identity: tuple[int, int],
        principal: str,
        scope: str,
        _channel_token: object | None,
    ) -> None:
        self._require_channel(_channel_token)
        with self._lock:
            self._require_open()
            writer = self._writers.get(writer_session)
            if (
                writer is None
                or writer.writer_binding is not writer_binding
                or writer.root_identity != root_identity
                or writer.principal != principal
                or writer.scope != scope
            ):
                raise DraftApprovalError(
                    "writer is not active in this approval authority session"
                )

    def _revoke_writer(
        self,
        *,
        writer_binding: object,
        writer_session: object,
        _channel_token: object | None,
    ) -> None:
        self._require_channel(_channel_token)
        with self._lock:
            if self._closed:
                return
            writer = self._writers.get(writer_session)
            if writer is None or writer.writer_binding is not writer_binding:
                return
            self._writers.pop(writer_session)
            self._revoke_records_for_writer(
                self._challenges,
                self._consumed_challenges,
                writer_session,
            )
            self._revoke_records_for_writer(
                self._approvals,
                self._consumed_approvals,
                writer_session,
            )
            self._revoke_records_for_writer(
                self._effect_grants,
                self._consumed_effect_grants,
                writer_session,
            )

    def _issue_challenge(
        self,
        *,
        proposal: DraftProposal,
        writer_binding: object,
        writer_session: object,
        root_identity: tuple[int, int],
        principal: str,
        scope: str,
        _channel_token: object | None,
    ) -> DraftApprovalChallenge:
        self._require_channel(_channel_token)
        with self._lock:
            self._require_open()
            writer = self._writers.get(writer_session)
            if (
                writer is None
                or writer.writer_binding is not writer_binding
                or writer.root_identity != root_identity
                or writer.principal != principal
                or writer.scope != scope
            ):
                raise DraftApprovalError(
                    "writer is not active in this approval authority session"
                )
            context = _DraftAuthorizationContext(
                configured_identity=self._configured_identity,
                principal=principal,
                scope=scope,
                tool="draft_create",
                effect="create",
                proposal=proposal,
                proposal_fingerprint=proposal.proposal_fingerprint,
                writer_binding=writer_binding,
                writer_session=writer_session,
                root_identity=root_identity,
                authority_session=self._session,
                resource_control=writer.resource_control,
            )
            challenge = DraftApprovalChallenge(
                _issuer_token=_DRAFT_APPROVAL_ISSUER_TOKEN
            )
            self._challenges[challenge] = _TimedAuthorizationRecord(
                context=context,
                expires_at=self._clock() + self._approval_ttl_seconds,
            )
            return challenge

    def _authorize_effect(
        self,
        *,
        proposal: DraftProposal,
        approval: DraftApproval,
        writer_binding: object,
        writer_session: object,
        root_identity: tuple[int, int],
        principal: str,
        scope: str,
        _channel_token: object | None,
    ) -> DraftEffectGrant:
        self._require_channel(_channel_token)
        if not isinstance(approval, DraftApproval):
            raise DraftApprovalError(
                "approval must be an opaque authority object"
            )
        with self._lock:
            self._require_open()
            record = self._approvals.get(approval)
            if record is None:
                if approval in self._consumed_approvals:
                    raise DraftApprovalError("draft approval was already consumed")
                raise DraftApprovalError(
                    "draft approval was not issued by this authority session"
                )
            now = self._clock()
            if now >= record.expires_at:
                self._approvals.pop(approval, None)
                self._consumed_approvals.add(approval)
                raise DraftApprovalError("draft approval expired")
            expected = _DraftAuthorizationContext(
                configured_identity=self._configured_identity,
                principal=principal,
                scope=scope,
                tool="draft_create",
                effect="create",
                proposal=proposal,
                proposal_fingerprint=proposal.proposal_fingerprint,
                writer_binding=writer_binding,
                writer_session=writer_session,
                root_identity=root_identity,
                authority_session=self._session,
                resource_control=record.context.resource_control,
            )
            if not _same_authorization_context(record.context, expected):
                raise DraftApprovalError(
                    "draft approval does not match the exact effect context"
                )
            self._require_context_writer(record.context)
            self._approvals.pop(approval)
            self._consumed_approvals.add(approval)
            effect_grant = DraftEffectGrant(
                approval_identity=record.context.configured_identity,
                principal=record.context.principal,
                scope=record.context.scope,
                proposal_fingerprint=record.context.proposal_fingerprint,
                _issuer_token=_DRAFT_EFFECT_ISSUER_TOKEN,
                _writer_binding=record.context.writer_binding,
                _writer_session=record.context.writer_session,
                _root_identity=record.context.root_identity,
                _authority_session=record.context.authority_session,
                _proposal=record.context.proposal,
                _expires_at=record.expires_at,
            )
            self._effect_grants[effect_grant] = _TimedAuthorizationRecord(
                context=record.context,
                expires_at=record.expires_at,
            )
            return effect_grant

    def _consume_effect_grant(
        self,
        *,
        proposal: DraftProposal,
        effect_grant: DraftEffectGrant,
        writer_binding: object,
        writer_session: object,
        root_identity: tuple[int, int],
        principal: str,
        scope: str,
        _channel_token: object | None,
    ) -> None:
        self._require_channel(_channel_token)
        with self._lock:
            self._require_open()
            record = self._effect_grants.get(effect_grant)
            if record is None:
                if effect_grant in self._consumed_effect_grants:
                    raise DraftApprovalError(
                        "effect grant was already consumed"
                    )
                raise DraftApprovalError(
                    "effect grant was not issued by this authority session"
                )
            now = self._clock()
            if now >= record.expires_at:
                self._effect_grants.pop(effect_grant, None)
                self._consumed_effect_grants.add(effect_grant)
                raise DraftApprovalError("effect grant expired")
            expected = _DraftAuthorizationContext(
                configured_identity=self._configured_identity,
                principal=principal,
                scope=scope,
                tool="draft_create",
                effect="create",
                proposal=proposal,
                proposal_fingerprint=proposal.proposal_fingerprint,
                writer_binding=writer_binding,
                writer_session=writer_session,
                root_identity=root_identity,
                authority_session=self._session,
                resource_control=record.context.resource_control,
            )
            if not _same_authorization_context(record.context, expected):
                raise DraftApprovalError(
                    "effect grant does not match the exact effect context"
                )
            self._require_context_writer(record.context)
            self._effect_grants.pop(effect_grant)
            self._consumed_effect_grants.add(effect_grant)

    def _require_context_writer(
        self,
        context: _DraftAuthorizationContext,
    ) -> None:
        writer = self._writers.get(context.writer_session)
        if (
            writer is None
            or writer.writer_binding is not context.writer_binding
            or writer.root_identity != context.root_identity
            or writer.principal != context.principal
            or writer.scope != context.scope
            or context.authority_session is not self._session
            or context.configured_identity != self._configured_identity
            or writer.resource_control is not context.resource_control
        ):
            raise DraftApprovalError(
                "approval context is no longer active"
            )

    @staticmethod
    def _require_channel(channel_token: object | None) -> None:
        if channel_token is not _DRAFT_AUTHORITY_CHANNEL_TOKEN:
            raise DraftApprovalError(
                "approval authority operations require a bound writer"
            )

    def _require_open(self) -> None:
        if self._closed:
            raise DraftApprovalError("draft approval authority is closed")

    @staticmethod
    def _revoke_records_for_writer(
        records: dict[object, _TimedAuthorizationRecord],
        consumed: set[object],
        writer_session: object,
    ) -> None:
        revoked = tuple(
            token
            for token, record in records.items()
            if record.context.writer_session is writer_session
        )
        for token in revoked:
            records.pop(token, None)
            consumed.add(token)


class DraftCreationResult(ToolSchema):
    filename: DraftFilename
    relative_path: Text
    content_sha256: Sha256
    bytes_written: Annotated[int, Field(ge=1)]
    created: Literal[True] = True


def _finalize_draft_writer(
    root_fd: int,
    authority: DraftApprovalAuthority,
    writer_binding: object,
    writer_session: object,
) -> None:
    try:
        authority._revoke_writer(
            writer_binding=writer_binding,
            writer_session=writer_session,
            _channel_token=_DRAFT_AUTHORITY_CHANNEL_TOKEN,
        )
    finally:
        os.close(root_fd)


class DraftWriterTool:
    """Prepara y crea solo tras una aprobación autenticada y efímera."""

    def __init__(
        self,
        drafts_dir: Path,
        *,
        principal: str,
        scope: str,
        approval_authority: DraftApprovalAuthority,
        output_policy: OutputPolicy,
        allowed_knowledge_ids: tuple[str, ...] = (),
        resource_control: ProductResourceControl | None = None,
    ) -> None:
        if not isinstance(drafts_dir, Path):
            raise TypeError("drafts_dir must be a Path")
        if not isinstance(approval_authority, DraftApprovalAuthority):
            raise TypeError(
                "approval_authority must be a DraftApprovalAuthority"
            )
        if not isinstance(output_policy, OutputPolicy):
            raise TypeError("output_policy must be an OutputPolicy")
        if resource_control is None:
            resource_control = ProductResourceControl("draft")
        if (
            not isinstance(resource_control, ProductResourceControl)
            or resource_control.profile != "draft"
        ):
            raise TypeError(
                "resource_control must use the draft resource profile"
            )
        if not drafts_dir.is_absolute():
            raise ValueError("drafts_dir must be absolute")
        if drafts_dir.name != "drafts" or drafts_dir.parent.name != "sandbox":
            raise ValueError("drafts_dir must end with sandbox/drafts")
        if drafts_dir.is_symlink() or drafts_dir.parent.is_symlink():
            raise SandboxViolationError(
                "sandbox directories cannot be symlinks"
            )

        try:
            root = drafts_dir.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValueError("drafts_dir must already exist") from exc
        if not root.is_dir():
            raise ValueError("drafts_dir must be a directory")
        if (
            not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
            or os.open not in os.supports_dir_fd
        ):
            raise RuntimeError(
                "draft creation requires dir_fd, O_DIRECTORY and O_NOFOLLOW"
            )

        root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            root_fd = os.open(root, root_flags)
        except OSError as exc:
            raise SandboxViolationError(
                "draft sandbox cannot be anchored"
            ) from exc
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            os.close(root_fd)
            raise SandboxViolationError("draft sandbox is not a directory")

        self._root = root
        self._root_fd = root_fd
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        self._principal = principal
        self._scope = scope
        self._binding = object()
        self._approval_authority = approval_authority
        self._output_policy = output_policy
        self._resource_control = resource_control
        try:
            self._prepare_grant = _issue_tool_grant(
                principal=principal,
                scope=scope,
                tool="draft_create",
                binding=self._binding,
                allowed_knowledge_ids=allowed_knowledge_ids,
            )
            self._writer_session = approval_authority._register_writer(
                writer_binding=self._binding,
                root_identity=self._root_identity,
                principal=principal,
                scope=scope,
                resource_control=resource_control,
                _channel_token=_DRAFT_AUTHORITY_CHANNEL_TOKEN,
            )
        except Exception:
            os.close(root_fd)
            raise
        self._finalizer = weakref.finalize(
            self,
            _finalize_draft_writer,
            root_fd,
            approval_authority,
            self._binding,
            self._writer_session,
        )
        self._lifecycle_lock = threading.RLock()
        self._closed = False
        self._prepared: dict[int, DraftProposal] = {}
        self._challenge_issued: set[int] = set()
        self._effect_grants: dict[int, DraftEffectGrant] = {}
        self._consumed_proposals: set[int] = set()

    @property
    def prepare_grant(self) -> ToolExecutionGrant:
        return self._prepare_grant

    @property
    def resource_control(self) -> ProductResourceControl:
        return self._resource_control

    def close(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            self._finalizer()
            self._prepared.clear()
            self._challenge_issued.clear()
            self._effect_grants.clear()
            self._consumed_proposals.clear()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def prepare(
        self,
        request: ModelToolRequest,
        *,
        grant: ToolExecutionGrant,
    ) -> DraftProposal:
        with self._lifecycle_lock:
            self._require_active()
            if not isinstance(request, ModelToolRequest):
                raise TypeError("request must be a ModelToolRequest")
            self._require_prepare_grant(grant)
            if request.name != "draft_create":
                raise ToolDeniedError(
                    "requested tool is not allowed in this flow"
                )

            require_utf8_size(
                request.arguments_json,
                MAX_TOOL_ARGUMENTS_BYTES,
            )
            try:
                arguments = DraftCreateArguments.model_validate_json(
                    request.arguments_json
                )
            except ValidationError as exc:
                raise ToolArgumentsError(
                    "draft_create arguments were rejected"
                ) from exc
            if not set(arguments.references).issubset(
                grant.allowed_knowledge_ids
            ):
                raise ToolDeniedError(
                    "draft references exceed the authorized scope"
                )
            checked_title = self._output_policy.check(
                arguments.title,
                channel="draft_title",
            )
            checked_body = self._output_policy.check(
                arguments.body,
                channel="draft_body",
            )
            try:
                safe_arguments = DraftCreateArguments(
                    filename=arguments.filename,
                    title=self._output_policy.unwrap(
                        checked_title,
                        channel="draft_title",
                    ),
                    body=self._output_policy.unwrap(
                        checked_body,
                        channel="draft_body",
                    ),
                    references=arguments.references,
                )
            except ValidationError:
                raise ToolArgumentsError(
                    "draft_create arguments were rejected"
                ) from None
            require_utf8_size(
                self._render(safe_arguments),
                MAX_DRAFT_MARKDOWN_BYTES,
            )
            self._resource_control.reserve_draft_proposal()
            proposal = DraftProposal.from_arguments(safe_arguments)
            self._prepared[id(proposal)] = proposal
            return proposal

    def issue_approval_challenge(
        self,
        proposal: DraftProposal,
    ) -> DraftApprovalChallenge:
        with self._lifecycle_lock:
            self._require_active()
            self._require_prepared_proposal(proposal)
            proposal_identity = id(proposal)
            if proposal_identity in self._challenge_issued:
                raise DraftApprovalError(
                    "an approval challenge was already issued for this proposal"
                )
            self._resource_control.reserve_draft_challenge()
            challenge = self._approval_authority._issue_challenge(
                proposal=proposal,
                writer_binding=self._binding,
                writer_session=self._writer_session,
                root_identity=self._root_identity,
                principal=self._principal,
                scope=self._scope,
                _channel_token=_DRAFT_AUTHORITY_CHANNEL_TOKEN,
            )
            self._challenge_issued.add(proposal_identity)
            return challenge

    def authorize_effect(
        self,
        proposal: DraftProposal,
        approval: DraftApproval,
    ) -> DraftEffectGrant:
        with self._lifecycle_lock:
            self._require_active()
            self._require_prepared_proposal(proposal)
            proposal_identity = id(proposal)
            if proposal_identity in self._effect_grants:
                raise DraftApprovalError(
                    "an effect grant was already issued for this proposal"
                )
            if not isinstance(approval, DraftApproval):
                raise DraftApprovalError(
                    "approval must be an opaque authority object"
                )
            self._resource_control.reserve_draft_grant()
            effect_grant = self._approval_authority._authorize_effect(
                proposal=proposal,
                approval=approval,
                writer_binding=self._binding,
                writer_session=self._writer_session,
                root_identity=self._root_identity,
                principal=self._principal,
                scope=self._scope,
                _channel_token=_DRAFT_AUTHORITY_CHANNEL_TOKEN,
            )
            self._effect_grants[proposal_identity] = effect_grant
            return effect_grant

    def create(
        self,
        proposal: DraftProposal,
        effect_grant: DraftEffectGrant,
    ) -> DraftCreationResult:
        with self._lifecycle_lock:
            with self._approval_authority._lock:
                return self._create_locked(proposal, effect_grant)

    def _create_locked(
        self,
        proposal: DraftProposal,
        effect_grant: DraftEffectGrant,
    ) -> DraftCreationResult:
        self._require_active()
        self._require_prepared_proposal(proposal)
        self._require_effect_grant(proposal, effect_grant)
        proposal_identity = id(proposal)
        if proposal_identity in self._consumed_proposals:
            raise DraftApprovalError("effect grant was already consumed")

        content = self._render(proposal)
        require_utf8_size(content, MAX_DRAFT_MARKDOWN_BYTES)
        self._resource_control.reserve_draft_file()
        self._approval_authority._consume_effect_grant(
            proposal=proposal,
            effect_grant=effect_grant,
            writer_binding=self._binding,
            writer_session=self._writer_session,
            root_identity=self._root_identity,
            principal=self._principal,
            scope=self._scope,
            _channel_token=_DRAFT_AUTHORITY_CHANNEL_TOKEN,
        )
        self._consumed_proposals.add(proposal_identity)

        self._assert_root_unchanged()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            file_fd = os.open(
                proposal.filename,
                flags,
                0o600,
                dir_fd=self._root_fd,
            )
        except OSError as exc:
            if exc.errno in {errno.EEXIST, errno.ELOOP}:
                raise DraftAlreadyExistsError(
                    "draft target already exists; overwrite is forbidden"
                ) from None
            raise SandboxViolationError(
                "draft target could not be created safely"
            ) from exc

        try:
            os.fchmod(file_fd, 0o600)
            with os.fdopen(
                file_fd,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as handle:
                file_fd = -1
                handle.write(content)
        finally:
            if file_fd >= 0:
                os.close(file_fd)

        encoded = content.encode("utf-8")
        return DraftCreationResult(
            filename=proposal.filename,
            relative_path=f"sandbox/drafts/{proposal.filename}",
            content_sha256=sha256(encoded).hexdigest(),
            bytes_written=len(encoded),
        )

    def _require_prepare_grant(self, grant: ToolExecutionGrant) -> None:
        if not isinstance(grant, ToolExecutionGrant):
            raise TypeError("grant must be a ToolExecutionGrant")
        if (
            grant is not self._prepare_grant
            or grant._binding is not self._binding
            or grant.principal != self._principal
            or grant.scope != self._scope
            or grant.tool != "draft_create"
        ):
            raise ToolDeniedError(
                "tool grant does not belong to this principal and scope"
            )

    def _require_prepared_proposal(
        self,
        proposal: DraftProposal,
    ) -> None:
        if not isinstance(proposal, DraftProposal):
            raise TypeError("proposal must be a DraftProposal")
        if self._prepared.get(id(proposal)) is not proposal:
            raise DraftProposalError(
                "proposal was not prepared by this writer instance and root"
            )

    def _require_effect_grant(
        self,
        proposal: DraftProposal,
        effect_grant: DraftEffectGrant,
    ) -> None:
        if not isinstance(effect_grant, DraftEffectGrant):
            raise TypeError("effect_grant must be a DraftEffectGrant")
        proposal_identity = id(proposal)
        if (
            self._effect_grants.get(proposal_identity) is not effect_grant
            or effect_grant._writer_binding is not self._binding
            or effect_grant._writer_session is not self._writer_session
            or effect_grant._root_identity != self._root_identity
            or (
                effect_grant._authority_session
                is not self._approval_authority._session
            )
            or effect_grant._proposal is not proposal
            or (
                effect_grant.approval_identity
                != self._approval_authority.configured_identity
            )
            or effect_grant.principal != self._principal
            or effect_grant.scope != self._scope
            or effect_grant.tool != "draft_create"
            or effect_grant.proposal_fingerprint
            != proposal.proposal_fingerprint
            or effect_grant.effect != "create"
        ):
            raise DraftApprovalError(
                "effect grant does not authorize this writer and proposal"
            )

    def _require_active(self) -> None:
        if self._closed or not self._finalizer.alive:
            raise DraftApprovalError("draft writer is closed")
        self._approval_authority._assert_writer_active(
            writer_binding=self._binding,
            writer_session=self._writer_session,
            root_identity=self._root_identity,
            principal=self._principal,
            scope=self._scope,
            _channel_token=_DRAFT_AUTHORITY_CHANNEL_TOKEN,
        )

    def _assert_root_unchanged(self) -> None:
        if not self._finalizer.alive:
            raise SandboxViolationError("draft sandbox is no longer available")
        try:
            path_stat = os.stat(self._root, follow_symlinks=False)
            descriptor_stat = os.fstat(self._root_fd)
        except OSError as exc:
            raise SandboxViolationError(
                "draft sandbox is no longer available"
            ) from exc
        path_identity = (path_stat.st_dev, path_stat.st_ino)
        descriptor_identity = (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
        )
        if (
            not stat.S_ISDIR(path_stat.st_mode)
            or path_identity != self._root_identity
            or descriptor_identity != self._root_identity
        ):
            raise SandboxViolationError("draft sandbox location changed")

    @staticmethod
    def _render(proposal: DraftContent) -> str:
        content = f"# {proposal.title}\n\n{proposal.body}"
        if proposal.references:
            references = "\n".join(
                f"- {reference}" for reference in proposal.references
            )
            content += f"\n\n## Referencias\n\n{references}"
        if not content.endswith("\n"):
            content += "\n"
        return content
