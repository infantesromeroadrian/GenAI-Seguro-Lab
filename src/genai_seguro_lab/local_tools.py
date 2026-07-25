"""Herramientas locales con autoridad de aplicación y datos acotados."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import weakref
from collections.abc import Iterable
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
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

HUMAN_CONFIRMATION_RESIDUAL = "PGS-04-M04"
_GRANT_ISSUER_TOKEN = object()
_KNOWLEDGE_TOOL_FACTORY_TOKEN = object()
_DRAFT_EFFECT_ISSUER_TOKEN = object()


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


class DraftConfirmationError(PermissionError):
    """La confirmación no autoriza esta propuesta exacta."""


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
        return KnowledgeSearchResult(query=arguments.query, hits=hits)

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


class DraftConfirmation(ToolSchema):
    """Consentimiento literal no autenticado; residual de PGS-04-M04."""

    proposal_fingerprint: Sha256
    confirmed_by_user: Literal[True]


class _DraftEffectContract(ToolSchema):
    principal: OperationPrincipal
    scope: OperationScope
    tool: Literal["draft_create"]
    proposal_fingerprint: Sha256
    effect: Literal["create"]
    human_identity_authenticated: Literal[False]
    residual_control: Literal["PGS-04-M04"]


@dataclass(frozen=True, slots=True, init=False)
class DraftEffectGrant:
    """Grant explícito de creación, ligado a una propuesta y una instancia."""

    principal: str
    scope: str
    tool: Literal["draft_create"]
    proposal_fingerprint: str
    effect: Literal["create"]
    human_identity_authenticated: Literal[False]
    residual_control: Literal["PGS-04-M04"]
    _writer_binding: object = field(repr=False, compare=False)
    _proposal_identity: int = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        principal: str,
        scope: str,
        proposal_fingerprint: str,
        _issuer_token: object | None = None,
        _writer_binding: object | None = None,
        _proposal_identity: int | None = None,
    ) -> None:
        if (
            _issuer_token is not _DRAFT_EFFECT_ISSUER_TOKEN
            or _writer_binding is None
            or _proposal_identity is None
        ):
            raise ToolPolicyError(
                "draft effect grants must be issued by the writer"
            )
        try:
            contract = _DraftEffectContract(
                principal=principal,
                scope=scope,
                tool="draft_create",
                proposal_fingerprint=proposal_fingerprint,
                effect="create",
                human_identity_authenticated=False,
                residual_control=HUMAN_CONFIRMATION_RESIDUAL,
            )
        except ValidationError as exc:
            raise ToolPolicyError(
                "draft effect grant contract is invalid"
            ) from exc
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
            "human_identity_authenticated",
            contract.human_identity_authenticated,
        )
        object.__setattr__(
            self,
            "residual_control",
            contract.residual_control,
        )
        object.__setattr__(self, "_writer_binding", _writer_binding)
        object.__setattr__(self, "_proposal_identity", _proposal_identity)


class DraftCreationResult(ToolSchema):
    filename: DraftFilename
    relative_path: Text
    content_sha256: Sha256
    bytes_written: Annotated[int, Field(ge=1)]
    created: Literal[True] = True


class DraftWriterTool:
    """Prepara sin efecto y crea con un grant explícito dentro de drafts."""

    def __init__(
        self,
        drafts_dir: Path,
        *,
        principal: str,
        scope: str,
        allowed_knowledge_ids: tuple[str, ...] = (),
    ) -> None:
        if not isinstance(drafts_dir, Path):
            raise TypeError("drafts_dir must be a Path")
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
        self._finalizer = weakref.finalize(self, os.close, root_fd)
        self._principal = principal
        self._scope = scope
        self._binding = object()
        self._prepare_grant = _issue_tool_grant(
            principal=principal,
            scope=scope,
            tool="draft_create",
            binding=self._binding,
            allowed_knowledge_ids=allowed_knowledge_ids,
        )
        self._prepared: dict[int, DraftProposal] = {}
        self._effect_grants: dict[int, DraftEffectGrant] = {}
        self._consumed_proposals: set[int] = set()

    @property
    def prepare_grant(self) -> ToolExecutionGrant:
        return self._prepare_grant

    def close(self) -> None:
        self._finalizer()

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
        if not isinstance(request, ModelToolRequest):
            raise TypeError("request must be a ModelToolRequest")
        self._require_prepare_grant(grant)
        if request.name != "draft_create":
            raise ToolDeniedError("requested tool is not allowed in this flow")

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
        proposal = DraftProposal.from_arguments(arguments)
        self._prepared[id(proposal)] = proposal
        return proposal

    def authorize_effect(
        self,
        proposal: DraftProposal,
        confirmation: DraftConfirmation,
    ) -> DraftEffectGrant:
        self._require_prepared_proposal(proposal)
        if not isinstance(confirmation, DraftConfirmation):
            raise TypeError("confirmation must be a DraftConfirmation")
        if confirmation.proposal_fingerprint != proposal.proposal_fingerprint:
            raise DraftConfirmationError(
                "confirmation does not match the exact proposal"
            )
        proposal_identity = id(proposal)
        if proposal_identity in self._effect_grants:
            raise DraftConfirmationError(
                "an effect grant was already issued for this proposal"
            )
        effect_grant = DraftEffectGrant(
            principal=self._principal,
            scope=self._scope,
            proposal_fingerprint=proposal.proposal_fingerprint,
            _issuer_token=_DRAFT_EFFECT_ISSUER_TOKEN,
            _writer_binding=self._binding,
            _proposal_identity=proposal_identity,
        )
        self._effect_grants[proposal_identity] = effect_grant
        return effect_grant

    def create(
        self,
        proposal: DraftProposal,
        effect_grant: DraftEffectGrant,
    ) -> DraftCreationResult:
        self._require_prepared_proposal(proposal)
        self._require_effect_grant(proposal, effect_grant)
        proposal_identity = id(proposal)
        if proposal_identity in self._consumed_proposals:
            raise DraftConfirmationError("effect grant was already consumed")

        self._assert_root_unchanged()
        content = self._render(proposal)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
        )
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

        self._consumed_proposals.add(proposal_identity)
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
            or effect_grant._proposal_identity != proposal_identity
            or effect_grant.principal != self._principal
            or effect_grant.scope != self._scope
            or effect_grant.tool != "draft_create"
            or effect_grant.proposal_fingerprint
            != proposal.proposal_fingerprint
            or effect_grant.effect != "create"
        ):
            raise DraftConfirmationError(
                "effect grant does not authorize this writer and proposal"
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
    def _render(proposal: DraftProposal) -> str:
        content = f"# {proposal.title}\n\n{proposal.body}"
        if proposal.references:
            references = "\n".join(
                f"- {reference}" for reference in proposal.references
            )
            content += f"\n\n## Referencias\n\n{references}"
        if not content.endswith("\n"):
            content += "\n"
        return content
