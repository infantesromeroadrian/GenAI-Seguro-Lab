"""Herramientas locales con lectura acotada y escritura confirmada."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
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


class ToolSchema(BaseModel):
    """Base estricta e inmutable para entradas y resultados de herramientas."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ToolDeniedError(PermissionError):
    """La solicitud no pertenece al alcance autorizado."""


class ToolArgumentsError(ValueError):
    """Los argumentos no cumplen el esquema de la herramienta."""


class ToolPolicyError(ValueError):
    """La política de ejecución no es válida para una herramienta."""


class DraftConfirmationError(PermissionError):
    """La confirmación no autoriza esta propuesta exacta."""


class DraftAlreadyExistsError(FileExistsError):
    """La política create-only impide escribir el destino."""


class SandboxViolationError(PermissionError):
    """El destino ya no cumple el límite físico del sandbox."""


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


class ToolExecutionPolicy(ToolSchema):
    """Allowlist inmutable aportada por la aplicación, no por el modelo."""

    allowed_tools: Annotated[
        tuple[KnownToolName, ...],
        Field(min_length=1, max_length=2),
    ]
    allowed_knowledge_ids: Annotated[
        tuple[KnowledgeId, ...],
        Field(max_length=8),
    ] = ()

    @field_validator("allowed_tools", "allowed_knowledge_ids")
    @classmethod
    def reject_duplicate_policy_values(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("execution policy values must be unique")
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


class KnowledgeSearchTool:
    """Busca solo en documentos sintéticos cargados y autorizados."""

    def __init__(self, documents: Iterable[KnowledgeRecord]) -> None:
        indexed: dict[str, KnowledgeRecord] = {}
        for document in documents:
            if not isinstance(document, KnowledgeRecord):
                raise TypeError("documents must contain KnowledgeRecord values")
            if document.id in indexed:
                raise ValueError("knowledge document identifiers must be unique")
            indexed[document.id] = document

        if not indexed:
            raise ValueError("at least one knowledge document is required")
        self._documents = indexed

    def search(
        self,
        request: ModelToolRequest,
        *,
        policy: ToolExecutionPolicy,
    ) -> KnowledgeSearchResult:
        if not isinstance(request, ModelToolRequest):
            raise TypeError("request must be a ModelToolRequest")
        if not isinstance(policy, ToolExecutionPolicy):
            raise TypeError("policy must be a ToolExecutionPolicy")
        if (
            request.name != "knowledge_search"
            or request.name not in policy.allowed_tools
        ):
            raise ToolDeniedError("requested tool is not allowed in this flow")

        try:
            arguments = KnowledgeSearchArguments.model_validate_json(
                request.arguments_json
            )
        except ValidationError as exc:
            raise ToolArgumentsError(
                "knowledge_search arguments were rejected"
            ) from exc

        allowed = set(policy.allowed_knowledge_ids)
        if not allowed.issubset(self._documents):
            raise ToolPolicyError(
                "knowledge_search policy references unknown data"
            )
        requested = set(arguments.knowledge_ids)
        if not requested.issubset(allowed):
            raise ToolDeniedError(
                "knowledge request exceeds the incident scope"
            )
        if not requested.issubset(self._documents):
            raise ToolDeniedError("knowledge request references unknown data")

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
    proposal_fingerprint: Sha256
    confirmed_by_user: Literal[True]


class DraftCreationResult(ToolSchema):
    filename: DraftFilename
    relative_path: Text
    content_sha256: Sha256
    bytes_written: Annotated[int, Field(ge=1)]
    created: Literal[True] = True


class DraftWriterTool:
    """Prepara propuestas y crea archivos nuevos dentro de sandbox/drafts."""

    def __init__(self, drafts_dir: Path) -> None:
        if not isinstance(drafts_dir, Path):
            raise TypeError("drafts_dir must be a Path")
        if not drafts_dir.is_absolute():
            raise ValueError("drafts_dir must be absolute")
        if drafts_dir.name != "drafts" or drafts_dir.parent.name != "sandbox":
            raise ValueError("drafts_dir must end with sandbox/drafts")
        if drafts_dir.is_symlink() or drafts_dir.parent.is_symlink():
            raise SandboxViolationError("sandbox directories cannot be symlinks")

        try:
            root = drafts_dir.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValueError("drafts_dir must already exist") from exc
        if not root.is_dir():
            raise ValueError("drafts_dir must be a directory")

        self._root = root
        self._consumed_confirmations: set[str] = set()

    def prepare(
        self,
        request: ModelToolRequest,
        *,
        policy: ToolExecutionPolicy,
    ) -> DraftProposal:
        if not isinstance(request, ModelToolRequest):
            raise TypeError("request must be a ModelToolRequest")
        if not isinstance(policy, ToolExecutionPolicy):
            raise TypeError("policy must be a ToolExecutionPolicy")
        if (
            request.name != "draft_create"
            or request.name not in policy.allowed_tools
        ):
            raise ToolDeniedError("requested tool is not allowed in this flow")

        try:
            arguments = DraftCreateArguments.model_validate_json(
                request.arguments_json
            )
        except ValidationError as exc:
            raise ToolArgumentsError("draft_create arguments were rejected") from exc
        if not set(arguments.references).issubset(
            policy.allowed_knowledge_ids
        ):
            raise ToolDeniedError(
                "draft references exceed the authorized scope"
            )
        return DraftProposal.from_arguments(arguments)

    def create(
        self,
        proposal: DraftProposal,
        confirmation: DraftConfirmation,
    ) -> DraftCreationResult:
        if not isinstance(proposal, DraftProposal):
            raise TypeError("proposal must be a DraftProposal")
        if not isinstance(confirmation, DraftConfirmation):
            raise TypeError("confirmation must be a DraftConfirmation")
        if confirmation.proposal_fingerprint != proposal.proposal_fingerprint:
            raise DraftConfirmationError(
                "confirmation does not match the exact proposal"
            )
        if proposal.proposal_fingerprint in self._consumed_confirmations:
            raise DraftConfirmationError("confirmation was already consumed")

        self._assert_root_unchanged()
        target = self._root / proposal.filename
        if target.parent != self._root:
            raise SandboxViolationError("draft target escaped the sandbox")

        content = self._render(proposal)
        try:
            with target.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
        except FileExistsError:
            raise DraftAlreadyExistsError(
                "draft target already exists; overwrite is forbidden"
            ) from None

        self._consumed_confirmations.add(proposal.proposal_fingerprint)
        encoded = content.encode("utf-8")
        return DraftCreationResult(
            filename=proposal.filename,
            relative_path=f"sandbox/drafts/{proposal.filename}",
            content_sha256=sha256(encoded).hexdigest(),
            bytes_written=len(encoded),
        )

    def _assert_root_unchanged(self) -> None:
        if self._root.is_symlink() or not self._root.is_dir():
            raise SandboxViolationError("draft sandbox is no longer valid")
        try:
            current = self._root.resolve(strict=True)
        except FileNotFoundError as exc:
            raise SandboxViolationError(
                "draft sandbox is no longer available"
            ) from exc
        if current != self._root:
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
