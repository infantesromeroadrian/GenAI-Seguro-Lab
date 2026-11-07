"""Contrato HTTP público cerrado para las dos Functions de Vercel."""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .benign_flow import BenignFlowError
from .cloud_analysis import UnknownCloudIncidentError
from .data_contract import IncidentCategory, IncidentId
from .local_tools import ToolArgumentsError, ToolDeniedError
from .ollama_cloud_adapter import OllamaCloudError
from .public_analysis import (
    PublicAnalysisEnvelope,
    analyze_public_incident,
)
from .resource_control import ResourceLimitError
from .security_events import SecurityEventError

MAX_PUBLIC_REQUEST_BYTES: Final = 1024
PUBLIC_CSRF_COOKIE: Final = "__Host-gsl-csrf"
PUBLIC_CSRF_HEADER: Final = "X-GSL-CSRF"
PUBLIC_SNAPSHOT_PATH: Final = (
    Path(__file__).with_name("web_assets")
    / "snapshots"
    / "public-profile-v1.json"
)
_CSRF_TOKEN_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{43}$")
_PUBLIC_HOST_PATTERN: Final = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$"
)
_API_SECURITY_HEADERS: Final = (
    ("Cache-Control", "no-store"),
    (
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; sandbox",
    ),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
)


class PublicApiSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PublicAnalyzeRequest(PublicApiSchema):
    incident_id: Annotated[str, Field(pattern=r"^INC-BEN-[0-9]{3}$")]


class PublicIncident(PublicApiSchema):
    category: IncidentCategory
    id: IncidentId
    title: Annotated[str, Field(min_length=1)]


@dataclass(frozen=True, slots=True)
class PublicHttpRequest:
    method: str
    target: str
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""

    def header_values(self, name: str) -> tuple[str, ...]:
        lowered = name.casefold()
        return tuple(
            value
            for candidate, value in self.headers
            if candidate.casefold() == lowered
        )


@dataclass(frozen=True, slots=True)
class PublicHttpResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class _DuplicateJsonKey(ValueError):
    pass


def public_llm_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """El kill switch solo acepta el valor literal y sensible a caso `true`."""

    source = os.environ if environ is None else environ
    return source.get("PUBLIC_LLM_ENABLED") == "true"


def allowed_public_hosts(
    environ: Mapping[str, str] | None = None,
) -> frozenset[str]:
    """Acepta únicamente los hosts automáticos actual y de producción."""

    source = os.environ if environ is None else environ
    hosts = {
        value
        for name in ("VERCEL_URL", "VERCEL_PROJECT_PRODUCTION_URL")
        if isinstance((value := source.get(name)), str)
        and _PUBLIC_HOST_PATTERN.fullmatch(value) is not None
    }
    return frozenset(hosts)


def _json_response(
    status: HTTPStatus,
    document: object,
    *,
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> PublicHttpResponse:
    body = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    headers = (
        *_API_SECURITY_HEADERS,
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
        *extra_headers,
    )
    return PublicHttpResponse(int(status), headers, body)


def _error(
    status: HTTPStatus,
    code: str,
    message: str,
) -> PublicHttpResponse:
    return _json_response(
        status,
        {"error": {"code": code, "message": message}},
    )


def _require_target(
    request: PublicHttpRequest,
    *,
    method: str,
    path: str,
) -> PublicHttpResponse | None:
    if request.method != method:
        return _error(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Método no permitido.",
        )
    if "?" in request.target or request.target != path:
        return _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "Solicitud no válida.",
        )
    return None


def _require_public_request_context(
    request: PublicHttpRequest,
    *,
    environ: Mapping[str, str] | None,
    require_origin: bool,
) -> tuple[str | None, PublicHttpResponse | None]:
    hosts = allowed_public_hosts(environ)
    if not hosts:
        return None, _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "service_unavailable",
            "Servicio temporalmente no disponible.",
        )

    host_values = request.header_values("Host")
    if len(host_values) != 1 or host_values[0] not in hosts:
        return None, _error(
            HTTPStatus.MISDIRECTED_REQUEST,
            "invalid_host",
            "Solicitud rechazada.",
        )
    host = host_values[0]
    if request.header_values("X-Forwarded-Proto") != ("https",):
        return None, _error(
            HTTPStatus.FORBIDDEN,
            "request_rejected",
            "Solicitud rechazada.",
        )
    if request.header_values("Sec-Fetch-Site") != ("same-origin",):
        return None, _error(
            HTTPStatus.FORBIDDEN,
            "request_rejected",
            "Solicitud rechazada.",
        )

    expected_origin = f"https://{host}"
    origin_values = request.header_values("Origin")
    if require_origin:
        origin_matches = (
            len(origin_values) == 1
            and hmac.compare_digest(origin_values[0], expected_origin)
        )
    else:
        origin_matches = (
            not origin_values
            or (
                len(origin_values) == 1
                and hmac.compare_digest(origin_values[0], expected_origin)
            )
        )
    if not origin_matches:
        return None, _error(
            HTTPStatus.FORBIDDEN,
            "request_rejected",
            "Solicitud rechazada.",
        )
    return host, None


def _load_public_incidents(snapshot_path: Path) -> tuple[PublicIncident, ...]:
    try:
        document = json.loads(snapshot_path.read_text(encoding="utf-8"))
        raw_incidents = document["incidents"]
        profile = document["profile"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        raise ValueError("public snapshot is unavailable") from None
    if profile != "public_static_snapshot" or not isinstance(
        raw_incidents, list
    ):
        raise ValueError("public snapshot is unavailable")
    try:
        incidents = tuple(
            PublicIncident.model_validate(item) for item in raw_incidents
        )
    except ValidationError:
        raise ValueError("public snapshot is unavailable") from None
    if len(incidents) != 12 or len({item.id for item in incidents}) != 12:
        raise ValueError("public snapshot is unavailable")
    return incidents


def handle_public_status(
    request: PublicHttpRequest,
    *,
    environ: Mapping[str, str] | None = None,
    snapshot_path: Path = PUBLIC_SNAPSHOT_PATH,
    token_factory: Callable[[int], str] = secrets.token_urlsafe,
) -> PublicHttpResponse:
    target_error = _require_target(
        request,
        method="GET",
        path="/api/status",
    )
    if target_error is not None:
        return target_error
    _, context_error = _require_public_request_context(
        request,
        environ=environ,
        require_origin=False,
    )
    if context_error is not None:
        return context_error
    if request.body:
        return _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "Solicitud no válida.",
        )

    try:
        incidents = _load_public_incidents(snapshot_path)
        csrf_token = token_factory(32)
    except Exception:
        return _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "service_unavailable",
            "Servicio temporalmente no disponible.",
        )
    if (
        not isinstance(csrf_token, str)
        or _CSRF_TOKEN_PATTERN.fullmatch(csrf_token) is None
    ):
        return _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "service_unavailable",
            "Servicio temporalmente no disponible.",
        )

    enabled = public_llm_enabled(environ)
    return _json_response(
        HTTPStatus.OK,
        {
            "app": {
                "analysis_calls_per_operation": 2,
                "baseline_provider": "public_static_snapshot",
                "deterministic": False,
                "external_calls": enabled,
                "id": "GSL-PUBLIC-LLM-001",
                "mode": "public_llm",
                "persistence": False,
                "public_llm_enabled": enabled,
                "version": "1.0.0",
            },
            "capabilities": {
                "analyze": enabled,
                "baseline": True,
                "free_prompt": False,
                "uploads": False,
            },
            "csrf_token": csrf_token,
            "incidents": [
                incident.model_dump(mode="json") for incident in incidents
            ],
        },
        extra_headers=(
            (
                "Set-Cookie",
                (
                    f"{PUBLIC_CSRF_COOKIE}={csrf_token}; Path=/; "
                    "Max-Age=600; HttpOnly; Secure; SameSite=Strict"
                ),
            ),
        ),
    )


def _csrf_cookie_values(request: PublicHttpRequest) -> tuple[str, ...]:
    matches: list[str] = []
    for header in request.header_values("Cookie"):
        for fragment in header.split(";"):
            name, separator, value = fragment.strip().partition("=")
            if separator and name == PUBLIC_CSRF_COOKIE:
                matches.append(value)
    return tuple(matches)


def _require_csrf(request: PublicHttpRequest) -> PublicHttpResponse | None:
    header_values = request.header_values(PUBLIC_CSRF_HEADER)
    cookie_values = _csrf_cookie_values(request)
    if len(header_values) != 1 or len(cookie_values) != 1:
        return _error(
            HTTPStatus.FORBIDDEN,
            "request_rejected",
            "Solicitud rechazada.",
        )
    header_token = header_values[0]
    cookie_token = cookie_values[0]
    if (
        _CSRF_TOKEN_PATTERN.fullmatch(header_token) is None
        or _CSRF_TOKEN_PATTERN.fullmatch(cookie_token) is None
        or not hmac.compare_digest(header_token, cookie_token)
    ):
        return _error(
            HTTPStatus.FORBIDDEN,
            "request_rejected",
            "Solicitud rechazada.",
        )
    return None


def _duplicate_rejecting_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise _DuplicateJsonKey
        document[key] = value
    return document


def _parse_analyze_request(
    request: PublicHttpRequest,
) -> tuple[PublicAnalyzeRequest | None, PublicHttpResponse | None]:
    if request.header_values("Content-Encoding"):
        return None, _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "Solicitud no válida.",
        )
    if request.header_values("Transfer-Encoding"):
        return None, _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "Solicitud no válida.",
        )
    if request.header_values("Content-Type") != ("application/json",):
        return None, _error(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Se requiere application/json.",
        )
    length_values = request.header_values("Content-Length")
    if (
        len(length_values) != 1
        or re.fullmatch(r"[0-9]+", length_values[0]) is None
    ):
        return None, _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "Solicitud no válida.",
        )
    content_length = int(length_values[0])
    if content_length > MAX_PUBLIC_REQUEST_BYTES:
        return None, _error(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "request_too_large",
            "La solicitud supera el límite permitido.",
        )
    if content_length != len(request.body):
        return None, _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "Solicitud no válida.",
        )
    try:
        document = json.loads(
            request.body.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
        )
        parsed = PublicAnalyzeRequest.model_validate(document)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        ValidationError,
    ):
        return None, _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
            "Solicitud no válida.",
        )
    return parsed, None


def handle_public_analyze(
    request: PublicHttpRequest,
    *,
    environ: Mapping[str, str] | None = None,
    analyzer: Callable[[str], PublicAnalysisEnvelope] = (
        analyze_public_incident
    ),
) -> PublicHttpResponse:
    target_error = _require_target(
        request,
        method="POST",
        path="/api/analyze",
    )
    if target_error is not None:
        return target_error
    _, context_error = _require_public_request_context(
        request,
        environ=environ,
        require_origin=True,
    )
    if context_error is not None:
        return context_error
    csrf_error = _require_csrf(request)
    if csrf_error is not None:
        return csrf_error
    parsed, request_error = _parse_analyze_request(request)
    if request_error is not None:
        return request_error
    if not public_llm_enabled(environ):
        return _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "analysis_unavailable",
            "Análisis temporalmente no disponible.",
        )
    if parsed is None:
        raise RuntimeError("validated request unavailable")

    try:
        result = analyzer(parsed.incident_id)
        if not isinstance(result, PublicAnalysisEnvelope):
            raise TypeError("analyzer returned an invalid envelope")
    except UnknownCloudIncidentError:
        return _error(
            HTTPStatus.NOT_FOUND,
            "unknown_incident",
            "Incidente sintético no encontrado.",
        )
    except OllamaCloudError:
        return _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "analysis_unavailable",
            "Análisis temporalmente no disponible.",
        )
    except (
        BenignFlowError,
        ToolArgumentsError,
        ToolDeniedError,
        ResourceLimitError,
        SecurityEventError,
        ValidationError,
    ):
        return _error(
            HTTPStatus.BAD_GATEWAY,
            "analysis_failed",
            "El análisis alojado no pudo completarse.",
        )
    except Exception:
        return _error(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "internal_error",
            "La operación no pudo completarse.",
        )

    return _json_response(
        HTTPStatus.OK,
        result.model_dump(mode="json"),
    )
