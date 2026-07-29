"""Contrato focal, sin red, del perfil público con análisis alojado."""

from __future__ import annotations

import json
from collections.abc import Mapping
from http import HTTPStatus
from pathlib import Path

import pytest

from genai_seguro_lab.ollama_cloud_adapter import (
    OLLAMA_NUM_PREDICT,
    OLLAMA_PUBLIC_TIMEOUT_SECONDS,
    OllamaCloudAdapter,
)
from genai_seguro_lab.public_analysis import analyze_public_incident
from genai_seguro_lab.public_api import (
    MAX_PUBLIC_REQUEST_BYTES,
    PUBLIC_CSRF_COOKIE,
    PublicHttpRequest,
    handle_public_analyze,
    handle_public_status,
    public_llm_enabled,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
PREVIEW_HOST = "gsl-preview-abc.vercel.app"
PRODUCTION_HOST = "genai-seguro-lab.vercel.app"
TOKEN = "a" * 43
ENABLED_ENV = {
    "PUBLIC_LLM_ENABLED": "true",
    "VERCEL_PROJECT_PRODUCTION_URL": PRODUCTION_HOST,
    "VERCEL_URL": PREVIEW_HOST,
}


class SequenceTransport:
    def __init__(self, responses: tuple[bytes, ...]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> bytes:
        self.calls.append(
            {
                "document": json.loads(body),
                "header_names": frozenset(headers),
                "max_response_bytes": max_response_bytes,
                "timeout_seconds": timeout_seconds,
                "url": url,
            }
        )
        if not self._responses:
            raise AssertionError("unexpected provider call")
        return self._responses.pop(0)


def _remote_tool_response() -> bytes:
    return json.dumps(
        {
            "done": True,
            "message": {
                "content": "",
                "role": "assistant",
                "thinking": "RAW_REASONING_MUST_NOT_BE_PUBLIC",
                "tool_calls": [
                    {
                        "function": {
                            "arguments": {
                                "knowledge_ids": ["KB-001"],
                                "limit": 1,
                                "query": "phishing",
                            },
                            "name": "knowledge_search",
                        },
                        "type": "function",
                    }
                ],
            },
            "raw_provider_body": "REMOTE_BODY_MUST_NOT_BE_PUBLIC",
        }
    ).encode()


def _remote_final_response() -> bytes:
    return json.dumps(
        {
            "done": True,
            "message": {
                "content": (
                    '{"actions_executed":false,'
                    '"compromise_confirmed":false,'
                    '"incident_id":"INC-BEN-001",'
                    '"knowledge_ids":["KB-001"],'
                    '"summary":"No se confirma compromiso."}'
                ),
                "role": "assistant",
                "thinking": "FINAL_REASONING_MUST_NOT_BE_PUBLIC",
            },
        }
    ).encode()


def _status_request(host: str = PRODUCTION_HOST) -> PublicHttpRequest:
    return PublicHttpRequest(
        method="GET",
        target="/api/status",
        headers=(
            ("Host", host),
            ("Sec-Fetch-Site", "same-origin"),
            ("X-Forwarded-Proto", "https"),
        ),
    )


def _analyze_request(
    *,
    body: bytes = b'{"incident_id":"INC-BEN-001"}',
    host: str = PRODUCTION_HOST,
    token: str = TOKEN,
    extra_headers: tuple[tuple[str, str], ...] = (),
    target: str = "/api/analyze",
) -> PublicHttpRequest:
    return PublicHttpRequest(
        method="POST",
        target=target,
        headers=(
            ("Host", host),
            ("Origin", f"https://{host}"),
            ("Sec-Fetch-Site", "same-origin"),
            ("X-Forwarded-Proto", "https"),
            ("Content-Length", str(len(body))),
            ("Content-Type", "application/json"),
            ("Cookie", f"unrelated=x; {PUBLIC_CSRF_COOKIE}={token}"),
            ("X-GSL-CSRF", token),
            *extra_headers,
        ),
        body=body,
    )


def _response_json(response: object) -> dict[str, object]:
    body = getattr(response, "body")
    parsed = json.loads(body)
    assert isinstance(parsed, dict)
    return parsed


def _header_values(response: object, name: str) -> tuple[str, ...]:
    return tuple(
        value
        for candidate, value in getattr(response, "headers")
        if candidate.casefold() == name.casefold()
    )


@pytest.mark.parametrize("host", (PREVIEW_HOST, PRODUCTION_HOST))
def test_status_accepts_only_declared_https_vercel_hosts(host: str) -> None:
    response = handle_public_status(
        _status_request(host),
        environ=ENABLED_ENV,
        token_factory=lambda _: TOKEN,
    )

    assert response.status == HTTPStatus.OK
    payload = _response_json(response)
    assert payload["app"] == {
        "analysis_calls_per_operation": 2,
        "baseline_provider": "public_static_snapshot",
        "deterministic": False,
        "external_calls": True,
        "id": "GSL-PUBLIC-LLM-001",
        "mode": "public_llm",
        "persistence": False,
        "public_llm_enabled": True,
        "version": "1.0.0",
    }
    assert payload["capabilities"] == {
        "analyze": True,
        "baseline": True,
        "free_prompt": False,
        "uploads": False,
    }
    assert len(payload["incidents"]) == 12
    assert "provider" not in payload["app"]
    assert "model" not in payload["app"]
    assert "OLLAMA_API_KEY" not in response.body.decode()
    cookie = _header_values(response, "Set-Cookie")
    assert cookie == (
        (
            f"{PUBLIC_CSRF_COOKIE}={TOKEN}; Path=/; Max-Age=600; "
            "HttpOnly; Secure; SameSite=Strict"
        ),
    )
    assert _header_values(response, "Content-Type") == (
        "application/json",
    )
    assert _header_values(response, "Cache-Control") == ("no-store",)
    assert not _header_values(response, "Access-Control-Allow-Origin")


def test_public_post_reuses_cloud_flow_and_returns_only_safe_projection() -> None:
    transport = SequenceTransport(
        (_remote_tool_response(), _remote_final_response())
    )
    adapter = OllamaCloudAdapter(
        transport=transport,
        api_key_loader=lambda: "test-only-placeholder",
        timeout_seconds=OLLAMA_PUBLIC_TIMEOUT_SECONDS,
    )

    response = handle_public_analyze(
        _analyze_request(),
        environ=ENABLED_ENV,
        analyzer=lambda incident_id: analyze_public_incident(
            incident_id,
            data_dir=DATA_DIR,
            adapter=adapter,
            clock=lambda: 0.0,
        ),
    )

    assert response.status == HTTPStatus.OK
    assert len(transport.calls) == 2
    assert all(
        call["timeout_seconds"] == 25.0 for call in transport.calls
    )
    assert all(
        call["document"]["options"]["num_predict"] == OLLAMA_NUM_PREDICT
        for call in transport.calls
    )
    payload = _response_json(response)
    assert set(payload["result"]) == {
        "category",
        "cost_eur",
        "deterministic",
        "external_calls",
        "incident_id",
        "knowledge_ids",
        "model_invocations",
        "output_text",
        "status",
        "tool_requests",
    }
    assert payload["result"]["incident_id"] == "INC-BEN-001"
    assert payload["result"]["model_invocations"] == 2
    assert payload["result"]["tool_requests"] == 1
    assert payload["result"]["external_calls"] is True
    assert payload["result"]["cost_eur"] is None
    assert set(payload["security_report"]) == {
        "bytes_used",
        "control_id",
        "correlations_count",
        "events",
        "events_count",
        "profile",
        "version",
    }
    assert set(payload["security_report"]["events"][0]) == {
        "elapsed_ms",
        "kind",
        "outcome",
        "sequence",
        "signal",
        "source",
    }
    serialized = response.body.decode()
    for forbidden in (
        "provider",
        "request_fingerprints",
        "correlation_id",
        "event_sha256",
        "previous_event_sha256",
        "RAW_REASONING_MUST_NOT_BE_PUBLIC",
        "REMOTE_BODY_MUST_NOT_BE_PUBLIC",
        "FINAL_REASONING_MUST_NOT_BE_PUBLIC",
        "test-only-placeholder",
        "gpt-oss:120b",
    ):
        assert forbidden not in serialized
    assert _header_values(response, "Content-Type") == (
        "application/json",
    )
    assert _header_values(response, "Cache-Control") == ("no-store",)
    assert not _header_values(response, "Access-Control-Allow-Origin")


@pytest.mark.parametrize(
    ("value", "enabled"),
    (
        (None, False),
        ("", False),
        ("false", False),
        ("TRUE", False),
        (" true", False),
        ("true", True),
    ),
)
def test_public_llm_kill_switch_accepts_only_literal_true(
    value: str | None,
    enabled: bool,
) -> None:
    environ = {
        "VERCEL_PROJECT_PRODUCTION_URL": PRODUCTION_HOST,
        "VERCEL_URL": PREVIEW_HOST,
    }
    if value is not None:
        environ["PUBLIC_LLM_ENABLED"] = value
    assert public_llm_enabled(environ) is enabled

    status = handle_public_status(
        _status_request(),
        environ=environ,
        token_factory=lambda _: TOKEN,
    )
    assert _response_json(status)["capabilities"]["analyze"] is enabled


def test_disabled_analyze_returns_sanitized_503_without_calling_runner() -> None:
    calls = 0

    def analyzer(_: str) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("runner must not be called")

    environ = {
        "PUBLIC_LLM_ENABLED": "false",
        "VERCEL_PROJECT_PRODUCTION_URL": PRODUCTION_HOST,
        "VERCEL_URL": PREVIEW_HOST,
    }
    response = handle_public_analyze(
        _analyze_request(),
        environ=environ,
        analyzer=analyzer,  # type: ignore[arg-type]
    )

    assert response.status == HTTPStatus.SERVICE_UNAVAILABLE
    assert _response_json(response) == {
        "error": {
            "code": "analysis_unavailable",
            "message": "Análisis temporalmente no disponible.",
        }
    }
    assert calls == 0


@pytest.mark.parametrize(
    ("http_request", "status", "code"),
    (
        (
            _analyze_request(target="/api/analyze?debug=1"),
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
        ),
        (
            _analyze_request(
                extra_headers=(("Content-Encoding", "gzip"),)
            ),
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
        ),
        (
            _analyze_request(
                extra_headers=(("Transfer-Encoding", "chunked"),)
            ),
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
        ),
        (
            _analyze_request(
                extra_headers=(("Content-Type", "application/json"),)
            ),
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ),
        (
            _analyze_request(
                body=b"{" + b" " * MAX_PUBLIC_REQUEST_BYTES + b"}"
            ),
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "request_too_large",
        ),
        (
            _analyze_request(
                body=(
                    b'{"incident_id":"INC-BEN-001",'
                    b'"incident_id":"INC-BEN-002"}'
                )
            ),
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
        ),
        (
            _analyze_request(
                body=b'{"incident_id":"INC-BEN-001","prompt":"x"}'
            ),
            HTTPStatus.BAD_REQUEST,
            "invalid_request",
        ),
        (
            _analyze_request(
                extra_headers=(("X-GSL-CSRF", "b" * 43),)
            ),
            HTTPStatus.FORBIDDEN,
            "request_rejected",
        ),
    ),
)
def test_public_request_contract_fails_closed(
    http_request: PublicHttpRequest,
    status: HTTPStatus,
    code: str,
) -> None:
    response = handle_public_analyze(
        http_request,
        environ=ENABLED_ENV,
        analyzer=lambda _: pytest.fail("runner must not be called"),
    )

    assert response.status == status
    assert _response_json(response)["error"]["code"] == code
    assert not _header_values(response, "Access-Control-Allow-Origin")


def test_wrong_host_origin_and_fetch_site_are_rejected() -> None:
    wrong_host = _analyze_request(host="attacker.example")
    wrong_origin = PublicHttpRequest(
        method="POST",
        target="/api/analyze",
        headers=tuple(
            (
                name,
                "https://attacker.example" if name == "Origin" else value,
            )
            for name, value in _analyze_request().headers
        ),
        body=_analyze_request().body,
    )
    wrong_fetch = PublicHttpRequest(
        method="POST",
        target="/api/analyze",
        headers=tuple(
            (
                name,
                "cross-site" if name == "Sec-Fetch-Site" else value,
            )
            for name, value in _analyze_request().headers
        ),
        body=_analyze_request().body,
    )

    assert handle_public_analyze(
        wrong_host, environ=ENABLED_ENV
    ).status == HTTPStatus.MISDIRECTED_REQUEST
    assert handle_public_analyze(
        wrong_origin, environ=ENABLED_ENV
    ).status == HTTPStatus.FORBIDDEN
    assert handle_public_analyze(
        wrong_fetch, environ=ENABLED_ENV
    ).status == HTTPStatus.FORBIDDEN
