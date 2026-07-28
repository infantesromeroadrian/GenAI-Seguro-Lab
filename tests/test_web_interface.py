"""Pruebas del frontal HTTP local y de sus límites de confianza."""

from __future__ import annotations

import http.client
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Thread
from typing import Any

from genai_seguro_lab.web import (
    CONTENT_SECURITY_POLICY,
    MAX_REQUEST_BYTES,
    create_server,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DRAFTS_DIR = ROOT / "sandbox" / "drafts"


@contextmanager
def _running_server() -> Iterator[tuple[str, int]]:
    server = create_server(DATA_DIR, port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        assert host == "127.0.0.1"
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def _request(
    server_address: tuple[str, int],
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    host, port = server_address
    connection = http.client.HTTPConnection(host, port, timeout=5)
    request_headers = dict(headers or {})
    if body is not None:
        request_headers.setdefault("Content-Length", str(len(body)))
    try:
        connection.request(
            method,
            path,
            body=body,
            headers=request_headers,
        )
        response = connection.getresponse()
        response_body = response.read()
        response_headers = {
            name.lower(): value for name, value in response.getheaders()
        }
        return response.status, response_headers, response_body
    finally:
        connection.close()


def _status(server_address: tuple[str, int]) -> dict[str, Any]:
    status, _, body = _request(server_address, "GET", "/api/status")
    assert status == 200
    return json.loads(body)


def _post_headers(
    server_address: tuple[str, int],
    token: str,
) -> dict[str, str]:
    host, port = server_address
    return {
        "Content-Type": "application/json",
        "Origin": f"http://{host}:{port}",
        "Sec-Fetch-Site": "same-origin",
        "X-GSL-CSRF": token,
    }


def test_server_binds_only_to_loopback_and_lists_closed_capabilities() -> None:
    with _running_server() as server_address:
        payload = _status(server_address)

    assert payload["app"] == {
        "external_calls": False,
        "id": "GSL-WEB-001",
        "mode": "local_synthetic_deterministic",
        "model": "deterministic/scripted-v1",
        "persistence": False,
        "version": "1.0.0",
    }
    assert payload["capabilities"] == {
        "analyze": True,
        "baseline": True,
        "free_prompt": False,
        "uploads": False,
    }
    assert len(payload["csrf_token"]) >= 32
    assert [item["id"] for item in payload["incidents"]] == [
        f"INC-BEN-{number:03d}" for number in range(1, 13)
    ]


def test_frontend_assets_are_local_and_receive_security_headers() -> None:
    with _running_server() as server_address:
        status, headers, html = _request(server_address, "GET", "/")
        css_status, css_headers, css = _request(
            server_address,
            "GET",
            "/assets/app.css",
        )
        js_status, js_headers, javascript = _request(
            server_address,
            "GET",
            "/assets/app.js",
        )

    assert status == css_status == js_status == 200
    assert b"GenAI Seguro Lab" in html
    assert b"/assets/app.css" in html
    assert b"/assets/app.js" in html
    assert b"https://" not in html
    assert b"http://" not in html
    assert b"prefers-reduced-motion" in css
    assert b"textContent" in javascript
    assert b"innerHTML" not in javascript
    for response_headers in (headers, css_headers, js_headers):
        assert response_headers["cache-control"] == "no-store"
        assert (
            response_headers["content-security-policy"]
            == CONTENT_SECURITY_POLICY
        )
        assert response_headers["cross-origin-opener-policy"] == "same-origin"
        assert (
            response_headers["cross-origin-resource-policy"] == "same-origin"
        )
        assert response_headers["referrer-policy"] == "no-referrer"
        assert response_headers["x-content-type-options"] == "nosniff"
        assert response_headers["x-frame-options"] == "DENY"
        assert "access-control-allow-origin" not in response_headers


def test_analysis_reuses_safe_flow_and_emits_ephemeral_security_report() -> None:
    before = tuple(sorted(path.name for path in DRAFTS_DIR.iterdir()))
    with _running_server() as server_address:
        token = _status(server_address)["csrf_token"]
        status, headers, body = _request(
            server_address,
            "POST",
            "/api/analyze",
            body=b'{"incident_id":"INC-BEN-001"}',
            headers=_post_headers(server_address, token),
        )

    payload = json.loads(body)
    assert status == 200
    assert headers["content-type"] == "application/json; charset=utf-8"
    assert payload["result"]["incident_id"] == "INC-BEN-001"
    assert payload["result"]["category"] == "phishing"
    assert payload["result"]["status"] == "passed"
    assert payload["result"]["external_calls"] is False
    assert payload["result"]["cost_eur"] == 0
    assert payload["result"]["model_invocations"] == 2
    assert payload["result"]["tool_requests"] == 1
    assert payload["security_report"]["profile"] == "analyze"
    assert payload["security_report"]["events_count"] == 10
    assert payload["security_report"]["events"][-1]["kind"] == (
        "operation_completed"
    )
    assert tuple(sorted(path.name for path in DRAFTS_DIR.iterdir())) == before


def test_baseline_returns_all_cases_without_external_calls_or_writes() -> None:
    before = tuple(sorted(path.name for path in DRAFTS_DIR.iterdir()))
    with _running_server() as server_address:
        token = _status(server_address)["csrf_token"]
        status, _, body = _request(
            server_address,
            "POST",
            "/api/baseline",
            body=b"{}",
            headers=_post_headers(server_address, token),
        )

    payload = json.loads(body)
    assert status == 200
    assert payload["result"]["summary"] == {
        "cases_failed": 0,
        "cases_passed": 12,
        "cases_total": 12,
        "cost_eur": 0,
        "external_calls": 0,
        "model_invocations": 24,
        "tool_requests": 12,
    }
    assert len(payload["result"]["cases"]) == 12
    assert payload["security_report"]["profile"] == "baseline"
    assert payload["security_report"]["events_count"] > 10
    assert tuple(sorted(path.name for path in DRAFTS_DIR.iterdir())) == before


def test_post_requires_same_origin_and_ephemeral_csrf_token() -> None:
    with _running_server() as server_address:
        token = _status(server_address)["csrf_token"]
        wrong_origin_headers = _post_headers(server_address, token)
        wrong_origin_headers["Origin"] = "https://attacker.example"
        origin_status, origin_headers, origin_body = _request(
            server_address,
            "POST",
            "/api/analyze",
            body=b'{"incident_id":"INC-BEN-001"}',
            headers=wrong_origin_headers,
        )
        token_status, _, token_body = _request(
            server_address,
            "POST",
            "/api/analyze",
            body=b'{"incident_id":"INC-BEN-001"}',
            headers=_post_headers(server_address, "wrong-token"),
        )

    assert origin_status == token_status == 403
    assert json.loads(origin_body)["error"]["code"] == "request_rejected"
    assert json.loads(token_body)["error"]["code"] == "request_rejected"
    assert "access-control-allow-origin" not in origin_headers


def test_web_contract_rejects_unknown_extra_and_oversized_inputs() -> None:
    with _running_server() as server_address:
        token = _status(server_address)["csrf_token"]
        headers = _post_headers(server_address, token)
        unknown_status, _, unknown_body = _request(
            server_address,
            "POST",
            "/api/analyze",
            body=b'{"incident_id":"INC-BEN-999"}',
            headers=headers,
        )
        extra_status, _, extra_body = _request(
            server_address,
            "POST",
            "/api/analyze",
            body=b'{"incident_id":"INC-BEN-001","prompt":"ignored"}',
            headers=headers,
        )
        oversized_status, _, oversized_body = _request(
            server_address,
            "POST",
            "/api/analyze",
            body=b"{" + b" " * MAX_REQUEST_BYTES + b"}",
            headers=headers,
        )
        baseline_status, _, baseline_body = _request(
            server_address,
            "POST",
            "/api/baseline",
            body=b'{"unexpected":true}',
            headers=headers,
        )

    assert unknown_status == 404
    assert json.loads(unknown_body)["error"]["code"] == "unknown_incident"
    assert extra_status == baseline_status == 400
    assert json.loads(extra_body)["error"]["code"] == "invalid_request"
    assert json.loads(baseline_body)["error"]["code"] == "invalid_request"
    assert oversized_status == 413
    assert json.loads(oversized_body)["error"]["code"] == "request_too_large"


def test_invalid_host_and_unsupported_methods_fail_closed() -> None:
    with _running_server() as server_address:
        host, port = server_address
        connection = http.client.HTTPConnection(host, port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True)
            connection.putheader("Host", "attacker.example")
            connection.endheaders()
            response = connection.getresponse()
            invalid_host_status = response.status
            invalid_host_body = json.loads(response.read())
        finally:
            connection.close()

        options_status, options_headers, options_body = _request(
            server_address,
            "OPTIONS",
            "/api/analyze",
            headers={
                "Origin": "https://attacker.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        trace_status, trace_headers, trace_body = _request(
            server_address,
            "TRACE",
            "/api/status",
        )

    assert invalid_host_status == 421
    assert invalid_host_body["error"]["code"] == "invalid_host"
    assert options_status == 405
    assert json.loads(options_body)["error"]["code"] == "method_not_allowed"
    assert "access-control-allow-origin" not in options_headers
    assert trace_status == 405
    assert json.loads(trace_body)["error"]["code"] == "method_not_allowed"
    assert trace_headers["content-security-policy"] == CONTENT_SECURITY_POLICY
