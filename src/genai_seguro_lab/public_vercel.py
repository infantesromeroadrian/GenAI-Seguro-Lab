"""Adaptación mínima de BaseHTTPRequestHandler al contrato público puro."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from typing import Any, Literal

from .public_api import (
    MAX_PUBLIC_REQUEST_BYTES,
    PublicHttpRequest,
    PublicHttpResponse,
    handle_public_analyze,
    handle_public_status,
)


class PublicVercelHandler(BaseHTTPRequestHandler):
    """Handler compartido sin estado, logging de entrada ni lógica de producto."""

    endpoint: Literal["status", "analyze"]
    protocol_version = "HTTP/1.1"
    server_version = "GenAI-Seguro-Lab"
    sys_version = ""

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        """No conserva rutas, cabeceras, cookies ni cuerpos."""

    def _read_bounded_body(self) -> bytes:
        if (
            self.headers.get_all("Transfer-Encoding")
            or self.headers.get_all("Content-Encoding")
        ):
            return b""
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) != 1 or not lengths[0].isdigit():
            return b""
        length = int(lengths[0])
        if length > MAX_PUBLIC_REQUEST_BYTES:
            return b""
        return self.rfile.read(length)

    def _dispatch(self) -> None:
        request = PublicHttpRequest(
            method=self.command,
            target=self.path,
            headers=tuple(self.headers.raw_items()),
            body=self._read_bounded_body(),
        )
        response = (
            handle_public_status(request)
            if self.endpoint == "status"
            else handle_public_analyze(request)
        )
        self._send_public_response(response)

    def _send_public_response(self, response: PublicHttpResponse) -> None:
        self.send_response(response.status)
        for name, value in response.headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_OPTIONS = _dispatch
    do_HEAD = _dispatch
    do_TRACE = _dispatch
    do_CONNECT = _dispatch
