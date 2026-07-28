"""Interfaz web local y acotada para el flujo benigno del laboratorio."""

from __future__ import annotations

import hmac
import json
import secrets
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Annotated, Any, Final, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .baseline import (
    UnknownIncidentError,
    run_functional_baseline,
    run_incident,
)
from .data_contract import load_dataset
from .resource_control import (
    ResourceLimitError,
    ResourceLockError,
    exclusive_process_lock,
)
from .security_events import SecurityEventError, SecurityEventJournal

MAX_REQUEST_BYTES: Final = 1024
REQUEST_TIMEOUT_SECONDS: Final = 5.0
DEFAULT_PORT: Final = 8765
LOOPBACK_HOST: Final = "127.0.0.1"
WEB_ASSETS: Final = Path(__file__).with_name("web_assets")

STATIC_ROUTES: Final = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/assets/app.css": ("app.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/assets/favicon.svg": ("favicon.svg", "image/svg+xml"),
}

CONTENT_SECURITY_POLICY: Final = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'none'",
        "connect-src 'self'",
        "font-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "img-src 'self' data:",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
    )
)


class WebSchema(BaseModel):
    """Base estricta para los mensajes de la interfaz web."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AnalyzeRequest(WebSchema):
    incident_id: Annotated[str, Field(pattern=r"^INC-BEN-[0-9]{3}$")]


class GenAISeguroHTTPServer(ThreadingHTTPServer):
    """Servidor de loopback con estado efímero mínimo."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 8

    def __init__(self, data_dir: Path, port: int) -> None:
        if not isinstance(data_dir, Path):
            raise TypeError("data_dir must be a Path")
        if isinstance(port, bool) or not isinstance(port, int):
            raise TypeError("port must be an integer")
        if port < 0 or port > 65535:
            raise ValueError("port must be between 0 and 65535")

        bundle = load_dataset(data_dir)
        self.data_dir = data_dir
        self.csrf_token = secrets.token_urlsafe(32)
        self.incidents = tuple(
            {
                "category": incident.category,
                "id": incident.id,
                "title": incident.title,
            }
            for incident in bundle.incidents
        )
        super().__init__((LOOPBACK_HOST, port), GenAISeguroRequestHandler)

    @property
    def allowed_hosts(self) -> frozenset[str]:
        port = self.server_address[1]
        return frozenset(
            {
                f"{LOOPBACK_HOST}:{port}",
                f"localhost:{port}",
            }
        )


class GenAISeguroRequestHandler(BaseHTTPRequestHandler):
    """Expone únicamente assets y dos operaciones benignas cerradas."""

    protocol_version = "HTTP/1.1"
    server_version = "GenAI-Seguro-Lab"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)

    @property
    def lab_server(self) -> GenAISeguroHTTPServer:
        return cast(GenAISeguroHTTPServer, self.server)

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        """Evita registrar rutas, cabeceras o cuerpos de petición."""

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy",
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _send_bytes(
        self,
        status: HTTPStatus,
        content: bytes,
        content_type: str,
        *,
        extra_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        for name, value in extra_headers:
            self.send_header(name, value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(content)
        self.close_connection = True

    def _send_json(
        self,
        status: HTTPStatus,
        document: dict[str, Any],
        *,
        extra_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        content = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self._send_bytes(
            status,
            content,
            "application/json; charset=utf-8",
            extra_headers=extra_headers,
        )

    def _send_error_json(
        self,
        status: HTTPStatus,
        code: str,
        message: str,
    ) -> None:
        self._send_json(
            status,
            {"error": {"code": code, "message": message}},
        )

    def _host_is_allowed(self) -> bool:
        host = self.headers.get("Host", "")
        return any(
            hmac.compare_digest(host, allowed)
            for allowed in self.lab_server.allowed_hosts
        )

    def _require_allowed_host(self) -> bool:
        if self._host_is_allowed():
            return True
        self._send_error_json(
            HTTPStatus.MISDIRECTED_REQUEST,
            "invalid_host",
            "Solicitud rechazada.",
        )
        return False

    def _require_same_origin(self) -> bool:
        host = self.headers.get("Host", "")
        expected_origin = f"http://{host}"
        origin = self.headers.get("Origin", "")
        fetch_site = self.headers.get("Sec-Fetch-Site")
        token = self.headers.get("X-GSL-CSRF", "")
        if (
            hmac.compare_digest(origin, expected_origin)
            and hmac.compare_digest(token, self.lab_server.csrf_token)
            and fetch_site in {None, "none", "same-origin"}
        ):
            return True
        self._send_error_json(
            HTTPStatus.FORBIDDEN,
            "request_rejected",
            "Solicitud rechazada.",
        )
        return False

    def _read_json_body(self) -> dict[str, Any] | None:
        if self.headers.get("Transfer-Encoding") is not None:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "Solicitud no válida.",
            )
            return None
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            self._send_error_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Se requiere application/json.",
            )
            return None
        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length or "")
        except ValueError:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "Solicitud no válida.",
            )
            return None
        if content_length < 0:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "Solicitud no válida.",
            )
            return None
        if content_length > MAX_REQUEST_BYTES:
            self._send_error_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request_too_large",
                "La solicitud supera el límite permitido.",
            )
            return None
        try:
            raw_body = self.rfile.read(content_length)
            if len(raw_body) != content_length:
                raise ValueError
            document = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid_json",
                "JSON no válido.",
            )
            return None
        if not isinstance(document, dict):
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "Solicitud no válida.",
            )
            return None
        return document

    def _status_document(self) -> dict[str, Any]:
        return {
            "app": {
                "external_calls": False,
                "id": "GSL-WEB-001",
                "mode": "local_synthetic_deterministic",
                "model": "deterministic/scripted-v1",
                "persistence": False,
                "version": "1.0.0",
            },
            "capabilities": {
                "analyze": True,
                "baseline": True,
                "free_prompt": False,
                "uploads": False,
            },
            "csrf_token": self.lab_server.csrf_token,
            "incidents": self.lab_server.incidents,
        }

    def _run_analysis(self, incident_id: str) -> dict[str, Any]:
        journal = SecurityEventJournal("analyze")
        try:
            with exclusive_process_lock(
                self.lab_server.data_dir / "manifest.json",
                security_journal=journal,
            ):
                bundle = load_dataset(self.lab_server.data_dir)
                result = run_incident(
                    bundle,
                    incident_id,
                    security_journal=journal,
                )
        except Exception:
            if not journal.is_finished:
                journal.finish(succeeded=False)
            raise
        return {
            "result": result.model_dump(mode="json"),
            "security_report": journal.report().model_dump(mode="json"),
        }

    def _run_baseline(self) -> dict[str, Any]:
        journal = SecurityEventJournal("baseline")
        try:
            with exclusive_process_lock(
                self.lab_server.data_dir / "manifest.json",
                security_journal=journal,
            ):
                result = run_functional_baseline(
                    self.lab_server.data_dir,
                    security_journal=journal,
                )
        except Exception:
            if not journal.is_finished:
                journal.finish(succeeded=False)
            raise
        return {
            "result": result.model_dump(mode="json"),
            "security_report": journal.report().model_dump(mode="json"),
        }

    def do_GET(self) -> None:
        if not self._require_allowed_host():
            return
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "Recurso no encontrado.",
            )
            return
        if parsed.path == "/api/status":
            self._send_json(HTTPStatus.OK, self._status_document())
            return
        static = STATIC_ROUTES.get(parsed.path)
        if static is None:
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "Recurso no encontrado.",
            )
            return
        filename, content_type = static
        try:
            content = (WEB_ASSETS / filename).read_bytes()
        except OSError:
            self._send_error_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "interface_unavailable",
                "Interfaz no disponible.",
            )
            return
        self._send_bytes(HTTPStatus.OK, content, content_type)

    def do_POST(self) -> None:
        if not self._require_allowed_host() or not self._require_same_origin():
            return
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "Recurso no encontrado.",
            )
            return
        if parsed.path not in {"/api/analyze", "/api/baseline"}:
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "Recurso no encontrado.",
            )
            return
        document = self._read_json_body()
        if document is None:
            return
        if parsed.path == "/api/baseline" and document:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "Solicitud no válida.",
            )
            return

        try:
            if parsed.path == "/api/analyze":
                request = AnalyzeRequest.model_validate(document)
                response = self._run_analysis(request.incident_id)
            else:
                response = self._run_baseline()
        except ValidationError:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "Solicitud no válida.",
            )
            return
        except UnknownIncidentError:
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "unknown_incident",
                "Incidente sintético no disponible.",
            )
            return
        except ResourceLockError:
            self._send_error_json(
                HTTPStatus.CONFLICT,
                "operation_busy",
                "El laboratorio está atendiendo otra operación.",
            )
            return
        except (
            LookupError,
            OSError,
            PermissionError,
            ResourceLimitError,
            RuntimeError,
            SecurityEventError,
            TypeError,
            ValueError,
        ):
            self._send_error_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "operation_unavailable",
                "La operación no está disponible.",
            )
            return
        self._send_json(HTTPStatus.OK, response)

    def _reject_method(self) -> None:
        if not self._require_allowed_host():
            return
        self._send_error_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Método no permitido.",
        )

    do_DELETE = _reject_method
    do_HEAD = _reject_method
    do_OPTIONS = _reject_method
    do_PATCH = _reject_method
    do_PUT = _reject_method
    do_TRACE = _reject_method


def create_server(
    data_dir: Path,
    *,
    port: int = DEFAULT_PORT,
) -> GenAISeguroHTTPServer:
    """Crea un listener fijo en loopback; ``port=0`` se reserva a tests."""

    return GenAISeguroHTTPServer(data_dir, port)


def serve(data_dir: Path, *, port: int = DEFAULT_PORT) -> int:
    """Atiende la interfaz hasta recibir una interrupción del operador."""

    server = create_server(data_dir, port=port)
    actual_port = server.server_address[1]
    sys.stderr.write(
        f"GenAI Seguro Lab disponible en http://{LOOPBACK_HOST}:{actual_port}\n"
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0
