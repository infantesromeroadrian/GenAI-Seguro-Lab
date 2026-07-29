"""Contrato focal del perfil público estático y reproducible."""

from __future__ import annotations

import importlib.util
import json
from hashlib import sha256
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"
VERCEL_CONFIG = ROOT / "vercel.json"
ASSETS = ROOT / "src" / "genai_seguro_lab" / "web_assets"
EXPECTED_IDS = tuple(
    f"INC-BEN-{number:03d}" for number in range(1, 13)
)


def _load_generator() -> ModuleType:
    path = ROOT / "scripts" / "generate_public_snapshot.py"
    specification = importlib.util.spec_from_file_location(
        "gsl_public_snapshot_generator",
        path,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("public snapshot generator cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


GENERATOR = _load_generator()
SNAPSHOT_PATH = GENERATOR.SNAPSHOT_PATH


def test_snapshot_regenerates_byte_for_byte_from_deterministic_flows() -> None:
    generated = GENERATOR.build_public_snapshot(ROOT / "data")
    serialized = GENERATOR.canonical_public_snapshot(generated)

    assert serialized == SNAPSHOT_PATH.read_text(encoding="utf-8")
    assert generated["snapshot_id"] == "GSL-PUBLIC-PROFILE-001"
    assert generated["schema_version"] == "1.0.0"
    assert generated["profile"] == "public_static_snapshot"
    assert tuple(item["id"] for item in generated["incidents"]) == EXPECTED_IDS
    assert tuple(generated["analyses"]) == EXPECTED_IDS


def test_snapshot_is_local_sanitized_and_contains_all_safe_results() -> None:
    snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))

    assert snapshot["runtime"] == {
        "cost_eur": 0,
        "deterministic": True,
        "external_calls": False,
        "id": "GSL-PUBLIC-STATIC-001",
        "model": "scripted-v1",
        "persistence": False,
        "provider": "deterministic",
    }
    assert snapshot["baseline"]["result"]["summary"] == {
        "cases_failed": 0,
        "cases_passed": 12,
        "cases_total": 12,
        "cost_eur": 0,
        "external_calls": 0,
        "model_invocations": 24,
        "tool_requests": 12,
    }
    assert snapshot["baseline"]["security_report"]["profile"] == "baseline"
    for incident_id in EXPECTED_IDS:
        envelope = snapshot["analyses"][incident_id]
        assert envelope["result"]["incident_id"] == incident_id
        assert envelope["result"]["external_calls"] is False
        assert envelope["result"]["cost_eur"] == 0
        assert envelope["security_report"]["profile"] == "analyze"
        assert all(
            event["elapsed_ms"] == 0
            for event in envelope["security_report"]["events"]
        )

    normalized = SNAPSHOT_PATH.read_text(encoding="utf-8").casefold()
    for forbidden in (
        "authorization",
        "expected_result",
        "gpt-oss",
        "ollama",
        "oracle",
        "prompt",
    ):
        assert forbidden not in normalized


def test_vercel_profile_is_static_only_and_sets_security_headers() -> None:
    config = json.loads(VERCEL_CONFIG.read_text(encoding="utf-8"))

    assert set(config) == {
        "$schema",
        "headers",
        "outputDirectory",
        "rewrites",
    }
    assert config["outputDirectory"] == "src/genai_seguro_lab/web_assets"
    assert config["rewrites"] == [
        {
            "destination": "/:path*",
            "source": "/assets/:path*",
        }
    ]
    assert "functions" not in config
    assert "builds" not in config
    assert "/api/" not in json.dumps(config)

    header_map = {
        item["key"]: item["value"]
        for item in config["headers"][0]["headers"]
    }
    assert set(header_map) == {
        "Content-Security-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Permissions-Policy",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
    }
    assert "frame-ancestors 'none'" in header_map["Content-Security-Policy"]
    assert header_map["Cross-Origin-Opener-Policy"] == "same-origin"
    assert header_map["Cross-Origin-Resource-Policy"] == "same-origin"
    assert header_map["Referrer-Policy"] == "no-referrer"
    assert header_map["X-Content-Type-Options"] == "nosniff"
    assert header_map["X-Frame-Options"] == "DENY"
    assert header_map["Strict-Transport-Security"].startswith("max-age=")


def test_shared_assets_are_safe_and_describe_snapshot_not_execution() -> None:
    javascript = (ASSETS / "app.js").read_text(encoding="utf-8")
    html = (ASSETS / "index.html").read_text(encoding="utf-8")
    combined = f"{javascript}\n{html}"

    assert "innerHTML" not in javascript
    assert "/snapshots/public-profile-v1.json" in javascript
    assert "/api/status" in javascript
    assert "Demo pública · snapshot determinista" in javascript
    assert "Mostrar análisis precomputado" in javascript
    assert "Mostrar baseline precomputada" in javascript
    assert "publicSnapshot" in javascript
    assert "https://" not in combined
    assert "http://" not in combined
    assert "OLLAMA_API_KEY" not in combined


def test_public_copy_replaces_local_execution_language_only_in_snapshot() -> None:
    javascript = (ASSETS / "app.js").read_text(encoding="utf-8")
    html = (ASSETS / "index.html").read_text(encoding="utf-8")
    compact_html = " ".join(html.split())
    local_initializer = javascript.split(
        "function initializeLocal",
        maxsplit=1,
    )[1].split("function initializePublic", maxsplit=1)[0]
    public_initializer = javascript.split(
        "function initializePublic",
        maxsplit=1,
    )[1].split("async function initialize", maxsplit=1)[0]

    for local_copy in (
        "límites explícitos del backend seleccionado",
        "Ejecuta un caso para ver el diagnóstico",
        "después de ejecutar una operación",
        "GENAI SEGURO LAB · GSL-WEB-001",
    ):
        assert local_copy in compact_html
        assert local_copy in local_initializer

    for public_copy in (
        "evidencia precomputada",
        "Selecciona un caso para mostrar",
        "La cronología precomputada aparecerá",
        "GENAI SEGURO LAB · GSL-PUBLIC-STATIC-001",
    ):
        assert public_copy in public_initializer
    assert "backend" not in public_initializer
    assert "Ejecuta un caso" not in public_initializer
    assert "después de ejecutar una operación" not in public_initializer


def test_dat25_remains_immutable() -> None:
    assert sha256(DAT25.read_bytes()).hexdigest() == (
        "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"
    )


def test_public_profile_documentation_is_linked_and_honest() -> None:
    specification = (
        ROOT / "docs" / "public-static-profile-spec.md"
    ).read_text(encoding="utf-8")
    threat_model = (
        ROOT / "docs" / "public-static-threat-model.md"
    ).read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    docs_index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    combined = "\n".join((specification, threat_model))

    for marker in (
        "`GSL-PUBLIC-STATIC-001`",
        "snapshot determinista",
        "sin Functions",
        "POST",
        "secretos",
        "`DAT-25`",
        "URL",
    ):
        assert marker.casefold() in combined.casefold()
    assert "./docs/public-static-profile-spec.md" in readme
    assert "./public-static-profile-spec.md" in docs_index
    assert "https://genai-seguro-lab.vercel.app" in readme
    assert "https://genai-seguro-lab.vercel.app" in combined
    assert "dpl_AXzDDfADN3s5YjLbeNUYi949MTMW" in combined
