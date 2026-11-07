"""Materializa el perfil público estático desde el flujo determinista real."""

from __future__ import annotations

import json
import sys
from hashlib import sha256
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
SRC: Final = ROOT / "src"
DATA_DIR: Final = ROOT / "data"
SNAPSHOT_PATH: Final = (
    SRC
    / "genai_seguro_lab"
    / "web_assets"
    / "snapshots"
    / "public-profile-v1.json"
)

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from genai_seguro_lab.baseline import (  # noqa: E402
    run_functional_baseline,
    run_incident,
)
from genai_seguro_lab.data_contract import load_dataset  # noqa: E402
from genai_seguro_lab.security_events import (  # noqa: E402
    SecurityEventJournal,
)

SNAPSHOT_ID: Final = "GSL-PUBLIC-PROFILE-001"
SNAPSHOT_SCHEMA_VERSION: Final = "1.0.0"
_FORBIDDEN_MARKERS: Final = (
    "authorization",
    "expected_result",
    "gpt-oss",
    "ollama",
    "oracle",
    "prompt",
)


def _clock() -> float:
    """Reloj constante: todos los tiempos observables son reproducibles."""

    return 0.0


class _DeterministicTokenBytes:
    """Emite bytes opacos reproducibles sin usar secretos o aleatoriedad."""

    def __init__(self, namespace: str) -> None:
        self._namespace = namespace
        self._counter = 0

    def __call__(self, size: int) -> bytes:
        if isinstance(size, bool) or not isinstance(size, int) or size < 1:
            raise TypeError("size must be a positive integer")
        self._counter += 1
        material = b""
        block = 0
        while len(material) < size:
            block += 1
            label = (
                f"{SNAPSHOT_ID}:{self._namespace}:"
                f"{self._counter}:{block}"
            ).encode("ascii")
            material += sha256(label).digest()
        return material[:size]


def _journal(profile: str, namespace: str) -> SecurityEventJournal:
    return SecurityEventJournal(
        profile,  # type: ignore[arg-type]
        clock=_clock,
        token_bytes=_DeterministicTokenBytes(namespace),
    )


def _envelope(result: object, journal: SecurityEventJournal) -> dict[str, object]:
    if not hasattr(result, "model_dump"):
        raise TypeError("result must be a validated model")
    return {
        "result": result.model_dump(mode="json"),  # type: ignore[union-attr]
        "security_report": journal.report().model_dump(mode="json"),
    }


def build_public_snapshot(
    data_dir: Path = DATA_DIR,
) -> dict[str, object]:
    """Regenera en memoria el snapshot público sin red ni proveedor."""

    if not isinstance(data_dir, Path):
        raise TypeError("data_dir must be a Path")
    bundle = load_dataset(data_dir)
    incidents = tuple(
        {
            "category": incident.category,
            "id": incident.id,
            "title": incident.title,
        }
        for incident in bundle.incidents
    )

    analyses: dict[str, object] = {}
    for incident in bundle.incidents:
        journal = _journal("analyze", f"analysis:{incident.id}")
        result = run_incident(
            bundle,
            incident.id,
            clock=_clock,
            security_journal=journal,
        )
        analyses[incident.id] = _envelope(result, journal)

    baseline_journal = _journal("baseline", "baseline")
    baseline = run_functional_baseline(
        data_dir,
        clock=_clock,
        security_journal=baseline_journal,
    )
    return {
        "analyses": analyses,
        "baseline": _envelope(baseline, baseline_journal),
        "incidents": incidents,
        "profile": "public_static_snapshot",
        "runtime": {
            "cost_eur": 0,
            "deterministic": True,
            "external_calls": False,
            "id": "GSL-PUBLIC-STATIC-001",
            "model": "scripted-v1",
            "persistence": False,
            "provider": "deterministic",
        },
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "snapshot_id": SNAPSHOT_ID,
    }


def canonical_public_snapshot(document: dict[str, object]) -> str:
    if not isinstance(document, dict):
        raise TypeError("document must be a dictionary")
    content = (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    normalized = content.casefold()
    if any(marker in normalized for marker in _FORBIDDEN_MARKERS):
        raise ValueError("public snapshot contains a forbidden marker")
    return content


def main() -> int:
    content = canonical_public_snapshot(build_public_snapshot())
    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_PATH.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
