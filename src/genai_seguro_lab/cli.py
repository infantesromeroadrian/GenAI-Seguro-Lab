"""Interfaz local de solo lectura para la baseline funcional benigna."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from .baseline import (
    UnknownIncidentError,
    canonical_json,
    run_functional_baseline,
    run_incident,
)
from .data_contract import load_dataset
from .resource_control import ResourceLimitError, exclusive_process_lock
from .security_events import (
    SecurityEventError,
    SecurityEventJournal,
    SecurityEventReport,
)


def repository_data_dir() -> Path:
    """Resuelve el corpus versionado desde el checkout local instalado."""

    return Path(__file__).resolve().parents[2] / "data"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="genai-seguro-lab",
        description=(
            "Ejecuta el flujo benigno determinista sobre el corpus sintético."
        ),
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Ejecuta un incidente benigno por identificador.",
        allow_abbrev=False,
    )
    analyze.add_argument(
        "--incident",
        required=True,
        help="Identificador exacto con formato INC-BEN-NNN.",
    )
    analyze.add_argument(
        "--security-report",
        action="store_true",
        help="Incluye un journal de seguridad saneado en un sobre JSON.",
    )

    baseline = subparsers.add_parser(
        "baseline",
        help="Ejecuta los 12 casos y emite la baseline JSON por stdout.",
        allow_abbrev=False,
    )
    baseline.add_argument(
        "--security-report",
        action="store_true",
        help="Incluye un journal de seguridad saneado en un sobre JSON.",
    )
    return parser


def _canonical_security_envelope(
    result: BaseModel,
    report: SecurityEventReport,
) -> str:
    if not isinstance(result, BaseModel):
        raise TypeError("result must be a validated model")
    if not isinstance(report, SecurityEventReport):
        raise TypeError("report must be a SecurityEventReport")
    return (
        json.dumps(
            {
                "result": result.model_dump(mode="json"),
                "security_report": report.model_dump(mode="json"),
            },
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Ejecuta la CLI sin red ni escritura de archivos."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    data_dir = repository_data_dir()
    profile = "analyze" if arguments.command == "analyze" else "baseline"
    journal = SecurityEventJournal(profile)

    try:
        with exclusive_process_lock(
            data_dir / "manifest.json",
            security_journal=journal,
        ):
            if arguments.command == "analyze":
                try:
                    bundle = load_dataset(data_dir)
                except ResourceLimitError:
                    journal.signal(
                        "resource_limit_exceeded",
                        source="data_contract",
                        outcome="limited",
                    )
                    raise
                except (OSError, TypeError, ValueError):
                    journal.signal(
                        "data_integrity_violation",
                        source="data_contract",
                        outcome="denied",
                    )
                    raise
                result = run_incident(
                    bundle,
                    arguments.incident,
                    security_journal=journal,
                )
            else:
                result = run_functional_baseline(
                    data_dir,
                    security_journal=journal,
                )
    except UnknownIncidentError:
        if not journal.is_finished:
            journal.finish(succeeded=False)
        print("error: unknown benign incident identifier", file=sys.stderr)
        return 2
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
        if not journal.is_finished:
            journal.finish(succeeded=False)
        print("error: functional baseline is unavailable", file=sys.stderr)
        return 1

    if arguments.security_report:
        sys.stdout.write(
            _canonical_security_envelope(result, journal.report())
        )
    else:
        sys.stdout.write(canonical_json(result))
    return 0
