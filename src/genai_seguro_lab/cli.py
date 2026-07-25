"""Interfaz local de solo lectura para la baseline funcional benigna."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .baseline import (
    UnknownIncidentError,
    canonical_json,
    run_functional_baseline,
    run_incident,
)
from .data_contract import load_dataset


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

    subparsers.add_parser(
        "baseline",
        help="Ejecuta los 12 casos y emite la baseline JSON por stdout.",
        allow_abbrev=False,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Ejecuta la CLI sin red ni escritura de archivos."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    data_dir = repository_data_dir()

    try:
        if arguments.command == "analyze":
            bundle = load_dataset(data_dir)
            result = run_incident(bundle, arguments.incident)
        else:
            result = run_functional_baseline(data_dir)
    except UnknownIncidentError:
        print("error: unknown benign incident identifier", file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError):
        print("error: functional baseline is unavailable", file=sys.stderr)
        return 1

    sys.stdout.write(canonical_json(result))
    return 0
