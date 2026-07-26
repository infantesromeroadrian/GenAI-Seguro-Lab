"""Verifica el registro canónico de hallazgos sin ejecutar evaluaciones."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from genai_seguro_lab.control_findings import (  # noqa: E402
    canonical_json,
    verify_control_findings,
)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        if arguments:
            raise ValueError("this offline verifier accepts no arguments")
        report = verify_control_findings(PROJECT_ROOT)
    except Exception:
        print("error: control findings unavailable", file=sys.stderr)
        return 1

    sys.stdout.write(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
