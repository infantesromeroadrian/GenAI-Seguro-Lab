"""Emite el snapshot canónico offline de utilidad benigna."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from genai_seguro_lab.benign_utility import (  # noqa: E402
    analyze_benign_utility,
    canonical_json,
)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        if arguments:
            raise ValueError("this offline analyzer accepts no arguments")
        snapshot = analyze_benign_utility(PROJECT_ROOT)
    except Exception:  # noqa: BLE001
        print("error: benign utility metrics unavailable", file=sys.stderr)
        return 1

    sys.stdout.write(canonical_json(snapshot))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
