"""Emite exclusivamente el snapshot canónico del retest final M07."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

sys.dont_write_bytecode = True
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from genai_seguro_lab.final_retest import (  # noqa: E402
    CANONICAL_RUN_ID,
    analyze_final_retest,
    canonical_json,
)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        if arguments:
            raise ValueError("this final retest accepts no arguments")
        snapshot = analyze_final_retest(
            PROJECT_ROOT,
            execution_mode="CANONICAL_FINAL",
            run_id=CANONICAL_RUN_ID,
        )
    except Exception:  # noqa: BLE001
        print("error: final retest unavailable", file=sys.stderr)
        return 1
    sys.stdout.write(canonical_json(snapshot))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
