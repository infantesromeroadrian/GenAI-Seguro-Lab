"""Punto de entrada local y explícito de GenAI Seguro Lab."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from genai_seguro_lab.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
