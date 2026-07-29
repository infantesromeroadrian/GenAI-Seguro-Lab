"""POST /api/analyze para un único incidente sintético validado."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from genai_seguro_lab.public_vercel import PublicVercelHandler


class handler(PublicVercelHandler):
    endpoint = "analyze"
