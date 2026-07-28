"""Valida que la omisión de M04 no se presente como revisión o cierre."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DECISION = ROOT / "reviews" / "independent-review-omission-v1.json"
DOCUMENT = ROOT / "docs" / "independent-review-omission.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"


def test_m04_is_omitted_without_claiming_review_or_acceptance() -> None:
    decision = json.loads(DECISION.read_text(encoding="utf-8"))

    assert decision["schema_version"] == 1
    assert decision["decision_id"] == "GSL-REV-OMISSION-001"
    assert decision["microtask"] == "PGS-07-M04"
    assert decision["status"] == "OMITTED_BY_OWNER"
    assert decision["reviewer"] is None
    assert decision["review_performed"] is False
    assert decision["findings_received"] == 0
    assert all(decision["not_claimed"].values())
    assert "- [-] **PGS-07-M04**" in PLAN.read_text(encoding="utf-8")


def test_omission_preserves_open_parent_criteria_and_dat25() -> None:
    decision = json.loads(DECISION.read_text(encoding="utf-8"))
    document = DOCUMENT.read_text(encoding="utf-8")
    serialized = json.dumps(decision, ensure_ascii=False).casefold()

    assert "P01-M11 cannot be completed" in " ".join(decision["implications"])
    assert "SEC-1" in " ".join(decision["implications"])
    assert "no puede cerrarse" in document
    assert "no es una revisión" in document
    assert decision["dat25"] == {
        "executed": False,
        "changed": False,
        "sha256": DAT25_SHA256,
    }
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
    assert re.search(r"/(?:users|home)/[^/\\s]+", serialized) is None
