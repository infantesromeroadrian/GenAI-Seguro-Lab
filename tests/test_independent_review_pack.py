"""Valida el paquete preparado sin atribuir una revisión inexistente."""

from __future__ import annotations

import json
import re
import subprocess
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "reviews" / "independent-review-pack-v1.json"
REQUEST = ROOT / "docs" / "independent-review-request.md"
DOCS_README = ROOT / "docs" / "README.md"
TESTS_README = ROOT / "tests" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"


def _load() -> dict[str, object]:
    return json.loads(PACK.read_text(encoding="utf-8"))


def _git_show(commit: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def test_pack_is_pinned_to_an_existing_candidate_and_human_reviewer() -> None:
    pack = _load()
    candidate = pack["candidate"]
    reviewer = pack["reviewer_requirement"]

    assert pack["schema_version"] == 1
    assert pack["pack_id"] == "GSL-REV-PACK-001"
    assert pack["microtask"] == "PGS-07-M04"
    assert pack["status"] == "READY_AWAITING_HUMAN_REVIEW"
    assert pack["review_performed"] is False
    assert candidate["commit"] == "1508cad250ecdcc3cd7e68de583c2a528e54a183"
    assert candidate["tree"] == "3975ab84d14f575281ee484c2fc5085f68e4d490"
    observed_tree = subprocess.run(
        ["git", "rev-parse", f"{candidate['commit']}^{{tree}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert observed_tree == candidate["tree"]
    assert reviewer["kind"] == "human"
    assert reviewer["distinct_from_designer"] is True
    assert reviewer["distinct_from_implementer"] is True
    assert reviewer["must_accept_assignment"] is True


def test_threat_model_and_selected_test_hashes_match_candidate() -> None:
    pack = _load()
    commit = pack["candidate"]["commit"]

    assert len(pack["threat_model_scope"]) == 6
    for artifact in pack["threat_model_scope"]:
        assert sha256(_git_show(commit, artifact["path"])).hexdigest() == artifact[
            "sha256"
        ]

    selected = pack["selected_test"]
    assert sha256(_git_show(commit, selected["test_path"])).hexdigest() == selected[
        "test_sha256"
    ]
    assert sha256(
        _git_show(commit, selected["implementation_path"])
    ).hexdigest() == selected["implementation_sha256"]
    source = _git_show(commit, selected["test_path"]).decode("utf-8")
    assert f"def {selected['test_name']}(" in source
    assert selected["case_id"] == "ADV-TOL-005"
    assert selected["abuse_case"] == "AC-TOL-05"


def test_response_contract_and_execution_limits_are_explicit() -> None:
    pack = _load()
    required = pack["required_response"]
    limits = " ".join(pack["execution_limits"])

    assert all(
        required[field] is True
        for field in (
            "reviewer_public_identity",
            "qualification_summary",
            "conflict_statement",
            "candidate_commit_confirmed",
            "files_reviewed",
            "test_command_and_result",
            "disagreements_or_none",
            "review_completed_at",
        )
    )
    assert required["findings"]["required"] is True
    assert required["findings"]["allowed_severities"] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]
    assert "run_final_retest.py" in limits
    for case_id in ("ADV-DOS-001", "ADV-DOS-002", "ADV-DOS-003", "ADV-SC-001"):
        assert case_id in limits
    assert "does not by itself authorise a fix" in limits


def test_pack_preserves_dat25_and_does_not_close_m04() -> None:
    pack = _load()
    request = REQUEST.read_text(encoding="utf-8")
    serialized = json.dumps(pack, ensure_ascii=False).casefold()

    assert pack["dat25"] == {
        "executed": False,
        "changed": False,
        "sha256": DAT25_SHA256,
    }
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
    assert re.search(r"/(?:users|home)/[^/\\s]+", serialized) is None
    assert "revisión realizada | no" in request.casefold()
    assert "pgs-07-m04` sigue abierta" in request.casefold()
    assert "- [ ] **PGS-07-M04**" in PLAN.read_text(encoding="utf-8")


def test_pack_is_linked_without_changing_the_roadmap_counter() -> None:
    assert "./independent-review-request.md" in DOCS_README.read_text(encoding="utf-8")
    assert "test_independent_review_pack.py" in TESTS_README.read_text(
        encoding="utf-8"
    )
    assert "./reviews/independent-review-pack-v1.json" in README.read_text(
        encoding="utf-8"
    )
    assert "60 de 66 microtareas (90,9 %)" in README.read_text(encoding="utf-8")
