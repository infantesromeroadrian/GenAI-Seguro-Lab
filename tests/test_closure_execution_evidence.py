"""Valida la ejecución de cierre acotada de PGS-07-M02."""

from __future__ import annotations

import json
import re
import subprocess
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evaluations" / "closure-execution-v1.json"
EVALUATIONS_README = ROOT / "evaluations" / "README.md"
DOCS_README = ROOT / "docs" / "README.md"
TESTS_README = ROOT / "tests" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"

EXECUTED_CASES = [
    "ADV-PI-001",
    "ADV-PI-002",
    "ADV-PI-003",
    "ADV-JB-001",
    "ADV-JB-002",
    "ADV-JB-003",
    "ADV-EX-001",
    "ADV-EX-002",
    "ADV-EX-003",
    "ADV-TOL-001",
    "ADV-TOL-002",
    "ADV-TOL-003",
    "ADV-TOL-004",
    "ADV-TOL-005",
]
INERT_CASES = ["ADV-DOS-001", "ADV-DOS-002", "ADV-DOS-003", "ADV-SC-001"]


def _load() -> dict[str, object]:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _git_show(commit: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def test_execution_is_pinned_to_an_existing_public_candidate() -> None:
    evidence = _load()
    candidate = evidence["candidate"]

    assert evidence["schema_version"] == 1
    assert evidence["snapshot_id"] == "GSL-CLOSURE-EXECUTION-001"
    assert evidence["microtask"] == "PGS-07-M02"
    assert evidence["result"] == "PASS"
    assert candidate == {
        "commit": "6d4f132cd13a4448847016d7ae8e198b85573022",
        "tree": "0c47db4b19ef3bc02ede497bb8223392e1be8e33",
        "branch": "main",
        "remote": "https://github.com/infantesromeroadrian/GenAI-Seguro-Lab.git",
        "fresh_public_clone": True,
    }

    observed_tree = subprocess.run(
        ["git", "rev-parse", f"{candidate['commit']}^{{tree}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert observed_tree == candidate["tree"]


def test_candidate_inputs_match_the_recorded_hashes() -> None:
    evidence = _load()
    commit = evidence["candidate"]["commit"]

    for path, expected_hash in evidence["inputs"].items():
        assert sha256(_git_show(commit, path)).hexdigest() == expected_hash


def test_full_suite_and_benign_results_are_closed_and_consistent() -> None:
    evidence = _load()
    suite = evidence["full_test_suite"]
    benign = evidence["benign_corpus"]

    assert suite == {
        "command": "uv run --frozen --no-sync pytest -p no:cacheprovider",
        "collected": 327,
        "passed": 327,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "duration_seconds": 16.52,
        "result": "PASS",
    }
    assert benign["repetitions"] == 2
    assert benign["canonical_capture"] == 2
    assert benign["stdout_bytes"] == 24111
    assert benign["stdout_sha256"] == (
        "df30a8b2c09b61948380601ba0ed9644fb6d6b9d4838b407d24094f7940a129c"
    )
    assert benign["stderr_bytes"] == 0
    assert benign["summary"] == {
        "cases_total": 12,
        "cases_passed": 12,
        "cases_failed": 0,
        "model_invocations": 24,
        "tool_requests": 12,
        "external_calls": 0,
        "cost_eur": 0,
    }
    assert benign["result"] == "PASS"


def test_only_the_fourteen_authorised_adversarial_cases_were_executed() -> None:
    evidence = _load()
    adversarial = evidence["authorised_adversarial_corpus"]
    commit = evidence["candidate"]["commit"]
    records = [
        json.loads(line)
        for line in _git_show(commit, "data/adversarial/inputs.jsonl").splitlines()
    ]

    assert adversarial["repetitions"] == 2
    assert adversarial["execution_2"] == {
        "collected": 20,
        "passed": 20,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "duration_seconds": 0.84,
    }
    assert adversarial["executed_cases"] == EXECUTED_CASES
    assert adversarial["inert_not_executed"] == INERT_CASES
    assert {record["id"] for record in records if record["fixture_state"] == "test_wired"} == set(
        EXECUTED_CASES
    )
    assert {
        record["id"] for record in records if record["fixture_state"] == "inert_not_wired"
    } == set(INERT_CASES)
    assert set(EXECUTED_CASES).isdisjoint(INERT_CASES)
    assert adversarial["result"] == "PASS"


def test_evidence_is_sanitised_preserves_dat25_and_closes_m02() -> None:
    evidence = _load()
    serialized = json.dumps(evidence, ensure_ascii=False).casefold()

    assert re.search(r"/(?:users|home)/[^/\\s]+", serialized) is None
    assert "run_final_retest.py" not in serialized
    assert evidence["dat25"] == {
        "executed": False,
        "changed": False,
        "sha256": DAT25_SHA256,
    }
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
    assert evidence["postconditions"] == {
        "tracked_diff_count": 0,
        "status_count": 0,
        "raw_output_retained": False,
        "temporary_root_cleanup": "MOVED_TO_TRASH",
    }
    assert "closure-execution-v1.json" in _read(EVALUATIONS_README)
    assert "../evaluations/closure-execution-v1.json" in _read(DOCS_README)
    assert "test_closure_execution_evidence.py" in _read(TESTS_README)
    assert "./evaluations/closure-execution-v1.json" in _read(README)
    assert "- [x] **PGS-07-M02**" in _read(PLAN)
