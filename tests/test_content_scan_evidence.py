"""Valida la evidencia saneada de secretos y datos de PGS-07-M03."""

from __future__ import annotations

import json
import re
import subprocess
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evaluations" / "content-scan-v1.json"
EVALUATIONS_README = ROOT / "evaluations" / "README.md"
DOCS_README = ROOT / "docs" / "README.md"
TESTS_README = ROOT / "tests" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"

CORPUS_FILES = (
    "data/incidents.jsonl",
    "data/knowledge.jsonl",
    "data/adversarial/inputs.jsonl",
    "data/adversarial/oracles.jsonl",
)


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


def test_scan_is_pinned_to_the_exact_candidate_tree() -> None:
    evidence = _load()
    candidate = evidence["candidate"]

    assert evidence["schema_version"] == 1
    assert evidence["snapshot_id"] == "GSL-CONTENT-SCAN-001"
    assert evidence["microtask"] == "PGS-07-M03"
    assert evidence["result"] == "PASS_WITH_DECLARED_HISTORICAL_RESIDUAL"
    assert candidate == {
        "commit": "7f007a9573c7790e50953d205d64c65a4d4b3c0b",
        "tree": "795f3e52a966984e2e036c1061170227bc57ccee",
        "branch": "main",
        "tracked_files": 176,
        "tracked_bytes": 1960699,
    }

    observed_tree = subprocess.run(
        ["git", "rev-parse", f"{candidate['commit']}^{{tree}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert observed_tree == candidate["tree"]


def test_gitleaks_scans_are_zero_finding_but_not_overclaimed() -> None:
    evidence = _load()
    scan = evidence["secret_scan"]

    assert scan["scanner"] == "gitleaks"
    assert scan["version"] == "8.30.1"
    assert scan["redaction_percent"] == 100
    assert scan["tracked_tree"] == {
        "source": "git archive of the candidate tree",
        "bytes_scanned": 1960699,
        "findings": 0,
        "exit_code": 0,
        "result": "PASS",
    }
    assert scan["git_history"] == {
        "scope": "all refs",
        "commits_scanned": 67,
        "bytes_scanned": 2425087,
        "findings": 0,
        "exit_code": 0,
        "result": "PASS",
    }
    assert scan["raw_reports_retained"] is False
    assert "not proof that no secret can exist" in " ".join(evidence["limits"])


def test_all_versioned_corpus_records_are_declared_synthetic() -> None:
    evidence = _load()
    commit = evidence["candidate"]["commit"]
    records = []
    for path in CORPUS_FILES:
        records.extend(
            json.loads(line) for line in _git_show(commit, path).splitlines()
        )

    assert len(records) == 56
    assert all(record["synthetic"] is True for record in records)
    assert {record["sensitivity"] for record in records} == {"synthetic_internal"}
    classification = evidence["real_data_classification"]
    assert classification["structured_corpus_records"] == 56
    assert classification["records_marked_synthetic"] == 56
    assert classification["records_with_other_sensitivity"] == 0
    assert classification["non_fixture_home_path_hits_in_current_tree"] == 0
    assert classification["non_example_email_hits_in_current_tree"] == 0
    assert classification["government_identity_number_hits"] == 0
    assert classification["payment_card_candidates_after_hex_boundary_filter"] == 0
    assert classification["ipv4_addresses"] == {
        "unique": 6,
        "documentation_ranges": 6,
        "other": 0,
    }
    assert classification["url_hosts"]["unclassified"] == 0


def test_event_artifacts_are_pinned_and_history_residual_is_explicit() -> None:
    evidence = _load()
    commit = evidence["candidate"]["commit"]
    artifacts = evidence["versioned_artifacts"]

    assert artifacts["machine_readable_evaluation_files"] == 19
    assert artifacts["event_records"] == 32
    assert artifacts["secret_or_real_identity_marker_hits_in_event_files"] == 0
    assert artifacts["sensitive_filename_hits"] == 0
    for event_file in artifacts["versioned_event_files"]:
        payload = _git_show(commit, event_file["path"])
        assert len(payload.splitlines()) == event_file["records"]
        assert sha256(payload).hexdigest() == event_file["sha256"]

    residual = evidence["historical_provenance_residual"]
    assert residual == {
        "present": True,
        "secret": False,
        "personal_author_email_identities": 1,
        "commits_touching_a_removed_personal_home_path": 4,
        "files_touching_a_removed_personal_home_path": 3,
        "raw_values_recorded": False,
        "current_tree_occurrences": 0,
        "history_rewrite_performed": False,
        "reason_not_rewritten": (
            "Public history rewriting is destructive and outside the authorised "
            "microtask."
        ),
        "disposition": "DECLARED_RESIDUAL",
    }


def test_evidence_is_sanitised_preserves_dat25_and_closes_m03() -> None:
    evidence = _load()
    serialized = json.dumps(evidence, ensure_ascii=False).casefold()

    assert re.search(r"/(?:users|home)/[^/\\s]+", serialized) is None
    assert "@gmail." not in serialized
    assert "run_final_retest.py" not in serialized
    assert evidence["dat25"] == {
        "executed": False,
        "changed": False,
        "sha256": DAT25_SHA256,
    }
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
    assert "content-scan-v1.json" in _read(EVALUATIONS_README)
    assert "../evaluations/content-scan-v1.json" in _read(DOCS_README)
    assert "test_content_scan_evidence.py" in _read(TESTS_README)
    assert "./evaluations/content-scan-v1.json" in _read(README)
    assert "- [x] **PGS-07-M03**" in _read(PLAN)
