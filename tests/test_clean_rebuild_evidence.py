"""Valida la evidencia saneada de reconstrucción limpia de PGS-07-M01."""

from __future__ import annotations

import json
import re
import subprocess
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evaluations" / "clean-rebuild-v1.json"
EVALUATIONS_README = ROOT / "evaluations" / "README.md"
DOCS_README = ROOT / "docs" / "README.md"
TESTS_README = ROOT / "tests" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"

EXPECTED_PACKAGES = {
    ("annotated-types", "0.8.0"),
    ("iniconfig", "2.3.0"),
    ("packaging", "26.2"),
    ("pluggy", "1.6.0"),
    ("pydantic", "2.13.4"),
    ("pydantic-core", "2.46.4"),
    ("pygments", "2.20.0"),
    ("pytest", "9.1.1"),
    ("typing-extensions", "4.16.0"),
    ("typing-inspection", "0.4.2"),
}


def _load() -> dict[str, object]:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_clean_rebuild_is_pinned_to_an_existing_candidate() -> None:
    evidence = _load()
    candidate = evidence["candidate"]

    assert evidence["schema_version"] == 1
    assert evidence["snapshot_id"] == "GSL-CLEAN-REBUILD-001"
    assert evidence["microtask"] == "PGS-07-M01"
    assert evidence["result"] == "PASS"
    assert candidate == {
        "commit": "93d9a0587a94e5d621f0735b673a90450cc5da70",
        "tree": "af53562353360cdd504411842f56c2218e707ce1",
        "branch": "main",
        "remote": "https://github.com/infantesromeroadrian/GenAI-Seguro-Lab.git",
    }

    subprocess.run(
        ["git", "cat-file", "-e", f"{candidate['commit']}^{{commit}}"],
        cwd=ROOT,
        check=True,
    )
    observed_tree = subprocess.run(
        ["git", "rev-parse", f"{candidate['commit']}^{{tree}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert observed_tree == candidate["tree"]


def test_clean_rebuild_inputs_and_environment_are_explicit() -> None:
    evidence = _load()

    assert evidence["inputs"] == {
        ".python-version": sha256((ROOT / ".python-version").read_bytes()).hexdigest(),
        "pyproject.toml": sha256((ROOT / "pyproject.toml").read_bytes()).hexdigest(),
        "uv.lock": sha256((ROOT / "uv.lock").read_bytes()).hexdigest(),
    }
    assert evidence["environment"] == {
        "os": "Darwin",
        "architecture": "arm64",
        "os_version": "26.6",
        "python": "3.12.8",
        "uv": "0.6.10",
        "uv_commit": "f2a2d982b",
    }
    packages = {
        (package["name"], package["version"])
        for package in evidence["installed_packages"]
    }
    assert packages == EXPECTED_PACKAGES


def test_clean_rebuild_protocol_proves_only_the_claimed_scope() -> None:
    evidence = _load()
    protocol = evidence["protocol"]
    sync = protocol["sync"]

    assert protocol["fresh_public_clone"] is True
    assert protocol["local_clone_reuse"] is False
    assert protocol["pre_status_count"] == 0
    assert protocol["lock_check"]["result"] == "PASS"
    assert sync["result"] == "PASS"
    assert sync["network_used"] is True
    assert sync["cache_reuse"] is False
    assert sync["locked_external_packages"] == 11
    assert sync["installed_packages"] == len(EXPECTED_PACKAGES)
    assert protocol["sync_check"] == {
        "command": "uv sync --frozen --check",
        "result": "PASS",
        "changes_required": 0,
    }
    assert protocol["dependency_imports"] == {"pydantic": "PASS", "pytest": "PASS"}
    assert protocol["cli_smoke"]["exit_code"] == 0
    assert protocol["post_status_count"] == 0
    assert protocol["post_tracked_diff_count"] == 0
    assert protocol["venv_ignored"] is True
    assert protocol["temporary_root_cleanup"] == "MOVED_TO_TRASH"

    limits = " ".join(evidence["limits"]).casefold()
    for required_limit in (
        "single clean rebuild",
        "not an offline or hermetic build",
        "reserved for pgs-07-m02",
        "reserved for pgs-07-m03",
        "no vulnerability",
        "dat-25 was neither executed nor changed",
    ):
        assert required_limit in limits


def test_evidence_is_sanitised_and_preserves_dat25() -> None:
    evidence = _load()
    serialized = json.dumps(evidence, ensure_ascii=False)

    assert re.search(r"/(?:users|home)/[^/\\s]+", serialized.casefold()) is None
    assert evidence["dat25"] == {
        "executed": False,
        "changed": False,
        "sha256": DAT25_SHA256,
    }
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256


def test_documentation_and_roadmap_close_m01() -> None:
    assert "clean-rebuild-v1.json" in _read(EVALUATIONS_README)
    assert "../evaluations/clean-rebuild-v1.json" in _read(DOCS_README)
    assert "test_clean_rebuild_evidence.py" in _read(TESTS_README)
    assert "./evaluations/clean-rebuild-v1.json" in _read(README)
    assert "- [x] **PGS-07-M01**" in _read(PLAN)
