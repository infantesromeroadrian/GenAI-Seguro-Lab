"""Ejecutor explícito de GSL-RETEST-ADVERSARIAL-001."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from genai_seguro_lab.adversarial_retest import (  # noqa: E402
    AdversarialRetestError,
    CandidateSnapshot,
    RuntimeFileSnapshot,
    RuntimeSnapshot,
    default_adversarial_retest_authorization,
    run_adversarial_retest,
    write_adversarial_retest_artifacts,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run-adversarial-retest",
        description=(
            "Ejecuta una vez las 14 fixtures autorizadas contra un checkout "
            "endurecido limpio y escribe evidencia neutral solo bajo $TMP."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-branch", default="main")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--executed-at-utc", required=True)
    parser.add_argument("--uv-version", required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        executed_at = _parse_utc(arguments.executed_at_utc)
        before = _candidate_snapshot(
            expected_commit=arguments.expected_commit,
            expected_tree=arguments.expected_tree,
            expected_branch=arguments.expected_branch,
        )
        uv_lock = PROJECT_ROOT / "uv.lock"
        runtime = RuntimeSnapshot(
            python=platform.python_version(),
            uv=arguments.uv_version,
            pydantic=version("pydantic"),
            platform=sys.platform,
            uv_lock=RuntimeFileSnapshot(
                path="$REPO/uv.lock",
                sha256=_sha256(uv_lock),
                bytes=uv_lock.stat().st_size,
            ),
            external_calls=False,
            cost_eur="0.00",
        )
        sanitized_command = (
            "uv",
            "run",
            "--frozen",
            "python",
            "evaluations/run_adversarial_retest.py",
            "--expected-commit",
            before.commit,
            "--expected-tree",
            before.tree,
            "--expected-branch",
            before.branch,
            "--run-id",
            arguments.run_id,
            "--executed-at-utc",
            arguments.executed_at_utc,
            "--uv-version",
            arguments.uv_version,
            "--run-root",
            "$TMP/adversarial-retest-v1",
        )

        def candidate_unchanged() -> bool:
            try:
                current = _candidate_snapshot(
                    expected_commit=before.commit,
                    expected_tree=before.tree,
                    expected_branch=before.branch,
                )
            except AdversarialRetestError:
                return False
            return current == before and _sha256(uv_lock) == runtime.uv_lock.sha256

        artifacts = run_adversarial_retest(
            repository_root=PROJECT_ROOT,
            run_root=arguments.run_root,
            candidate=before,
            runtime=runtime,
            run_id=arguments.run_id,
            executed_at_utc=executed_at,
            sanitized_command=sanitized_command,
            authorization=default_adversarial_retest_authorization(),
            verify_candidate_unchanged=candidate_unchanged,
        )
        manifest = write_adversarial_retest_artifacts(
            artifacts=artifacts,
            output_dir=arguments.run_root / "reviewed",
        )
    except (
        AdversarialRetestError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        ValueError,
    ):
        print("error: adversarial retest did not complete", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "candidate_commit": manifest.candidate_commit,
                "candidate_tree": manifest.candidate_tree,
                "evidence_directory": (
                    "$TMP/adversarial-retest-v1/reviewed"
                ),
                "final_retest": False,
                "retest_id": manifest.retest_id,
                "run_id": manifest.run_id,
                "status": artifacts.results.summary.status,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0 if artifacts.results.summary.status == "COMPLETED" else 2


def _candidate_snapshot(
    *,
    expected_commit: str,
    expected_tree: str,
    expected_branch: str,
) -> CandidateSnapshot:
    commit = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    branch = _git("branch", "--show-current")
    status = _git("status", "--porcelain=v1", "--untracked-files=all")
    if (
        commit != expected_commit
        or tree != expected_tree
        or branch != expected_branch
        or status
    ):
        raise AdversarialRetestError(
            "candidate does not match the requested clean checkout"
        )
    return CandidateSnapshot(
        commit=commit,
        tree=tree,
        branch=branch,
        clean_before_run=True,
        posture="hardened_checkout",
    )


def _git(*arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        raise AdversarialRetestError("candidate metadata is unavailable")
    return completed.stdout.strip()


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
    ):
        raise ValueError("executed-at must be UTC")
    return parsed


def _sha256(path: Path) -> str:
    from hashlib import sha256

    return sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
