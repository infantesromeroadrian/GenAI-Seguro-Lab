"""Ejecutor explícito de GSL-BASELINE-ADVERSARIAL-001."""

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

from genai_seguro_lab.adversarial_baseline import (  # noqa: E402
    AdversarialBaselineError,
    CandidateSnapshot,
    RuntimeSnapshot,
    default_adversarial_baseline_authorization,
    run_adversarial_baseline,
    write_adversarial_baseline_artifacts,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run-adversarial-baseline",
        description=(
            "Ejecuta una vez las 14 fixtures autorizadas y escribe evidencia "
            "saneada únicamente bajo $TMP."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--expected-commit", required=True)
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
            expected_branch=arguments.expected_branch,
        )
        runtime = RuntimeSnapshot(
            python=platform.python_version(),
            uv=arguments.uv_version,
            pydantic=version("pydantic"),
            platform=sys.platform,
            external_calls=False,
            cost_eur="0.00",
        )
        sanitized_command = (
            "uv",
            "run",
            "--frozen",
            "python",
            "evaluations/run_adversarial_baseline.py",
            "--expected-commit",
            before.commit,
            "--expected-branch",
            before.branch,
            "--run-id",
            arguments.run_id,
            "--executed-at-utc",
            arguments.executed_at_utc,
            "--uv-version",
            arguments.uv_version,
            "--run-root",
            "$TMP/adversarial-baseline-v1",
        )

        def candidate_unchanged() -> bool:
            current = _candidate_snapshot(
                expected_commit=before.commit,
                expected_branch=before.branch,
            )
            return current == before

        artifacts = run_adversarial_baseline(
            repository_root=PROJECT_ROOT,
            run_root=arguments.run_root,
            candidate=before,
            runtime=runtime,
            run_id=arguments.run_id,
            executed_at_utc=executed_at,
            sanitized_command=sanitized_command,
            authorization=default_adversarial_baseline_authorization(),
            verify_candidate_unchanged=candidate_unchanged,
        )
        manifest = write_adversarial_baseline_artifacts(
            artifacts=artifacts,
            output_dir=arguments.run_root / "reviewed",
        )
    except (
        AdversarialBaselineError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        ValueError,
    ):
        print("error: adversarial baseline did not complete", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "baseline_id": manifest.baseline_id,
                "candidate_commit": manifest.candidate_commit,
                "evidence_directory": "$TMP/adversarial-baseline-v1/reviewed",
                "run_id": manifest.run_id,
                "status": "COMPLETED",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


def _candidate_snapshot(
    *,
    expected_commit: str,
    expected_branch: str,
) -> CandidateSnapshot:
    commit = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    branch = _git("branch", "--show-current")
    status = _git("status", "--porcelain=v1", "--untracked-files=all")
    if commit != expected_commit or branch != expected_branch or status:
        raise AdversarialBaselineError(
            "candidate does not match the requested clean checkout"
        )
    return CandidateSnapshot(
        commit=commit,
        tree=tree,
        branch=branch,
        clean_before_run=True,
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
        raise AdversarialBaselineError("candidate metadata is unavailable")
    return completed.stdout.strip()


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("executed-at must be UTC")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
