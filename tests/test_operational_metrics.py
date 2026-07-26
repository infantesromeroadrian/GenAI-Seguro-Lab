from __future__ import annotations

import importlib.util
import json
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

import genai_seguro_lab.operational_metrics as metrics

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = PROJECT_ROOT / "evaluations" / "run_operational_metrics.py"


def _measurement(value: int) -> metrics.ProcessMeasurement:
    return metrics.ProcessMeasurement(
        exit_code=0,
        stdout_bytes=100,
        stdout_sha256="0" * 64,
        stderr_bytes=0,
        parsed_baseline_id="GSL-BASELINE-BENIGN-001",
        parsed_manifest_sha256=metrics.EXPECTED_MANIFEST_SHA256,
        wall_time_ns=value,
        cpu_user_ns=value,
        cpu_system_ns=value,
        cpu_total_ns=value * 2,
        max_rss_bytes=value,
    )


def test_integer_statistics_are_exact_and_nearest_rank() -> None:
    values = (1, 2, 3, 4)

    assert metrics.integer_median(values) == 3
    assert metrics.median_absolute_deviation(values) == 1
    assert metrics.p95_nearest_rank(values) == 4
    assert metrics.summarize(values).model_dump() == {
        "n": 4,
        "median": 3,
        "mad": 1,
        "p95_nearest_rank": 4,
    }
    assert metrics.integer_median((-2, -1)) == -2


@pytest.mark.parametrize("values", ((), (True,), (1.5,)))
def test_statistics_reject_invalid_samples(values: tuple[object, ...]) -> None:
    with pytest.raises((TypeError, ValueError)):
        metrics.summarize(values)  # type: ignore[arg-type]


def test_schema_is_closed_strict_and_recomputes_deltas() -> None:
    pre = _measurement(10)
    post = _measurement(20)
    sample = metrics.PairSample(
        pair=1,
        order="PRE_POST",
        pre_controls=pre,
        post_controls=post,
        post_minus_pre=metrics._measurement_delta(post, pre),
    )
    payload = sample.model_dump(mode="json")
    payload["unexpected"] = True

    with pytest.raises(ValidationError):
        metrics.PairSample.model_validate(payload)
    with pytest.raises(ValidationError):
        metrics.PairSample.model_validate(
            {
                **sample.model_dump(mode="json"),
                "pair": "1",
            }
        )
    with pytest.raises(ValidationError):
        metrics.PairSample(
            pair=1,
            order="PRE_POST",
            pre_controls=pre,
            post_controls=post,
            post_minus_pre=metrics.MeasurementDelta(
                wall_time_ns=0,
                cpu_user_ns=0,
                cpu_system_ns=0,
                cpu_total_ns=0,
                max_rss_bytes=0,
            ),
        )


def test_execution_metadata_is_derived_and_baseline_tamper_fails_closed() -> None:
    stdout = (
        PROJECT_ROOT / "evaluations" / "benign-baseline-v1.json"
    ).read_bytes()
    metadata = metrics._validated_execution_metadata(
        exit_code=0,
        stdout=stdout,
        stderr=b"",
    )

    assert metadata == {
        "exit_code": 0,
        "stdout_bytes": len(stdout),
        "stdout_sha256": sha256(stdout).hexdigest(),
        "stderr_bytes": 0,
        "parsed_baseline_id": "GSL-BASELINE-BENIGN-001",
        "parsed_manifest_sha256": metrics.EXPECTED_MANIFEST_SHA256,
    }
    document = json.loads(stdout)
    document["dataset"]["manifest_sha256"] = "0" * 64
    tampered = json.dumps(document).encode()
    with pytest.raises(
        metrics.EvidenceIntegrityError,
        match="manifest identity mismatch",
    ):
        metrics._validated_execution_metadata(
            exit_code=0,
            stdout=tampered,
            stderr=b"",
        )
    with pytest.raises(
        metrics.EvidenceIntegrityError,
        match="emitted stderr",
    ):
        metrics._validated_execution_metadata(
            exit_code=0,
            stdout=stdout,
            stderr=b"tampered",
        )


def test_candidate_file_hash_verification_fails_closed_on_tamper(
    tmp_path: Path,
) -> None:
    for relative_path in metrics.PINNED_FILE_SHA256:
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"tampered")

    with pytest.raises(
        metrics.EvidenceIntegrityError,
        match="hash mismatch",
    ):
        metrics._verify_candidate_files(
            tmp_path,
            metrics.PINNED_FILE_SHA256,
        )


def test_candidate_tree_verification_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    responses = iter(
        (
            f"{metrics.PRE_CONTROL_COMMIT}\n".encode(),
            b"0" * 40 + b"\n",
        )
    )
    monkeypatch.setattr(metrics, "_git_output", lambda *_args: next(responses))

    with pytest.raises(
        metrics.EvidenceIntegrityError,
        match="tree mismatch",
    ):
        metrics._materialize_candidate(
            PROJECT_ROOT,
            "pre_controls",
            metrics.PRE_CONTROL_COMMIT,
            metrics.PRE_CONTROL_TREE,
            tmp_path / "candidate",
        )


def test_reduced_real_smoke_verifies_both_candidates_without_repo_mutation() -> None:
    head_before = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
    ).stdout
    diff_before = subprocess.run(
        ("git", "diff", "--binary"),
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
    ).stdout

    snapshot = metrics.analyze_operational_metrics(
        PROJECT_ROOT,
        warmup_pairs=0,
        measured_pairs=1,
    )

    assert snapshot.sources.pre_controls.commit == metrics.PRE_CONTROL_COMMIT
    assert snapshot.sources.post_controls.commit == metrics.POST_CONTROL_COMMIT
    assert snapshot.sources.inputs_byte_identical is True
    assert snapshot.samples[0].order == "PRE_POST"
    assert snapshot.consumption.pre_controls.tool_executions == 12
    assert snapshot.consumption.post_controls.provider_api_cost_cents == 0
    assert (
        snapshot.consumption.post_controls
        .cloud_infrastructure_cost_cents
        == 0
    )
    assert (
        snapshot.consumption.post_controls.tool_executions_derivation
        == "DERIVED_FROM_ONE_SUCCESSFUL_SEARCH_PER_CASE"
    )
    assert snapshot.samples[0].pre_controls.exit_code == 0
    assert snapshot.samples[0].pre_controls.stderr_bytes == 0
    assert snapshot.samples[0].pre_controls.stdout_bytes > 0
    assert len(snapshot.samples[0].pre_controls.stdout_sha256) == 64
    assert (
        snapshot.samples[0].post_controls.parsed_manifest_sha256
        == metrics.EXPECTED_MANIFEST_SHA256
    )
    assert snapshot.environment.perf_counter_resolution_ns >= 1
    assert snapshot.protocol.rss_normalization in {
        "DARWIN_BYTES",
        "LINUX_KIB_TO_BYTES",
    }
    assert "network_not_kernel_isolated" in snapshot.limitations
    assert snapshot.complexity.operator_burden == "UNCHANGED"
    assert snapshot.complexity.internal_control_surface == "INCREASED"
    assert snapshot.complexity.composite_score is None
    assert snapshot.universal_performance_threshold is None
    assert snapshot.statistical_significance_claimed is False
    assert subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
    ).stdout == head_before
    assert subprocess.run(
        ("git", "diff", "--binary"),
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
    ).stdout == diff_before


def test_injected_samples_preserve_order_outliers_and_paired_statistics() -> None:
    values = iter((10, 20, 1, 1000))

    snapshot = metrics.analyze_operational_metrics(
        PROJECT_ROOT,
        warmup_pairs=0,
        measured_pairs=2,
        sample_runner=lambda _root: _measurement(next(values)),
    )

    assert tuple(sample.order for sample in snapshot.samples) == (
        "PRE_POST",
        "POST_PRE",
    )
    assert snapshot.samples[1].pre_controls.wall_time_ns == 1000
    assert snapshot.samples[1].post_controls.wall_time_ns == 1
    deltas = tuple(
        sample.post_minus_pre.wall_time_ns for sample in snapshot.samples
    )
    assert deltas == (10, -999)
    assert (
        snapshot.statistics.paired_post_minus_pre.wall_time_ns
        == metrics.summarize(deltas)
    )
    document = json.loads(metrics.canonical_json(snapshot))
    assert "/Users/" not in json.dumps(document)
    assert "timestamp" not in json.dumps(document)


def test_runner_rejects_arguments_without_starting_analysis(
    capsys: pytest.CaptureFixture[str],
) -> None:
    spec = importlib.util.spec_from_file_location(
        "run_operational_metrics",
        RUNNER_PATH,
    )
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)

    assert runner.main(("unexpected",)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: operational metrics unavailable\n"
