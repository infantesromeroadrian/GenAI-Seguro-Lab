"""Comparación offline de coste y recursos entre candidatos fijados."""

from __future__ import annotations

import io
import json
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable, Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from hashlib import sha256
from pathlib import Path, PurePosixPath
from time import get_clock_info, perf_counter_ns
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .baseline import FunctionalBaseline

PRE_CONTROL_COMMIT = "df13683abc2b2387f8dd29be64c4d49216e08e3a"
PRE_CONTROL_TREE = "0f43bd07f968008fe14d2eb913594d8a34379e4f"
POST_CONTROL_COMMIT = "ba600ca8ca25074a7806b6502ad59c0847212650"
POST_CONTROL_TREE = "4949fba137ccc52bb6d666db7dabda4cd485e06f"

EXPECTED_CASE_IDS = tuple(f"INC-BEN-{number:03d}" for number in range(1, 13))
EXPECTED_MANIFEST_SHA256 = (
    "e758a72747dd33dbd78f17551a436dd6ae6278ca5e5306bf2ddb10fe56124926"
)
PINNED_FILE_SHA256: Mapping[str, str] = {
    "data/manifest.json": EXPECTED_MANIFEST_SHA256,
    "main.py": (
        "5c0872a85f1585de2c0949e1c7215131474b2646b3e02322cbcabd75bea2aef6"
    ),
    "pyproject.toml": (
        "cb3ca6ea34bda636d4ae4b49a751642a25001287e525bc8b24473d0a1b0fc699"
    ),
    "uv.lock": (
        "7a7cb70dac5c0d018cfbd7cea07f8ad3345ac96408a21e635f6c2e84d93617be"
    ),
}

CHILD_ENVIRONMENT: Mapping[str, str] = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUTF8": "1",
}

GitOid = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Sha256Value = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(ge=1)]
PairOrder = Literal["PRE_POST", "POST_PRE"]


class EvidenceIntegrityError(RuntimeError):
    """Una fuente o ejecución fijada no cumple el contrato esperado."""


class OperationalSchema(BaseModel):
    """Base estricta, cerrada e inmutable de la evidencia."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class VerifiedFile(OperationalSchema):
    path: Literal[
        "data/manifest.json",
        "main.py",
        "pyproject.toml",
        "uv.lock",
    ]
    sha256: Sha256Value


class CandidateSource(OperationalSchema):
    candidate: Literal["pre_controls", "post_controls"]
    commit: GitOid
    tree: GitOid
    verified_files: Annotated[
        tuple[VerifiedFile, ...],
        Field(min_length=4, max_length=4),
    ]

    @model_validator(mode="after")
    def verify_files(self) -> Self:
        if tuple(item.path for item in self.verified_files) != tuple(
            PINNED_FILE_SHA256
        ):
            raise ValueError("verified file order is invalid")
        if {
            item.path: item.sha256 for item in self.verified_files
        } != dict(PINNED_FILE_SHA256):
            raise ValueError("verified file identities are invalid")
        return self


class Sources(OperationalSchema):
    pre_controls: CandidateSource
    post_controls: CandidateSource
    inputs_byte_identical: Literal[True]


class ExecutionEnvironment(OperationalSchema):
    python_implementation: str
    python_version: Annotated[
        str,
        Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$"),
    ]
    operating_system: Literal["Darwin", "Linux"]
    machine: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")]
    same_sys_executable: Literal[True]
    perf_counter_resolution_ns: PositiveInt
    child_environment: Literal[
        "PYTHONDONTWRITEBYTECODE=1;"
        "PYTHONHASHSEED=0;"
        "PYTHONNOUSERSITE=1;"
        "PYTHONUTF8=1"
    ]


class BenchmarkProtocol(OperationalSchema):
    warmup_pairs_discarded: NonNegativeInt
    measured_pairs: PositiveInt
    order: Literal["AB_BA_ALTERNATING_CONTIGUOUS"]
    process_per_candidate_sample: Literal[1]
    retries: Literal[0]
    outliers_removed: Literal[False]
    wall_clock: Literal["time.perf_counter_ns"]
    child_usage_source: Literal["os.wait4"]
    rss_normalization: Literal["DARWIN_BYTES", "LINUX_KIB_TO_BYTES"]
    p95_method: Literal["nearest_rank"]
    dynamic_evidence_byte_identical_on_rerun: Literal[False]


class ProcessMeasurement(OperationalSchema):
    exit_code: Literal[0]
    stdout_bytes: PositiveInt
    stdout_sha256: Sha256Value
    stderr_bytes: Literal[0]
    parsed_baseline_id: Literal["GSL-BASELINE-BENIGN-001"]
    parsed_manifest_sha256: Literal[
        "e758a72747dd33dbd78f17551a436dd6ae6278ca5e5306bf2ddb10fe56124926"
    ]
    wall_time_ns: PositiveInt
    cpu_user_ns: NonNegativeInt
    cpu_system_ns: NonNegativeInt
    cpu_total_ns: NonNegativeInt
    max_rss_bytes: PositiveInt

    @model_validator(mode="after")
    def verify_cpu_total(self) -> Self:
        if self.cpu_total_ns != self.cpu_user_ns + self.cpu_system_ns:
            raise ValueError("cpu total does not match its components")
        return self


class MeasurementDelta(OperationalSchema):
    wall_time_ns: int
    cpu_user_ns: int
    cpu_system_ns: int
    cpu_total_ns: int
    max_rss_bytes: int


class PairSample(OperationalSchema):
    pair: PositiveInt
    order: PairOrder
    pre_controls: ProcessMeasurement
    post_controls: ProcessMeasurement
    post_minus_pre: MeasurementDelta

    @model_validator(mode="after")
    def verify_delta(self) -> Self:
        expected = _measurement_delta(
            self.post_controls,
            self.pre_controls,
        )
        if self.post_minus_pre != expected:
            raise ValueError("paired delta does not match measurements")
        return self


class Distribution(OperationalSchema):
    n: PositiveInt
    median: int
    mad: NonNegativeInt
    p95_nearest_rank: int


class MeasurementStatistics(OperationalSchema):
    wall_time_ns: Distribution
    cpu_user_ns: Distribution
    cpu_system_ns: Distribution
    cpu_total_ns: Distribution
    max_rss_bytes: Distribution


class Statistics(OperationalSchema):
    pre_controls: MeasurementStatistics
    post_controls: MeasurementStatistics
    paired_post_minus_pre: MeasurementStatistics


class DeterministicConsumption(OperationalSchema):
    cases: Literal[12]
    model_invocations: Literal[24]
    tool_requests: Literal[12]
    tool_executions: Literal[12]
    tool_executions_derivation: Literal[
        "DERIVED_FROM_ONE_SUCCESSFUL_SEARCH_PER_CASE"
    ]
    external_calls: Literal[0]
    provider_api_cost_cents: Literal[0]
    cloud_infrastructure_cost_cents: Literal[0]
    energy_wh: None
    infrastructure_amortization_cents: None
    human_work_minutes: None


class Consumption(OperationalSchema):
    pre_controls: DeterministicConsumption
    post_controls: DeterministicConsumption


class OperatorBurden(OperationalSchema):
    commands: Literal[1]
    foreground_processes: Literal[1]
    background_processes: Literal[0]
    external_services: Literal[0]
    external_integrations: Literal[0]
    required_secrets: Literal[0]
    persistent_logs: Literal[0]


class InternalControlSurface(OperationalSchema):
    advisory_lock: bool
    resource_budget: bool
    output_policy: bool
    in_memory_journal: bool
    scoped_grant: bool


class ComplexityCandidate(OperationalSchema):
    operator_burden: OperatorBurden
    internal_control_surface: InternalControlSurface


class Complexity(OperationalSchema):
    pre_controls: ComplexityCandidate
    post_controls: ComplexityCandidate
    operator_burden: Literal["UNCHANGED"]
    internal_control_surface: Literal["INCREASED"]
    composite_score: None


class OperationalMetricsSnapshot(OperationalSchema):
    schema_version: Literal["1.0.0"]
    metrics_id: Literal["GSL-METRICS-OPERATIONAL-001"]
    sources: Sources
    environment: ExecutionEnvironment
    protocol: BenchmarkProtocol
    samples: tuple[PairSample, ...]
    statistics: Statistics
    consumption: Consumption
    complexity: Complexity
    universal_performance_threshold: None
    statistical_significance_claimed: Literal[False]
    limitations: tuple[
        Literal["single_host_single_session"],
        Literal["process_startup_is_material_for_short_workload"],
        Literal["scheduler_cache_and_temperature_add_noise"],
        Literal["rss_is_process_high_water_mark"],
        Literal["deterministic_offline_model"],
        Literal["energy_not_measured"],
        Literal["tco_not_measured"],
        Literal["concurrency_not_measured"],
        Literal["sustained_load_not_measured"],
        Literal["results_do_not_generalize_to_other_hosts"],
        Literal["network_not_kernel_isolated"],
    ]

    @model_validator(mode="after")
    def verify_measurements(self) -> Self:
        if len(self.samples) != self.protocol.measured_pairs:
            raise ValueError("sample count does not match protocol")
        expected_pairs = tuple(range(1, len(self.samples) + 1))
        if tuple(sample.pair for sample in self.samples) != expected_pairs:
            raise ValueError("pair sequence is invalid")
        expected_orders = tuple(
            _pair_order(self.protocol.warmup_pairs_discarded + index)
            for index in range(len(self.samples))
        )
        if tuple(sample.order for sample in self.samples) != expected_orders:
            raise ValueError("pair order is invalid")
        if self.statistics != _statistics(self.samples):
            raise ValueError("statistics do not match raw samples")
        return self


SampleRunner = Callable[[Path], ProcessMeasurement]


def canonical_json(document: OperationalMetricsSnapshot) -> str:
    """Serializa únicamente evidencia validada y saneada."""

    if not isinstance(document, OperationalMetricsSnapshot):
        raise TypeError("document must be operational metrics evidence")
    return (
        json.dumps(
            document.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def integer_median(values: Sequence[int]) -> int:
    """Calcula una mediana exacta y la redondea a entero, half-up."""

    return _round_decimal(_median_decimal(values))


def median_absolute_deviation(values: Sequence[int]) -> int:
    """Calcula MAD sobre la mediana exacta, con salida entera."""

    center = _median_decimal(values)
    deviations = tuple(abs(Decimal(value) - center) for value in values)
    return _round_decimal(_median_decimal(deviations))


def p95_nearest_rank(values: Sequence[int]) -> int:
    """Calcula p95 mediante nearest-rank sin interpolación."""

    checked = _integer_values(values)
    rank = (95 * len(checked) + 99) // 100
    return sorted(checked)[rank - 1]


def summarize(values: Sequence[int]) -> Distribution:
    """Resume una secuencia conservando un contrato estadístico verificable."""

    checked = _integer_values(values)
    return Distribution(
        n=len(checked),
        median=integer_median(checked),
        mad=median_absolute_deviation(checked),
        p95_nearest_rank=p95_nearest_rank(checked),
    )


def analyze_operational_metrics(
    project_root: Path,
    *,
    warmup_pairs: int = 3,
    measured_pairs: int = 30,
    sample_runner: SampleRunner | None = None,
) -> OperationalMetricsSnapshot:
    """Ejecuta la comparación fijada sin alterar el checkout."""

    _require_count(warmup_pairs, allow_zero=True)
    _require_count(measured_pairs, allow_zero=False)
    root = _require_project_root(project_root)
    runner = sample_runner or _run_candidate_sample

    with tempfile.TemporaryDirectory(prefix="gsl-operational-metrics-") as temp:
        temporary_root = Path(temp)
        pre_root = temporary_root / "pre"
        post_root = temporary_root / "post"
        pre_source = _materialize_candidate(
            root,
            "pre_controls",
            PRE_CONTROL_COMMIT,
            PRE_CONTROL_TREE,
            pre_root,
        )
        post_source = _materialize_candidate(
            root,
            "post_controls",
            POST_CONTROL_COMMIT,
            POST_CONTROL_TREE,
            post_root,
        )
        _verify_byte_identical_inputs(pre_root, post_root)

        total_pairs = warmup_pairs + measured_pairs
        retained: list[PairSample] = []
        for absolute_index in range(total_pairs):
            order = _pair_order(absolute_index)
            pre, post = _run_pair(pre_root, post_root, order, runner)
            if absolute_index >= warmup_pairs:
                retained.append(
                    PairSample(
                        pair=len(retained) + 1,
                        order=order,
                        pre_controls=pre,
                        post_controls=post,
                        post_minus_pre=_measurement_delta(post, pre),
                    )
                )

    samples = tuple(retained)
    return OperationalMetricsSnapshot(
        schema_version="1.0.0",
        metrics_id="GSL-METRICS-OPERATIONAL-001",
        sources=Sources(
            pre_controls=pre_source,
            post_controls=post_source,
            inputs_byte_identical=True,
        ),
        environment=_environment(),
        protocol=BenchmarkProtocol(
            warmup_pairs_discarded=warmup_pairs,
            measured_pairs=measured_pairs,
            order="AB_BA_ALTERNATING_CONTIGUOUS",
            process_per_candidate_sample=1,
            retries=0,
            outliers_removed=False,
            wall_clock="time.perf_counter_ns",
            child_usage_source="os.wait4",
            rss_normalization=_rss_normalization(),
            p95_method="nearest_rank",
            dynamic_evidence_byte_identical_on_rerun=False,
        ),
        samples=samples,
        statistics=_statistics(samples),
        consumption=_consumption(),
        complexity=_complexity(),
        universal_performance_threshold=None,
        statistical_significance_claimed=False,
        limitations=(
            "single_host_single_session",
            "process_startup_is_material_for_short_workload",
            "scheduler_cache_and_temperature_add_noise",
            "rss_is_process_high_water_mark",
            "deterministic_offline_model",
            "energy_not_measured",
            "tco_not_measured",
            "concurrency_not_measured",
            "sustained_load_not_measured",
            "results_do_not_generalize_to_other_hosts",
            "network_not_kernel_isolated",
        ),
    )


def _integer_values(values: Sequence[int | Decimal]) -> tuple[int, ...]:
    if not isinstance(values, Sequence) or isinstance(
        values,
        (str, bytes, bytearray),
    ):
        raise TypeError("values must be an integer sequence")
    checked = tuple(values)
    if not checked:
        raise ValueError("values must not be empty")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in checked):
        raise TypeError("values must contain integers")
    return checked


def _median_decimal(
    values: Sequence[int | Decimal],
) -> Decimal:
    checked = tuple(values)
    if not checked:
        raise ValueError("values must not be empty")
    if any(
        isinstance(value, bool) or not isinstance(value, (int, Decimal))
        for value in checked
    ):
        raise TypeError("values must be numeric")
    ordered = sorted(Decimal(value) for value in checked)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / Decimal(2)


def _round_decimal(value: Decimal) -> int:
    return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _require_count(value: int, *, allow_zero: bool) -> None:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError("benchmark pair count is invalid")


def _require_project_root(project_root: Path) -> Path:
    if not isinstance(project_root, Path):
        raise TypeError("project_root must be a Path")
    if not (project_root / ".git").exists():
        raise EvidenceIntegrityError("project git repository is unavailable")
    return project_root.resolve()


def _git_output(project_root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", "-C", str(project_root), *arguments),
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0 or completed.stderr:
        raise EvidenceIntegrityError("pinned git evidence is unavailable")
    return completed.stdout


def _materialize_candidate(
    project_root: Path,
    candidate: Literal["pre_controls", "post_controls"],
    commit: str,
    tree: str,
    destination: Path,
) -> CandidateSource:
    observed_commit = _git_output(
        project_root,
        "rev-parse",
        f"{commit}^{{commit}}",
    ).decode("ascii").strip()
    observed_tree = _git_output(
        project_root,
        "rev-parse",
        f"{commit}^{{tree}}",
    ).decode("ascii").strip()
    if observed_commit != commit:
        raise EvidenceIntegrityError("pinned candidate commit mismatch")
    if observed_tree != tree:
        raise EvidenceIntegrityError("pinned candidate tree mismatch")

    archive = _git_output(project_root, "archive", "--format=tar", commit)
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise EvidenceIntegrityError("candidate archive is unsafe")
        tar.extractall(destination, filter="data")

    files = _verify_candidate_files(destination, PINNED_FILE_SHA256)
    return CandidateSource(
        candidate=candidate,
        commit=commit,
        tree=tree,
        verified_files=files,
    )


def _verify_candidate_files(
    candidate_root: Path,
    expected: Mapping[str, str],
) -> tuple[VerifiedFile, ...]:
    verified: list[VerifiedFile] = []
    for relative_path, expected_digest in expected.items():
        file_path = candidate_root / relative_path
        try:
            content = file_path.read_bytes()
        except OSError as exc:
            raise EvidenceIntegrityError(
                "pinned candidate file is unavailable"
            ) from exc
        if sha256(content).hexdigest() != expected_digest:
            raise EvidenceIntegrityError("pinned candidate file hash mismatch")
        verified.append(
            VerifiedFile(path=relative_path, sha256=expected_digest)
        )
    return tuple(verified)


def _verify_byte_identical_inputs(pre_root: Path, post_root: Path) -> None:
    for relative_path in PINNED_FILE_SHA256:
        if (pre_root / relative_path).read_bytes() != (
            post_root / relative_path
        ).read_bytes():
            raise EvidenceIntegrityError(
                "candidate benchmark inputs are not byte-identical"
            )


def _run_pair(
    pre_root: Path,
    post_root: Path,
    order: PairOrder,
    runner: SampleRunner,
) -> tuple[ProcessMeasurement, ProcessMeasurement]:
    if order == "PRE_POST":
        return runner(pre_root), runner(post_root)
    post = runner(post_root)
    pre = runner(pre_root)
    return pre, post


def _pair_order(absolute_index: int) -> PairOrder:
    return "PRE_POST" if absolute_index % 2 == 0 else "POST_PRE"


def _run_candidate_sample(candidate_root: Path) -> ProcessMeasurement:
    if sys.platform not in {"darwin", "linux"} or not hasattr(os, "wait4"):
        raise EvidenceIntegrityError("child resource accounting is unsupported")

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        started = perf_counter_ns()
        process = subprocess.Popen(
            (sys.executable, "main.py", "baseline"),
            cwd=candidate_root,
            env=dict(CHILD_ENVIRONMENT),
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
        )
        waited_pid, status, usage = os.wait4(process.pid, 0)
        ended = perf_counter_ns()
        process.returncode = os.waitstatus_to_exitcode(status)
        if waited_pid != process.pid:
            raise EvidenceIntegrityError("unexpected child process was reaped")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read()
        stderr = stderr_file.read()

    execution = _validated_execution_metadata(
        exit_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )

    user_ns = _seconds_to_ns(usage.ru_utime)
    system_ns = _seconds_to_ns(usage.ru_stime)
    rss_bytes = int(usage.ru_maxrss)
    if sys.platform == "linux":
        rss_bytes *= 1024
    if rss_bytes <= 0:
        raise EvidenceIntegrityError("candidate RSS measurement is invalid")
    return ProcessMeasurement(
        **execution,
        wall_time_ns=ended - started,
        cpu_user_ns=user_ns,
        cpu_system_ns=system_ns,
        cpu_total_ns=user_ns + system_ns,
        max_rss_bytes=rss_bytes,
    )


def _seconds_to_ns(value: float) -> int:
    if not isinstance(value, float) or value < 0:
        raise EvidenceIntegrityError("child CPU measurement is invalid")
    return _round_decimal(Decimal(str(value)) * Decimal(1_000_000_000))


def _validated_execution_metadata(
    *,
    exit_code: int,
    stdout: bytes,
    stderr: bytes,
) -> dict[str, object]:
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise TypeError("exit_code must be an integer")
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise TypeError("process output must be bytes")
    if exit_code != 0:
        raise EvidenceIntegrityError("candidate baseline process failed")
    if stderr:
        raise EvidenceIntegrityError("candidate baseline emitted stderr")
    baseline = _validate_baseline(stdout)
    return {
        "exit_code": 0,
        "stdout_bytes": len(stdout),
        "stdout_sha256": sha256(stdout).hexdigest(),
        "stderr_bytes": 0,
        "parsed_baseline_id": baseline.baseline_id,
        "parsed_manifest_sha256": baseline.dataset.manifest_sha256,
    }


def _validate_baseline(stdout: bytes) -> FunctionalBaseline:
    try:
        baseline = FunctionalBaseline.model_validate_json(stdout)
    except Exception as exc:
        raise EvidenceIntegrityError(
            "candidate baseline stdout is invalid"
        ) from exc
    if baseline.baseline_id != "GSL-BASELINE-BENIGN-001":
        raise EvidenceIntegrityError("candidate baseline identifier mismatch")
    if baseline.dataset.id != "GSL-DATASET-001":
        raise EvidenceIntegrityError("candidate dataset identifier mismatch")
    if baseline.dataset.version != "1.0.0":
        raise EvidenceIntegrityError("candidate dataset version mismatch")
    if baseline.dataset.manifest_sha256 != EXPECTED_MANIFEST_SHA256:
        raise EvidenceIntegrityError("candidate manifest identity mismatch")
    if tuple(case.incident_id for case in baseline.cases) != EXPECTED_CASE_IDS:
        raise EvidenceIntegrityError("candidate case order mismatch")
    expected_summary = {
        "cases_total": 12,
        "cases_passed": 12,
        "cases_failed": 0,
        "model_invocations": 24,
        "tool_requests": 12,
        "external_calls": 0,
        "cost_eur": 0,
    }
    if baseline.summary.model_dump() != expected_summary:
        raise EvidenceIntegrityError("candidate counters mismatch")
    for case in baseline.cases:
        if (
            case.status != "passed"
            or case.model_invocations != 2
            or case.tool_requests != 1
            or not case.knowledge_ids
            or case.external_calls
            or case.cost_eur != 0
        ):
            raise EvidenceIntegrityError("candidate case counters mismatch")
    return baseline


def _measurement_delta(
    post: ProcessMeasurement,
    pre: ProcessMeasurement,
) -> MeasurementDelta:
    return MeasurementDelta(
        wall_time_ns=post.wall_time_ns - pre.wall_time_ns,
        cpu_user_ns=post.cpu_user_ns - pre.cpu_user_ns,
        cpu_system_ns=post.cpu_system_ns - pre.cpu_system_ns,
        cpu_total_ns=post.cpu_total_ns - pre.cpu_total_ns,
        max_rss_bytes=post.max_rss_bytes - pre.max_rss_bytes,
    )


def _measurement_statistics(
    measurements: Sequence[ProcessMeasurement | MeasurementDelta],
) -> MeasurementStatistics:
    return MeasurementStatistics(
        wall_time_ns=summarize(
            tuple(item.wall_time_ns for item in measurements)
        ),
        cpu_user_ns=summarize(
            tuple(item.cpu_user_ns for item in measurements)
        ),
        cpu_system_ns=summarize(
            tuple(item.cpu_system_ns for item in measurements)
        ),
        cpu_total_ns=summarize(
            tuple(item.cpu_total_ns for item in measurements)
        ),
        max_rss_bytes=summarize(
            tuple(item.max_rss_bytes for item in measurements)
        ),
    )


def _statistics(samples: Sequence[PairSample]) -> Statistics:
    if not samples:
        raise ValueError("measured samples must not be empty")
    return Statistics(
        pre_controls=_measurement_statistics(
            tuple(sample.pre_controls for sample in samples)
        ),
        post_controls=_measurement_statistics(
            tuple(sample.post_controls for sample in samples)
        ),
        paired_post_minus_pre=_measurement_statistics(
            tuple(sample.post_minus_pre for sample in samples)
        ),
    )


def _consumption() -> Consumption:
    values = {
        "cases": 12,
        "model_invocations": 24,
        "tool_requests": 12,
        "tool_executions": 12,
        "tool_executions_derivation": (
            "DERIVED_FROM_ONE_SUCCESSFUL_SEARCH_PER_CASE"
        ),
        "external_calls": 0,
        "provider_api_cost_cents": 0,
        "cloud_infrastructure_cost_cents": 0,
        "energy_wh": None,
        "infrastructure_amortization_cents": None,
        "human_work_minutes": None,
    }
    return Consumption(
        pre_controls=DeterministicConsumption(**values),
        post_controls=DeterministicConsumption(**values),
    )


def _complexity() -> Complexity:
    burden = OperatorBurden(
        commands=1,
        foreground_processes=1,
        background_processes=0,
        external_services=0,
        external_integrations=0,
        required_secrets=0,
        persistent_logs=0,
    )
    return Complexity(
        pre_controls=ComplexityCandidate(
            operator_burden=burden,
            internal_control_surface=InternalControlSurface(
                advisory_lock=False,
                resource_budget=False,
                output_policy=False,
                in_memory_journal=False,
                scoped_grant=False,
            ),
        ),
        post_controls=ComplexityCandidate(
            operator_burden=burden,
            internal_control_surface=InternalControlSurface(
                advisory_lock=True,
                resource_budget=True,
                output_policy=True,
                in_memory_journal=True,
                scoped_grant=True,
            ),
        ),
        operator_burden="UNCHANGED",
        internal_control_surface="INCREASED",
        composite_score=None,
    )


def _environment() -> ExecutionEnvironment:
    operating_system = platform.system()
    if operating_system not in {"Darwin", "Linux"}:
        raise EvidenceIntegrityError("benchmark operating system is unsupported")
    return ExecutionEnvironment(
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        operating_system=operating_system,
        machine=platform.machine(),
        same_sys_executable=True,
        perf_counter_resolution_ns=max(
            1,
            _round_decimal(
                Decimal(str(get_clock_info("perf_counter").resolution))
                * Decimal(1_000_000_000)
            ),
        ),
        child_environment=";".join(
            f"{name}={value}" for name, value in CHILD_ENVIRONMENT.items()
        ),
    )


def _rss_normalization() -> Literal[
    "DARWIN_BYTES",
    "LINUX_KIB_TO_BYTES",
]:
    if sys.platform == "darwin":
        return "DARWIN_BYTES"
    if sys.platform == "linux":
        return "LINUX_KIB_TO_BYTES"
    raise EvidenceIntegrityError("benchmark operating system is unsupported")
