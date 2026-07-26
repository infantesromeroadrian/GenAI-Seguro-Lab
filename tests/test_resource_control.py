"""Límites focales del control preventivo de recursos."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from genai_seguro_lab import resource_control
from genai_seguro_lab.baseline import (
    _build_flow,
    run_functional_baseline,
    run_incident,
)
from genai_seguro_lab.benign_flow import BenignAnalysisFlow
from genai_seguro_lab.data_contract import load_dataset
from genai_seguro_lab.local_tools import (
    DraftApprovalAuthority,
    DraftApprovalError,
    DraftWriterTool,
    KnowledgeCatalog,
    KnowledgeHit,
    KnowledgeSearchResult,
    KnowledgeSearchTool,
)
from genai_seguro_lab.model_adapter import (
    ModelDescriptor,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelResult,
    ModelToolRequest,
)
from genai_seguro_lab.output_policy import OutputPolicy
from genai_seguro_lab.resource_control import (
    MAX_BENIGN_CORPUS_BYTES,
    MAX_DRAFT_MARKDOWN_BYTES,
    MAX_FINAL_SUMMARY_BYTES,
    MAX_KNOWLEDGE_RESULT_BYTES,
    MAX_MODEL_REQUEST_BYTES,
    MAX_MODEL_RESPONSE_BYTES,
    MAX_TOOL_ARGUMENTS_BYTES,
    ProductResourceControl,
    ResourceLimitError,
    read_bounded_regular_file,
    require_serialized_size,
    require_utf8_size,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
ENTRYPOINT = ROOT / "main.py"
IDENTITY = "synthetic-approver"
CREDENTIAL = "synthetic-credential"


def _dataset_copy(tmp_path: Path) -> Path:
    target = tmp_path / "data"
    shutil.copytree(DATA_DIR, target)
    return target


def _draft_request(
    *,
    filename: str = "resource-test.md",
    body: str = "Contenido sintético acotado.",
) -> ModelToolRequest:
    return ModelToolRequest(
        request_id="CALL-RESOURCE-DRAFT",
        name="draft_create",
        arguments_json=json.dumps(
            {
                "body": body,
                "filename": filename,
                "references": ["KB-001"],
                "title": "Resumen",
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _writer(tmp_path: Path) -> tuple[DraftApprovalAuthority, DraftWriterTool]:
    drafts = tmp_path / "sandbox" / "drafts"
    drafts.mkdir(parents=True)
    authority = DraftApprovalAuthority(
        configured_identity=IDENTITY,
        credential=CREDENTIAL,
    )
    writer = DraftWriterTool(
        drafts,
        principal="resource-test",
        scope="draft:resource-test",
        approval_authority=authority,
        output_policy=OutputPolicy(),
        allowed_knowledge_ids=("KB-001",),
    )
    return authority, writer


def test_benign_corpus_total_accepts_at_limit_and_rejects_above(
    tmp_path: Path,
) -> None:
    data_dir = _dataset_copy(tmp_path)
    paths = tuple(
        data_dir / name
        for name in ("manifest.json", "incidents.jsonl", "knowledge.jsonl")
    )
    current = sum(path.stat().st_size for path in paths)
    manifest = paths[0]
    manifest.write_bytes(
        manifest.read_bytes() + b" " * (MAX_BENIGN_CORPUS_BYTES - current)
    )

    assert load_dataset(data_dir).manifest.id == "GSL-DATASET-001"

    manifest.write_bytes(manifest.read_bytes() + b" ")
    with pytest.raises(
        ResourceLimitError,
        match="product resource limit exceeded",
    ):
        load_dataset(data_dir)


@pytest.mark.parametrize(
    ("record_count", "record_bytes", "expected_error"),
    (
        (32, 2, ValueError),
        (33, 2, ResourceLimitError),
        (1, 8 * 1024, ValueError),
        (1, 8 * 1024 + 1, ResourceLimitError),
    ),
)
def test_jsonl_preflight_limits_apply_before_parsing(
    tmp_path: Path,
    record_count: int,
    record_bytes: int,
    expected_error: type[Exception],
) -> None:
    data_dir = _dataset_copy(tmp_path)
    line = b"x" * record_bytes
    (data_dir / "incidents.jsonl").write_bytes(
        b"\n".join(line for _ in range(record_count)) + b"\n"
    )

    with pytest.raises(expected_error):
        load_dataset(data_dir)


def test_bounded_reader_detects_growth_after_stat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "growing.json"
    target.write_bytes(b"1234")
    original_fstat = resource_control.os.fstat
    changed = False

    def grow_after_stat(descriptor: int):
        nonlocal changed
        metadata = original_fstat(descriptor)
        if not changed:
            changed = True
            with target.open("ab") as handle:
                handle.write(b"5" * 1024)
        return metadata

    monkeypatch.setattr(resource_control.os, "fstat", grow_after_stat)

    with pytest.raises(ResourceLimitError):
        read_bounded_regular_file(target, 4)


def test_oversized_request_is_rejected_before_adapter() -> None:
    bundle = load_dataset(DATA_DIR)
    incident = bundle.incidents[0].model_copy(
        update={"scenario": "x" * (8 * 1024)}
    )

    class UnexpectedAdapter:
        descriptor = ModelDescriptor()
        calls = 0

        def generate(self, request: ModelRequest) -> ModelResult:
            self.calls += 1
            raise AssertionError("adapter must not be called")

    adapter = UnexpectedAdapter()
    flow = BenignAnalysisFlow(
        adapter,
        KnowledgeCatalog(bundle.knowledge),
        output_policy=OutputPolicy(),
    )

    with pytest.raises(ResourceLimitError):
        flow.analyze(incident)
    assert adapter.calls == 0


def test_model_request_and_response_serialized_limits_are_exact() -> None:
    def request_with_content(content: str) -> ModelRequest:
        return ModelRequest(
            request_id="REQ-RESOURCE-BOUNDARY",
            instruction_boundary="separated",
            messages=(
                ModelMessage(
                    role="system",
                    trust_class="trusted_instruction",
                    content="s",
                ),
                ModelMessage(
                    role="user",
                    trust_class="user_data",
                    content="u",
                ),
                ModelMessage(
                    role="user",
                    trust_class="untrusted_content",
                    content=content,
                ),
            ),
        )

    request_overhead = len(
        request_with_content("x").model_dump_json().encode("utf-8")
    ) - 1
    exact_request = request_with_content(
        "x" * (MAX_MODEL_REQUEST_BYTES - request_overhead)
    )
    above_request = request_with_content(
        "x" * (MAX_MODEL_REQUEST_BYTES - request_overhead + 1)
    )
    control = ProductResourceControl("analyze", clock=lambda: 0.0)

    control.before_model_call(exact_request)
    with pytest.raises(ResourceLimitError):
        control.before_model_call(above_request)
    assert control.usage.model_invocations == 1

    def response_with_content(content: str) -> ModelResponse:
        return ModelResponse(finish_reason="stop", output_text=content)

    response_overhead = len(
        response_with_content("x").model_dump_json().encode("utf-8")
    ) - 1
    exact_response = response_with_content(
        "x" * (MAX_MODEL_RESPONSE_BYTES - response_overhead)
    )
    above_response = response_with_content(
        "x" * (MAX_MODEL_RESPONSE_BYTES - response_overhead + 1)
    )

    control.after_model_call(exact_response)
    with pytest.raises(ResourceLimitError):
        control.after_model_call(above_response)


def test_tool_arguments_result_and_summary_utf8_limits_are_exact() -> None:
    argument_overhead = len('{"x":""}'.encode("utf-8"))
    exact_arguments = (
        '{"x":"'
        + "x" * (MAX_TOOL_ARGUMENTS_BYTES - argument_overhead)
        + '"}'
    )
    ModelToolRequest(
        request_id="CALL-RESOURCE-ARGUMENTS",
        name="knowledge_search",
        arguments_json=exact_arguments,
    )
    with pytest.raises(ResourceLimitError):
        ModelToolRequest(
            request_id="CALL-RESOURCE-ARGUMENTS-ABOVE",
            name="knowledge_search",
            arguments_json=exact_arguments[:-2] + 'x"}',
        )

    def result_with_content(content: str) -> KnowledgeSearchResult:
        return KnowledgeSearchResult(
            query="q",
            hits=(
                KnowledgeHit(
                    id="KB-001",
                    topic="phishing",
                    title="t",
                    content=content,
                    procedures=("p",),
                ),
            ),
        )

    result_overhead = len(
        result_with_content("x").model_dump_json().encode("utf-8")
    ) - 1
    exact_result = result_with_content(
        "x" * (MAX_KNOWLEDGE_RESULT_BYTES - result_overhead)
    )
    above_result = result_with_content(
        "x" * (MAX_KNOWLEDGE_RESULT_BYTES - result_overhead + 1)
    )
    control = ProductResourceControl("analyze", clock=lambda: 0.0)

    control.after_tool_execution(exact_result)
    with pytest.raises(ResourceLimitError):
        control.after_tool_execution(above_result)
    control.accept_final_summary("x" * MAX_FINAL_SUMMARY_BYTES)
    with pytest.raises(ResourceLimitError):
        control.accept_final_summary("x" * (MAX_FINAL_SUMMARY_BYTES + 1))


def test_operation_budget_is_cumulative_and_observable() -> None:
    bundle = load_dataset(DATA_DIR)
    request = BenignAnalysisFlow.build_initial_request(bundle.incidents[0])
    response = ModelResponse(finish_reason="stop", output_text="ok")
    result = load_dataset(DATA_DIR)
    knowledge = KnowledgeCatalog(result.knowledge).for_incident(
        result.incidents[0],
        principal="resource-test",
        scope=f"incident:{result.incidents[0].id}",
    )
    tool_result = knowledge.search(
        ModelToolRequest(
            request_id="CALL-RESOURCE-KNOWLEDGE",
            name="knowledge_search",
            arguments_json=json.dumps(
                {
                    "knowledge_ids": ["KB-001"],
                    "limit": 1,
                    "query": "phishing",
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
        ),
        grant=knowledge.execution_grant,
    )
    control = ProductResourceControl("baseline", clock=lambda: 0.0)

    for _ in range(12):
        control.begin_case()
        control.accept_tool_request("{}")
        control.before_tool_execution()
    for _ in range(24):
        control.before_model_call(request)
        control.after_model_call(response)
    control.after_tool_execution(tool_result)

    assert control.usage.cases == 12
    assert control.usage.model_invocations == 24
    assert control.usage.tool_requests == 12
    assert control.usage.tool_executions == 12
    with pytest.raises(ResourceLimitError):
        control.begin_case()


def test_cooperative_deadline_is_checked_after_synchronous_adapter_call() -> None:
    bundle = load_dataset(DATA_DIR)
    incident = bundle.incidents[0]
    catalog = KnowledgeCatalog(bundle.knowledge)
    configured = _build_flow((incident,), catalog, bundle.knowledge)
    now = [0.0]

    class AdvancingAdapter:
        descriptor = configured._adapter.descriptor
        calls = 0

        def generate(self, request: ModelRequest) -> ModelResult:
            self.calls += 1
            result = configured._adapter.generate(request)
            now[0] = 1.01
            return result

    adapter = AdvancingAdapter()
    flow = BenignAnalysisFlow(
        adapter,
        catalog,
        output_policy=OutputPolicy(),
    )
    control = ProductResourceControl("analyze", clock=lambda: now[0])

    with pytest.raises(ResourceLimitError):
        flow.analyze(incident, resource_control=control)
    assert adapter.calls == 1
    assert control.usage.model_invocations == 1
    assert control.usage.tool_executions == 0


def test_product_operations_execute_the_real_search_exactly_once_per_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    original_search = KnowledgeSearchTool.search

    def counted_search(
        self: KnowledgeSearchTool,
        request: ModelToolRequest,
        *,
        grant,
    ) -> KnowledgeSearchResult:
        nonlocal calls
        calls += 1
        return original_search(self, request, grant=grant)

    monkeypatch.setattr(KnowledgeSearchTool, "search", counted_search)
    bundle = load_dataset(DATA_DIR)

    run_incident(bundle, "INC-BEN-001")
    assert calls == 1

    calls = 0
    run_functional_baseline(DATA_DIR)
    assert calls == 12


def test_draft_session_caps_authentication_and_lifecycle(
    tmp_path: Path,
) -> None:
    authority, writer = _writer(tmp_path)
    proposal = writer.prepare(
        _draft_request(),
        grant=writer.prepare_grant,
    )
    with pytest.raises(ResourceLimitError):
        writer.prepare(
            _draft_request(filename="second.md"),
            grant=writer.prepare_grant,
        )
    challenge = writer.issue_approval_challenge(proposal)
    for _ in range(3):
        with pytest.raises(DraftApprovalError):
            authority.approve(
                challenge,
                identity=IDENTITY,
                credential="wrong",
            )
    with pytest.raises(ResourceLimitError):
        authority.approve(
            challenge,
            identity=IDENTITY,
            credential=CREDENTIAL,
        )
    assert writer.resource_control.usage.draft_proposals == 1
    assert writer.resource_control.usage.draft_challenges == 1
    assert writer.resource_control.usage.authentication_attempts == 3
    assert tuple((tmp_path / "sandbox" / "drafts").iterdir()) == ()


def test_draft_markdown_utf8_limit_is_exact() -> None:
    prefix_and_suffix = len("# T\n\n\n".encode("utf-8"))
    exact_body = "😀" * 4094 + "x" * (
        MAX_DRAFT_MARKDOWN_BYTES - prefix_and_suffix - 4094 * 4
    )
    exact = f"# T\n\n{exact_body}\n"

    require_utf8_size(exact, MAX_DRAFT_MARKDOWN_BYTES)
    with pytest.raises(ResourceLimitError):
        require_utf8_size(exact + "x", MAX_DRAFT_MARKDOWN_BYTES)


def test_cli_lock_conflict_is_immediate_and_keeps_stdout_empty() -> None:
    descriptor = os.open(DATA_DIR / "manifest.json", os.O_RDONLY)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            (sys.executable, str(ENTRYPOINT), "baseline"),
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    finally:
        os.close(descriptor)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == "error: functional baseline is unavailable\n"
