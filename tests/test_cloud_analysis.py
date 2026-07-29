"""Integración alojada con transporte falso y herramientas locales reales."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from genai_seguro_lab.benign_flow import BenignFlowError
from genai_seguro_lab.cloud_analysis import (
    UnknownCloudIncidentError,
    run_cloud_incident,
)
from genai_seguro_lab.data_contract import load_dataset
from genai_seguro_lab.local_tools import ToolDeniedError
from genai_seguro_lab.local_tools import ToolArgumentsError
from genai_seguro_lab.ollama_cloud_adapter import (
    OllamaCloudAdapter,
    OllamaCloudConfigurationError,
)
from genai_seguro_lab.security_events import SecurityEventJournal

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DRAFTS_DIR = ROOT / "sandbox" / "drafts"


class SequenceTransport:
    def __init__(self, responses: tuple[bytes, ...]) -> None:
        self._responses = list(responses)
        self.documents: list[dict[str, object]] = []

    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> bytes:
        document = json.loads(body)
        assert isinstance(document, dict)
        self.documents.append(document)
        if not self._responses:
            raise AssertionError("unexpected provider call")
        return self._responses.pop(0)


def _tool_response(
    name: str = "knowledge_search",
    *,
    query: str = "phishing",
) -> bytes:
    return json.dumps(
        {
            "done": True,
            "message": {
                "role": "assistant",
                "content": "",
                "thinking": "discard this trace",
                "tool_calls": [
                    {
                        "type": "function",
                        "function": {
                            "index": 0,
                            "name": name,
                            "arguments": {
                                "knowledge_ids": ["KB-001"],
                                "limit": 1,
                                "query": query,
                            },
                        },
                    }
                ],
            },
        }
    ).encode()


def _final_response(content: str | None = None) -> bytes:
    return json.dumps(
        {
            "done": True,
            "message": {
                "role": "assistant",
                "content": content
                or (
                    '{"actions_executed":false,'
                    '"compromise_confirmed":false,'
                    '"incident_id":"INC-BEN-001",'
                    '"knowledge_ids":["KB-001"],'
                    '"summary":"No se confirma compromiso."}'
                ),
                "thinking": "discard this final trace",
            },
        }
    ).encode()


def _adapter(transport: SequenceTransport) -> OllamaCloudAdapter:
    return OllamaCloudAdapter(
        transport=transport,
        api_key_loader=lambda: "test-only-placeholder",
    )


def test_cloud_runner_calls_provider_twice_and_local_tool_once() -> None:
    before = tuple(sorted(path.name for path in DRAFTS_DIR.iterdir()))
    transport = SequenceTransport((_tool_response(), _final_response()))
    journal = SecurityEventJournal("cloud_analyze")

    result = run_cloud_incident(
        load_dataset(DATA_DIR),
        "INC-BEN-001",
        adapter=_adapter(transport),
        security_journal=journal,
    )

    assert len(transport.documents) == 2
    assert "tools" in transport.documents[0]
    assert "tools" not in transport.documents[1]
    assert result.incident_id == "INC-BEN-001"
    assert result.knowledge_ids == ("KB-001",)
    assert result.model_invocations == 2
    assert result.tool_requests == 1
    assert result.provider == "ollama"
    assert result.model == "gpt-oss:120b"
    assert result.deterministic is False
    assert result.external_calls is True
    assert result.cost_eur is None
    report = journal.report()
    assert report.profile == "cloud_analyze"
    assert report.events[-1].kind == "operation_completed"
    assert tuple(sorted(path.name for path in DRAFTS_DIR.iterdir())) == before


def test_wrong_tool_is_rejected_before_search_or_second_call() -> None:
    transport = SequenceTransport((_tool_response("draft_create"),))
    journal = SecurityEventJournal("cloud_analyze")

    with pytest.raises(ToolDeniedError, match="not allowed"):
        run_cloud_incident(
            load_dataset(DATA_DIR),
            "INC-BEN-001",
            adapter=_adapter(transport),
            security_journal=journal,
        )

    assert len(transport.documents) == 1
    signals = [
        event.signal for event in journal.report().events if event.signal
    ]
    assert signals == ["tool_denied"]


def test_empty_remote_query_is_rejected_before_search_or_second_call() -> None:
    transport = SequenceTransport((_tool_response(query=""),))
    journal = SecurityEventJournal("cloud_analyze")

    with pytest.raises(ToolArgumentsError, match="arguments were rejected"):
        run_cloud_incident(
            load_dataset(DATA_DIR),
            "INC-BEN-001",
            adapter=_adapter(transport),
            security_journal=journal,
        )

    assert len(transport.documents) == 1
    assert all(
        event.kind != "tool_result" for event in journal.report().events
    )


@pytest.mark.parametrize(
    "content",
    (
        "not-json",
        (
            '{"actions_executed":true,'
            '"compromise_confirmed":false,'
            '"incident_id":"INC-BEN-001",'
            '"knowledge_ids":["KB-001"],'
            '"summary":"No se confirma compromiso."}'
        ),
        (
            '{"actions_executed":false,'
            '"compromise_confirmed":false,'
            '"incident_id":"INC-BEN-001",'
            '"knowledge_ids":["KB-999"],'
            '"summary":"No se confirma compromiso."}'
        ),
    ),
)
def test_final_json_fails_closed_before_safe_result(content: str) -> None:
    transport = SequenceTransport((_tool_response(), _final_response(content)))

    with pytest.raises(BenignFlowError):
        run_cloud_incident(
            load_dataset(DATA_DIR),
            "INC-BEN-001",
            adapter=_adapter(transport),
        )

    assert len(transport.documents) == 2


def test_invalid_remote_final_content_is_not_retained_as_exception_context() -> None:
    marker = "REMOTE_FINAL_CONTENT_MUST_NOT_SURVIVE"
    transport = SequenceTransport(
        (_tool_response(), _final_response(marker))
    )

    with pytest.raises(BenignFlowError) as captured:
        run_cloud_incident(
            load_dataset(DATA_DIR),
            "INC-BEN-001",
            adapter=_adapter(transport),
        )

    assert marker not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_missing_key_emits_only_sanitized_provider_signal() -> None:
    transport = SequenceTransport(())
    adapter = OllamaCloudAdapter(
        transport=transport,
        api_key_loader=lambda: "",
    )
    journal = SecurityEventJournal("cloud_analyze")

    with pytest.raises(
        OllamaCloudConfigurationError,
        match="credentials are unavailable",
    ):
        run_cloud_incident(
            load_dataset(DATA_DIR),
            "INC-BEN-001",
            adapter=adapter,
            security_journal=journal,
        )

    assert transport.documents == []
    signals = [
        event.signal for event in journal.report().events if event.signal
    ]
    assert signals == ["provider_error"]


def test_unknown_cloud_incident_does_not_call_provider() -> None:
    transport = SequenceTransport(())

    with pytest.raises(UnknownCloudIncidentError):
        run_cloud_incident(
            load_dataset(DATA_DIR),
            "INC-BEN-999",
            adapter=_adapter(transport),
        )

    assert transport.documents == []
