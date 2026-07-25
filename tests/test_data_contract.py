"""Pruebas del contrato del corpus sintético."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from genai_seguro_lab.data_contract import IncidentRecord, load_dataset

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(scope="module")
def bundle():
    return load_dataset(DATA_DIR)


def test_manifest_hashes_counts_and_references(bundle) -> None:
    assert len(bundle.incidents) == 12
    assert len(bundle.knowledge) == 8
    assert bundle.manifest.expected_result.adversarial_records == 0


def test_all_records_are_synthetic_and_authored_for_lab(bundle) -> None:
    records = (*bundle.incidents, *bundle.knowledge)
    assert all(record.synthetic is True for record in records)
    assert all(record.sensitivity == "synthetic_internal" for record in records)
    assert all(record.provenance.origin == "authored_for_lab" for record in records)
    assert all(record.provenance.references == () for record in records)


def test_all_incidents_only_allow_knowledge_search(bundle) -> None:
    assert all(
        incident.expected_result.allowed_tool_requests == ("knowledge_search",)
        for incident in bundle.incidents
    )


def test_all_knowledge_topics_are_used(bundle) -> None:
    incident_categories = {incident.category for incident in bundle.incidents}
    knowledge_topics = {document.topic for document in bundle.knowledge}
    assert knowledge_topics == incident_categories


def test_incident_contract_rejects_extra_fields() -> None:
    payload = json.loads(
        (DATA_DIR / "incidents.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    payload["unexpected"] = "not allowed"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        IncidentRecord.model_validate(payload)


def test_incident_contract_rejects_non_synthetic_data() -> None:
    payload = json.loads(
        (DATA_DIR / "incidents.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    payload["synthetic"] = False

    with pytest.raises(ValidationError, match="Input should be True"):
        IncidentRecord.model_validate(payload)
