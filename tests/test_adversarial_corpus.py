"""Pruebas del contrato y del estado de conexión del corpus adversario."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from genai_seguro_lab.cli import build_parser
from genai_seguro_lab.data_contract import (
    EXPECTED_ADVERSARIAL_ABUSE_CASES,
    EXPECTED_ADVERSARIAL_FAMILY_BY_ABUSE_CASE,
    EXPECTED_ADVERSARIAL_FAMILIES,
    AdversarialCorpusBundle,
    AdversarialCorpusManifest,
    AdversarialInputRecord,
    load_adversarial_corpus,
)

ROOT = Path(__file__).resolve().parents[1]
ADVERSARIAL_DIR = ROOT / "data" / "adversarial"


@pytest.fixture(scope="module")
def adversarial_bundle() -> AdversarialCorpusBundle:
    return load_adversarial_corpus(ADVERSARIAL_DIR)


def _file_hashes(directory: Path) -> dict[str, str]:
    return {
        path.name: sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


def test_manifest_fixes_scope_counts_and_partial_test_wiring(
    adversarial_bundle: AdversarialCorpusBundle,
) -> None:
    expected = adversarial_bundle.manifest.expected_result

    assert adversarial_bundle.manifest.id == "GSL-ADVERSARIAL-CORPUS-001"
    assert adversarial_bundle.manifest.version == "1.1.0"
    assert adversarial_bundle.manifest.rules_of_engagement == "GSL-ROE-001"
    assert (
        adversarial_bundle.manifest.target_profile
        == "GSL-PROFILE-VULNERABLE-001"
    )
    assert expected.input_records == len(adversarial_bundle.inputs) == 18
    assert expected.oracle_records == len(adversarial_bundle.oracles) == 18
    assert expected.unique_abuse_cases == 17
    assert expected.threat_families == 6
    assert expected.test_wired_records == 3
    assert expected.inert_records == 15
    assert expected.canonical_evaluation_records == 0
    assert (
        adversarial_bundle.manifest.fixture_state
        == "partially_wired_for_tests"
    )


def test_corpus_covers_all_abuse_cases_and_six_families(
    adversarial_bundle: AdversarialCorpusBundle,
) -> None:
    counts = Counter(record.abuse_case_id for record in adversarial_bundle.inputs)
    families = {record.family for record in adversarial_bundle.inputs}

    assert set(counts) == EXPECTED_ADVERSARIAL_ABUSE_CASES
    assert counts["AC-JB-01"] == 2
    assert all(
        count == 1
        for case_id, count in counts.items()
        if case_id != "AC-JB-01"
    )
    assert families == EXPECTED_ADVERSARIAL_FAMILIES
    assert all(
        record.family
        == EXPECTED_ADVERSARIAL_FAMILY_BY_ABUSE_CASE[record.abuse_case_id]
        for record in adversarial_bundle.inputs
    )


def test_inputs_and_oracles_are_strictly_separated_and_joined(
    adversarial_bundle: AdversarialCorpusBundle,
) -> None:
    inputs = {record.id: record for record in adversarial_bundle.inputs}
    oracles = {record.case_id: record for record in adversarial_bundle.oracles}

    assert inputs.keys() == oracles.keys()
    assert all(
        inputs[case_id].abuse_case_id == oracles[case_id].abuse_case_id
        for case_id in inputs
    )
    assert all(oracle.fixed_before_execution for oracle in oracles.values())
    assert all(oracle.required_observations for oracle in oracles.values())

    raw_inputs = (ADVERSARIAL_DIR / "inputs.jsonl").read_text(encoding="utf-8")
    assert "expected_outcome" not in raw_inputs
    assert "required_observations" not in raw_inputs


def test_all_records_are_synthetic_local_and_explicitly_wired_or_inert(
    adversarial_bundle: AdversarialCorpusBundle,
) -> None:
    records = (*adversarial_bundle.inputs, *adversarial_bundle.oracles)

    assert all(record.synthetic is True for record in records)
    assert all(record.sensitivity == "synthetic_internal" for record in records)
    assert all(record.provenance.origin == "authored_for_lab" for record in records)
    assert all(
        record.scope == "local_lab_only"
        and record.external_target is False
        for record in adversarial_bundle.inputs
    )
    test_wired = {
        record.id
        for record in adversarial_bundle.inputs
        if record.fixture_state == "test_wired"
    }
    assert test_wired == {"ADV-PI-001", "ADV-PI-002", "ADV-PI-003"}
    assert all(
        record.fixture_state == "inert_not_wired"
        for record in adversarial_bundle.inputs
        if record.id not in test_wired
    )
    input_bytes = (ADVERSARIAL_DIR / "inputs.jsonl").read_bytes()
    assert len(input_bytes) <= 10_485_760
    assert all(len(line) <= 65_536 for line in input_bytes.splitlines())


def test_only_oversized_dataset_case_requires_roe_extension(
    adversarial_bundle: AdversarialCorpusBundle,
) -> None:
    extension_cases = {
        record.abuse_case_id
        for record in adversarial_bundle.inputs
        if record.roe_status == "requires_extension"
    }
    oversized_oracle = next(
        oracle
        for oracle in adversarial_bundle.oracles
        if oracle.abuse_case_id == "AC-DOS-03"
    )

    assert extension_cases == {"AC-DOS-03"}
    assert oversized_oracle.expected_outcome == "not_authorized"
    assert oversized_oracle.expected_effect == "none"


def test_loading_is_read_only(adversarial_bundle: AdversarialCorpusBundle) -> None:
    before = _file_hashes(ADVERSARIAL_DIR)

    reloaded = load_adversarial_corpus(ADVERSARIAL_DIR)

    assert reloaded == adversarial_bundle
    assert _file_hashes(ADVERSARIAL_DIR) == before


def test_loader_rejects_tampered_input_hash(tmp_path: Path) -> None:
    copied = tmp_path / "adversarial"
    shutil.copytree(ADVERSARIAL_DIR, copied)
    input_path = copied / "inputs.jsonl"
    input_path.write_text(
        input_path.read_text(encoding="utf-8").replace(
            "Prompt directo",
            "Prompt sintético",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="hash mismatch for inputs.jsonl"):
        load_adversarial_corpus(copied)


def test_input_contract_rejects_extra_and_non_synthetic_fields() -> None:
    payload = json.loads(
        (ADVERSARIAL_DIR / "inputs.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AdversarialInputRecord.model_validate(
            {
                **payload,
                "unexpected": "not allowed",
            }
        )
    with pytest.raises(ValidationError, match="Input should be True"):
        AdversarialInputRecord.model_validate(
            {
                **payload,
                "synthetic": False,
            }
        )


def test_manifest_cannot_claim_more_wired_or_canonical_records() -> None:
    payload = json.loads(
        (ADVERSARIAL_DIR / "manifest.json").read_text(encoding="utf-8")
    )
    payload["expected_result"]["test_wired_records"] = 18

    with pytest.raises(ValidationError, match="Input should be 3"):
        AdversarialCorpusManifest.model_validate_json(json.dumps(payload))

    payload["expected_result"]["test_wired_records"] = 3
    payload["expected_result"]["canonical_evaluation_records"] = 1
    with pytest.raises(ValidationError, match="Input should be 0"):
        AdversarialCorpusManifest.model_validate_json(json.dumps(payload))


def test_default_cli_exposes_no_adversarial_command(capsys) -> None:
    parser = build_parser()
    help_text = parser.format_help().casefold()

    assert "adversarial" not in help_text
    assert "attack" not in help_text

    with pytest.raises(SystemExit) as error:
        parser.parse_args(["attack"])

    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
