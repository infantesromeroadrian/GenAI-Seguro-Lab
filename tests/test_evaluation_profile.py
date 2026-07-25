"""Pruebas del perfil vulnerable aislado, sin ejecutar ataques."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from genai_seguro_lab.cli import build_parser
from genai_seguro_lab.data_contract import DatasetBundle, load_dataset
from genai_seguro_lab.evaluation_profile import (
    EvaluationAuthorization,
    EvaluationProfileIsolationError,
    UnknownEvaluationIncidentError,
    VulnerableEvaluationProfile,
    VulnerableProfileDescriptor,
    create_vulnerable_evaluation_profile,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def dataset() -> DatasetBundle:
    return load_dataset(ROOT / "data")


@pytest.fixture
def authorization() -> EvaluationAuthorization:
    return EvaluationAuthorization(
        profile_id="GSL-PROFILE-VULNERABLE-001",
        rules_of_engagement="GSL-ROE-001",
        purpose="authorized_security_evaluation",
        synthetic_data=True,
        external_network=False,
        attack_execution=False,
        canonical_checkout_mutation=False,
    )


@pytest.fixture
def temporary_drafts(tmp_path: Path) -> Path:
    drafts = tmp_path / "sandbox" / "drafts"
    drafts.mkdir(parents=True)
    return drafts


def test_profile_is_explicitly_non_default_and_non_executable() -> None:
    descriptor = VulnerableProfileDescriptor()

    assert descriptor.model_dump(mode="json") == {
        "profile_id": "GSL-PROFILE-VULNERABLE-001",
        "version": "1.0.0",
        "evaluation_only": True,
        "default_profile": False,
        "cli_reachable": False,
        "synthetic_data_only": True,
        "external_calls": False,
        "execution_enabled": False,
        "instruction_boundary": "deliberately_merged",
        "tool_policy": "model_selected_local_tools",
        "confirmation_policy": "caller_asserted_not_authenticated",
        "available_tools": ["knowledge_search", "draft_create"],
        "weaknesses": [
            "untrusted_content_as_instruction",
            "model_selected_tools",
            "unauthenticated_confirmation_contract",
        ],
    }

    with pytest.raises(ValidationError):
        VulnerableProfileDescriptor.model_validate(
            {
                **descriptor.model_dump(),
                "cli_reachable": True,
            }
        )


def test_profile_requires_exact_rules_and_non_execution_declaration() -> None:
    valid = {
        "profile_id": "GSL-PROFILE-VULNERABLE-001",
        "rules_of_engagement": "GSL-ROE-001",
        "purpose": "authorized_security_evaluation",
        "synthetic_data": True,
        "external_network": False,
        "attack_execution": False,
        "canonical_checkout_mutation": False,
    }

    for field, invalid in (
        ("rules_of_engagement", "OTHER-ROE"),
        ("synthetic_data", False),
        ("external_network", True),
        ("attack_execution", True),
        ("canonical_checkout_mutation", True),
    ):
        with pytest.raises(ValidationError):
            EvaluationAuthorization.model_validate(
                {
                    **valid,
                    field: invalid,
                }
            )


def test_factory_binds_only_a_temporary_sandbox(
    authorization: EvaluationAuthorization,
    dataset: DatasetBundle,
    temporary_drafts: Path,
) -> None:
    before = tuple(temporary_drafts.iterdir())

    profile = create_vulnerable_evaluation_profile(
        authorization=authorization,
        dataset=dataset,
        drafts_dir=temporary_drafts,
    )

    assert profile.authorization == authorization
    assert profile.dataset_id == "GSL-DATASET-001"
    assert profile.drafts_dir == temporary_drafts.resolve()
    assert tuple(temporary_drafts.iterdir()) == before == ()


def test_factory_rejects_the_canonical_checkout_sandbox(
    authorization: EvaluationAuthorization,
    dataset: DatasetBundle,
) -> None:
    with pytest.raises(EvaluationProfileIsolationError):
        create_vulnerable_evaluation_profile(
            authorization=authorization,
            dataset=dataset,
            drafts_dir=ROOT / "sandbox" / "drafts",
        )


def test_factory_rejects_an_incomplete_dataset_bundle(
    authorization: EvaluationAuthorization,
    dataset: DatasetBundle,
    temporary_drafts: Path,
) -> None:
    with pytest.raises(
        EvaluationProfileIsolationError,
        match="non-empty validated dataset",
    ):
        create_vulnerable_evaluation_profile(
            authorization=authorization,
            dataset=replace(dataset, incidents=()),
            drafts_dir=temporary_drafts,
        )


def test_factory_rejects_direct_construction(
    authorization: EvaluationAuthorization,
    dataset: DatasetBundle,
    temporary_drafts: Path,
) -> None:
    with pytest.raises(EvaluationProfileIsolationError):
        VulnerableEvaluationProfile(
            authorization=authorization,
            descriptor=VulnerableProfileDescriptor(),
            dataset=dataset,
            drafts_dir=temporary_drafts,
            _factory_token=object(),
        )


def test_request_is_marked_and_omits_the_evaluation_oracle(
    authorization: EvaluationAuthorization,
    dataset: DatasetBundle,
    temporary_drafts: Path,
) -> None:
    profile = create_vulnerable_evaluation_profile(
        authorization=authorization,
        dataset=dataset,
        drafts_dir=temporary_drafts,
    )

    request = profile.build_initial_request("INC-BEN-001")

    assert request.request_id == "REQ-EVAL-INC-BEN-001"
    assert request.instruction_boundary == "deliberately_merged"
    assert request.available_tools == ("knowledge_search", "draft_create")
    assert (
        "[EVALUATION_PROFILE:GSL-PROFILE-VULNERABLE-001]"
        in request.messages[0].content
    )
    assert [message.trust_class for message in request.messages] == [
        "trusted_instruction",
        "user_data",
        "untrusted_content",
    ]
    user_data = json.loads(request.messages[1].content)
    assert user_data["profile_id"] == "GSL-PROFILE-VULNERABLE-001"
    assert user_data["synthetic"] is True
    payload = json.loads(request.messages[2].content)
    assert payload["id"] == "INC-BEN-001"
    assert "expected_result" not in payload
    assert tuple(temporary_drafts.iterdir()) == ()


def test_unknown_incident_fails_without_disclosing_dataset(
    authorization: EvaluationAuthorization,
    dataset: DatasetBundle,
    temporary_drafts: Path,
) -> None:
    profile = create_vulnerable_evaluation_profile(
        authorization=authorization,
        dataset=dataset,
        drafts_dir=temporary_drafts,
    )

    with pytest.raises(
        UnknownEvaluationIncidentError,
        match="unknown synthetic evaluation incident",
    ):
        profile.build_initial_request("INC-BEN-999")


def test_default_cli_exposes_no_profile_selector(capsys) -> None:
    parser = build_parser()
    help_text = parser.format_help()

    assert "profile" not in help_text.casefold()
    assert "evaluate" not in help_text.casefold()

    with pytest.raises(SystemExit) as error:
        parser.parse_args(
            [
                "analyze",
                "--incident",
                "INC-BEN-001",
                "--profile",
                "GSL-PROFILE-VULNERABLE-001",
            ]
        )

    assert error.value.code == 2
    assert "unrecognized arguments: --profile" in capsys.readouterr().err
