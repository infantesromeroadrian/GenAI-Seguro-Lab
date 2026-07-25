"""Pruebas unitarias de la política de salida PGS-04-M05."""

from __future__ import annotations

import json

import pytest

from genai_seguro_lab.output_policy import (
    OutputPolicy,
    OutputPolicyRejectedError,
    PolicyCheckedText,
    PolicyCheckedTextError,
)


def test_safe_text_is_byte_identical_and_has_allow_evidence() -> None:
    policy = OutputPolicy()
    original = "Resumen sintético: no se confirma un compromiso. ñ\n"

    checked = policy.check(original, channel="final_summary")

    assert policy.unwrap(checked, channel="final_summary") == original
    assert (
        policy.unwrap(checked, channel="final_summary").encode("utf-8")
        == original.encode("utf-8")
    )
    assert checked.metadata.decision == "allow"
    assert checked.metadata.redaction_categories == ()
    assert checked.metadata.redaction_counts == ()


def test_redaction_is_deterministic_idempotent_and_value_free() -> None:
    text = (
        "Contacta con analyst@example.test desde "
        "/Users/operator/private/report.txt o "
        r"C:\Users\operator\private\report.txt."
    )
    first_policy = OutputPolicy()
    second_policy = OutputPolicy()

    first = first_policy.check(text, channel="final_summary")
    second = second_policy.check(text, channel="final_summary")
    sanitized = first_policy.unwrap(first, channel="final_summary")

    assert sanitized == second_policy.unwrap(second, channel="final_summary")
    assert "analyst@example.test" not in sanitized
    assert "/Users/operator" not in sanitized
    assert r"C:\Users\operator" not in sanitized
    assert sanitized.count("[REDACTED_EMAIL]") == 1
    assert sanitized.count("[REDACTED_LOCAL_PATH]") == 2
    assert first.metadata.redaction_categories == ("email", "local_path")
    assert tuple(
        (item.category, item.count)
        for item in first.metadata.redaction_counts
    ) == (("email", 1), ("local_path", 2))

    checked_again = first_policy.check(
        sanitized,
        channel="final_summary",
    )
    assert (
        first_policy.unwrap(checked_again, channel="final_summary")
        == sanitized
    )
    assert checked_again.metadata.decision == "allow"
    serialized_metadata = json.dumps(
        {
            "categories": first.metadata.redaction_categories,
            "counts": [
                (item.category, item.count)
                for item in first.metadata.redaction_counts
            ],
        },
        sort_keys=True,
    )
    assert "example.test" not in serialized_metadata
    assert "operator" not in serialized_metadata


@pytest.mark.parametrize(
    "unsafe",
    (
        "CANARY_GSL_EX_003",
        "-----BEGIN PRIVATE KEY-----",
        "Authorization: Bearer secret-token-value",
        "credential=high-signal-value",
        '"api_key": "high-signal-value"',
        "Compromiso confirmado.",
        "Resumen: compromiso confirmado.",
        "El equipo ya está aislado.",
        "Las credenciales ya están revocadas.",
        "Compromise confirmed.",
        "Summary: compromise confirmed.",
        "The host is already isolated.",
        "The credentials are already revoked.",
        "The device has already been isolated.",
        "The credentials have already been revoked.",
        "texto\u202esecreto",
    ),
)
def test_rejection_is_generic_and_does_not_reflect_raw_text(
    unsafe: str,
) -> None:
    policy = OutputPolicy()

    with pytest.raises(OutputPolicyRejectedError) as captured:
        policy.check(unsafe, channel="final_summary")

    rendered = f"{captured.value!s}\n{captured.value!r}"
    assert rendered == (
        "output rejected by application policy\n"
        "OutputPolicyRejectedError('output rejected by application policy')"
    )
    assert unsafe not in rendered


def test_reject_precedes_redaction() -> None:
    policy = OutputPolicy()
    text = "analyst@example.test CANARY_GSL_EX_003"

    with pytest.raises(OutputPolicyRejectedError):
        policy.check(text, channel="final_summary")


@pytest.mark.parametrize(
    "active",
    (
        "https://outside.example/resource",
        "[externo](https://outside.example/resource)",
        "![[embedded-note]]",
        "<script>alert(1)</script>",
        "javascript:alert(1)",
    ),
)
def test_active_content_is_rejected_only_for_draft_channels(
    active: str,
) -> None:
    final_policy = OutputPolicy()
    checked = final_policy.check(active, channel="final_summary")
    assert final_policy.unwrap(checked, channel="final_summary") == active

    for channel in ("draft_title", "draft_body"):
        with pytest.raises(OutputPolicyRejectedError):
            OutputPolicy().check(active, channel=channel)  # type: ignore[arg-type]


def test_checked_text_is_bound_to_policy_instance_and_channel() -> None:
    first_policy = OutputPolicy()
    second_policy = OutputPolicy()
    checked = first_policy.check("Texto seguro.", channel="draft_body")

    assert "Texto seguro." not in repr(checked)
    assert "text=<opaque>" in repr(checked)
    with pytest.raises(TypeError):
        vars(checked)
    with pytest.raises(TypeError):
        json.dumps(checked)
    with pytest.raises(PolicyCheckedTextError):
        first_policy.unwrap(checked, channel="draft_title")
    with pytest.raises(PolicyCheckedTextError):
        second_policy.unwrap(checked, channel="draft_body")

    fabricated = object.__new__(PolicyCheckedText)
    with pytest.raises(PolicyCheckedTextError):
        first_policy.unwrap(fabricated, channel="draft_body")
    with pytest.raises(PolicyCheckedTextError):
        PolicyCheckedText(checked.metadata)
