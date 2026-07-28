"""Valida el registro de dependencias y supply chain de PGS-06-M08."""

from __future__ import annotations

import re
import tomllib
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs" / "dependency-supply-chain-register.md"
INVENTORY = ROOT / "docs" / "system-inventory.md"
RISK_REGISTER = ROOT / "docs" / "risk-register.md"
CONTROL_MAP = ROOT / "docs" / "control-responsibility-mapping.md"
DOCS_README = ROOT / "docs" / "README.md"
README = ROOT / "README.md"
PLAN = ROOT / "plan-proyecto-GenAI-Seguro-Lab.md"
LOCK = ROOT / "uv.lock"
DAT25 = ROOT / "evaluations" / "final-retest-v1.json"

EXPECTED_PACKAGES = {
    "annotated-types": "0.8.0",
    "colorama": "0.4.6",
    "iniconfig": "2.3.0",
    "packaging": "26.2",
    "pluggy": "1.6.0",
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "pygments": "2.20.0",
    "pytest": "9.1.1",
    "typing-extensions": "4.16.0",
    "typing-inspection": "0.4.2",
}
EXPECTED_PACKAGE_IDS = {f"SC-PKG-{index:02d}" for index in range(1, 12)}
EXPECTED_TOOL_IDS = {f"SC-TOOL-{index:02d}" for index in range(1, 6)}
EXPECTED_GAP_IDS = {f"SCG-{index:02d}" for index in range(1, 9)}
FILE_HASHES = {
    "pyproject.toml": "cb3ca6ea34bda636d4ae4b49a751642a25001287e525bc8b24473d0a1b0fc699",
    "uv.lock": "7a7cb70dac5c0d018cfbd7cea07f8ad3345ac96408a21e635f6c2e84d93617be",
    ".python-version": "7b55f8e67b5623c4bef3fa691288da9437d79d3aba156de48d481db32ac7d16d",
}
DAT25_SHA256 = "05d3e93eb8493f7c8501afbc2cb1c26307c37c3140c65f19d70173a5bbd9714d"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _marked(document: str, name: str) -> str:
    start = f"<!-- {name}:start -->"
    end = f"<!-- {name}:end -->"
    assert document.count(start) == 1
    assert document.count(end) == 1
    return document.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_lock_and_register_cover_all_external_packages_with_hashes() -> None:
    lock = tomllib.loads(_read(LOCK))
    packages = {
        package["name"]: package
        for package in lock["package"]
        if package["name"] != "genai-seguro-lab"
    }
    assert {name: package["version"] for name, package in packages.items()} == (
        EXPECTED_PACKAGES
    )

    for package in packages.values():
        assert package["source"]["registry"] == "https://pypi.org/simple"
        assert package["sdist"]["hash"].startswith("sha256:")
        assert package["wheels"]
        assert all(wheel["hash"].startswith("sha256:") for wheel in package["wheels"])

    document = _read(REGISTER)
    section = _marked(document, "dependency-register")
    assert set(re.findall(r"`(SC-PKG-\d{2})`", section)) == EXPECTED_PACKAGE_IDS
    for name, version in EXPECTED_PACKAGES.items():
        assert f"`{name} {version}`" in section


def test_register_pins_source_files_and_declares_toolchain() -> None:
    document = _read(REGISTER)
    for relative, expected in FILE_HASHES.items():
        assert sha256((ROOT / relative).read_bytes()).hexdigest() == expected
        assert expected in document

    toolchain = _marked(document, "toolchain-register")
    assert set(re.findall(r"`(SC-TOOL-\d{2})`", toolchain)) == EXPECTED_TOOL_IDS
    for observed in ("3.12.8", "0.6.10", "2.50.1", "PyPI", "GitHub"):
        assert observed in toolchain


def test_gaps_remain_explicit_without_false_vulnerability_claims() -> None:
    document = _read(REGISTER)
    gaps = _marked(document, "supply-chain-gaps")
    assert set(re.findall(r"`(SCG-\d{2})`", gaps)) == EXPECTED_GAP_IDS
    for gap in (
        "SBOM",
        "firma",
        "CI/CD",
        "release",
        "SECURITY.md",
        "CODEOWNERS",
        "Licencias",
        "Vulnerabilidades",
        "Build no hermética",
    ):
        assert gap.casefold() in gaps.casefold()

    compact = " ".join(document.split()).casefold()
    assert "no equivale a “sin vulnerabilidades”" in compact
    assert "`rr-03` permanece `abierto`" in compact
    assert "`rdec-03` continúa `pendiente_humana`" in compact
    assert re.search(r"/(?:users|home)/[^/\s]+", compact) is None


def test_documentation_and_roadmap_link_completed_m08() -> None:
    for path in (INVENTORY, RISK_REGISTER, CONTROL_MAP, DOCS_README):
        assert "./dependency-supply-chain-register.md" in _read(path)
    assert "./docs/dependency-supply-chain-register.md" in _read(README)
    assert "./docs/dependency-supply-chain-register.md" in _read(PLAN)
    assert "- [x] **PGS-06-M08**" in _read(PLAN)


def test_dat25_remains_immutable() -> None:
    assert sha256(DAT25.read_bytes()).hexdigest() == DAT25_SHA256
