"""Golden-file tests for the converter.

The converter must produce byte-identical output for a given input.
Brittleness mitigation per fresh-round F21:
- PyYAML pinned to 6.0.2 in pyproject.toml
- All test inputs and expected outputs use LF line endings (enforced by .gitattributes)
- Unicode NFC normalization expected in all expected/ files
"""

from pathlib import Path
import unicodedata

import pytest

from tools.rule_to_skill_converter import convert_rule_file


def _normalize(text: str) -> str:
    """Normalize text for byte-equivalence comparison."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = unicodedata.normalize("NFC", text)
    return text


def test_golden_python_skill(tmp_path):
    """Converter produces byte-identical output for sample-python.md."""
    input_path = Path("tools/tests/converter/golden/inputs/sample-python.md")
    expected_path = Path("tools/tests/converter/golden/expected/python-security/SKILL.md")

    fake_rule = tmp_path / "rules" / "languages" / "python" / "CLAUDE.md"
    fake_rule.parent.mkdir(parents=True)
    fake_rule.write_text(input_path.read_text())

    actual_path = convert_rule_file(fake_rule, tmp_path / "out", strict=False)
    actual = _normalize(actual_path.read_text())
    expected = _normalize(expected_path.read_text())

    # The Source: line contains a path + date that varies between
    # actual (fake rule path + today) and expected (fixture path + 2026-05-25).
    # Compare everything except that line.
    actual_lines = [l for l in actual.split("\n") if "Source:" not in l]
    expected_lines = [l for l in expected.split("\n") if "Source:" not in l]
    assert actual_lines == expected_lines


def test_golden_is_idempotent(tmp_path):
    """Running the converter twice on the same input produces no diff."""
    input_path = Path("tools/tests/converter/golden/inputs/sample-python.md")
    fake_rule = tmp_path / "rules" / "languages" / "python" / "CLAUDE.md"
    fake_rule.parent.mkdir(parents=True)
    fake_rule.write_text(input_path.read_text())

    out_dir = tmp_path / "out"
    first = convert_rule_file(fake_rule, out_dir, strict=False)
    first_content = first.read_text()
    second = convert_rule_file(fake_rule, out_dir, strict=False)
    second_content = second.read_text()
    assert first_content == second_content
