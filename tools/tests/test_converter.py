"""Tests for tools/rule_to_skill_converter.py."""

import json
from pathlib import Path

import pytest

from tools.rule_to_skill_converter import (
    convert_rule_file,
    parse_frontmatter,
    derive_paths_glob,
)


def test_convert_rule_file_produces_skill_md(tmp_path):
    """Converter reads a v1 rule file and emits a SKILL.md with frontmatter."""
    rule_content = """# Python Security Rules

This file teaches Python-specific security patterns.

## Rule: No eval on user input

**Level**: `strict`

**Refs**: CWE-95, OWASP A03:2025
"""
    rule_file = tmp_path / "input" / "languages" / "python" / "CLAUDE.md"
    rule_file.parent.mkdir(parents=True)
    rule_file.write_text(rule_content)

    out_dir = tmp_path / "output"
    skill_md_path = convert_rule_file(rule_file, out_dir, strict=False)

    assert skill_md_path.exists()
    assert skill_md_path.name == "SKILL.md"
    assert skill_md_path.parent.name == "python-security"

    content = skill_md_path.read_text()
    assert content.startswith("---\n")
    assert "name: python-security" in content
    assert "paths:" in content
