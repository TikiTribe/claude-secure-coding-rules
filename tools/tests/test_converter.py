"""Tests for tools/rule_to_skill_converter.py."""

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


@pytest.mark.parametrize("rule_path,expected_name", [
    ("rules/languages/python/CLAUDE.md", "python-security"),
    ("rules/languages/javascript/CLAUDE.md", "javascript-security"),
    ("rules/backend/fastapi/CLAUDE.md", "fastapi-security"),
    ("rules/frontend/react/CLAUDE.md", "react-security"),
    ("rules/iac/terraform/CLAUDE.md", "terraform-security"),
    ("rules/containers/docker/CLAUDE.md", "docker-security"),
    ("rules/cicd/github-actions/CLAUDE.md", "github-actions-security"),
    ("rules/_core/owasp-2025.md", "applying-owasp-top-10"),
    ("rules/_core/mcp-security.md", "applying-mcp-security"),
    ("rules/_core/ai-security.md", "applying-ai-ml-security"),
])
def test_derive_skill_name(rule_path, expected_name):
    """Skill names follow the documented naming convention."""
    from tools.rule_to_skill_converter import derive_skill_name
    assert derive_skill_name(Path(rule_path)) == expected_name


def test_strict_mode_requires_audit_entry(tmp_path):
    """In strict mode, conversion refuses if the rule is not in the audit output."""
    rule_file = tmp_path / "rules" / "languages" / "python" / "CLAUDE.md"
    rule_file.parent.mkdir(parents=True)
    rule_file.write_text("# Python rules\n")

    audit = tmp_path / "audit.yaml"
    audit.write_text("audited_rules: []\n")  # empty audit

    with pytest.raises(ValueError, match="not in audit"):
        convert_rule_file(rule_file, tmp_path / "out", strict=True, audit_path=audit)


def test_strict_mode_passes_with_audit_entry(tmp_path):
    """In strict mode, conversion succeeds if the rule is in the audit output."""
    rule_file = tmp_path / "rules" / "languages" / "python" / "CLAUDE.md"
    rule_file.parent.mkdir(parents=True)
    rule_file.write_text("# Python rules\n")

    audit = tmp_path / "audit.yaml"
    audit.write_text(
        "audited_rules:\n"
        f"  - path: {rule_file.as_posix()}\n"
        "    status: passed\n"
        "    reviewed_by: rock-lambros\n"
        "    reviewed_on: 2026-05-25\n"
    )

    skill_md = convert_rule_file(rule_file, tmp_path / "out", strict=True, audit_path=audit)
    assert skill_md.exists()


def test_strict_mode_refuses_failed_status(tmp_path):
    """In strict mode, even an entry with status=failed is refused."""
    rule_file = tmp_path / "rules" / "languages" / "python" / "CLAUDE.md"
    rule_file.parent.mkdir(parents=True)
    rule_file.write_text("# Python rules\n")

    audit = tmp_path / "audit.yaml"
    audit.write_text(
        "audited_rules:\n"
        f"  - path: {rule_file.as_posix()}\n"
        "    status: failed\n"
        "    reviewed_by: rock-lambros\n"
        "    reviewed_on: 2026-05-25\n"
    )

    with pytest.raises(ValueError, match="not in audit"):
        convert_rule_file(rule_file, tmp_path / "out", strict=True, audit_path=audit)


def test_strict_mode_requires_audit_path(tmp_path):
    """In strict mode without audit_path, raises an explicit error."""
    rule_file = tmp_path / "rules" / "languages" / "python" / "CLAUDE.md"
    rule_file.parent.mkdir(parents=True)
    rule_file.write_text("# Python rules\n")

    with pytest.raises(ValueError, match="strict mode requires audit_path"):
        convert_rule_file(rule_file, tmp_path / "out", strict=True)


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


def test_cli_invocation_writes_skill_md(tmp_path):
    """`python -m tools.rule_to_skill_converter` writes SKILL.md."""
    from tools.rule_to_skill_converter import main

    rule_file = tmp_path / "rules" / "languages" / "python" / "CLAUDE.md"
    rule_file.parent.mkdir(parents=True)
    rule_file.write_text("# Python Security Rules\n\nBody.\n")

    out_dir = tmp_path / "skills"
    exit_code = main([str(rule_file), "--out", str(out_dir)])

    assert exit_code == 0
    assert (out_dir / "python-security" / "SKILL.md").exists()


def test_cli_strict_without_audit_returns_nonzero(tmp_path):
    """--strict without --audit prints an error and returns nonzero."""
    from tools.rule_to_skill_converter import main

    rule_file = tmp_path / "rules" / "_core" / "owasp-2025.md"
    rule_file.parent.mkdir(parents=True)
    rule_file.write_text("# OWASP\n\nBody.\n")

    out_dir = tmp_path / "skills"
    exit_code = main([str(rule_file), "--out", str(out_dir), "--strict"])

    assert exit_code == 2


def test_cli_strict_with_passed_audit_writes_skill(tmp_path):
    """--strict succeeds when the rule is in the audit YAML with status=passed."""
    from tools.rule_to_skill_converter import main

    rule_file = tmp_path / "rules" / "_core" / "owasp-2025.md"
    rule_file.parent.mkdir(parents=True)
    rule_file.write_text("# OWASP\n\nBody.\n")

    audit_file = tmp_path / "audit.yaml"
    audit_file.write_text(
        "audited_rules:\n"
        f"  - path: {rule_file.as_posix()}\n"
        "    status: passed\n"
        "    reviewed_by: rocklambros\n"
        "    reviewed_on: 2026-05-26\n"
    )

    out_dir = tmp_path / "skills"
    exit_code = main(
        [str(rule_file), "--out", str(out_dir), "--strict", "--audit", str(audit_file)]
    )

    assert exit_code == 0
    assert (out_dir / "applying-owasp-top-10" / "SKILL.md").exists()
