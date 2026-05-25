"""Tests for tools/lint_skills.py — validates SKILL.md frontmatter."""

import pytest
from tools.lint_skills import lint_skill_md, LintError


def test_lint_rejects_skill_without_frontmatter(tmp_path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# Just markdown, no frontmatter\n")
    errors = lint_skill_md(skill)
    assert any("missing frontmatter" in e.message for e in errors)


def test_lint_rejects_skill_missing_required_field(tmp_path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("""---
name: python-security
version: 2.0.0
---
# Body
""")
    errors = lint_skill_md(skill)
    assert any("description" in e.message for e in errors)
    assert any("paths" in e.message for e in errors)


def test_lint_accepts_complete_skill(tmp_path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("""---
name: python-security
description: |
  Apply Python-specific security rules.
paths:
  - "**/*.py"
when_to_use: |
  User is writing Python.
version: 2.0.0
sigma: 18
---
# Python security
""")
    errors = lint_skill_md(skill)
    assert errors == []


def test_lint_warns_on_description_too_long(tmp_path):
    long_desc = "x" * 1600
    skill = tmp_path / "SKILL.md"
    skill.write_text(f"""---
name: python-security
description: |
  {long_desc}
paths:
  - "**/*.py"
when_to_use: |
  Use this skill.
version: 2.0.0
sigma: 18
---
# Body
""")
    errors = lint_skill_md(skill)
    assert any("1536" in e.message for e in errors)
