"""Structural lint for SKILL.md files.

Validates:
- Frontmatter exists and parses as YAML
- Required fields: name, description, paths, when_to_use, version
- description + when_to_use combined ≤ 1536 chars (Claude Code skill listing budget)
- name uses lowercase + hyphens + digits only
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

REQUIRED_FIELDS = {"name", "description", "paths", "when_to_use", "version"}
NAME_PATTERN = re.compile(r"^[a-z0-9-]+$")
DESCRIPTION_CHAR_BUDGET = 1536


@dataclass
class LintError:
    file: Path
    message: str


def parse_frontmatter(text: str) -> dict | None:
    """Extract YAML frontmatter between --- markers; return None if absent."""
    match = re.match(r"^---\n(.+?)\n---\n", text, re.DOTALL)
    if not match:
        return None
    return yaml.safe_load(match.group(1))


def lint_skill_md(path: Path) -> list[LintError]:
    """Lint a single SKILL.md file. Returns a list of errors (empty if valid)."""
    errors: list[LintError] = []
    text = path.read_text()
    frontmatter = parse_frontmatter(text)
    if frontmatter is None:
        errors.append(LintError(path, "missing frontmatter (no `---` block at top)"))
        return errors

    missing = REQUIRED_FIELDS - frontmatter.keys()
    for field in sorted(missing):
        errors.append(LintError(path, f"missing required field: {field}"))

    name = frontmatter.get("name", "")
    if name and not NAME_PATTERN.match(name):
        errors.append(LintError(path, f"name '{name}' must match {NAME_PATTERN.pattern}"))

    desc = frontmatter.get("description", "")
    wtu = frontmatter.get("when_to_use", "")
    combined = f"{desc}{wtu}"
    if len(combined) > DESCRIPTION_CHAR_BUDGET:
        errors.append(
            LintError(
                path,
                f"description + when_to_use is {len(combined)} chars, exceeds 1536 budget",
            )
        )

    return errors


def lint_all(skills_dir: Path) -> list[LintError]:
    """Lint every SKILL.md under skills_dir."""
    errors: list[LintError] = []
    for skill_md in sorted(skills_dir.rglob("SKILL.md")):
        errors.extend(lint_skill_md(skill_md))
    return errors


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1] if len(sys.argv) > 1 else "skills")
    errors = lint_all(target)
    for err in errors:
        print(f"{err.file}: {err.message}")
    sys.exit(1 if errors else 0)
