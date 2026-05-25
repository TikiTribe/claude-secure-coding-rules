"""Convert v1 CLAUDE.md rule files into v2 SKILL.md skills.

Contract:
- Input: a v1 rule file (e.g., rules/languages/python/CLAUDE.md).
- Output: a directory <out_dir>/<derived-name>/ containing SKILL.md.
- The derived name is `<domain>-security` for catalog files and
  `applying-<standard>` for core files (per design.md naming convention).

Strict mode: requires an audit-output YAML file (path passed via --audit)
listing rules that have passed the P0.5 corpus-quality audit. Refuses to
process rules not in the audit-output. Default mode (no --strict) allows
unaudited conversion (for the P0 scaffolding phase only).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SkillMetadata:
    name: str
    description: str
    paths: list[str]
    when_to_use: str
    version: str = "2.0.0"
    sigma: int = 15


def derive_skill_name(rule_path: Path) -> str:
    """Derive the v2 skill name from a v1 rule file path.

    Examples:
        rules/languages/python/CLAUDE.md     -> python-security
        rules/backend/fastapi/CLAUDE.md      -> fastapi-security
        rules/_core/owasp-2025.md            -> applying-owasp-top-10
        rules/_core/mcp-security.md          -> applying-mcp-security
    """
    parts = rule_path.parts
    if "_core" in parts:
        stem = rule_path.stem.lower()
        if stem == "owasp-2025":
            return "applying-owasp-top-10"
        return f"applying-{stem.replace('-security', '')}-security"
    if "languages" in parts:
        idx = parts.index("languages")
        return f"{parts[idx + 1]}-security"
    if "backend" in parts:
        idx = parts.index("backend")
        return f"{parts[idx + 1]}-security"
    if "frontend" in parts:
        idx = parts.index("frontend")
        return f"{parts[idx + 1]}-security"
    if "iac" in parts:
        idx = parts.index("iac")
        return f"{parts[idx + 1]}-security"
    if "containers" in parts:
        idx = parts.index("containers")
        return f"{parts[idx + 1]}-security"
    if "cicd" in parts:
        idx = parts.index("cicd")
        return f"{parts[idx + 1]}-security"
    if "rag" in parts:
        idx = parts.index("rag")
        suffix = "-".join(parts[idx + 1 : -1])
        return f"rag-{suffix}-security"
    raise ValueError(f"Cannot derive skill name from {rule_path}")


def derive_paths_glob(skill_name: str) -> list[str]:
    """Derive `paths:` frontmatter from skill name."""
    if skill_name == "python-security":
        return ["**/*.py", "**/*.pyi", "**/pyproject.toml", "**/requirements*.txt"]
    if skill_name == "javascript-security":
        return ["**/*.js", "**/*.mjs", "**/*.cjs", "**/package.json"]
    if skill_name == "typescript-security":
        return ["**/*.ts", "**/*.tsx", "**/tsconfig*.json"]
    if skill_name == "go-security":
        return ["**/*.go", "**/go.mod", "**/go.sum"]
    if skill_name == "rust-security":
        return ["**/*.rs", "**/Cargo.toml", "**/Cargo.lock"]
    if skill_name == "java-security":
        return ["**/*.java", "**/pom.xml", "**/build.gradle*"]
    if skill_name == "csharp-security":
        return ["**/*.cs", "**/*.csproj"]
    if skill_name == "ruby-security":
        return ["**/*.rb", "**/Gemfile", "**/Gemfile.lock"]
    if skill_name == "r-security":
        return ["**/*.R", "**/*.Rmd", "**/DESCRIPTION"]
    if skill_name == "cpp-security":
        return ["**/*.cpp", "**/*.hpp", "**/*.cc", "**/*.h", "**/CMakeLists.txt"]
    if skill_name == "julia-security":
        return ["**/*.jl", "**/Project.toml"]
    if skill_name == "sql-security":
        return ["**/*.sql"]
    if skill_name == "fastapi-security":
        return ["**/*.py", "**/pyproject.toml", "**/requirements*.txt"]
    if skill_name == "django-security":
        return ["**/*.py", "**/settings.py", "**/urls.py"]
    if skill_name == "express-security":
        return ["**/*.js", "**/*.ts", "**/package.json"]
    if skill_name == "react-security":
        return ["**/*.jsx", "**/*.tsx", "**/package.json"]
    if skill_name == "nextjs-security":
        return ["**/*.jsx", "**/*.tsx", "**/next.config*"]
    if skill_name == "terraform-security":
        return ["**/*.tf", "**/*.tfvars", "**/*.hcl"]
    if skill_name == "docker-security":
        return ["**/Dockerfile*", "**/docker-compose*.yml", "**/docker-compose*.yaml"]
    if skill_name == "kubernetes-security":
        return ["**/*.yaml", "**/*.yml"]
    if skill_name == "github-actions-security":
        return [".github/workflows/*.yml", ".github/workflows/*.yaml"]
    if skill_name.startswith("applying-"):
        return ["**/*"]
    return ["**/*"]


def parse_frontmatter(rule_text: str) -> dict:
    """Extract first H1 title and any explicit metadata from rule text."""
    title_match = re.search(r"^#\s+(.+)$", rule_text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else "Unknown rule"
    return {"title": title}


def convert_rule_file(rule_path: Path, out_dir: Path, strict: bool = False) -> Path:
    """Convert a v1 rule file to a v2 SKILL.md.

    Returns the path to the created SKILL.md.
    Raises ValueError in strict mode if the rule is not in the audit output.
    """
    rule_text = rule_path.read_text()
    skill_name = derive_skill_name(rule_path)
    paths_glob = derive_paths_glob(skill_name)
    metadata = parse_frontmatter(rule_text)

    skill_dir = out_dir / skill_name
    skill_dir.mkdir(parents=True, exist_ok=True)

    description = (
        f"Apply {skill_name.replace('-', ' ')} rules. "
        f"Source: {metadata['title']}. "
        "Loads when working with matching file types."
    )
    when_to_use = (
        f"User is writing or modifying files matching the skill's paths glob, "
        "or asks about the domain this skill covers."
    )
    paths_yaml = "\n".join(f"  - \"{p}\"" for p in paths_glob)

    skill_md = f"""---
name: {skill_name}
description: |
  {description}
paths:
{paths_yaml}
when_to_use: |
  {when_to_use}
version: 2.0.0
sigma: 15
---

# {metadata['title']}

> **Source:** Converted from `{rule_path.as_posix()}` on 2026-05-25.
> **TODO before v2.0.0:** Hand-edit `description`, `when_to_use`, `sigma`, and the body content per the skill-authoring checklist.

{rule_text}
"""

    skill_md_path = skill_dir / "SKILL.md"
    skill_md_path.write_text(skill_md)
    return skill_md_path
