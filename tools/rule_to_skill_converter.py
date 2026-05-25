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
import yaml
from dataclasses import dataclass
from datetime import date
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
        SPECIAL_CORE_NAMES = {
            "owasp-2025": "applying-owasp-top-10",
            "ai-security": "applying-ai-ml-security",
            "agent-security": "applying-agentic-ai-security",
            "mcp-security": "applying-mcp-security",
            "rag-security": "applying-rag-security",
            "graph-database-security": "applying-graph-db-security",
        }
        if stem in SPECIAL_CORE_NAMES:
            return SPECIAL_CORE_NAMES[stem]
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


PATHS_BY_SKILL: dict[str, list[str]] = {
    # Language skills
    "python-security": ["**/*.py", "**/*.pyi", "**/pyproject.toml", "**/requirements*.txt"],
    "javascript-security": ["**/*.js", "**/*.mjs", "**/*.cjs", "**/package.json"],
    "typescript-security": ["**/*.ts", "**/*.tsx", "**/tsconfig*.json"],
    "go-security": ["**/*.go", "**/go.mod", "**/go.sum"],
    "rust-security": ["**/*.rs", "**/Cargo.toml", "**/Cargo.lock"],
    "java-security": ["**/*.java", "**/pom.xml", "**/build.gradle*"],
    "csharp-security": ["**/*.cs", "**/*.csproj"],
    "ruby-security": ["**/*.rb", "**/Gemfile", "**/Gemfile.lock"],
    "r-security": ["**/*.R", "**/*.Rmd", "**/DESCRIPTION"],
    "cpp-security": ["**/*.cpp", "**/*.hpp", "**/*.cc", "**/*.h", "**/CMakeLists.txt"],
    "julia-security": ["**/*.jl", "**/Project.toml"],
    "sql-security": ["**/*.sql"],
    # Backend framework skills
    "fastapi-security": ["**/*.py", "**/pyproject.toml", "**/requirements*.txt"],
    "django-security": ["**/*.py", "**/settings.py", "**/urls.py"],
    "flask-security": ["**/*.py", "**/app.py"],
    "express-security": ["**/*.js", "**/*.ts", "**/package.json"],
    "nestjs-security": ["**/*.ts", "**/nest-cli.json"],
    "langchain-security": ["**/*.py"],
    "crewai-security": ["**/*.py"],
    "autogen-security": ["**/*.py"],
    "transformers-security": ["**/*.py"],
    "vllm-security": ["**/*.py"],
    "triton-security": ["**/*.py", "**/config.pbtxt"],
    "torchserve-security": ["**/*.py", "**/*.mar"],
    "ray-serve-security": ["**/*.py"],
    "bentoml-security": ["**/*.py", "**/bentofile.yaml"],
    "mlflow-security": ["**/*.py", "**/MLproject"],
    "modal-security": ["**/*.py"],
    # Frontend framework skills
    "react-security": ["**/*.jsx", "**/*.tsx", "**/package.json"],
    "nextjs-security": ["**/*.jsx", "**/*.tsx", "**/next.config*"],
    "vue-security": ["**/*.vue", "**/*.js", "**/*.ts"],
    "angular-security": ["**/*.ts", "**/*.html", "**/angular.json"],
    "svelte-security": ["**/*.svelte"],
    # IaC skills
    "terraform-security": ["**/*.tf", "**/*.tfvars", "**/*.hcl"],
    "pulumi-security": ["**/*.py", "**/*.ts", "**/Pulumi.yaml"],
    # Container skills
    "docker-security": ["**/Dockerfile*", "**/docker-compose*.yml", "**/docker-compose*.yaml"],
    "kubernetes-security": ["**/*.yaml", "**/*.yml"],
    "helm-security": ["**/Chart.yaml", "**/values*.yaml", "**/templates/**/*.yaml"],
    # CI/CD skills
    "github-actions-security": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
    "gitlab-ci-security": [".gitlab-ci.yml", "**/.gitlab-ci.yml"],
}


def derive_paths_glob(skill_name: str) -> list[str]:
    """Derive `paths:` frontmatter from skill name.

    Returns the hard-coded paths for known skills. For applying-* core
    skills and any unknown skill, returns ["**/*"] (load broadly).
    """
    if skill_name in PATHS_BY_SKILL:
        return PATHS_BY_SKILL[skill_name]
    if skill_name.startswith("applying-"):
        return ["**/*"]
    if skill_name.startswith("rag-"):
        return ["**/*.py"]
    return ["**/*"]


def parse_frontmatter(rule_text: str) -> dict:
    """Extract first H1 title and any explicit metadata from rule text."""
    title_match = re.search(r"^#\s+(.+)$", rule_text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else "Unknown rule"
    return {"title": title}


def convert_rule_file(
    rule_path: Path,
    out_dir: Path,
    strict: bool = False,
    audit_path: Path | None = None,
) -> Path:
    """Convert a v1 rule file to a v2 SKILL.md.

    Returns the path to the created SKILL.md.

    Args:
        rule_path:   Path to the source v1 rule file.
        out_dir:     Directory to write the output skill directory into.
        strict:      When True, refuse to process rules not present in the
                     audit output with status: passed.
        audit_path:  Path to the P0.5 audit-output YAML file. Required when
                     strict=True. The file must contain an ``audited_rules``
                     sequence whose entries each carry:
                       - path: <absolute posix path>
                       - status: passed | failed | skipped
                       - reviewed_by: <str>
                       - reviewed_on: <YYYY-MM-DD>

    Raises:
        ValueError: In strict mode when audit_path is missing, or when the
                    rule is absent from the audit or does not have
                    status=passed.
    """
    if strict:
        if audit_path is None:
            raise ValueError("strict mode requires audit_path")
        audit = yaml.safe_load(audit_path.read_text()) or {}
        audited = {entry["path"]: entry for entry in audit.get("audited_rules", [])}
        entry = audited.get(rule_path.as_posix())
        if entry is None or entry.get("status") != "passed":
            raise ValueError(
                f"rule {rule_path.as_posix()} not in audit (or status != passed)"
                " — refusing under --strict"
            )

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

> **Source:** Converted from `{rule_path.as_posix()}` on {date.today().isoformat()}.
> **TODO before v2.0.0:** Hand-edit `description`, `when_to_use`, `sigma`, and the body content per the skill-authoring checklist.

{rule_text}
"""

    skill_md_path = skill_dir / "SKILL.md"
    skill_md_path.write_text(skill_md)
    return skill_md_path
