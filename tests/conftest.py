"""
Pytest configuration and shared fixtures for security rules testing.

This module provides fixtures for loading, parsing, and validating
security rules from markdown files.
"""

import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml


# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent
RULES_DIR = PROJECT_ROOT / "rules"


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "structural: structural validation tests")
    config.addinivalue_line("markers", "code_validation: code example validation tests")
    config.addinivalue_line("markers", "security: security analysis tests")
    config.addinivalue_line("markers", "coverage: coverage analysis tests")
    config.addinivalue_line("markers", "slow: tests that take longer to run")


def pytest_collection_modifyitems(config: pytest.Config, items: list) -> None:
    """Add markers based on test location."""
    for item in items:
        if "structural" in str(item.fspath):
            item.add_marker(pytest.mark.structural)
        elif "code_validation" in str(item.fspath):
            item.add_marker(pytest.mark.code_validation)
        elif "security" in str(item.fspath):
            item.add_marker(pytest.mark.security)
        elif "coverage" in str(item.fspath):
            item.add_marker(pytest.mark.coverage)


class RuleParser:
    """Parser for security rules in markdown format."""

    # Required sections for a valid rule
    REQUIRED_SECTIONS = ["Level", "When", "Do", "Don't", "Why", "Refs"]

    # Valid enforcement levels
    VALID_LEVELS = ["strict", "warning", "advisory"]

    # Pattern for extracting sections
    SECTION_PATTERN = re.compile(
        r"\*\*(\w+(?:'t)?)\*\*:\s*(.+?)(?=\*\*\w+(?:'t)?\*\*:|##|\Z)",
        re.DOTALL
    )

    # Pattern for extracting code blocks
    CODE_BLOCK_PATTERN = re.compile(
        r"```(\w+)?\n(.*?)```",
        re.DOTALL
    )

    # Pattern for rule headers
    RULE_HEADER_PATTERN = re.compile(r"^###\s+Rule:\s+(.+)$", re.MULTILINE)

    def __init__(self, content: str, filepath: Path) -> None:
        """Initialize parser with markdown content."""
        self.content = content
        self.filepath = filepath
        self.rules: list[dict[str, Any]] = []
        self._parse()

    def _parse(self) -> None:
        """Parse all rules from the markdown content."""
        # Split content by rule headers
        rule_splits = re.split(r"(?=^### Rule:)", self.content, flags=re.MULTILINE)

        for rule_text in rule_splits:
            if not rule_text.strip() or "### Rule:" not in rule_text:
                continue

            rule = self._parse_rule(rule_text)
            if rule:
                self.rules.append(rule)

    def _parse_rule(self, rule_text: str) -> dict[str, Any] | None:
        """Parse a single rule from text."""
        # Extract rule name
        name_match = self.RULE_HEADER_PATTERN.search(rule_text)
        if not name_match:
            return None

        rule: dict[str, Any] = {
            "name": name_match.group(1).strip(),
            "filepath": self.filepath,
            "sections": {},
            "code_blocks": [],
            "raw_text": rule_text
        }

        # Extract sections
        for match in self.SECTION_PATTERN.finditer(rule_text):
            section_name = match.group(1)
            section_content = match.group(2).strip()
            rule["sections"][section_name] = section_content

        # Extract code blocks with their languages
        for match in self.CODE_BLOCK_PATTERN.finditer(rule_text):
            language = match.group(1) or "text"
            code = match.group(2)

            # Determine if this is a "do" or "don't" example
            block_start = match.start()
            preceding_text = rule_text[:block_start].lower()

            example_type = "unknown"
            if "don't" in preceding_text[-100:] or "dont" in preceding_text[-100:]:
                example_type = "dont"
            elif "do" in preceding_text[-50:]:
                example_type = "do"

            rule["code_blocks"].append({
                "language": language.lower(),
                "code": code,
                "type": example_type
            })

        return rule

    def get_rules(self) -> list[dict[str, Any]]:
        """Return all parsed rules."""
        return self.rules


def find_rule_files() -> list[Path]:
    """Find all markdown files containing security rules."""
    rule_files = []

    if not RULES_DIR.exists():
        return rule_files

    # Find all .md files in rules directory
    for md_file in RULES_DIR.rglob("*.md"):
        # Skip README files
        if md_file.name.lower() == "readme.md":
            continue
        rule_files.append(md_file)

    # Also check for CLAUDE.md files which contain rules
    for claude_file in RULES_DIR.rglob("CLAUDE.md"):
        if claude_file not in rule_files:
            rule_files.append(claude_file)

    return rule_files


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return the project root directory."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    """Return the rules directory."""
    return RULES_DIR


@pytest.fixture(scope="session")
def rule_files() -> list[Path]:
    """Return all rule files in the project."""
    return find_rule_files()


@pytest.fixture(scope="session")
def all_rules(rule_files: list[Path]) -> list[dict[str, Any]]:
    """Parse and return all rules from all files."""
    all_parsed_rules = []

    for filepath in rule_files:
        try:
            content = filepath.read_text(encoding="utf-8")
            parser = RuleParser(content, filepath)
            all_parsed_rules.extend(parser.get_rules())
        except Exception as e:
            # Log error but continue with other files
            print(f"Warning: Failed to parse {filepath}: {e}")

    return all_parsed_rules


@pytest.fixture(scope="session")
def rules_by_file(rule_files: list[Path]) -> dict[Path, list[dict[str, Any]]]:
    """Return rules organized by file."""
    rules_dict: dict[Path, list[dict[str, Any]]] = {}

    for filepath in rule_files:
        try:
            content = filepath.read_text(encoding="utf-8")
            parser = RuleParser(content, filepath)
            rules_dict[filepath] = parser.get_rules()
        except Exception as e:
            print(f"Warning: Failed to parse {filepath}: {e}")
            rules_dict[filepath] = []

    return rules_dict


@pytest.fixture(scope="session")
def code_blocks_by_language(all_rules: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Return code blocks organized by programming language."""
    blocks: dict[str, list[dict[str, Any]]] = {}

    for rule in all_rules:
        for block in rule["code_blocks"]:
            language = block["language"]
            if language not in blocks:
                blocks[language] = []
            blocks[language].append({
                "code": block["code"],
                "type": block["type"],
                "rule_name": rule["name"],
                "filepath": rule["filepath"]
            })

    return blocks


@pytest.fixture
def rule_parser_class() -> type[RuleParser]:
    """Return the RuleParser class for custom parsing needs."""
    return RuleParser


@pytest.fixture(scope="session")
def cwe_references(all_rules: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Extract all CWE references from rules."""
    cwe_pattern = re.compile(r"CWE-(\d+)")
    cwe_refs: dict[str, list[str]] = {}

    for rule in all_rules:
        refs_section = rule["sections"].get("Refs", "")
        cwes = cwe_pattern.findall(refs_section)

        for cwe in cwes:
            cwe_id = f"CWE-{cwe}"
            if cwe_id not in cwe_refs:
                cwe_refs[cwe_id] = []
            cwe_refs[cwe_id].append(rule["name"])

    return cwe_refs


@pytest.fixture(scope="session")
def owasp_references(all_rules: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Extract all OWASP references from rules."""
    owasp_pattern = re.compile(r"A\d{2}:\d{4}")
    owasp_refs: dict[str, list[str]] = {}

    for rule in all_rules:
        refs_section = rule["sections"].get("Refs", "")
        items = owasp_pattern.findall(refs_section)

        for item in items:
            if item not in owasp_refs:
                owasp_refs[item] = []
            owasp_refs[item].append(rule["name"])

    return owasp_refs
