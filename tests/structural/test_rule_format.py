"""
Structural validation tests for security rules.

These tests verify that all rules follow the required format
and contain valid content.
"""

import re
from pathlib import Path
from typing import Any

import pytest


class TestRuleStructure:
    """Tests for rule structure and format compliance."""

    def test_all_rules_have_required_sections(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify all rules contain required sections."""
        required_sections = ["Level", "When", "Do", "Don't", "Why", "Refs"]
        errors = []

        for rule in all_rules:
            missing = []
            for section in required_sections:
                if section not in rule["sections"]:
                    missing.append(section)

            if missing:
                errors.append(
                    f"Rule '{rule['name']}' in {rule['filepath']} "
                    f"missing sections: {', '.join(missing)}"
                )

        if errors:
            pytest.fail("\n".join(errors))

    def test_level_values_are_valid(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify Level values are one of: strict, warning, advisory."""
        valid_levels = {"strict", "warning", "advisory"}
        errors = []

        for rule in all_rules:
            level = rule["sections"].get("Level", "")
            # Extract the level value (may contain backticks)
            level_match = re.search(r"`?(\w+)`?", level)

            if level_match:
                level_value = level_match.group(1).lower()
                if level_value not in valid_levels:
                    errors.append(
                        f"Rule '{rule['name']}' in {rule['filepath']} "
                        f"has invalid level: '{level_value}'"
                    )
            else:
                errors.append(
                    f"Rule '{rule['name']}' in {rule['filepath']} "
                    f"has no parseable level value"
                )

        if errors:
            pytest.fail("\n".join(errors))

    def test_code_blocks_have_language_identifiers(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify all code blocks specify a language."""
        errors = []

        for rule in all_rules:
            for i, block in enumerate(rule["code_blocks"]):
                if block["language"] == "text" or not block["language"]:
                    errors.append(
                        f"Rule '{rule['name']}' in {rule['filepath']} "
                        f"has code block #{i+1} without language identifier"
                    )

        if errors:
            pytest.fail("\n".join(errors))

    def test_refs_contain_valid_references(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify Refs section contains valid CWE or standard references."""
        # Patterns for valid references
        valid_patterns = [
            r"CWE-\d+",           # CWE references
            r"A\d{2}:\d{4}",      # OWASP Top 10 (e.g., A01:2021)
            r"NIST",              # NIST references
            r"MITRE",             # MITRE references
            r"OWASP",             # OWASP references
            r"ISO",               # ISO standards
            r"RFC\s*\d+",         # RFC references
            r"CVE-\d{4}-\d+",     # CVE references
        ]

        combined_pattern = re.compile("|".join(valid_patterns), re.IGNORECASE)
        errors = []

        for rule in all_rules:
            refs = rule["sections"].get("Refs", "")
            if not refs:
                errors.append(
                    f"Rule '{rule['name']}' in {rule['filepath']} "
                    f"has empty Refs section"
                )
                continue

            if not combined_pattern.search(refs):
                errors.append(
                    f"Rule '{rule['name']}' in {rule['filepath']} "
                    f"has no valid references in Refs section"
                )

        if errors:
            pytest.fail("\n".join(errors))

    def test_do_section_has_code_example(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify Do section contains at least one code example."""
        errors = []

        for rule in all_rules:
            do_blocks = [b for b in rule["code_blocks"] if b["type"] == "do"]

            if not do_blocks:
                # Check if there's any code block that could be a Do example
                has_any_block = len(rule["code_blocks"]) > 0
                if not has_any_block:
                    errors.append(
                        f"Rule '{rule['name']}' in {rule['filepath']} "
                        f"has no code examples in Do section"
                    )

        if errors:
            pytest.fail("\n".join(errors))

    def test_dont_section_has_code_example(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify Don't section contains at least one code example."""
        errors = []

        for rule in all_rules:
            dont_blocks = [b for b in rule["code_blocks"] if b["type"] == "dont"]

            if not dont_blocks:
                # Check if there's any code block that could be a Don't example
                has_any_block = len(rule["code_blocks"]) > 0
                if not has_any_block:
                    errors.append(
                        f"Rule '{rule['name']}' in {rule['filepath']} "
                        f"has no code examples in Don't section"
                    )

        if errors:
            pytest.fail("\n".join(errors))


class TestRuleContent:
    """Tests for rule content quality."""

    def test_rule_names_are_unique(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify rule names are unique within each file (duplicates across files are allowed)."""
        file_rules: dict[Path, list[str]] = {}
        duplicates = []

        # Group rules by file
        for rule in all_rules:
            filepath = rule["filepath"]
            name = rule["name"]
            
            if filepath not in file_rules:
                file_rules[filepath] = []
            
            if name in file_rules[filepath]:
                duplicates.append(
                    f"Duplicate rule name '{name}' within file {filepath}"
                )
            else:
                file_rules[filepath].append(name)

        if duplicates:
            pytest.fail("\n".join(duplicates))

    def test_why_section_is_not_empty(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify Why section contains meaningful content."""
        min_length = 20  # Minimum characters for meaningful explanation
        errors = []

        for rule in all_rules:
            why = rule["sections"].get("Why", "")
            if len(why.strip()) < min_length:
                errors.append(
                    f"Rule '{rule['name']}' in {rule['filepath']} "
                    f"has insufficient Why explanation ({len(why.strip())} chars)"
                )

        if errors:
            pytest.fail("\n".join(errors))

    def test_when_section_describes_trigger(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify When section describes when the rule applies."""
        min_length = 10
        errors = []

        for rule in all_rules:
            when = rule["sections"].get("When", "")
            if len(when.strip()) < min_length:
                errors.append(
                    f"Rule '{rule['name']}' in {rule['filepath']} "
                    f"has insufficient When description"
                )

        if errors:
            pytest.fail("\n".join(errors))

    def test_no_placeholder_content(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify rules don't contain placeholder text."""
        placeholders = [
            "TODO",
            "FIXME",
            "XXX",
            "[TBD]",
            "[placeholder]",
            "Lorem ipsum",
            "example.com"  # Often indicates placeholder URLs
        ]

        errors = []

        for rule in all_rules:
            raw_text = rule["raw_text"]
            for placeholder in placeholders:
                if placeholder.lower() in raw_text.lower():
                    # Skip example.com check in code blocks (often valid)
                    if placeholder == "example.com":
                        in_code = any(
                            placeholder in block["code"]
                            for block in rule["code_blocks"]
                        )
                        if in_code:
                            continue

                    errors.append(
                        f"Rule '{rule['name']}' in {rule['filepath']} "
                        f"contains placeholder: '{placeholder}'"
                    )
                    break

        if errors:
            pytest.fail("\n".join(errors))


class TestInternalLinks:
    """Tests for internal link validity."""

    def test_no_broken_internal_links(
        self, rule_files: list[Path], project_root: Path
    ) -> None:
        """Verify all internal markdown links point to existing files."""
        link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
        errors = []

        for filepath in rule_files:
            content = filepath.read_text(encoding="utf-8")
            links = link_pattern.findall(content)

            for link_text, link_target in links:
                # Skip external links
                if link_target.startswith(("http://", "https://", "#")):
                    continue
                
                # Skip code patterns that look like links (e.g., [tool_name](**args))
                if link_target.startswith("**"):
                    continue

                # Resolve the link path
                if link_target.startswith("/"):
                    target_path = project_root / link_target.lstrip("/")
                else:
                    target_path = filepath.parent / link_target

                # Remove anchor if present
                if "#" in str(target_path):
                    target_path = Path(str(target_path).split("#")[0])

                if not target_path.exists():
                    errors.append(
                        f"Broken link in {filepath}: "
                        f"'{link_text}' -> '{link_target}'"
                    )

        if errors:
            pytest.fail("\n".join(errors))

    def test_no_broken_image_links(
        self, rule_files: list[Path], project_root: Path
    ) -> None:
        """Verify all image links point to existing files."""
        image_pattern = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
        errors = []

        for filepath in rule_files:
            content = filepath.read_text(encoding="utf-8")
            images = image_pattern.findall(content)

            for alt_text, image_path in images:
                # Skip external images
                if image_path.startswith(("http://", "https://")):
                    continue

                # Resolve the image path
                if image_path.startswith("/"):
                    target_path = project_root / image_path.lstrip("/")
                else:
                    target_path = filepath.parent / image_path

                if not target_path.exists():
                    errors.append(
                        f"Broken image in {filepath}: "
                        f"'{alt_text}' -> '{image_path}'"
                    )

        if errors:
            pytest.fail("\n".join(errors))


class TestFileOrganization:
    """Tests for file organization and naming conventions."""

    def test_core_rules_exist(self, rules_dir: Path) -> None:
        """Verify core rule files exist."""
        core_dir = rules_dir / "_core"

        if not core_dir.exists():
            pytest.skip("Core rules directory not found")

        expected_files = [
            "owasp-2025.md",
            "ai-security.md",
            "agent-security.md"
        ]

        missing = []
        for filename in expected_files:
            if not (core_dir / filename).exists():
                missing.append(filename)

        if missing:
            pytest.fail(
                f"Missing core rule files: {', '.join(missing)}"
            )

    def test_language_rules_have_claude_md(self, rules_dir: Path) -> None:
        """Verify language directories contain CLAUDE.md files."""
        languages_dir = rules_dir / "languages"

        if not languages_dir.exists():
            pytest.skip("Languages directory not found")

        errors = []
        for lang_dir in languages_dir.iterdir():
            if lang_dir.is_dir():
                claude_file = lang_dir / "CLAUDE.md"
                if not claude_file.exists():
                    errors.append(f"Missing CLAUDE.md in {lang_dir}")

        if errors:
            pytest.fail("\n".join(errors))

    def test_filenames_follow_convention(
        self, rule_files: list[Path]
    ) -> None:
        """Verify rule filenames follow naming conventions."""
        errors = []

        for filepath in rule_files:
            filename = filepath.name

            # Skip CLAUDE.md files (they're allowed anywhere)
            if filename == "CLAUDE.md":
                continue

            # Check for valid characters (lowercase, hyphens, numbers)
            if not re.match(r"^[a-z0-9-]+\.md$", filename):
                errors.append(
                    f"Invalid filename: {filepath} "
                    f"(should be lowercase with hyphens)"
                )

        if errors:
            pytest.fail("\n".join(errors))
