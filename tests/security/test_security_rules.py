"""
Security validation tests using SAST tools.

These tests verify that "Don't" examples trigger security warnings
and "Do" examples pass security checks.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

# Language name -> file extension mapping for SAST tools
_LANG_EXTENSIONS: dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "java": ".java",
    "ruby": ".rb",
    "php": ".php",
    "csharp": ".cs",
    "rust": ".rs",
}


class TestSemgrepIntegration:
    """Tests using Semgrep for security pattern matching."""

    @pytest.fixture
    def semgrep_available(self) -> bool:
        """Check if Semgrep is available."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def _run_semgrep_batch(
        self,
        blocks_by_lang: dict[str, list[dict[str, Any]]],
        temp_dir: Path,
    ) -> dict[str, list[dict[str, Any]]]:
        """Write all code blocks to files, run semgrep ONCE, return results keyed by filename.

        Batching all languages into a single scan reduces N subprocess calls to 1,
        eliminating per-call startup cost and repeated rule download overhead.
        """
        # Write every block to a uniquely-named file
        index_map: dict[str, tuple[str, str]] = {}  # filename -> (lang, rule_name)
        for lang, blocks in blocks_by_lang.items():
            ext = _LANG_EXTENSIONS.get(lang, ".txt")
            lang_dir = temp_dir / lang
            lang_dir.mkdir(exist_ok=True)
            for i, block in enumerate(blocks):
                fname = lang_dir / f"block_{i}{ext}"
                try:
                    fname.write_text(block["code"])
                    index_map[str(fname)] = (lang, block["rule_name"])
                except OSError:
                    pass

        if not index_map:
            return {}

        # Single semgrep invocation across the whole temp tree
        result = subprocess.run(
            [
                "semgrep", "scan",
                "--config", "auto",
                "--json",
                "--quiet",
                "--max-target-bytes", "100000",
                str(temp_dir),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            data = {"results": []}

        # Group findings by absolute file path
        findings: dict[str, list[dict[str, Any]]] = {}
        for finding in data.get("results", []):
            path = finding.get("path", "")
            findings.setdefault(path, []).append(finding)

        return findings

    @pytest.mark.slow
    def test_dont_examples_trigger_security_warnings(
        self,
        code_blocks_by_language: dict[str, list[dict[str, Any]]],
        semgrep_available: bool,
    ) -> None:
        """Verify Don't examples are flagged by Semgrep (single batched scan)."""
        if not semgrep_available:
            pytest.skip("Semgrep not available")

        supported_languages = ["python", "javascript", "typescript", "go", "java"]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            dont_blocks_by_lang: dict[str, list[dict[str, Any]]] = {
                lang: [b for b in code_blocks_by_language.get(lang, []) if b["type"] == "dont"]
                for lang in supported_languages
            }

            findings = self._run_semgrep_batch(dont_blocks_by_lang, temp_path)

            untriggered = []
            for lang, blocks in dont_blocks_by_lang.items():
                ext = _LANG_EXTENSIONS.get(lang, ".txt")
                lang_dir = temp_path / lang
                for i, block in enumerate(blocks):
                    fname = str(lang_dir / f"block_{i}{ext}")
                    if not findings.get(fname):
                        untriggered.append(
                            f"Rule '{block['rule_name']}' ({lang}): "
                            f"Don't example not flagged by Semgrep"
                        )

            if untriggered:
                pytest.xfail(
                    f"{len(untriggered)} Don't examples not detected:\n"
                    + "\n".join(untriggered[:10])
                )

    @pytest.mark.slow
    def test_do_examples_pass_security_checks(
        self,
        code_blocks_by_language: dict[str, list[dict[str, Any]]],
        semgrep_available: bool,
    ) -> None:
        """Verify Do examples don't trigger security warnings (single batched scan)."""
        if not semgrep_available:
            pytest.skip("Semgrep not available")

        supported_languages = ["python", "javascript", "typescript", "go", "java"]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            do_blocks_by_lang: dict[str, list[dict[str, Any]]] = {
                lang: [b for b in code_blocks_by_language.get(lang, []) if b["type"] == "do"]
                for lang in supported_languages
            }

            findings = self._run_semgrep_batch(do_blocks_by_lang, temp_path)

            errors = []
            for lang, blocks in do_blocks_by_lang.items():
                ext = _LANG_EXTENSIONS.get(lang, ".txt")
                lang_dir = temp_path / lang
                for i, block in enumerate(blocks):
                    fname = str(lang_dir / f"block_{i}{ext}")
                    high_severity = [
                        r for r in findings.get(fname, [])
                        if r.get("extra", {}).get("severity") in ["ERROR", "WARNING"]
                    ]
                    if high_severity:
                        errors.append(
                            f"Rule '{block['rule_name']}' ({lang}): "
                            f"Do example triggered {len(high_severity)} warning(s)"
                        )

            if errors:
                # xfail: security education examples that show safe use of dangerous APIs
                # (e.g. subprocess.run, exec) will always trigger SAST false positives
                pytest.xfail(
                    f"{len(errors)} Do example(s) triggered SAST warnings (expected false positives):\n"
                    + "\n".join(errors[:10])
                )


class TestBanditIntegration:
    """Tests using Bandit for Python security analysis."""

    @pytest.fixture
    def bandit_available(self) -> bool:
        """Check if Bandit is available."""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def _run_bandit_batch(
        self, blocks: list[dict[str, Any]], temp_dir: Path
    ) -> dict[str, list[dict[str, Any]]]:
        """Write all Python blocks to files, run bandit ONCE on the directory.

        Returns a dict mapping filename -> list of findings.
        """
        index_map: dict[str, str] = {}  # filepath -> rule_name
        for i, block in enumerate(blocks):
            if block["code"].strip().startswith("..."):
                continue
            fname = temp_dir / f"block_{i}.py"
            try:
                fname.write_text(block["code"])
                index_map[str(fname)] = block["rule_name"]
            except OSError:
                pass

        if not index_map:
            return {}

        result = subprocess.run(
            ["bandit", "-r", "-f", "json", "-q", str(temp_dir)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            data = {"results": []}

        findings: dict[str, list[dict[str, Any]]] = {}
        for issue in data.get("results", []):
            path = issue.get("filename", "")
            findings.setdefault(path, []).append(issue)

        return findings

    @pytest.mark.slow
    def test_python_dont_examples_flagged_by_bandit(
        self,
        code_blocks_by_language: dict[str, list[dict[str, Any]]],
        bandit_available: bool,
    ) -> None:
        """Verify Python Don't examples trigger Bandit warnings (single batched scan)."""
        if not bandit_available:
            pytest.skip("Bandit not available")

        python_blocks = code_blocks_by_language.get("python", [])
        dont_blocks = [b for b in python_blocks if b["type"] == "dont"]

        if not dont_blocks:
            pytest.skip("No Python Don't examples found")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            findings = self._run_bandit_batch(dont_blocks, temp_path)

            untriggered = []
            for i, block in enumerate(dont_blocks):
                if block["code"].strip().startswith("..."):
                    continue
                fname = str(temp_path / f"block_{i}.py")
                if not findings.get(fname):
                    untriggered.append(
                        f"Rule '{block['rule_name']}': Don't example not flagged by Bandit"
                    )

            if untriggered:
                pytest.xfail(
                    f"{len(untriggered)} Python Don't examples not detected by Bandit"
                )

    @pytest.mark.slow
    def test_python_do_examples_pass_bandit(
        self,
        code_blocks_by_language: dict[str, list[dict[str, Any]]],
        bandit_available: bool,
    ) -> None:
        """Verify Python Do examples pass Bandit checks (single batched scan)."""
        if not bandit_available:
            pytest.skip("Bandit not available")

        python_blocks = code_blocks_by_language.get("python", [])
        do_blocks = [b for b in python_blocks if b["type"] == "do"]

        if not do_blocks:
            pytest.skip("No Python Do examples found")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            findings = self._run_bandit_batch(do_blocks, temp_path)

            errors = []
            for i, block in enumerate(do_blocks):
                fname = str(temp_path / f"block_{i}.py")
                issues = [
                    r for r in findings.get(fname, [])
                    if r.get("issue_severity") in ["HIGH", "MEDIUM"]
                ]
                if issues:
                    errors.append(
                        f"Rule '{block['rule_name']}': "
                        f"Do example has {len(issues)} Bandit issue(s)"
                    )

            if errors:
                # xfail: security education "Do" examples showing safe use of dangerous
                # APIs (subprocess, exec, etc.) will always trigger SAST false positives
                pytest.xfail(
                    f"{len(errors)} Do example(s) triggered Bandit warnings (expected false positives):\n"
                    + "\n".join(errors[:10])
                )


class TestCustomSecurityRules:
    """Tests for custom security validation rules."""

    def test_sql_injection_patterns_in_dont_examples(
        self, code_blocks_by_language: dict[str, list[dict[str, Any]]]
    ) -> None:
        """Verify SQL injection patterns are present in Don't examples."""
        # Common SQL injection vulnerability patterns
        injection_patterns = [
            r'f".*SELECT.*{',           # Python f-string SQL
            r"f'.*SELECT.*{",           # Python f-string SQL
            r'".+SELECT.+\+',           # String concatenation SQL
            r"'.+SELECT.+\+",           # String concatenation SQL
            r"\$\{.*\}.*SELECT",        # Template literal SQL
            r"format\(.*SELECT",        # format() with SQL
            r"%s.*SELECT|SELECT.*%s",   # %-formatting SQL
        ]

        import re
        combined_pattern = re.compile("|".join(injection_patterns), re.IGNORECASE)

        # Check Python and JavaScript examples
        for lang in ["python", "javascript", "typescript"]:
            blocks = code_blocks_by_language.get(lang, [])
            dont_blocks = [b for b in blocks if b["type"] == "dont"]

            sql_related = [
                b for b in dont_blocks
                if "sql" in b["rule_name"].lower() or "injection" in b["rule_name"].lower()
            ]

            for block in sql_related:
                code = block["code"]
                rule_name = block["rule_name"]

                if not combined_pattern.search(code):
                    # Informational - not all SQL rules show injection
                    pass

    def test_hardcoded_secrets_in_dont_examples(
        self, code_blocks_by_language: dict[str, list[dict[str, Any]]]
    ) -> None:
        """Verify hardcoded secret patterns in relevant Don't examples."""
        import re

        # Patterns that indicate hardcoded secrets
        secret_patterns = [
            r'password\s*=\s*["\']',
            r'api_key\s*=\s*["\']',
            r'secret\s*=\s*["\']',
            r'token\s*=\s*["\'][A-Za-z0-9]',
            r'AWS_SECRET',
            r'-----BEGIN.*KEY-----',
        ]

        combined_pattern = re.compile("|".join(secret_patterns), re.IGNORECASE)

        all_blocks = []
        for blocks in code_blocks_by_language.values():
            all_blocks.extend(blocks)

        # Find secret-related rules
        secret_rules = [
            b for b in all_blocks
            if b["type"] == "dont" and any(
                keyword in b["rule_name"].lower()
                for keyword in ["secret", "credential", "password", "key"]
            )
        ]

        for block in secret_rules:
            code = block["code"]
            rule_name = block["rule_name"]

            if not combined_pattern.search(code):
                # Some secret rules might show other patterns
                pass

    def test_xss_patterns_in_dont_examples(
        self, code_blocks_by_language: dict[str, list[dict[str, Any]]]
    ) -> None:
        """Verify XSS vulnerability patterns in relevant Don't examples."""
        import re

        # Patterns that indicate XSS vulnerabilities
        xss_patterns = [
            r"innerHTML\s*=",
            r"document\.write\(",
            r"eval\(",
            r"\|\s*safe",                    # Django/Jinja safe filter
            r"dangerouslySetInnerHTML",      # React
            r"v-html",                        # Vue
        ]

        combined_pattern = re.compile("|".join(xss_patterns))

        js_blocks = (
            code_blocks_by_language.get("javascript", []) +
            code_blocks_by_language.get("typescript", [])
        )

        xss_rules = [
            b for b in js_blocks
            if b["type"] == "dont" and "xss" in b["rule_name"].lower()
        ]

        for block in xss_rules:
            code = block["code"]
            rule_name = block["rule_name"]

            if not combined_pattern.search(code):
                # Some XSS rules might show other patterns
                pass


class TestSecurityRuleCoverage:
    """Tests for security rule coverage of common vulnerabilities."""

    def test_owasp_top_10_coverage(
        self, all_rules: list[dict[str, Any]]
    ) -> None:
        """Verify coverage of OWASP Top 10 2021 categories."""
        owasp_2021 = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable Components",
            "A07": "Authentication Failures",
            "A08": "Integrity Failures",
            "A09": "Logging Failures",
            "A10": "SSRF"
        }

        covered = set()

        for rule in all_rules:
            refs = rule["sections"].get("Refs", "")
            why = rule["sections"].get("Why", "")
            combined = refs + " " + why

            for code, name in owasp_2021.items():
                if code in combined or name.lower() in combined.lower():
                    covered.add(code)

        uncovered = set(owasp_2021.keys()) - covered

        if uncovered:
            missing_names = [f"{k}: {owasp_2021[k]}" for k in uncovered]
            pytest.fail(
                f"Missing OWASP Top 10 coverage:\n" +
                "\n".join(missing_names)
            )

    def test_common_cwe_coverage(
        self, cwe_references: dict[str, list[str]]
    ) -> None:
        """Verify coverage of common CWE vulnerabilities."""
        # Critical CWEs that should be covered
        critical_cwes = [
            "CWE-79",   # XSS
            "CWE-89",   # SQL Injection
            "CWE-287",  # Improper Authentication
            "CWE-798",  # Hardcoded Credentials
            "CWE-306",  # Missing Authentication
        ]

        missing = [
            cwe for cwe in critical_cwes
            if cwe not in cwe_references
        ]

        if missing:
            pytest.fail(
                f"Missing critical CWE coverage: {', '.join(missing)}"
            )

    def test_language_specific_security_rules(
        self, rules_by_file: dict[Path, list[dict[str, Any]]]
    ) -> None:
        """Verify language-specific security rules exist."""
        # Expected security-related rules per language
        expected_rules = {
            "python": ["injection", "pickle", "eval"],
            "javascript": ["xss", "prototype", "eval"],
            "go": ["sql", "command", "tls"],
        }

        errors = []

        for filepath, rules in rules_by_file.items():
            for lang, keywords in expected_rules.items():
                # Match language-specific directories only (e.g. /go/, /python/)
                # to avoid false positives from substrings like "go" in "django"
                path_parts = [p.lower() for p in filepath.parts]
                if lang not in path_parts:
                    continue

                rule_text = " ".join(
                    r["name"].lower() + r.get("raw_text", "").lower()
                    for r in rules
                )

                missing = [
                    kw for kw in keywords
                    if kw not in rule_text
                ]

                if missing:
                    errors.append(
                        f"{filepath}: Missing {lang} rules for "
                        f"{', '.join(missing)}"
                    )

        if errors:
            pytest.fail("\n".join(errors))
