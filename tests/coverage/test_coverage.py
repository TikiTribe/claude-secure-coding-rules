"""
Coverage analysis tests for security rules.

These tests track coverage of security standards, generate
coverage reports, and identify gaps.
"""

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest


class TestCWECoverage:
    """Tests for CWE coverage tracking."""

    # CWE categories with common entries
    CWE_CATEGORIES = {
        "Injection": [
            "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90",
            "CWE-91", "CWE-94", "CWE-917"
        ],
        "Authentication": [
            "CWE-287", "CWE-306", "CWE-307", "CWE-384", "CWE-521",
            "CWE-522", "CWE-523", "CWE-613", "CWE-620"
        ],
        "Authorization": [
            "CWE-269", "CWE-285", "CWE-639", "CWE-732", "CWE-863"
        ],
        "Cryptography": [
            "CWE-261", "CWE-310", "CWE-311", "CWE-319", "CWE-320",
            "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330"
        ],
        "Data Exposure": [
            "CWE-200", "CWE-201", "CWE-209", "CWE-212", "CWE-215",
            "CWE-312", "CWE-319", "CWE-359", "CWE-532", "CWE-538"
        ],
        "Input Validation": [
            "CWE-20", "CWE-79", "CWE-89", "CWE-120", "CWE-129",
            "CWE-134", "CWE-190", "CWE-434", "CWE-611", "CWE-918"
        ],
        "Resource Management": [
            "CWE-400", "CWE-401", "CWE-404", "CWE-416", "CWE-476",
            "CWE-772", "CWE-770", "CWE-789"
        ],
        "Secrets Management": [
            "CWE-259", "CWE-321", "CWE-798", "CWE-260"
        ]
    }

    def test_cwe_coverage_by_category(
        self, cwe_references: dict[str, list[str]]
    ) -> None:
        """Report CWE coverage by category."""
        coverage_report: dict[str, dict[str, Any]] = {}

        for category, cwes in self.CWE_CATEGORIES.items():
            covered = [cwe for cwe in cwes if cwe in cwe_references]
            coverage_report[category] = {
                "total": len(cwes),
                "covered": len(covered),
                "percentage": round(len(covered) / len(cwes) * 100, 1),
                "covered_cwes": covered,
                "missing_cwes": [c for c in cwes if c not in covered]
            }

        # Print coverage report
        print("\n\nCWE Coverage Report:")
        print("=" * 50)

        total_cwes = 0
        total_covered = 0

        for category, data in coverage_report.items():
            print(f"\n{category}:")
            print(f"  Coverage: {data['covered']}/{data['total']} ({data['percentage']}%)")

            if data["missing_cwes"]:
                print(f"  Missing: {', '.join(data['missing_cwes'][:5])}")

            total_cwes += data["total"]
            total_covered += data["covered"]

        overall = round(total_covered / total_cwes * 100, 1)
        print(f"\n{'=' * 50}")
        print(f"Overall CWE Coverage: {total_covered}/{total_cwes} ({overall}%)")

        # Fail if coverage drops below 70% threshold
        if overall < 70:
            pytest.fail(f"CWE coverage is {overall}%, below 70% threshold")

    def test_high_priority_cwes_covered(
        self, cwe_references: dict[str, list[str]]
    ) -> None:
        """Verify high-priority CWEs from MITRE Top 25 are covered."""
        # 2023 CWE Top 25 Most Dangerous Software Weaknesses
        top_25 = [
            "CWE-787",  # Out-of-bounds Write
            "CWE-79",   # XSS
            "CWE-89",   # SQL Injection
            "CWE-416",  # Use After Free
            "CWE-78",   # OS Command Injection
            "CWE-20",   # Improper Input Validation
            "CWE-125",  # Out-of-bounds Read
            "CWE-22",   # Path Traversal
            "CWE-352",  # CSRF
            "CWE-434",  # Unrestricted Upload
            "CWE-862",  # Missing Authorization
            "CWE-476",  # NULL Pointer Dereference
            "CWE-287",  # Improper Authentication
            "CWE-190",  # Integer Overflow
            "CWE-502",  # Deserialization
        ]

        covered = [cwe for cwe in top_25 if cwe in cwe_references]
        missing = [cwe for cwe in top_25 if cwe not in cwe_references]

        coverage_pct = round(len(covered) / len(top_25) * 100, 1)

        print(f"\n\nCWE Top 25 Coverage: {len(covered)}/15 ({coverage_pct}%)")
        if missing:
            print(f"Missing: {', '.join(missing)}")

        # Require at least 90% coverage of top 25 CWEs
        threshold = round(len(top_25) * 0.9)
        if len(covered) < threshold:
            pytest.fail(
                f"Insufficient CWE Top 25 coverage: "
                f"{len(covered)}/{len(top_25)} ({coverage_pct}%). "
                f"Minimum required: {threshold}/{len(top_25)} (90%). "
                f"Missing: {', '.join(missing)}"
            )


class TestOWASPCoverage:
    """Tests for OWASP coverage tracking."""

    OWASP_2021 = {
        "A01:2021": "Broken Access Control",
        "A02:2021": "Cryptographic Failures",
        "A03:2021": "Injection",
        "A04:2021": "Insecure Design",
        "A05:2021": "Security Misconfiguration",
        "A06:2021": "Vulnerable and Outdated Components",
        "A07:2021": "Identification and Authentication Failures",
        "A08:2021": "Software and Data Integrity Failures",
        "A09:2021": "Security Logging and Monitoring Failures",
        "A10:2021": "Server-Side Request Forgery"
    }

    # OWASP LLM Top 10 — 2025 edition (v2.0, April 2025).
    # Source: https://genai.owasp.org/llm-top-10/
    # 2023 v1.1 numbering has been retired across the CSCR corpus; do not add
    # 2023 names back to this map without adding a year-aware match (the
    # substring test below uses `LLM0N` as a bare prefix, which matches both
    # `LLM01` and `LLM01:2025`, so the version qualifier is enforced in the
    # rule content itself, not here).
    OWASP_LLM = {
        "LLM01": "Prompt Injection",
        "LLM02": "Sensitive Information Disclosure",
        "LLM03": "Supply Chain",
        "LLM04": "Data and Model Poisoning",
        "LLM05": "Improper Output Handling",
        "LLM06": "Excessive Agency",
        "LLM07": "System Prompt Leakage",
        "LLM08": "Vector and Embedding Weaknesses",
        "LLM09": "Misinformation",
        "LLM10": "Unbounded Consumption"
    }

    def test_owasp_2021_coverage(
        self, owasp_references: dict[str, list[str]],
        combined_rule_text: str
    ) -> None:
        """Report OWASP Top 10 2021 coverage."""
        covered = set()

        # Check references
        for item in self.OWASP_2021.keys():
            code = item.split(":")[0]  # Get A01, A02, etc.
            if any(code in ref for ref in owasp_references.keys()):
                covered.add(item)

        # Also check rule content for OWASP mentions
        for item, name in self.OWASP_2021.items():
            if item.lower() in combined_rule_text or name.lower() in combined_rule_text:
                covered.add(item)

        missing = set(self.OWASP_2021.keys()) - covered
        coverage_pct = round(len(covered) / 10 * 100, 1)

        print(f"\n\nOWASP Top 10 2021 Coverage: {len(covered)}/10 ({coverage_pct}%)")

        if covered:
            print("Covered:")
            for item in sorted(covered):
                print(f"  - {item}: {self.OWASP_2021[item]}")

        if missing:
            print("Missing:")
            for item in sorted(missing):
                print(f"  - {item}: {self.OWASP_2021[item]}")

        # Require full OWASP Top 10 coverage
        if missing:
            pytest.fail(
                f"Incomplete OWASP Top 10 coverage. "
                f"Missing: {', '.join(sorted(missing))}"
            )

    def test_owasp_llm_coverage(
        self, combined_rule_text: str
    ) -> None:
        """Report OWASP LLM Top 10 coverage."""
        covered = set()

        for item, name in self.OWASP_LLM.items():
            if item.lower() in combined_rule_text or name.lower() in combined_rule_text:
                covered.add(item)

        missing = set(self.OWASP_LLM.keys()) - covered
        coverage_pct = round(len(covered) / 10 * 100, 1)

        print(f"\n\nOWASP LLM Top 10 Coverage: {len(covered)}/10 ({coverage_pct}%)")

        if missing:
            print(f"Missing: {', '.join(sorted(missing))}")

        # Require 90% OWASP LLM Top 10 coverage
        if len(covered) < 9:
            pytest.fail(
                f"Insufficient OWASP LLM Top 10 coverage: {len(covered)}/10 ({coverage_pct}%). "
                f"Minimum required: 9/10 (90%). Missing: {', '.join(sorted(missing))}"
            )


class TestStandardsCoverage:
    """Tests for coverage of various security standards."""

    def test_standards_mentioned(
        self, all_rules: list[dict[str, Any]], combined_rule_text: str
    ) -> None:
        """Track which security standards are referenced."""
        standards = {
            "OWASP": 0,
            "NIST": 0,
            "CWE": 0,
            "MITRE": 0,
            "ISO": 0,
            "SANS": 0,
            "PCI-DSS": 0,
            "GDPR": 0,
            "HIPAA": 0,
            "SOC2": 0
        }

        for rule in all_rules:
            refs = rule["sections"].get("Refs", "")
            text = rule["raw_text"]
            combined = (refs + " " + text).lower()

            for standard in standards:
                if standard.lower() in combined:
                    standards[standard] += 1

        print("\n\nStandards Coverage:")
        print("=" * 30)

        for standard, count in sorted(
            standards.items(), key=lambda x: x[1], reverse=True
        ):
            if count > 0:
                print(f"  {standard}: {count} rules")

        # Verify core standards are referenced
        core_standards = ["OWASP", "CWE", "NIST"]
        missing = [s for s in core_standards if standards.get(s, 0) == 0]

        if missing:
            pytest.fail(
                f"Core standards not referenced: {', '.join(missing)}"
            )

    def test_nist_framework_coverage(
        self, combined_rule_text: str
    ) -> None:
        """Check coverage of NIST frameworks."""
        nist_items = {
            "NIST SP 800-53": 0,
            "NIST SP 800-63": 0,
            "NIST SP 800-190": 0,
            "NIST AI RMF": 0,
            "NIST SSDF": 0,
            "NIST CSF": 0
        }

        for item in nist_items:
            if item in combined_rule_text:
                nist_items[item] = 1

        referenced = {k: v for k, v in nist_items.items() if v > 0}

        if referenced:
            print("\n\nNIST Framework References:")
            for item, count in referenced.items():
                print(f"  {item}: {count} rules")


class TestCoverageGaps:
    """Tests to identify gaps in security rule coverage."""

    def test_identify_language_coverage_gaps(
        self, rules_by_file: dict[Path, list[dict[str, Any]]]
    ) -> None:
        """Identify languages with insufficient rule coverage."""
        expected_languages = [
            "python", "javascript", "typescript", "go",
            "java", "csharp", "ruby", "rust"
        ]

        coverage: dict[str, int] = defaultdict(int)

        for filepath in rules_by_file:
            path_str = str(filepath).lower()
            for lang in expected_languages:
                if lang in path_str:
                    coverage[lang] += len(rules_by_file[filepath])

        # Report coverage
        print("\n\nLanguage Coverage:")
        print("=" * 30)

        for lang in expected_languages:
            count = coverage.get(lang, 0)
            status = "OK" if count >= 5 else "LOW" if count > 0 else "NONE"
            print(f"  {lang}: {count} rules [{status}]")

        # Identify gaps
        gaps = [
            lang for lang in expected_languages
            if coverage.get(lang, 0) < 5
        ]

        if gaps:
            pytest.fail(
                f"Languages with insufficient rule coverage (<5 rules): {', '.join(gaps)}"
            )

    def test_identify_attack_vector_gaps(
        self, combined_rule_text: str
    ) -> None:
        """Identify attack vectors not covered by rules."""
        attack_vectors = {
            "injection": ["sql", "command", "ldap", "xpath", "nosql"],
            "xss": ["reflected", "stored", "dom"],
            "auth": ["brute force", "credential", "session"],
            "crypto": ["weak", "hardcoded", "insecure"],
            "config": ["misconfiguration", "default", "exposed"],
            "ssrf": ["ssrf", "server-side request"],
            "deserialization": ["pickle", "yaml", "json"],
        }

        coverage: dict[str, list[str]] = {}

        for category, keywords in attack_vectors.items():
            covered = [kw for kw in keywords if kw in combined_rule_text]
            coverage[category] = covered

        print("\n\nAttack Vector Coverage:")
        print("=" * 30)

        gaps = []
        for category, keywords in attack_vectors.items():
            covered = coverage.get(category, [])
            missing = [kw for kw in keywords if kw not in covered]

            pct = round(len(covered) / len(keywords) * 100)
            print(f"\n{category} ({pct}%):")
            print(f"  Covered: {', '.join(covered) or 'none'}")

            if missing:
                print(f"  Missing: {', '.join(missing)}")
                if len(missing) > len(keywords) / 2:
                    gaps.append(category)

        if gaps:
            pytest.fail(
                f"Attack categories with major coverage gaps: {', '.join(gaps)}"
            )

    def test_identify_framework_coverage_gaps(
        self, rules_by_file: dict[Path, list[dict[str, Any]]]
    ) -> None:
        """Identify frameworks with insufficient rule coverage."""
        expected_frameworks = {
            "backend": ["fastapi", "express", "django", "flask", "nestjs"],
            "frontend": ["react", "vue", "angular", "nextjs"]
        }

        coverage: dict[str, int] = defaultdict(int)

        for filepath in rules_by_file:
            path_str = str(filepath).lower()
            for category, frameworks in expected_frameworks.items():
                for framework in frameworks:
                    if framework in path_str:
                        coverage[framework] += len(rules_by_file[filepath])

        print("\n\nFramework Coverage:")
        print("=" * 30)

        gaps = []
        for category, frameworks in expected_frameworks.items():
            print(f"\n{category.title()}:")
            for framework in frameworks:
                count = coverage.get(framework, 0)
                status = "OK" if count >= 3 else "LOW" if count > 0 else "NONE"
                print(f"  {framework}: {count} rules [{status}]")

                if count == 0:
                    gaps.append(framework)

        if gaps:
            pytest.fail(
                f"Frameworks with no coverage: {', '.join(gaps)}"
            )


class TestCoverageReport:
    """Generate comprehensive coverage reports."""

    def test_generate_coverage_summary(
        self,
        all_rules: list[dict[str, Any]],
        cwe_references: dict[str, list[str]],
        owasp_references: dict[str, list[str]]
    ) -> None:
        """Generate overall coverage summary."""
        summary = {
            "total_rules": len(all_rules),
            "unique_cwes": len(cwe_references),
            "owasp_items": len(owasp_references),
            "rules_with_code": sum(
                1 for r in all_rules if r["code_blocks"]
            ),
            "strict_rules": sum(
                1 for r in all_rules
                if "strict" in r["sections"].get("Level", "").lower()
            )
        }

        print("\n\nCoverage Summary")
        print("=" * 50)
        print(f"Total Rules: {summary['total_rules']}")
        print(f"Rules with Code Examples: {summary['rules_with_code']}")
        print(f"Strict Enforcement Rules: {summary['strict_rules']}")
        print(f"Unique CWEs Referenced: {summary['unique_cwes']}")
        print(f"OWASP Items Referenced: {summary['owasp_items']}")

        # Calculate completeness score
        completeness = (
            (summary['rules_with_code'] / max(summary['total_rules'], 1)) * 40 +
            (min(summary['unique_cwes'], 50) / 50) * 30 +
            (min(summary['owasp_items'], 10) / 10) * 30
        )

        print(f"\nCompleteness Score: {completeness:.1f}/100")

        if completeness < 90:
            pytest.fail(
                f"Completeness score {completeness:.1f}/100 is below 90% threshold. "
                f"Ensure all rules have code examples and sufficient CWE/OWASP references."
            )
