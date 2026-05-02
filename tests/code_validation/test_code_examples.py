"""
Code example validation tests.

These tests verify that code examples in security rules are
syntactically valid and parseable.
"""

import ast
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest


class TestPythonCodeExamples:
    """Tests for Python code example validity."""

    def test_python_examples_are_syntactically_valid(
        self, code_blocks_by_language: dict[str, list[dict[str, Any]]]
    ) -> None:
        """Verify all Python code examples parse correctly."""
        python_blocks = code_blocks_by_language.get("python", [])

        if not python_blocks:
            pytest.skip("No Python code examples found")

        errors = []

        for block in python_blocks:
            code = block["code"]
            rule_name = block["rule_name"]
            filepath = block["filepath"]

            # Skip if code is clearly a snippet (e.g., starts with ...)
            if code.strip().startswith("..."):
                continue

            try:
                ast.parse(code)
            except SyntaxError as e:
                # Try to provide context about the error
                errors.append(
                    f"Python syntax error in rule '{rule_name}' "
                    f"({filepath}):\n"
                    f"  Line {e.lineno}: {e.msg}\n"
                    f"  Code preview: {code[:100]}..."
                )

        if errors:
            pytest.fail("\n\n".join(errors))

    def test_python_imports_are_valid(
        self, code_blocks_by_language: dict[str, list[dict[str, Any]]]
    ) -> None:
        """Verify Python import statements are syntactically correct."""
        python_blocks = code_blocks_by_language.get("python", [])

        if not python_blocks:
            pytest.skip("No Python code examples found")

        errors = []

        for block in python_blocks:
            code = block["code"]
            rule_name = block["rule_name"]

            # Extract import lines
            import_lines = [
                line for line in code.split("\n")
                if line.strip().startswith(("import ", "from "))
            ]

            for import_line in import_lines:
                try:
                    ast.parse(import_line.strip())
                except SyntaxError as e:
                    errors.append(
                        f"Invalid import in rule '{rule_name}': "
                        f"{import_line.strip()} - {e.msg}"
                    )

        if errors:
            pytest.fail("\n".join(errors))


class TestJavaScriptCodeExamples:
    """Tests for JavaScript/TypeScript code example validity."""

    @pytest.fixture
    def node_available(self) -> bool:
        """Check if Node.js is available for validation."""
        try:
            result = subprocess.run(
                ["node", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def test_javascript_examples_parse_correctly(
        self,
        code_blocks_by_language: dict[str, list[dict[str, Any]]],
        node_available: bool
    ) -> None:
        """Verify JavaScript code examples are parseable."""
        js_blocks = (
            code_blocks_by_language.get("javascript", []) +
            code_blocks_by_language.get("js", [])
        )

        if not js_blocks:
            pytest.skip("No JavaScript code examples found")

        if not node_available:
            pytest.skip("Node.js not available for JavaScript validation")

        # Build a single Node.js checker script that validates all blocks in
        # one process invocation.  Each block is checked with new Function()
        # (CommonJS-style) first, then via SourceTextModule for ES-module
        # syntax (import/export).  Blocks are delimited by a sentinel line
        # written to a temp data file to avoid shell-argument limitations.
        # Results are printed as JSON so we can parse them back cleanly.
        sentinel = "<<<BLOCK_SEP>>>"
        combined = sentinel.join(b["code"] for b in js_blocks)

        checker = r"""
const fs = require('fs');
const vm = require('vm');
const data = fs.readFileSync(process.argv[2], 'utf8');
const SENTINEL = '<<<BLOCK_SEP>>>';
const blocks = data.split(SENTINEL);
const results = [];
for (const code of blocks) {
    let err = null;
    // Try SourceTextModule (handles ES module import/export)
    if (vm.SourceTextModule) {
        try {
            new vm.SourceTextModule(code, { context: vm.createContext({}) });
        } catch (e) {
            // SourceTextModule rejects non-module syntax too; fall back below
            try { new Function(code); } catch (e2) { err = e2.message; }
        }
    } else {
        try { new Function(code); } catch (e) { err = e.message; }
    }
    results.push(err);
}
process.stdout.write(JSON.stringify(results) + '\n');
"""

        import json as _json

        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write(checker)
            checker_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False, encoding="utf-8") as f:
            f.write(combined)
            data_path = f.name

        errors = []
        try:
            result = subprocess.run(
                ["node", "--experimental-vm-modules", checker_path, data_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                errors.append(f"Node.js checker failed: {result.stderr.strip()[:500]}")
            else:
                json_line = next(
                    (l for l in reversed(result.stdout.splitlines()) if l.strip().startswith("[")),
                    None,
                )
                if json_line is None:
                    errors.append(f"Node.js checker produced no output. stderr: {result.stderr.strip()[:300]}")
                else:
                    block_results = _json.loads(json_line)
                    for block, err_msg in zip(js_blocks, block_results):
                        if err_msg is not None:
                            errors.append(
                                f"JavaScript syntax error in rule '{block['rule_name']}': {err_msg}"
                            )
        except subprocess.TimeoutExpired:
            errors.append("JavaScript validation timed out")
        finally:
            Path(checker_path).unlink(missing_ok=True)
            Path(data_path).unlink(missing_ok=True)

        if errors:
            pytest.fail("\n".join(errors))

    def test_typescript_examples_parse_correctly(
        self,
        code_blocks_by_language: dict[str, list[dict[str, Any]]],
        node_available: bool
    ) -> None:
        """Verify TypeScript code examples are parseable."""
        ts_blocks = (
            code_blocks_by_language.get("typescript", []) +
            code_blocks_by_language.get("ts", [])
        )

        if not ts_blocks:
            pytest.skip("No TypeScript code examples found")

        # Check if TypeScript compiler is available
        try:
            result = subprocess.run(
                ["npx", "tsc", "--version"],
                capture_output=True,
                timeout=10
            )
            tsc_available = result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            tsc_available = False

        if not tsc_available:
            pytest.skip("TypeScript compiler not available")

        errors = []

        for block in ts_blocks:
            code = block["code"]
            rule_name = block["rule_name"]

            with tempfile.NamedTemporaryFile(
                suffix=".ts", mode="w", delete=False
            ) as f:
                f.write(code)
                temp_path = f.name

            try:
                result = subprocess.run(
                    ["npx", "tsc", "--noEmit", "--allowJs", temp_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode != 0:
                    # Filter out common false positives
                    stderr = result.stderr
                    if "Cannot find module" not in stderr:
                        errors.append(
                            f"TypeScript error in rule '{rule_name}': "
                            f"{stderr.strip()}"
                        )
            except subprocess.TimeoutExpired:
                errors.append(
                    f"TypeScript validation timeout for rule '{rule_name}'"
                )
            finally:
                Path(temp_path).unlink(missing_ok=True)

        if errors:
            pytest.fail("\n".join(errors))


class TestYamlJsonExamples:
    """Tests for YAML and JSON code example validity."""

    def test_yaml_examples_are_valid(
        self, code_blocks_by_language: dict[str, list[dict[str, Any]]]
    ) -> None:
        """Verify YAML code examples parse correctly."""
        import yaml

        yaml_blocks = (
            code_blocks_by_language.get("yaml", []) +
            code_blocks_by_language.get("yml", [])
        )

        if not yaml_blocks:
            pytest.skip("No YAML code examples found")

        errors = []

        # Build a loader that tolerates unknown tags (e.g. CloudFormation
        # !Ref, !Sub, !GetAtt) while still rejecting true YAML errors.
        class _PermissiveLoader(yaml.SafeLoader):
            pass

        _PermissiveLoader.add_multi_constructor(
            "", lambda loader, tag_suffix, node: (
                loader.construct_scalar(node)
                if isinstance(node, yaml.ScalarNode)
                else loader.construct_sequence(node)
                if isinstance(node, yaml.SequenceNode)
                else loader.construct_mapping(node)
            )
        )

        for block in yaml_blocks:
            code = block["code"]
            rule_name = block["rule_name"]

            try:
                yaml.load(code, Loader=_PermissiveLoader)  # noqa: S506
            except yaml.YAMLError as e:
                errors.append(
                    f"YAML syntax error in rule '{rule_name}': {e}"
                )

        if errors:
            pytest.fail("\n".join(errors))

    def test_json_examples_are_valid(
        self, code_blocks_by_language: dict[str, list[dict[str, Any]]]
    ) -> None:
        """Verify JSON code examples parse correctly."""
        json_blocks = code_blocks_by_language.get("json", [])

        if not json_blocks:
            pytest.skip("No JSON code examples found")

        errors = []

        for block in json_blocks:
            code = block["code"]
            rule_name = block["rule_name"]

            try:
                json.loads(code)
            except json.JSONDecodeError as e:
                errors.append(
                    f"JSON syntax error in rule '{rule_name}': "
                    f"Line {e.lineno}: {e.msg}"
                )

        if errors:
            pytest.fail("\n".join(errors))


class TestHclExamples:
    """Tests for HCL (Terraform) code example validity."""

    def test_hcl_examples_parse_correctly(
        self, code_blocks_by_language: dict[str, list[dict[str, Any]]]
    ) -> None:
        """Verify HCL/Terraform code examples are valid."""
        hcl_blocks = (
            code_blocks_by_language.get("hcl", []) +
            code_blocks_by_language.get("terraform", []) +
            code_blocks_by_language.get("tf", [])
        )

        if not hcl_blocks:
            pytest.skip("No HCL/Terraform code examples found")

        try:
            import hcl2
        except ImportError:
            pytest.skip("python-hcl2 not installed")

        errors = []

        for block in hcl_blocks:
            code = block["code"]
            rule_name = block["rule_name"]

            try:
                import io
                hcl2.load(io.StringIO(code))
            except Exception as e:
                errors.append(
                    f"HCL syntax error in rule '{rule_name}': {e}"
                )

        if errors:
            pytest.fail("\n".join(errors))


class TestShellExamples:
    """Tests for shell script code example validity."""

    @pytest.fixture
    def shellcheck_available(self) -> bool:
        """Check if shellcheck is available."""
        try:
            result = subprocess.run(
                ["shellcheck", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def test_shell_examples_have_valid_syntax(
        self,
        code_blocks_by_language: dict[str, list[dict[str, Any]]],
        shellcheck_available: bool
    ) -> None:
        """Verify shell script examples have valid syntax."""
        shell_blocks = (
            code_blocks_by_language.get("bash", []) +
            code_blocks_by_language.get("sh", []) +
            code_blocks_by_language.get("shell", [])
        )

        if not shell_blocks:
            pytest.skip("No shell script code examples found")

        if not shellcheck_available:
            pytest.skip("shellcheck not available")

        errors = []

        for block in shell_blocks:
            code = block["code"]
            rule_name = block["rule_name"]

            with tempfile.NamedTemporaryFile(
                suffix=".sh", mode="w", delete=False
            ) as f:
                f.write(code)
                temp_path = f.name

            try:
                result = subprocess.run(
                    ["shellcheck", "-s", "bash", temp_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                # Only report errors, not warnings
                if result.returncode == 1:
                    # Filter for actual errors
                    error_lines = [
                        line for line in result.stdout.split("\n")
                        if "error" in line.lower()
                    ]
                    if error_lines:
                        errors.append(
                            f"Shell script error in rule '{rule_name}': "
                            f"{'; '.join(error_lines)}"
                        )
            except subprocess.TimeoutExpired:
                errors.append(
                    f"Shell validation timeout for rule '{rule_name}'"
                )
            finally:
                Path(temp_path).unlink(missing_ok=True)

        if errors:
            pytest.fail("\n".join(errors))


class TestSqlExamples:
    """Tests for SQL code example validity."""

    def test_sql_examples_have_basic_validity(
        self, code_blocks_by_language: dict[str, list[dict[str, Any]]]
    ) -> None:
        """Verify SQL examples have basic structural validity."""
        sql_blocks = code_blocks_by_language.get("sql", [])

        if not sql_blocks:
            pytest.skip("No SQL code examples found")

        # Basic SQL keywords that should be present
        sql_keywords = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE",
            "ALTER", "DROP", "GRANT", "REVOKE"
        ]

        errors = []

        for block in sql_blocks:
            code = block["code"].upper()
            rule_name = block["rule_name"]

            # Check if it contains at least one SQL keyword
            has_keyword = any(keyword in code for keyword in sql_keywords)

            if not has_keyword:
                errors.append(
                    f"SQL example in rule '{rule_name}' "
                    f"doesn't appear to be valid SQL"
                )

            # Check for basic syntax issues
            if code.count("(") != code.count(")"):
                errors.append(
                    f"Unbalanced parentheses in SQL example "
                    f"for rule '{rule_name}'"
                )

        if errors:
            pytest.fail("\n".join(errors))


class TestGoExamples:
    """Tests for Go code example validity."""

    @pytest.fixture
    def go_available(self) -> bool:
        """Check if Go is available."""
        try:
            result = subprocess.run(
                ["go", "version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def test_go_examples_compile(
        self,
        code_blocks_by_language: dict[str, list[dict[str, Any]]],
        go_available: bool
    ) -> None:
        """Verify Go code examples compile correctly."""
        go_blocks = code_blocks_by_language.get("go", [])

        if not go_blocks:
            pytest.skip("No Go code examples found")

        if not go_available:
            pytest.skip("Go not available")

        errors = []

        for block in go_blocks:
            code = block["code"]
            rule_name = block["rule_name"]

            # Wrap code in package if not present
            if "package " not in code:
                code = "package main\n\n" + code

            with tempfile.NamedTemporaryFile(
                suffix=".go", mode="w", delete=False
            ) as f:
                f.write(code)
                temp_path = f.name

            try:
                result = subprocess.run(
                    ["go", "build", "-o", "/dev/null", temp_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode != 0:
                    stderr = result.stderr
                    # Skip errors expected in educational code snippets:
                    # - could not import / no required module provides: external packages
                    # - undefined: references to symbols declared outside the snippet
                    # - declared and not used: unused vars common in partial snippets
                    # - non-declaration statement outside function body: bare statements
                    # - function main is undeclared: snippets without a main() entry point
                    _snippet_errors = [
                        "could not import",
                        "no required module provides",
                        "undefined:",
                        "declared and not used:",
                        "non-declaration statement outside function body",
                        "function main is undeclared in the main package",
                    ]
                    if not any(pat in stderr for pat in _snippet_errors):
                        errors.append(
                            f"Go compilation error in rule '{rule_name}': "
                            f"{stderr.strip()}"
                        )
            except subprocess.TimeoutExpired:
                errors.append(
                    f"Go compilation timeout for rule '{rule_name}'"
                )
            finally:
                Path(temp_path).unlink(missing_ok=True)

        if errors:
            pytest.fail("\n".join(errors))
