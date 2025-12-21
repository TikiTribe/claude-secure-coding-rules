# Security Rules Testing Framework

Comprehensive testing framework for validating security rules using pytest.

## Overview

This testing framework validates:
- **Structural integrity** of rule files
- **Syntactic validity** of code examples
- **Security effectiveness** using SAST tools
- **Coverage analysis** of security standards

## Quick Start

### Installation

```bash
# Install test dependencies
pip install -r tests/requirements.txt

# Optional: Install system tools for full validation
# macOS
brew install shellcheck semgrep

# Ubuntu/Debian
apt-get install shellcheck
pip install semgrep
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/structural/          # Format validation
pytest tests/code_validation/     # Code syntax
pytest tests/security/            # SAST analysis
pytest tests/coverage/            # Coverage reports

# Run with coverage report
pytest tests/ --cov=tests --cov-report=html

# Run in parallel
pytest tests/ -n auto

# Run excluding slow tests
pytest tests/ -m "not slow"
```

## Test Categories

### Structural Tests (`tests/structural/`)

Validates rule format compliance:

- Required sections (Level, When, Do, Don't, Why, Refs)
- Valid enforcement levels (strict, warning, advisory)
- Code blocks have language identifiers
- References contain valid CWE/OWASP citations
- No broken internal links

```bash
pytest tests/structural/test_rule_format.py -v
```

### Code Validation Tests (`tests/code_validation/`)

Validates code examples are syntactically correct:

- Python: AST parsing
- JavaScript/TypeScript: Node.js validation
- YAML/JSON: Schema validation
- HCL/Terraform: HCL2 parsing
- Shell: shellcheck validation
- Go: Compilation check

```bash
pytest tests/code_validation/test_code_examples.py -v
```

### Security Tests (`tests/security/`)

Validates security effectiveness using SAST:

- **Semgrep**: Pattern matching across languages
- **Bandit**: Python security analysis
- Custom pattern detection for common vulnerabilities

```bash
# Requires semgrep and bandit installed
pytest tests/security/test_security_rules.py -v
```

### Coverage Tests (`tests/coverage/`)

Tracks security standard coverage:

- CWE coverage by category
- OWASP Top 10 2021 coverage
- OWASP LLM Top 10 coverage
- Language and framework coverage gaps
- Attack vector coverage analysis

```bash
pytest tests/coverage/test_coverage.py -v -s  # -s shows coverage reports
```

## Writing New Tests

### Adding Structural Tests

```python
# tests/structural/test_new_validation.py
def test_custom_validation(all_rules):
    """Validate custom requirement."""
    errors = []

    for rule in all_rules:
        if not meets_requirement(rule):
            errors.append(f"Rule '{rule['name']}' fails requirement")

    if errors:
        pytest.fail("\n".join(errors))
```

### Adding Code Validation Tests

```python
# tests/code_validation/test_new_language.py
def test_rust_examples(code_blocks_by_language):
    """Validate Rust code examples."""
    rust_blocks = code_blocks_by_language.get("rust", [])

    if not rust_blocks:
        pytest.skip("No Rust examples found")

    # Validation logic here
```

### Adding Security Tests

```python
# tests/security/test_custom_patterns.py
def test_custom_vulnerability_pattern(code_blocks_by_language):
    """Check for custom vulnerability pattern."""
    pattern = re.compile(r"vulnerable_pattern")

    for block in code_blocks_by_language.get("python", []):
        if block["type"] == "dont":
            assert pattern.search(block["code"]), \
                f"Expected vulnerability not found in {block['rule_name']}"
```

## Fixtures Reference

### Available Fixtures

| Fixture | Scope | Description |
|---------|-------|-------------|
| `project_root` | session | Project root Path |
| `rules_dir` | session | Rules directory Path |
| `rule_files` | session | List of all rule file Paths |
| `all_rules` | session | List of all parsed rules |
| `rules_by_file` | session | Dict mapping Path to rules |
| `code_blocks_by_language` | session | Dict mapping language to code blocks |
| `cwe_references` | session | Dict mapping CWE to rule names |
| `owasp_references` | session | Dict mapping OWASP item to rule names |
| `rule_parser_class` | function | RuleParser class for custom parsing |

### Rule Structure

```python
{
    "name": "SQL Injection Prevention",
    "filepath": Path("/path/to/rule.md"),
    "sections": {
        "Level": "`strict`",
        "When": "User input in SQL queries",
        "Do": "Use parameterized queries...",
        "Don't": "String concatenation...",
        "Why": "SQL injection allows...",
        "Refs": "CWE-89, A03:2021"
    },
    "code_blocks": [
        {
            "language": "python",
            "code": "cursor.execute('SELECT...', (param,))",
            "type": "do"
        }
    ],
    "raw_text": "Full markdown content..."
}
```

## CI/CD Integration

### GitHub Actions

The repository includes a CI workflow that runs on every PR:

- Structural validation
- Code example validation  
- Security analysis
- Markdown linting
- Coverage reporting

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: test-rules
        name: Test Security Rules
        entry: pytest tests/structural/ tests/code_validation/ -q
        language: system
        pass_filenames: false
        always_run: true
```

## Coverage Requirements

### Minimum Thresholds

| Metric | Threshold | Description |
|--------|-----------|-------------|
| CWE Top 25 | 50% | At least 8 of 15 critical CWEs |
| OWASP Top 10 | 100% | All 10 categories |
| Code Examples | 90% | Rules with valid code |
| Completeness | 50% | Overall coverage score |

### Coverage Reports

The coverage tests generate detailed reports:

```text
CWE Coverage Report:
==================================================

Injection:
  Coverage: 6/8 (75.0%)
  Missing: CWE-91, CWE-917

Authentication:
  Coverage: 7/9 (77.8%)
  Missing: CWE-523, CWE-620

==================================================
Overall CWE Coverage: 45/70 (64.3%)
```

## Troubleshooting

### Common Issues

**No rules found**

```bash
# Check rules directory exists
ls -la rules/

# Verify CLAUDE.md files
find rules -name "CLAUDE.md"
```

**Semgrep not available**

```bash
# Install semgrep
pip install semgrep

# Or skip security tests
pytest tests/ -m "not slow"
```

**Node.js validation fails**

```bash
# Install Node.js for JavaScript validation
# macOS
brew install node

# Or skip JavaScript tests
pytest tests/code_validation/ -k "not javascript"
```

**Test failures on PR**

```bash
# Run tests locally first
pytest tests/ -v --tb=short

# Check specific failing test
pytest tests/structural/test_rule_format.py::TestRuleStructure::test_all_rules_have_required_sections -v
```

## Contributing

### Adding Tests for New Languages

1. Add language extension mapping in `conftest.py`
2. Create validation test in `test_code_examples.py`
3. Add security patterns in `test_security_rules.py`
4. Update coverage tracking in `test_coverage.py`

### Test Quality Guidelines

- Use type hints for all functions
- Include docstrings explaining test purpose
- Handle edge cases gracefully
- Provide clear error messages
- Use appropriate pytest markers

## License

Same as main project (MIT).
