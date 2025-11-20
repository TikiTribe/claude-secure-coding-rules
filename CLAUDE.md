# CLAUDE.md - Secure Coding Rules for Claude Code

This repository provides comprehensive security rules for Claude Code, covering web applications, AI/ML systems, and agentic AI.

## Project Overview

**Purpose**: Open-source security rules that guide Claude Code to generate secure code by default

**Coverage**:
- OWASP Top 10 2025 (web application security)
- AI/ML security (NIST AI RMF, MITRE ATLAS, Google SAIF)
- Agentic AI security (tool use, autonomy, sandboxing)
- Language-specific rules (Python, JavaScript, TypeScript, Go, Rust, Java, C#, Ruby)
- Framework-specific rules (FastAPI, Express, Django, React, Next.js, etc.)

## Repository Structure

```
rules/
├── _core/                    # Foundation rules (apply to all projects)
│   ├── owasp-2025.md        # OWASP Top 10 2025 security rules
│   ├── ai-security.md       # AI/ML system security rules
│   └── agent-security.md    # Agentic AI security rules
├── languages/               # Language-specific security rules
│   ├── python/CLAUDE.md
│   ├── javascript/CLAUDE.md
│   └── ...
├── backend/                 # Backend framework rules
│   ├── fastapi/CLAUDE.md
│   └── ...
└── frontend/                # Frontend framework rules
    ├── react/CLAUDE.md
    └── ...
templates/                   # Templates for adding new rules
docs/                        # Documentation and guides
```

## Rule Format

All rules follow the **Do/Don't/Why/Refs** pattern:

```markdown
## Rule: [Name]

**Level**: `strict` | `warning` | `advisory`

**When**: [Trigger conditions]

**Do**: [Secure code example with explanation]

**Don't**: [Vulnerable code example with risk]

**Why**: [Attack vector and consequences]

**Refs**: [OWASP, NIST, CWE, MITRE ATLAS references]
```

## Enforcement Levels

| Level | Behavior | Use Case |
|-------|----------|----------|
| `strict` | Refuse to generate violating code | Critical vulnerabilities |
| `warning` | Warn and suggest alternatives | Significant risks |
| `advisory` | Mention as best practice | Defense in depth |

## Using These Rules

### For Claude Code Users

1. Copy relevant `CLAUDE.md` files to your project
2. Claude Code will automatically apply the rules
3. Rules are hierarchical: global → project → subdirectory

### For Contributors

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for:
- Rule format and templates
- Quality guidelines
- Standards references

## Standards Covered

| Standard | Description |
|----------|-------------|
| OWASP Top 10 2025 | Web application security risks |
| OWASP LLM Top 10 | LLM-specific security risks |
| NIST AI RMF | AI risk management framework |
| NIST SSDF | Secure software development |
| MITRE ATLAS | Adversarial ML attack taxonomy |
| ISO/IEC 23894 | AI risk management guidance |
| Google SAIF | Secure AI framework |

## Key Security Principles

1. **Input Validation**: Validate all inputs, especially for injection attacks
2. **Output Encoding**: Sanitize outputs for their context (HTML, SQL, etc.)
3. **Least Privilege**: Minimal permissions for tools and agents
4. **Defense in Depth**: Multiple layers of security controls
5. **Fail Secure**: Default to safe behavior on errors
6. **Audit Everything**: Log security-relevant actions

## Contributing

We welcome contributions! See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

[Add license information]
