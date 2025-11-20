# Contributing to Claude Secure Coding Rules

Thank you for your interest in contributing! This guide explains how to add, modify, or improve security rules.

## Quick Start

1. Fork the repository
2. Create a feature branch: `git checkout -b add-fastapi-rules`
3. Add or modify rules following the templates
4. Submit a pull request

## Rule Structure

### Rule Format

Every rule follows the **Do/Don't/Why/Refs** pattern:

```markdown
## Rule: [Descriptive Name]

**Level**: `strict` | `warning` | `advisory`

**When**: [Trigger conditions]

**Do**:
```[language]
# Secure implementation with explanation
```

**Don't**:
```[language]
# Vulnerable pattern with risk explanation
```

**Why**: [1-2 sentences on the security risk and attack vector]

**Refs**: [Standards - OWASP, NIST, CWE, MITRE ATLAS]
```

### Enforcement Levels

| Level | Claude Code Behavior | Use When |
|-------|---------------------|----------|
| `strict` | Must refuse to generate violating code | Critical vulnerabilities (SQLi, RCE, auth bypass) |
| `warning` | Warn and suggest secure alternatives | Significant risks with valid exceptions |
| `advisory` | Mention as best practice when relevant | Good practices, defense in depth |

## Directory Structure

```
rules/
├── _core/                    # Foundation rules (all projects)
│   ├── owasp-2025.md        # OWASP Top 10 2025
│   ├── ai-security.md       # AI/ML security
│   └── agent-security.md    # Agentic AI security
├── languages/               # Language-specific rules
│   ├── python/CLAUDE.md
│   ├── javascript/CLAUDE.md
│   └── ...
├── backend/                 # Backend framework rules
│   ├── fastapi/CLAUDE.md
│   ├── express/CLAUDE.md
│   └── ...
└── frontend/                # Frontend framework rules
    ├── react/CLAUDE.md
    ├── nextjs/CLAUDE.md
    └── ...
```

## Adding New Rules

### To an Existing Framework

1. Open the framework's `CLAUDE.md` file
2. Find the appropriate category (Input Validation, Authentication, etc.)
3. Add your rule following the template
4. Include references to `rules/_core/` where appropriate

### For a New Framework

1. Copy `templates/framework-template.md` to the correct location
2. Rename to `CLAUDE.md`
3. Fill in framework-specific details
4. Add prerequisite links to core and language rules
5. Create categorized rules

## Writing Guidelines

### Code Examples

**Do:**
- Use production-quality code (not pseudocode)
- Include all necessary imports
- Add comments explaining the security benefit
- Use realistic variable names
- Keep examples focused on the security pattern

**Don't:**
- Leave TODO comments
- Use placeholder values that look real (`password123`)
- Include unrelated boilerplate
- Mix multiple security issues in one example

### Why Sections

- Mention the specific attack type (SQL injection, XSS, SSRF)
- Explain the consequence (data breach, RCE, privilege escalation)
- Keep to 1-2 sentences
- Link to the attack vector, not generic security advice

### References

Always include at least one authoritative reference:

- **OWASP**: `OWASP A01:2025`, `OWASP LLM01`
- **CWE**: `CWE-89`, `CWE-79`
- **NIST**: `NIST SSDF PW.5.1`, `NIST AI RMF MAP 1.5`
- **MITRE ATLAS**: `AML.T0051` (Prompt Injection)
- **ISO**: `ISO/IEC 23894 A.9`

## Testing Rules

Before submitting:

1. **Verify accuracy**: Test the "Do" pattern actually works
2. **Confirm vulnerability**: The "Don't" pattern should be exploitable
3. **Check references**: Links should be valid and relevant
4. **Review clarity**: Another developer should understand the risk

## Quality Checklist

- [ ] Rule follows Do/Don't/Why/Refs format
- [ ] Code examples are copy-paste ready
- [ ] Appropriate enforcement level chosen
- [ ] At least one authoritative reference included
- [ ] Attack vector clearly explained
- [ ] No sensitive data in examples (real passwords, keys)
- [ ] Framework version compatibility noted if relevant

## Proposing Changes

### Issues

Open an issue for:
- Missing rules for common vulnerabilities
- Incorrect security advice
- Unclear rule descriptions
- Framework version updates

### Pull Requests

Include in your PR:
- What rule(s) you're adding/changing
- Why this change improves security
- Testing you performed
- Any version compatibility notes

## Standards References

Core rules should reference these standards:

| Standard | Focus Area | Example Reference |
|----------|------------|-------------------|
| OWASP Top 10 2025 | Web app security | `OWASP A01:2025` |
| OWASP LLM Top 10 | LLM security | `OWASP LLM01` |
| NIST SSDF | Secure development | `NIST SSDF PW.5.1` |
| NIST AI RMF | AI risk management | `NIST AI RMF MAP 1.5` |
| MITRE ATLAS | ML attack taxonomy | `AML.T0051` |
| ISO/IEC 23894 | AI risk guidance | `ISO/IEC 23894 A.9` |
| CWE | Weakness classification | `CWE-89` |

## Code of Conduct

- Be respectful in reviews and discussions
- Focus feedback on the security content
- Cite sources when referencing vulnerabilities
- Avoid vendor-specific criticism

## Questions?

Open an issue with the `question` label or start a discussion.

---

Thank you for helping make AI-assisted coding more secure!
