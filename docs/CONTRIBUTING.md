# Contributing to Claude Secure Coding Rules

Thank you for your interest in contributing! This guide explains how to add, modify, or improve security rules.

## Quick Start

1. Fork the repository
2. Create a feature branch: `git checkout -b add-spring-boot-rules`
3. Add or modify rules following the templates
4. Submit a pull request

## Project Overview

This project provides **25 security rule sets** covering:
- **3 Core rule sets**: OWASP 2025, AI/ML Security, Agent Security
- **12 Language rules**: Python, JavaScript, TypeScript, Go, Rust, Java, C#, Ruby, R, C++, Julia, SQL
- **5 Backend frameworks**: FastAPI, Express, Django, Flask, NestJS
- **5 Frontend frameworks**: React, Next.js, Vue, Angular, Svelte

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
claude-secure-coding-rules/
├── rules/
│   ├── _core/                       # Foundation rules (apply to all projects)
│   │   ├── owasp-2025.md           # OWASP Top 10 2025 web security
│   │   ├── ai-security.md          # AI/ML security (NIST AI RMF, MITRE ATLAS)
│   │   └── agent-security.md       # Agentic AI security (tool use, sandboxing)
│   │
│   ├── languages/                   # Language-specific security rules
│   │   ├── python/CLAUDE.md        # Deserialization, subprocess, SQL, crypto
│   │   ├── javascript/CLAUDE.md    # eval, prototype pollution, DOM, Node.js
│   │   ├── typescript/CLAUDE.md    # Type safety, validation, any types
│   │   ├── go/CLAUDE.md            # Concurrency, context, templates
│   │   ├── rust/CLAUDE.md          # unsafe blocks, FFI, memory safety
│   │   ├── java/CLAUDE.md          # Serialization, JNDI, reflection
│   │   ├── csharp/CLAUDE.md        # .NET patterns, LINQ injection
│   │   ├── ruby/CLAUDE.md          # Metaprogramming, ERB, mass assignment
│   │   ├── r/CLAUDE.md             # Shiny apps, data security, packages
│   │   ├── cpp/CLAUDE.md           # Memory safety, buffer overflows, RAII
│   │   ├── julia/CLAUDE.md         # Metaprogramming, serialization
│   │   └── sql/CLAUDE.md           # Injection, permissions, procedures
│   │
│   ├── backend/                     # Backend framework rules
│   │   ├── fastapi/CLAUDE.md       # Pydantic, JWT, authorization, CORS
│   │   ├── express/CLAUDE.md       # Helmet, sessions, rate limiting
│   │   ├── django/CLAUDE.md        # ORM, CSRF, templates, settings
│   │   ├── flask/CLAUDE.md         # Werkzeug, sessions, blueprints
│   │   └── nestjs/CLAUDE.md        # Decorators, guards, pipes
│   │
│   └── frontend/                    # Frontend framework rules
│       ├── react/CLAUDE.md         # XSS, state management, CSRF
│       ├── nextjs/CLAUDE.md        # Server Components, Server Actions
│       ├── vue/CLAUDE.md           # v-html, Vuex, router guards
│       ├── angular/CLAUDE.md       # DomSanitizer, HTTP client
│       └── svelte/CLAUDE.md        # {@html}, stores, SSR
│
├── templates/                       # Templates for contributors
│   ├── rule-template.md            # Template for individual rules
│   └── framework-template.md       # Template for framework rule sets
│
├── docs/                            # Documentation
│   └── CONTRIBUTING.md             # This file
│
├── CLAUDE.md                        # Project instructions for Claude Code
├── README.md                        # User documentation
└── LICENSE                          # MIT License
```

## Adding New Rules

### To an Existing Framework

1. Open the framework's `CLAUDE.md` file
2. Find the appropriate category (Input Validation, Authentication, etc.)
3. Add your rule following the template
4. Include references to `rules/_core/` where appropriate

### For a New Language

1. Create directory: `rules/languages/[language]/`
2. Copy `templates/rule-template.md` as `CLAUDE.md`
3. Add language-specific security rules organized by category
4. Include prerequisite links to core rules
5. Add Quick Reference table at the end

**Standard categories for languages:**
- Input Handling / Code Execution
- File Operations
- Cryptography
- Database/SQL Security
- Web Security
- Error Handling

### For a New Framework

1. Create directory in `rules/backend/` or `rules/frontend/`
2. Copy `templates/framework-template.md` to the correct location
3. Rename to `CLAUDE.md`
4. Add prerequisite links to core and language rules
5. Create categorized rules specific to the framework

**Standard categories for frameworks:**
- Input Validation
- Authentication & Session Management
- Authorization
- Data Protection
- Security Configuration

## Writing Guidelines

### Code Examples

**Do:**
- Use production-quality code (not pseudocode)
- Include all necessary imports
- Add comments explaining the security benefit
- Use realistic variable names
- Keep examples focused on the security pattern
- Show complete, runnable code snippets

**Don't:**
- Leave TODO comments
- Use placeholder values that look real (`password123`)
- Include unrelated boilerplate
- Mix multiple security issues in one example
- Use deprecated APIs or patterns

### Why Sections

- Mention the specific attack type (SQL injection, XSS, SSRF)
- Explain the consequence (data breach, RCE, privilege escalation)
- Keep to 1-2 sentences
- Link to the attack vector, not generic security advice

### Quick Reference Table

Every language/framework rule set should end with a Quick Reference table:

```markdown
## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Parameterized queries | strict | CWE-89 |
| Safe deserialization | strict | CWE-502 |
| Secure randomness | strict | CWE-330 |
```

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
5. **Check formatting**: Consistent with existing rules in the project

## Quality Checklist

- [ ] Rule follows Do/Don't/Why/Refs format
- [ ] Code examples are copy-paste ready
- [ ] Appropriate enforcement level chosen
- [ ] At least one authoritative reference included (CWE at minimum)
- [ ] Attack vector clearly explained
- [ ] No sensitive data in examples (real passwords, keys)
- [ ] Framework/language version compatibility noted if relevant
- [ ] Quick Reference table updated
- [ ] Prerequisites section links to relevant core/language rules

## Proposing Changes

### Issues

Open an issue for:
- Missing rules for common vulnerabilities
- Incorrect security advice
- Unclear rule descriptions
- Framework version updates
- New language/framework requests

### Pull Requests

Include in your PR:
- What rule(s) you're adding/changing
- Why this change improves security
- Testing you performed
- Any version compatibility notes

### Commit Messages

Follow this format:
```
Add [language/framework] security rules (Phase N)

- Brief description of rules added
- Key security areas covered
- Any notable patterns or references
```

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
| Google SAIF | Secure AI | `SAIF principle` |

## Roadmap - What's Needed

Priority areas for new contributions:

### Backend Frameworks
- [ ] Spring Boot (Java)
- [ ] Rails (Ruby)
- [ ] Laravel (PHP)
- [ ] ASP.NET Core (C#)
- [ ] Gin/Echo (Go)

### Frontend Frameworks
- [ ] SolidJS
- [ ] Qwik
- [ ] Remix

### Other Areas
- [ ] Mobile (React Native, Flutter, Swift, Kotlin)
- [ ] Infrastructure as Code (Terraform, Pulumi)
- [ ] Container security (Docker, Kubernetes)
- [ ] CI/CD security (GitHub Actions, GitLab CI)

## Code of Conduct

- Be respectful in reviews and discussions
- Focus feedback on the security content
- Cite sources when referencing vulnerabilities
- Avoid vendor-specific criticism
- Welcome contributors of all experience levels

## Questions?

Open an issue with the `question` label or start a discussion.

---

Thank you for helping make AI-assisted coding more secure!
