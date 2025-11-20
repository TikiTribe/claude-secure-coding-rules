# CLAUDE.md - Secure Coding Rules for Claude Code

This repository provides comprehensive security rules for Claude Code, covering web applications, AI/ML systems, and agentic AI.

## Project Overview

**Purpose**: Open-source security rules that guide Claude Code to generate secure code by default

**Coverage**:
- OWASP Top 10 2025 (web application security)
- AI/ML security (NIST AI RMF, MITRE ATLAS, Google SAIF)
- Agentic AI security (tool use, autonomy, sandboxing)
- Language-specific rules (Python, JavaScript, TypeScript, Go, Rust, Java, C#, Ruby)
- Framework-specific rules (FastAPI, Express, Django, Flask, NestJS, React, Next.js, Vue, Angular, Svelte)

## Repository Structure

```
claude-secure-coding-rules/
├── rules/
│   ├── _core/                      # Foundation rules (apply to all projects)
│   │   ├── owasp-2025.md          # OWASP Top 10 2025 security rules
│   │   ├── ai-security.md         # AI/ML system security rules
│   │   └── agent-security.md      # Agentic AI security rules
│   │
│   ├── languages/                  # Language-specific security rules
│   │   ├── python/CLAUDE.md       # Deserialization, subprocess, path traversal, crypto, SQL
│   │   ├── javascript/CLAUDE.md   # eval, prototype pollution, DOM security, Node.js
│   │   ├── typescript/CLAUDE.md   # Type safety, validation, any types
│   │   ├── go/CLAUDE.md           # Concurrency, context, templates, error handling
│   │   ├── rust/CLAUDE.md         # unsafe blocks, FFI, memory safety, crypto
│   │   ├── java/CLAUDE.md         # Serialization, JNDI, reflection, streams
│   │   ├── csharp/CLAUDE.md       # .NET patterns, LINQ injection, assemblies
│   │   └── ruby/CLAUDE.md         # Metaprogramming, ERB, mass assignment
│   │
│   ├── backend/                    # Backend framework rules
│   │   ├── fastapi/CLAUDE.md      # Pydantic validation, JWT, authorization, CORS
│   │   ├── express/CLAUDE.md      # Helmet, sessions, rate limiting, file uploads
│   │   ├── django/CLAUDE.md       # ORM, CSRF, templates, settings
│   │   ├── flask/CLAUDE.md        # Werkzeug, sessions, blueprints, extensions
│   │   └── nestjs/CLAUDE.md       # Decorators, guards, pipes, interceptors
│   │
│   └── frontend/                   # Frontend framework rules
│       ├── react/CLAUDE.md        # XSS prevention, state management, CSRF, forms
│       ├── nextjs/CLAUDE.md       # Server Components, Server Actions, middleware, env vars
│       ├── vue/CLAUDE.md          # v-html, computed properties, Vuex, router guards
│       ├── angular/CLAUDE.md      # DomSanitizer, template injection, HTTP client
│       └── svelte/CLAUDE.md       # {@html}, stores, SSR, form actions
│
├── templates/                      # Templates for adding new rules
│   ├── rule-template.md           # Template for individual rules
│   └── framework-template.md      # Template for framework rule sets
│
├── docs/                           # Documentation and guides
│   └── CONTRIBUTING.md            # Contribution guidelines with quality standards
│
├── compliance/                     # Compliance mapping (future)
│
├── CLAUDE.md                       # This file - project instructions
├── README.md                       # User documentation and implementation guide
└── LICENSE                         # MIT License
```

## Rule Counts

| Category | Count | Description |
|----------|-------|-------------|
| Core Rules | 3 | OWASP 2025, AI Security, Agent Security |
| Languages | 8 | Python, JavaScript, TypeScript, Go, Rust, Java, C#, Ruby |
| Backend Frameworks | 5 | FastAPI, Express, Django, Flask, NestJS |
| Frontend Frameworks | 5 | React, Next.js, Vue, Angular, Svelte |
| **Total Rule Sets** | **21** | Comprehensive security coverage |

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
| `strict` | Refuse to generate violating code | Critical vulnerabilities (injection, RCE) |
| `warning` | Warn and suggest alternatives | Significant risks (weak crypto, missing validation) |
| `advisory` | Mention as best practice | Defense in depth (headers, logging) |

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

| Standard | Description | Coverage |
|----------|-------------|----------|
| OWASP Top 10 2025 | Web application security risks | Full |
| OWASP LLM Top 10 | LLM-specific security risks | Full |
| NIST AI RMF | AI risk management framework | Full |
| NIST SSDF | Secure software development | Partial |
| MITRE ATLAS | Adversarial ML attack taxonomy | Full |
| ISO/IEC 23894 | AI risk management guidance | Partial |
| Google SAIF | Secure AI framework | Partial |

## Key Security Principles

1. **Input Validation**: Validate all inputs, especially for injection attacks
2. **Output Encoding**: Sanitize outputs for their context (HTML, SQL, etc.)
3. **Least Privilege**: Minimal permissions for tools and agents
4. **Defense in Depth**: Multiple layers of security controls
5. **Fail Secure**: Default to safe behavior on errors
6. **Audit Everything**: Log security-relevant actions

## Reference Materials

The repository includes reference PDFs for standards development:
- NIST AI RMF (NIST.AI.100-1.pdf)
- NIST SSDF (NIST.SP.800-218)
- MITRE ATLAS materials
- ISO/IEC standards (23894, 42005, 5259 series)
- Google SAIF summary
- Industry guides (SAIL Framework, SAFECode, CSI)

## Contributing

We welcome contributions! See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

### Adding New Rules

1. Use templates in `/templates`
2. Follow Do/Don't/Why/Refs pattern
3. Include CWE/OWASP references
4. Provide realistic code examples
5. Submit PR with test cases

## Development Commands

```bash
# View project structure
ls -la rules/

# Count rule files
find rules -name "CLAUDE.md" -o -name "*.md" | wc -l

# Search for specific patterns
grep -r "Level.*strict" rules/
```

## License

MIT License - see [LICENSE](LICENSE) for details.
