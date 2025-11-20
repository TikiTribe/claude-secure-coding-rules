# Claude Secure Coding Rules

**Open-source security rules that guide Claude Code to generate secure code by default.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/CONTRIBUTING.md)

## Overview

This repository provides comprehensive security rules for Claude Code, covering web applications, AI/ML systems, and agentic AI. When you include these rules in your project, Claude Code will automatically apply security best practices, refuse to generate vulnerable code patterns, and suggest secure alternatives.

### Key Features

- **OWASP Top 10 2025** - Complete coverage of modern web security risks
- **AI/ML Security** - Rules for machine learning systems using NIST AI RMF, MITRE ATLAS, and Google SAIF
- **Agentic AI Security** - Specialized rules for autonomous AI systems with tool use
- **25 Rule Sets** - Covering 12 languages, 5 backend frameworks, and 5 frontend frameworks
- **Enforcement Levels** - Strict, warning, and advisory modes for different risk levels

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/claude-secure-coding-rules.git
cd claude-secure-coding-rules
```

### 2. Copy Rules to Your Project

**Option A: Copy specific rules you need**

```bash
# Core rules (recommended for all projects)
cp rules/_core/*.md /path/to/your/project/.claude/

# Language-specific (e.g., Python)
cp rules/languages/python/CLAUDE.md /path/to/your/project/

# Framework-specific (e.g., FastAPI)
cp rules/backend/fastapi/CLAUDE.md /path/to/your/project/backend/
```

**Option B: Copy entire rules directory**

```bash
cp -r rules /path/to/your/project/.claude/rules
```

### 3. Claude Code Automatically Applies Rules

Once the `CLAUDE.md` files are in your project, Claude Code will:
- Refuse to generate code that violates `strict` rules
- Warn about `warning` level issues and suggest alternatives
- Mention `advisory` best practices when relevant

## Repository Structure

```
claude-secure-coding-rules/
├── rules/
│   ├── _core/                    # Foundation rules (apply to all projects)
│   │   ├── owasp-2025.md        # OWASP Top 10 2025 security rules
│   │   ├── ai-security.md       # AI/ML system security rules
│   │   └── agent-security.md    # Agentic AI security rules
│   │
│   ├── languages/               # Language-specific security rules
│   │   ├── python/CLAUDE.md     # Python security (deserialization, subprocess, etc.)
│   │   ├── javascript/CLAUDE.md # JavaScript security (XSS, prototype pollution, etc.)
│   │   ├── typescript/CLAUDE.md # TypeScript security (type safety, validation)
│   │   ├── go/CLAUDE.md         # Go security (concurrency, memory safety)
│   │   ├── rust/CLAUDE.md       # Rust security (unsafe blocks, FFI)
│   │   ├── java/CLAUDE.md       # Java security (serialization, JNDI)
│   │   ├── csharp/CLAUDE.md     # C# security (.NET patterns)
│   │   ├── ruby/CLAUDE.md       # Ruby security (metaprogramming, Rails)
│   │   ├── r/CLAUDE.md          # R security (Shiny, data science, packages)
│   │   ├── cpp/CLAUDE.md        # C++ security (memory safety, buffer overflows)
│   │   ├── julia/CLAUDE.md      # Julia security (metaprogramming, serialization)
│   │   └── sql/CLAUDE.md        # SQL security (injection, permissions)
│   │
│   ├── backend/                 # Backend framework rules
│   │   ├── fastapi/CLAUDE.md    # FastAPI (Pydantic, dependencies, auth)
│   │   ├── express/CLAUDE.md    # Express.js (middleware, Helmet, sessions)
│   │   ├── django/CLAUDE.md     # Django (ORM, CSRF, templates)
│   │   ├── flask/CLAUDE.md      # Flask (Werkzeug, sessions, blueprints)
│   │   └── nestjs/CLAUDE.md     # NestJS (decorators, guards, pipes)
│   │
│   └── frontend/                # Frontend framework rules
│       ├── react/CLAUDE.md      # React (XSS, state, forms)
│       ├── nextjs/CLAUDE.md     # Next.js (Server Components, Server Actions)
│       ├── vue/CLAUDE.md        # Vue (v-html, computed properties)
│       ├── angular/CLAUDE.md    # Angular (DomSanitizer, template injection)
│       └── svelte/CLAUDE.md     # Svelte ({@html}, stores)
│
├── templates/                   # Templates for adding new rules
│   ├── rule-template.md        # Template for individual rules
│   └── framework-template.md   # Template for framework rule sets
│
├── docs/                        # Documentation and guides
│   └── CONTRIBUTING.md         # Contribution guidelines
│
├── CLAUDE.md                    # Project-level instructions for Claude Code
└── README.md                    # This file
```

## Implementation Guide

### Understanding Rule Hierarchy

Claude Code applies rules hierarchically:

1. **Global rules** (`~/.claude/CLAUDE.md`) - Apply to all projects
2. **Project rules** (`/project/CLAUDE.md`) - Apply to entire project
3. **Directory rules** (`/project/src/CLAUDE.md`) - Apply to specific directories

More specific rules take precedence over general rules.

### Implementation Patterns

#### Pattern 1: Security-First Project Setup

For a new project with maximum security:

```bash
# Create project structure
mkdir -p myproject/.claude/rules

# Copy all core rules
cp rules/_core/*.md myproject/.claude/rules/

# Copy language rules
cp rules/languages/python/CLAUDE.md myproject/

# Copy framework rules
cp rules/backend/fastapi/CLAUDE.md myproject/backend/
cp rules/frontend/react/CLAUDE.md myproject/frontend/
```

#### Pattern 2: Gradual Security Adoption

For existing projects, start with core rules:

```bash
# Week 1: Add core OWASP rules
cp rules/_core/owasp-2025.md myproject/CLAUDE.md

# Week 2: Add language-specific rules
cp rules/languages/javascript/CLAUDE.md myproject/src/

# Week 3: Add framework rules
cp rules/backend/express/CLAUDE.md myproject/server/
```

#### Pattern 3: AI/ML Project Setup

For AI/ML projects:

```bash
# Copy AI-specific rules
cp rules/_core/ai-security.md myproject/.claude/
cp rules/_core/agent-security.md myproject/.claude/

# Add Python rules for ML code
cp rules/languages/python/CLAUDE.md myproject/ml/
```

### Customizing Rules

You can customize rules for your project:

```markdown
# In your project's CLAUDE.md

## Custom Security Configuration

### Override: Allow eval() in sandboxed REPL
The following modules may use eval() with proper sandboxing:
- src/repl/sandbox.py

### Additional Rule: Require MFA for admin routes
All routes under /admin/* must implement MFA.
```

## Rule Format

All rules follow the **Do/Don't/Why/Refs** pattern:

```markdown
## Rule: Parameterized Queries

**Level**: `strict`

**When**: Any database query with user input

**Do**:
```python
# Use parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

**Don't**:
```python
# Never concatenate user input into queries
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # SQL Injection!
```

**Why**: SQL injection allows attackers to read, modify, or delete data. It's been the #1 web vulnerability for over a decade.

**Refs**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
```

### Enforcement Levels

| Level | Behavior | Use Case |
|-------|----------|----------|
| `strict` | Claude refuses to generate violating code | SQL injection, command injection, hardcoded secrets |
| `warning` | Warns and suggests alternatives | Missing input validation, weak cryptography |
| `advisory` | Mentions as best practice | Security headers, rate limiting |

## Standards Coverage

### Web Application Security

| Standard | Coverage | Description |
|----------|----------|-------------|
| **OWASP Top 10 2025** | Full | All 10 categories with specific mitigations |
| **OWASP API Security Top 10** | Partial | Key API security risks |
| **CWE Top 25** | Partial | Most dangerous software weaknesses |

### AI/ML Security

| Standard | Coverage | Description |
|----------|----------|-------------|
| **NIST AI RMF** | Full | AI risk management framework |
| **MITRE ATLAS** | Full | Adversarial ML attack taxonomy |
| **OWASP LLM Top 10** | Full | LLM-specific security risks |
| **Google SAIF** | Partial | Secure AI framework |
| **ISO/IEC 23894** | Partial | AI risk management guidance |

### Secure Development

| Standard | Coverage | Description |
|----------|----------|-------------|
| **NIST SSDF** | Partial | Secure software development |
| **OWASP ASVS** | Partial | Application security verification |
| **OWASP SAMM** | Reference | Security maturity model |

## Examples by Technology

### Python + FastAPI

```bash
# Setup
cp rules/languages/python/CLAUDE.md myproject/
cp rules/backend/fastapi/CLAUDE.md myproject/app/

# Claude Code will now:
# - Enforce Pydantic validation for all inputs
# - Require proper JWT handling
# - Prevent SQL injection in SQLAlchemy queries
# - Flag insecure pickle/yaml deserialization
```

### JavaScript + React + Express

```bash
# Setup
cp rules/languages/javascript/CLAUDE.md myproject/
cp rules/frontend/react/CLAUDE.md myproject/client/
cp rules/backend/express/CLAUDE.md myproject/server/

# Claude Code will now:
# - Prevent XSS via dangerouslySetInnerHTML
# - Require Helmet middleware for security headers
# - Enforce parameterized queries
# - Flag prototype pollution patterns
```

### TypeScript + Next.js

```bash
# Setup
cp rules/languages/typescript/CLAUDE.md myproject/
cp rules/frontend/nextjs/CLAUDE.md myproject/

# Claude Code will now:
# - Properly handle Server Components vs Client Components
# - Secure Server Actions with validation
# - Protect environment variables
# - Apply CSP and security headers
```

### Go Backend

```bash
# Setup
cp rules/languages/go/CLAUDE.md myproject/

# Claude Code will now:
# - Prevent race conditions with proper mutex usage
# - Secure context handling
# - Apply template auto-escaping
# - Handle errors securely
```

### Rust Systems

```bash
# Setup
cp rules/languages/rust/CLAUDE.md myproject/

# Claude Code will now:
# - Minimize unsafe blocks
# - Properly handle FFI boundaries
# - Prevent memory safety issues
# - Apply cryptographic best practices
```

## Verifying Rules Are Active

To verify Claude Code is applying your rules:

1. **Ask Claude Code directly**:
   ```
   What security rules are you following for this project?
   ```

2. **Test with a vulnerable pattern**:
   ```
   Write a function that takes user input and passes it to eval()
   ```
   Claude Code should refuse or warn based on the rule level.

3. **Check rule application**:
   ```
   Why did you use parameterized queries instead of string formatting?
   ```
   Claude Code should reference the OWASP SQL injection rules.

## Contributing

We welcome contributions! See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for:

- How to write new rules using our templates
- Quality guidelines and code review process
- Standards references and verification
- Testing your rules

### Quick Contribution

1. Fork the repository
2. Create a branch: `git checkout -b feature/new-framework-rules`
3. Use templates in `/templates` for new rules
4. Submit a pull request with examples

## Roadmap

- [ ] Additional backend frameworks (Spring Boot, Rails, Laravel)
- [ ] Mobile frameworks (React Native, Flutter)
- [ ] Infrastructure as Code (Terraform, Pulumi)
- [ ] Container security (Docker, Kubernetes)
- [ ] CI/CD security (GitHub Actions, GitLab CI)
- [ ] Rule testing framework
- [ ] VS Code extension for rule management

## FAQ

### Do these rules work with all Claude interfaces?

These rules are specifically designed for **Claude Code** (CLI tool). They may work partially with other Claude interfaces but are optimized for the CLAUDE.md file format.

### Will these rules slow down Claude Code?

No. Rules are parsed once when Claude Code starts and applied during code generation. There's no runtime performance impact.

### Can I use rules without understanding security?

Yes! That's the point. The rules encode security expertise so you don't need to be a security expert. However, understanding why rules exist helps you make better decisions.

### How do I handle false positives?

You can override rules for specific cases by adding exceptions in your project's CLAUDE.md. Document why the exception is safe.

### Are these rules kept up to date?

Yes. We monitor OWASP, NIST, and other standards for updates. Major updates (like OWASP Top 10 revisions) are incorporated promptly.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [OWASP Foundation](https://owasp.org/) for security standards
- [NIST](https://www.nist.gov/) for AI RMF and SSDF
- [MITRE](https://atlas.mitre.org/) for ATLAS framework
- [Google](https://blog.google/technology/safety-security/introducing-googles-secure-ai-framework/) for SAIF

---

**Questions?** Open an issue or start a discussion.

**Found a vulnerability?** Please report it via [security@example.com](mailto:security@example.com) rather than opening a public issue.
