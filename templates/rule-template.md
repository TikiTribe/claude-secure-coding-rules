# Rule Template

Use this template when creating new security rules. Each rule should be actionable and include concrete code examples.

---

## Rule: [Descriptive Name]

**Level**: `strict` | `warning` | `advisory`

> - `strict`: Claude Code must refuse to generate code that violates this rule
> - `warning`: Claude Code should warn and suggest secure alternatives
> - `advisory`: Claude Code should mention as best practice when relevant

**When**: [Describe the trigger conditions - what code patterns, imports, or contexts activate this rule]

**Do**:
```[language]
# Secure implementation
# Include comments explaining WHY this is secure
```

**Don't**:
```[language]
# Vulnerable pattern
# Explain the specific vulnerability this creates
```

**Why**: [1-2 sentences explaining the security risk. Link to specific attack vectors or consequences.]

**Refs**: [Standards references - e.g., OWASP A05:2025, NIST SSDF PW.5.1, ISO/IEC 42001, MITRE ATLAS ML01]

---

## Example Rule

## Rule: Validate LLM Outputs Before Rendering

**Level**: `strict`

**When**: Rendering LLM-generated content in HTML, executing as code, or using in database queries.

**Do**:
```python
from markupsafe import escape

def render_llm_response(response: str) -> str:
    # Sanitize LLM output before rendering to prevent XSS
    return escape(response)
```

**Don't**:
```python
def render_llm_response(response: str) -> str:
    # VULNERABLE: Direct rendering allows XSS if LLM output contains malicious HTML
    return f"<div>{response}</div>"
```

**Why**: LLMs can be manipulated via prompt injection to generate malicious HTML/JavaScript. Always sanitize outputs before rendering to prevent XSS attacks.

**Refs**: OWASP A03:2025 (Injection), OWASP LLM01 (Prompt Injection), NIST AI 100-1 §3.2

---

## Guidelines

1. **Be specific**: Avoid vague guidance like "validate inputs". Show exactly what validation looks like.
2. **Show both patterns**: Always include Do and Don't examples for clarity.
3. **Explain the attack**: The "Why" should mention the specific attack vector (e.g., "SQL injection", "model poisoning").
4. **Use realistic code**: Examples should be production-quality, not pseudocode.
5. **Include all imports**: Show necessary imports so examples are copy-paste ready.
6. **Reference standards**: Always cite at least one authoritative source (OWASP, NIST, ISO).
