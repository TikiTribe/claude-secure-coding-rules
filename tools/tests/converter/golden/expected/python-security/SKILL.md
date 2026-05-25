---
name: python-security
description: |
  Apply python security rules. Source: Python Security Rules. Loads when working with matching file types.
paths:
  - "**/*.py"
  - "**/*.pyi"
  - "**/pyproject.toml"
  - "**/requirements*.txt"
when_to_use: |
  User is writing or modifying files matching the skill's paths glob, or asks about the domain this skill covers.
version: 2.0.0
sigma: 15
---

# Python Security Rules

> **Source:** Converted from `tools/tests/converter/golden/inputs/sample-python.md` on 2026-05-25.
> **TODO before v2.0.0:** Hand-edit `description`, `when_to_use`, `sigma`, and the body content per the skill-authoring checklist.

# Python Security Rules

Sample input for golden-file conversion test.

## Rule: No eval on user input

**Level**: `strict`

**Refs**: CWE-95, OWASP A03:2025

