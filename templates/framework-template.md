# Framework Template

Use this template when adding security rules for a new framework. Copy this file to the appropriate location (e.g., `rules/backend/[framework]/CLAUDE.md`) and customize.

---

# [Framework Name] Security Rules

This file provides security rules for Claude Code when working with [Framework Name].

## Overview

**Framework**: [Name and version]
**Category**: [Backend/Frontend/Language]
**Primary Use Case**: [Brief description]
**Security Profile**: [High-risk areas specific to this framework]

## Prerequisites

These rules assume familiarity with:
- `rules/_core/[relevant-core].md` - [Link to core security primitives]
- `rules/languages/[language]/CLAUDE.md` - [Link to base language rules]

---

## Rules

### Category 1: [Security Domain]

[Group related rules under meaningful categories like "Input Validation", "Authentication", "Data Handling", etc.]

#### Rule: [Name]
<!-- Copy from rule-template.md -->

**Level**: `strict` | `warning` | `advisory`

**When**: [Trigger conditions]

**Do**:
```[language]
# Secure pattern
```

**Don't**:
```[language]
# Insecure pattern
```

**Why**: [Risk explanation]

**Refs**: [Standards]

---

### Category 2: [Security Domain]

#### Rule: [Name]

[Continue with additional rules...]

---

## Framework-Specific Considerations

### [Consideration 1]

[Explain any unique security characteristics of this framework that don't fit into individual rules]

### [Consideration 2]

[Additional framework-specific guidance]

---

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| [Rule Name] | strict | [Brief risk] |
| [Rule Name] | warning | [Brief risk] |
| [Rule Name] | advisory | [Brief risk] |

---

## Version History

- **v1.0.0** - Initial release
- [Track updates to rules]
