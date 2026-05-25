# P0.5 Corpus Quality Audit — Output Schema

The audit produces `docs/p05-audit-output.yaml` matching this schema:

```yaml
audited_rules:
  - path: rules/languages/python/CLAUDE.md
    status: passed | failed | deferred
    reviewed_by: <github-handle>
    reviewed_on: YYYY-MM-DD
    notes: |
      Optional free-text notes.
    issues_filed: []  # GitHub issue numbers for failed/deferred items
```

## Status values

- **passed**: every Do example was reviewed against current standards and either passes as-is or was updated. Every Don't example was verified to contain the vulnerable pattern.
- **failed**: the rule contains a deprecated mitigation, contradictory example, or pattern superseded by a current standard. A GitHub issue must be filed with the `corpus-audit` label.
- **deferred**: the rule is correct in spirit but cannot be converted to a skill within v2.0.0 scope (e.g., requires major rewrite). Deferred to v2.1.

## Converter behavior

`tools/rule_to_skill_converter.py --strict --audit docs/p05-audit-output.yaml`:
- For each input rule file, looks up the path in `audited_rules`.
- If `status: passed`, converts.
- If `status: failed` or `deferred`, refuses with `ValueError`.
- If the path is not in the audit at all, refuses with `ValueError`.

## Auditor responsibility

The auditor reviews each rule file end-to-end:
1. Read the entire file.
2. For each `Do` example, confirm it passes current standards (check `docs/standards-pin.yaml` for the cited standard versions).
3. For each `Don't` example, confirm it represents a real, current vulnerability pattern.
4. Note any reference to deprecated mitigations (e.g., substring-based prompt-injection denylists per OWASP LLM01 2025).
5. Mark `passed`, `failed`, or `deferred`.
