# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| v2.x    | yes       |
| v1.x    | best-effort, security fixes only |

## Reporting a vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Email: rock@rockcyber.com (PGP key: TBD before v2.0.0 tag — Task 138)

Subject line: `[CSCR SECURITY] <one-line description>`

Include: affected version, reproduction steps, expected vs actual behavior, your assessment of severity.

## Response timeline

- Acknowledgement within 72 hours
- Initial triage within 7 days
- Coordinated disclosure within 90 days unless mutually agreed otherwise

## Scope

In scope:
- The plugin's `settings-template.json` (permission-rule template correctness)
- Skill content (incorrect security advice, deprecated mitigations recommended as canonical)
- Documented hook patterns in `docs/how-to/write-your-own-hook.md` (bypass classes not documented; security regressions in example code)
- The converter tool (`tools/rule-to-skill-converter.py`) and other repo-internal tooling

Out of scope:
- User-authored hooks (the user owns runtime trust for hooks they wrote)
- Claude Code platform bugs (report to Anthropic)
- Vulnerabilities in transitive dependencies that don't affect CSCR's controls

## Security advisories

Published as GitHub Security Advisories on this repository. Users who installed documented hook patterns from `write-your-own-hook.md` should subscribe to advisories to learn when a pattern's bypass class becomes known.
