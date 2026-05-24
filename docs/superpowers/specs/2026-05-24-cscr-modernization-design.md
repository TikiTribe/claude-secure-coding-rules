# tikitribe-secure-coding-rules v2 Modernization Design

**Status:** Approved design, ready for implementation planning
**Date:** 2026-05-24
**Author:** Rock Lambros
**Plugin name:** `tikitribe-secure-coding-rules`
**Target version:** v2.0.0

## Purpose

Convert `claude-secure-coding-rules` (CSCR) from a `cp`-distributed library of always-on CLAUDE.md rule files into a Claude Code plugin built on the 2026-era platform primitives: skills (description-matched, path-scoped, on-demand loading), hooks (deterministic enforcement), permission rules (declarative deny), and the community plugin marketplace.

The current repo's `Level: strict` label is advisory prose — nothing enforces it. The 93% prompt-approval rate (Hughes 2026) confirms that advisory text is not a control. The repo also ships 8,800+ lines in `_core/` alone, which when copied per the README burns a user's context window before they type a prompt. v2 fixes both problems and aligns architecturally with Rock's Claude Skills (RCS) so the two repos cover complementary lanes without overlap.

## Non-goals

- v2 is not a methodology repo. RCS already owns that lane (verb-named, decision-tree skills). CSCR stays a catalog (framework-specific, reference shape).
- v2 does not bundle SAST runners. The existing `tests/` Semgrep/Bandit integration validates rule examples; production SAST stays the user's responsibility.
- v2 does not enforce at the OS/sandbox layer. That belongs to Claude Code's sandbox feature, not to a plugin.

## Architecture overview

Three enforcement layers ranked by reliability. The current repo conflates all three under "Level: strict" prose; v2 separates them honestly.

| Layer | Mechanism | Strength | Coverage in v2 |
|---|---|---|---|
| 1. Hooks (deterministic) | `hooks/hooks.json` PreToolUse, exit 2 | Model cannot bypass | ~12 RCE/secret/deserialization patterns |
| 2. Permission rules (declarative) | `settings.json` deny array | Harness-enforced | File paths (`.env`, `secrets/**`), `curl\|sh`, force-push to protected branches |
| 3. Skills (advisory) | `SKILL.md` loaded on description match | Best-effort, model follows instructions | Framework idioms, defense-in-depth, everything else |

Layer 1 is new in v2. Layer 2 is shipped as `settings-template.json` for users to merge into their project settings. Layer 3 is the existing rule corpus, restructured as skills.

## Repository layout (v2)

```
claude-secure-coding-rules/
├── .claude-plugin/
│   └── plugin.json                  # name, version, author, marketplace metadata
├── skills/
│   ├── applying-owasp-top-10/
│   │   ├── SKILL.md
│   │   ├── reference/
│   │   └── evals/
│   ├── applying-ai-ml-security/
│   ├── applying-agentic-ai-security/
│   ├── applying-mcp-security/
│   ├── applying-rag-security/
│   ├── applying-graph-db-security/
│   ├── python-security/
│   ├── javascript-security/
│   ├── ...                          # ~42 skills total
│   └── README.md                    # cross-skill index, sigma-sorted
├── hooks/
│   ├── hooks.json                   # PreToolUse manifest
│   └── enforcement/
│       ├── block-rce-class.py
│       ├── block-sql-injection.py
│       ├── block-untrusted-deserialization.py
│       ├── block-hardcoded-secrets.py
│       ├── block-trust-remote-code.py
│       ├── block-xss-html.py
│       ├── block-curl-pipe-sh.py
│       ├── block-unpinned-installs.py
│       ├── block-chmod-777.py
│       └── block-force-push-protected.py
├── settings-template.json           # declarative deny rules users merge
├── tests/
│   ├── hooks/                       # pytest unit tests for each hook script
│   ├── structural/                  # legacy rule-format tests, adapted to SKILL.md
│   └── coverage/                    # OWASP/CWE coverage analysis
├── tools/
│   ├── rule-to-skill-converter.py   # mechanical v1 → v2 first pass
│   ├── run_evals.py                 # RCS-compatible eval harness
│   └── lint_skills.py               # frontmatter validation
├── docs/
│   ├── superpowers/specs/
│   ├── how-to/
│   │   ├── install.md
│   │   ├── enable-hooks.md
│   │   └── contribute-a-skill.md
│   └── explanation/
│       ├── three-layers.md
│       └── relationship-to-rcs.md
├── CLAUDE.md                        # project instructions
└── README.md                        # rewritten for plugin-install
```

## Skills catalog

Each domain becomes one skill directory. The conversion principle: a CLAUDE.md rule file becomes a SKILL.md with frontmatter that scopes loading (`paths:`, `description`, `when_to_use`), a body that teaches the patterns, and bundled `reference/` files for deep dives.

### Per-skill anatomy

```
skills/python-security/
├── SKILL.md                   # frontmatter + concise instructions, <400 lines
├── reference/
│   ├── deserialization.md     # detailed pickle/yaml/marshal patterns
│   ├── subprocess.md          # shell=True, command injection
│   └── crypto.md              # weak algos, hardcoded keys
├── examples/
│   ├── secure-sql.py
│   └── secure-subprocess.py
└── evals/
    ├── 01-happy-path.json
    ├── 02-edge-case.json
    ├── 03-anti-trigger.json
    └── 04-adversarial.json
```

### SKILL.md frontmatter pattern

```yaml
---
name: python-security
description: |
  Apply Python-specific security rules: refuse pickle.loads on untrusted bytes,
  refuse eval/exec on user input, refuse subprocess with shell=True+interpolation,
  use parameterized SQL queries, prefer cryptography over pycrypto. Loads when
  editing Python files or when the user asks about Python security patterns.
paths:
  - "**/*.py"
  - "**/*.pyi"
  - "**/pyproject.toml"
  - "**/requirements*.txt"
when_to_use: |
  User is writing Python that touches user input, subprocess, deserialization,
  crypto, file I/O, or database queries. User asks "is this Python code secure?"
version: 2.0.0
sigma: 18
---
```

The `paths:` field is the key change. The python skill no longer loads when editing Terraform. The 8,800-line `_core` problem dissolves because each skill is ~300–500 lines and loads only when its glob hits. Most sessions load 2–4 skills, not all 42.

### Catalog mapping

| Current v1 path | v2 skill | Σ |
|---|---|---|
| `_core/owasp-2025.md` | `applying-owasp-top-10` | 20 |
| `_core/ai-security.md` | `applying-ai-ml-security` | 19 |
| `_core/agent-security.md` | `applying-agentic-ai-security` | 19 |
| `_core/mcp-security.md` | `applying-mcp-security` | 19 |
| `_core/rag-security.md` | `applying-rag-security` | 18 |
| `_core/graph-database-security.md` | `applying-graph-db-security` | 15 |
| `languages/python/CLAUDE.md` | `python-security` | 18 |
| `languages/javascript/CLAUDE.md` | `javascript-security` | 18 |
| `languages/typescript/CLAUDE.md` | `typescript-security` | 16 |
| `languages/{go,rust,java,csharp,ruby,r,cpp,julia,sql}/CLAUDE.md` | one skill each | 12–16 |
| `backend/fastapi/CLAUDE.md` | `fastapi-security` | 17 |
| `backend/{express,django,flask,nestjs}/CLAUDE.md` | one skill each | 14–17 |
| `backend/{langchain,crewai,autogen,transformers,vllm,triton,torchserve,ray-serve,bentoml,mlflow,modal}/CLAUDE.md` | one skill each | 13–18 |
| `frontend/{react,nextjs,vue,angular,svelte}/CLAUDE.md` | one skill each | 14–17 |
| `rag/**` | grouped: `rag-orchestration-security`, `rag-vector-store-security`, `rag-graph-security`, `rag-document-processing-security`, `rag-embeddings-security`, `rag-chunking-security`, `rag-observability-security` | 14–18 |
| `iac/{terraform,pulumi}/CLAUDE.md` | one skill each | 17 |
| `containers/{docker,kubernetes,helm}/CLAUDE.md` | one skill each | 17 |
| `cicd/{github-actions,gitlab-ci}/CLAUDE.md` | one skill each | 16 |

Total: ~42 skills.

### Naming convention

- Active-voice gerund (`applying-owasp-top-10`) where the skill *does* something or applies a standard.
- `<domain>-security` (`python-security`, `fastapi-security`) where the skill encodes a reference catalog for that domain.

The naming split is the seam between RCS (methodology, verb-first) and CSCR (catalog, domain-first). The names signal which lane.

### Namespacing

Once published, skills are invoked as `/tikitribe-secure-coding-rules:python-security`. Skills auto-load via description match without users typing the namespace; explicit invocation uses the full path.

## Hybrid hook architecture

Two enforcement tiers deployed differently.

### Tier A — Strict blocking hooks (root-level, default-on)

Live at `hooks/hooks.json`. Fire on every PreToolUse for the relevant tool (Bash, Write, Edit), regardless of which skill is loaded. Exit 2 if the payload matches a high-confidence RCE/secret/deserialization pattern.

**The 12 strict patterns:**

| # | Pattern | Tools matched | Action |
|---|---|---|---|
| 1 | `eval(<user-supplied>)` / `exec(<user-supplied>)` in Python | Write, Edit | Block |
| 2 | `pickle.loads(...)` / `marshal.loads(...)` / `yaml.load(...)` without `SafeLoader` | Write, Edit | Block |
| 3 | `subprocess.*(..., shell=True)` with an f-string or `+` interpolation | Write, Edit | Block |
| 4 | `os.system(<interpolated>)` | Write, Edit | Block |
| 5 | f-string SQL: `cursor.execute(f"...{var}...")` / `.format()` / `%` against user vars | Write, Edit | Block |
| 6 | `dangerouslySetInnerHTML={{ __html: <unsanitized-var> }}` | Write, Edit | Block |
| 7 | `trust_remote_code=True` in transformers `from_pretrained` | Write, Edit | Block |
| 8 | Hardcoded secret patterns (AWS keys, OpenAI keys, GitHub PATs, private keys) | Write, Edit | Block |
| 9 | `curl ... \| sh` / `wget ... \| bash` / `iex (irm ...)` (PowerShell) | Bash | Block |
| 10 | `chmod 777` on anything | Bash, Write (shell scripts) | Block |
| 11 | npm/pip/uvx install of unpinned `@latest` / `--from git+` without ref | Bash | Block |
| 12 | `git push --force` / `--force-with-lease` to `main`/`master` | Bash | Block |

Each hook is one Python script under `hooks/enforcement/`. Stdin is the standard Claude Code hook JSON; the script greps the relevant field (`tool_input.command` or `tool_input.content` or `tool_input.new_string`) and exits 0 (pass) or 2 (block) with a descriptive stderr message.

### Escape hatch

`# cscr:allow <rule-id>` (or `// cscr:allow N` / `<!-- cscr:allow N -->`) on the same line or the preceding line bypasses the hook with the comment documenting why. Legitimate test fixtures, sandbox-mode REPLs, and security education content avoid noise. The comment is the audit trail.

### Default posture

Hooks ship enabled by default when the plugin is installed (the plugin's `settings.json` does this). Users who want a softer mode set `cscr.enforcement: "advisory"` in their local settings, which the hook scripts read and respect (exit 0 with a stderr warning instead of exit 2).

### hooks.json sketch

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-rce-class.py" },
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-sql-injection.py" },
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-untrusted-deserialization.py" },
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-hardcoded-secrets.py" },
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-trust-remote-code.py" },
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-xss-html.py" }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-curl-pipe-sh.py" },
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-unpinned-installs.py" },
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-chmod-777.py" },
          { "type": "command", "command": "${CLAUDE_PLUGIN_DIR}/hooks/enforcement/block-force-push-protected.py" }
        ]
      }
    ]
  }
}
```

### Tier B — Skill-scoped warning hooks (PostToolUse, advisory)

Live in each skill's `SKILL.md` frontmatter via the `hooks:` field. Fire only when the skill is active. PostToolUse, non-blocking — they emit `additionalContext` so Claude (and the user) sees a warning after the tool call completes.

Skill-scoped hooks have an activation-gap problem (the skill might not be loaded when the bad pattern is generated). For blocking, that gap is unacceptable — handled by Tier A. For warnings, the gap is acceptable. Worst case is a missed warning, not unsafe code shipped.

**Examples of Tier B coverage:**

- `fastapi-security`: endpoint without Pydantic model + no auth dependency
- `django-security`: `request.POST.get(...)` passed to ORM `.raw()`
- `langchain-security`: `Tool(...).run(<unvalidated user_input>)`
- `react-security`: `dangerouslySetInnerHTML` even with apparent sanitization (encourage DOMPurify reference)
- `terraform-security`: `aws_s3_bucket` resource without `aws_s3_bucket_public_access_block`
- `docker-security`: `FROM <image>` without `@sha256:` digest pin
- `github-actions-security`: `uses: actions/checkout@v4` without SHA pin

### SKILL.md hooks frontmatter excerpt

```yaml
hooks:
  PostToolUse:
    - matcher: "Write|Edit"
      command: "${CLAUDE_SKILL_DIR}/scripts/warn-missing-pydantic.py"
```

### Threat coverage by layer

| Threat | Layer that catches it |
|---|---|
| Model directly outputs `eval(user_input)` | Tier A (deterministic, model-independent) |
| Hardcoded API key written to source | Tier A |
| Force-push to main attempted via Bash | Tier A |
| FastAPI endpoint missing input validation | Tier B (advisory) |
| Terraform `aws_s3_bucket` left public | Tier B (advisory) |
| Defense-in-depth (security headers, logging) | Layer 3 skill text |
| Architectural choices (microservice trust boundaries) | Layer 3 skill text |

## Eval discipline

Every shipped skill carries 4 evals under `skills/<name>/evals/`. Schema mirrors RCS so RCS's `tools/run_evals.py` harness is reusable. PRAGMATIC discipline applies: Sonnet-only by default, full 3-model optional.

| File | Purpose | Pass condition |
|---|---|---|
| `01-happy-path.json` | User asks for the secure pattern in-scope | Model produces the canonical secure pattern and cites the rule |
| `02-edge-case.json` | Ambiguous / boundary scenario | Model flags the gating rule explicitly and applies it or asks the user to disambiguate; no silent insecure default |
| `03-anti-trigger.json` | Adjacent but unrelated request | Skill stays dormant; no noise |
| `04-adversarial.json` | Prompt-injection-flavored request to produce the insecure pattern | Hook blocks (when applicable) or model refuses and cites the rule; assertion is on outcome, not mechanism |

Hook unit tests live separately under `tests/hooks/` as pytest with malicious-payload fixtures. Hooks are deterministic Python — unit tests are faster, more thorough, and don't burn API credits. The adversarial eval confirms system-level outcome; unit tests confirm hook isolation.

**Shipped bar:** 4 passing evals + hook unit tests (if applicable). Matches RCS's "shipped" definition extended for the security-specific adversarial slot.

## Relationship to RCS

| Dimension | RCS | CSCR v2 |
|---|---|---|
| Content lane | Methodology (verb-named, decision-tree) | Catalog (framework-specific, reference) |
| Skill naming | `verb-noun` (`enforcing-seed-hygiene`) | `<domain>-security` for catalog + `applying-<standard>` for core |
| Skill format | Anthropic Skills format | Identical |
| Install path | Symlink from clone or community marketplace | Plugin install from community marketplace (and symlink for dev) |
| Eval shape | 3 JSON evals | 3 + adversarial (4) |
| Sigma scoring | Yes (1–20) | Yes (same rubric) |
| Hooks | None | Tier A (root) + Tier B (skill-scoped) |
| Governance | Per-skill SemVer + repo integration tags | Same |
| PRAGMATIC discipline | Sonnet-only by default | Same |
| Docs contract (Layer 3) | 11 required sections per skill | Same |

### The cross-pointer

RCS's existing `applying-secure-coding-rules` skill names CSCR as the corpus it applies. That pointer becomes load-bearing: RCS users working in a CSCR-covered stack get an explicit instruction to install the CSCR plugin. Conversely, CSCR's AI/ML skills (`applying-ai-ml-security`, `langchain-security`, `applying-mcp-security`) cite RCS skills like `auditing-train-test-split`, `threat-modeling-llm-app`, and `auditing-mcp-server-pre-trust` for the methodology side. No silent overlap claims, no duplicated content.

### README contract

Both repo READMEs carry a short "When to install the other" section. CSCR's: *"Need methodology (test selection, drift monitoring, audit checklists)? Install RCS."* RCS's: *"Need framework-specific control catalog (FastAPI, LangChain, Terraform)? Install CSCR."*

### Drift check

A CI job in CSCR fetches RCS's `skills/README.md` (the cross-track index) and verifies that any skill named in CSCR's "see also" blocks still exists in RCS. Same in reverse. Cheap, deterministic, catches one of the two repos quietly renaming a skill the other depends on.

## Migration plan

**Branch model:** `v2/` branch hosts the rebuild. `main` stays on the current `rules/` layout until v2 is tagged. After v2.0.0 release, `main` switches to the v2 layout; the pre-v2 `main` head gets a `v1.x` tag for users who pin to it.

### Phased build on `v2/`

1. **P0 — Scaffolding.** `.claude-plugin/plugin.json`, repo restructure (`skills/`, `hooks/`, `evals/`), settings template, `tools/rule-to-skill-converter.py`. CI updated.
2. **P1 — Core skills.** Convert `_core/*.md` to 6 skills (`applying-owasp-top-10`, `applying-ai-ml-security`, `applying-agentic-ai-security`, `applying-mcp-security`, `applying-rag-security`, `applying-graph-db-security`). Each with 4 evals.
3. **P2 — Language skills.** Convert `languages/**` to 12 skills. Each with 4 evals.
4. **P3 — Framework skills.** Convert `backend/**`, `frontend/**` to ~16 skills.
5. **P4 — Infra & RAG skills.** Convert `iac/**`, `containers/**`, `cicd/**`, `rag/**` to ~12 skills.
6. **P5 — Tier A hooks.** Author the 12 strict hook scripts + pytest fixtures.
7. **P6 — Tier B hooks.** Add `hooks:` frontmatter to skills that warrant warnings (estimate ~15 skills, not all 42).
8. **P7 — Marketplace submission.** Submit to `claude-plugins-community`. Update README. Tag v2.0.0.

### Backward compatibility

The `rules/` tree stays accessible from the `v1.x` git tag. The v2 README has a clear "Migrating from v1" section pointing to `/plugin install tikitribe-secure-coding-rules` and warning that the old `cp` flow is no longer maintained.

### Estimated scope

~42 skills × (SKILL.md + 4 evals + frontmatter) + 12 hook scripts + 12 hook test files + plugin scaffolding + converter tool + CI updates. This is a multi-week project, not a single PR. The implementation plan (separate document) will name the work items so it is plannable.

## Risk register

| Risk | Mitigation |
|---|---|
| Converter produces low-quality SKILL.md (rule text was written for prose, not skill activation) | Convert mechanically, then hand-edit each skill's `description` and `when_to_use`. Use RCS-quality descriptions as the bar. |
| Tier A false positives on legitimate test fixtures | `# cscr:allow` escape hatch documented up front; evals include false-positive cases. |
| Skill description truncation at 1,536 chars (Claude Code caps the listing) | Convention: first sentence = trigger phrase, second = the controls. Lint check in CI. |
| Community-marketplace review delay | Submit early on `v2/` branch with a preview tag; users can install via `--plugin-dir` while waiting. |
| Drift between RCS and CSCR cross-references | CI drift-check job (see Relationship to RCS). |
| Hook script performance overhead on every Bash/Write/Edit call | Hooks are Python with no imports beyond `sys`, `json`, `re`, `os`; pre-compiled regex at module top. Target <50ms per hook. CI benchmark gate. |
| Plugin `settings.json` enabling hooks by default surprises users | First-run notice via `SessionStart` hook explaining what is enabled and how to disable; documented in install README. |

## Open questions for implementation phase

None blocking the design. Items deferred to implementation:

- Exact `paths:` glob per skill (TS/TSX overlap, monorepo-friendly patterns).
- Whether the converter tool runs at CI-time (deterministic build) or only as a one-shot migration helper (looser).
- Whether to ship a `--cscr-baseline` Bash flag wrapper that pre-pipes existing `npx`/`uvx` commands through pin-checking — out of scope for v2.0.0, candidate for v2.1.

## Success criteria

v2.0.0 ships when:

1. Plugin is installable from the community marketplace as `/plugin install tikitribe-secure-coding-rules`.
2. All ~42 skills have 4 passing evals each.
3. All 12 Tier A hooks have passing unit tests.
4. The CI drift-check against RCS passes.
5. README's "Migrating from v1" section is in place.
6. The repo-level `CLAUDE.md` and the per-skill `SKILL.md` files together do not exceed the v1 line count by more than a small factor — the modernization should reduce total payload-per-session, not grow it.
