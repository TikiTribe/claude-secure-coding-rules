# tikitribe-secure-coding-rules v2 Modernization Design

**Status:** Approved design with Amendment 01 applied, ready for implementation planning
**Date:** 2026-05-24 (Amendment 01 applied 2026-05-24)
**Author:** Rock Lambros
**Plugin name:** `tikitribe-secure-coding-rules`
**Target version:** v2.0.0
**Amendment history:** Amendment 01 (this revision) — resolves Round 1 adversarial premortem findings M1–M11 (false-confidence reframing, escape-hatch hardening, AST hooks, supply-chain controls, SECURITY.md+VDP, corpus-quality audit, standards pinning, converter contract, cross-pointer hardening, staged hook rollout, outcome metrics). See `docs/superpowers/specs/2026-05-24-cscr-amendment-01.md` for finding-by-finding rationale.

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
| 1. Hooks (deterministic) | `hooks/hooks.json` PreToolUse, exit 2 | Deterministic block of 12 explicit patterns; see `docs/explanation/enforcement-coverage.md` for bypass classes per pattern | ~12 RCE/secret/deserialization patterns |
| 2. Permission rules (declarative) | `settings.json` deny array | Declarative file-path and command deny rules; ineffective against process-internal writes | File paths (`.env`, `secrets/**`), `curl\|sh`, force-push to protected branches |
| 3. Skills (advisory) | `SKILL.md` loaded on description match | Advisory model guidance, conditional on skill activation | Framework idioms, defense-in-depth, everything else |

Layer 1 is new in v2. Layer 2 is shipped as `settings-template.json` for users to merge into their project settings. Layer 3 is the existing rule corpus, restructured as skills.

**Honest-framing constraint.** The README and any user-facing copy may use enforcement verbs (`enforce`, `block`, `refuse`) only when describing Tier A hooks AND only for the bypass classes documented in `enforcement-coverage.md`. Layer 2 and Layer 3 use `advises`, `loads guidance for`, `documents`. A CI lint over README.md and docs/ flags marketing verbs in non-Tier-A contexts.

## Repository layout (v2)

```
claude-secure-coding-rules/
├── .claude-plugin/
│   └── plugin.json                  # name, version, author, marketplace metadata,
│                                    # plus hookScriptHashes map (SHA-256 per hook script)
├── .cscr-allowlist.json.example     # template for consuming projects: out-of-band
│                                    # registry of permitted (rule-id, file, line-hash) bypasses
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
│       ├── ast/                     # AST-based detectors (Python, JS, TS)
│       ├── coverage/                # per-hook bypass-class docs
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
├── SECURITY.md                      # VDP, reporting channel, disclosure policy
├── tests/
│   ├── hooks/                       # pytest unit tests for each hook script,
│   │                                # incl. known-FN payload fixtures per M3
│   ├── structural/                  # legacy rule-format tests, adapted to SKILL.md
│   ├── semantic/                    # NEW: Do/Don't examples run through Tier A hooks
│   └── coverage/                    # OWASP/CWE coverage analysis, semantic check
├── tools/
│   ├── rule-to-skill-converter.py   # mechanical v1 → v2 first pass; --strict mode
│   │                                # required for P1–P4
│   ├── tests/converter/golden/      # input rule files + expected SKILL.md output
│   ├── run_evals.py                 # RCS-compatible eval harness
│   └── lint_skills.py               # frontmatter validation
├── docs/
│   ├── standards-pin.yaml           # external standards version pins (OWASP, NIST,
│   │                                # MITRE) with publication dates and canonical URLs
│   ├── governance.md                # ownership, dispute resolution, update SLA,
│   │                                # release co-signing requirements
│   ├── superpowers/specs/
│   │   ├── 2026-05-24-cscr-modernization-design.md  # this file
│   │   └── 2026-05-24-cscr-amendment-01.md          # M1–M11 amendment
│   ├── how-to/
│   │   ├── install.md
│   │   ├── enable-hooks.md
│   │   ├── audit-cscr-pre-trust.md  # six-check audit applied to CSCR itself
│   │   ├── handle-rule-conflicts.md # org-wide carve-out via .cscr-allowlist.json
│   │   └── contribute-a-skill.md
│   └── explanation/
│       ├── three-layers.md
│       ├── enforcement-coverage.md  # per-hook CWE class, bypass classes, fallback layer
│       ├── converter-contract.md    # input grammar, output schema, idempotence rules
│       ├── sigma-score.md           # vendored from RCS
│       └── relationship-to-rcs.md
├── CLAUDE.md                        # project instructions
└── README.md                        # rewritten for plugin-install; honest-framing constraint
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

### Tier A — Strict blocking hooks (root-level, advisory-by-default in v2.0.0, strict-by-default in v2.1.0+)

Live at `hooks/hooks.json`. Fire on every PreToolUse for the relevant tool (Bash, Write, Edit), regardless of which skill is loaded. Exit 2 if the payload matches a high-confidence RCE/secret/deserialization pattern AND the user has enabled strict mode (see Default posture below).

**The 12 strict patterns** — each row names the AST-based call shapes covered AND the documented bypass classes that fall through to Layer 3:

| # | Pattern (call shapes covered) | Tools | Documented bypass classes |
|---|---|---|---|
| 1 | `eval(...)` / `exec(...)` / `compile(...)` on any non-literal arg (Python AST) | Write, Edit | `getattr(builtins, 'e'+'val')(...)` obfuscation; `__import__('builtins').eval(...)` |
| 2 | `pickle.loads`, `marshal.loads`, `yaml.load` w/o `SafeLoader`, `dill.loads`, `joblib.load` (AST) | Write, Edit | Custom deserialization wrappers; module-aliased imports |
| 3 | `subprocess.*`, `os.system`, `os.popen`, `os.exec*`, `pty.spawn`, `commands.getoutput` with shell=True + non-constant arg (AST) | Write, Edit | Multi-statement dataflow: `cmd = f"..."` then `subprocess.run(cmd, shell=True)` on later line |
| 4 | (Merged into #3 — `os.system` is part of the shell-execution AST check) | — | — |
| 5 | SQL execution: `execute`, `executemany`, `text`, `raw`, `query`, `sql.SQL` on any receiver with f-string/`.format()`/`%` arg (AST) | Write, Edit | Multi-statement dataflow; ORM `.raw()` with computed string from prior block |
| 6 | HTML injection: React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]`, Svelte `{@html}` with non-constant value (AST) | Write, Edit | Dynamic attribute name; computed expressions resolved at render time |
| 7 | `trust_remote_code=True` in transformers `from_pretrained` (AST, keyword-arg detection) | Write, Edit | Keyword forwarded via `**kwargs` dict |
| 8 | Hardcoded secrets: AWS keys, OpenAI keys, GitHub PATs, Stripe keys, private-key blocks (regex floor + entropy check) | Write, Edit | Base64-encoded; concatenation `"sk-" + "abcd..."`; loaded from a file |
| 9 | Pipe-to-shell: `curl ... \| sh`, `wget ... \| bash`, `iex (irm ...)` (Bash AST via shlex+pattern) | Bash | Tee-to-file then exec; download then chmod+exec sequence |
| 10 | `chmod 777` or `chmod a+rwx` on any path (Bash) | Bash, Write (shell scripts) | `chmod 0777` octal alias; per-bit `chmod +rwx,+rx,+rwx` |
| 11 | Unpinned installs: `pip install <pkg>` (no `==`), `npm install <pkg>@latest`, `uvx --from git+` without `@<ref>`, `curl \| sh` install scripts (Bash) | Bash | Cached package install from local index; offline install |
| 12 | `git push --force` / `--force-with-lease` targeting `main`/`master`/`release/*` (Bash AST) | Bash | Setting `push.default` to override; aliasing git via shell function |

**Pattern 8 (secrets) and Pattern 12 (force-push) are non-bypassable** — the escape hatch (M2 resolution) is rejected for these rules.

The merged Pattern 4 reduces the table to 11 enumerated patterns plus the merger note. The implementation still ships 12 hook scripts (the merger is logical, not file-level).

Each hook is one Python script under `hooks/enforcement/`. Stdin is the standard Claude Code hook JSON. Per-hook target ≤150ms; aggregate budget across 6 Write/Edit hooks ≤750ms, measured end-to-end by CI benchmark.

**Per-hook coverage docs.** Each hook ships with `hooks/enforcement/coverage/<hook-name>.md` enumerating exactly which call shapes are caught, which bypass classes are documented, and which Layer 3 skill is the fallback. The aggregate is `docs/explanation/enforcement-coverage.md`.

### Escape hatch (M2-hardened)

A bypass requires THREE conditions, not one:

1. **Inline marker with line-hash:** `# cscr:allow <rule-id>:<sha256-prefix-8>` (or `// cscr:allow N:HASH` / `<!-- cscr:allow N:HASH -->`) where the SHA-prefix is computed over the offending line plus a stable salt published with the plugin version. The hook computes the same hash; mismatch = block.
2. **Out-of-band allowlist registry:** `.cscr-allowlist.json` at the consuming project's root, owned by humans (not the model), lists permitted `(rule-id, file-path, line-hash)` tuples. A bypass that's NOT in `.cscr-allowlist.json` AND not matching its line-hash gets blocked.
3. **Non-bypassable rule deny-list:** Rules #8 (hardcoded secrets) and #12 (force-push to protected branches) are non-bypassable. The hook ignores `cscr:allow` for these.

**PR-diff gate (optional, for consuming projects).** A GitHub Action `cscr-allowlist-gate` blocks PRs that introduce new `cscr:allow` entries without a matching diff in `.cscr-allowlist.json`. Opt-in per consuming project.

**Bypass logging.** SessionEnd hook in the plugin writes any `cscr:allow` comments introduced during the session to `~/.claude/projects/<project>/cscr-bypass-log.jsonl`. Audited via `/cscr:audit-bypasses` skill.

### Default posture (M10-staged)

v2.0.0 ships `cscr.enforcement: "advisory"` by default. Hooks run in advisory mode (exit 0 with stderr warning) for the 30-day post-release window. v2.1.0 flips the default to `"strict"` (exit 2 = block) AFTER the project has received and addressed real-world false-positive reports.

First-run notice via SessionStart hook displays: "CSCR is in advisory mode. To enable blocking, set `cscr.enforcement: \"strict\"` in your project settings. See docs/how-to/enable-hooks.md."

Per-rule disable: users can set `cscr.rules.<rule-id>.enabled: false` to disable individual hooks while keeping the rest. The non-bypassable deny-list (rules #8 and #12) ignores this setting.

A telemetry-free FP feedback channel via `/cscr:report-false-positive` skill collects anonymized pattern data and opens a pre-filled GitHub issue. No silent telemetry.

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

| Threat | Layer that catches it | Bypass classes documented |
|---|---|---|
| Model directly outputs literal `eval(user_input)` (Python AST hit) | Tier A | Obfuscation via getattr/string-concat; multi-statement dataflow |
| Hardcoded API key written to source (Tier A pattern 8, non-bypassable) | Tier A | Base64; string concatenation; key loaded from a separately-written file |
| Force-push to main attempted via Bash (Tier A pattern 12, non-bypassable) | Tier A | Shell alias for `git`; modified `push.default` config (caught at Bash level) |
| FastAPI endpoint missing input validation | Tier B (advisory, contingent on skill activation) | Skill not loaded (no `.py` file open yet) |
| Terraform `aws_s3_bucket` left public | Tier B (advisory) | Skill not loaded; `paths:` glob miss in monorepo |
| SQL injection via multi-statement dataflow (`q = f"..."`; `cursor.execute(q)`) | Layer 3 skill text + recommended Semgrep rule | Tier A AST detects single-statement only |
| Defense-in-depth (security headers, logging) | Layer 3 skill text | Always advisory |
| Architectural choices (microservice trust boundaries) | Layer 3 skill text | Always advisory |

The per-hook `hooks/enforcement/coverage/<hook>.md` and the aggregate `docs/explanation/enforcement-coverage.md` enumerate the full bypass class set per pattern.

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

### Drift check (M9-hardened)

A CI job in CSCR clones RCS at a pinned commit SHA (not a tag, to avoid moving references), walks `skills/*/*/SKILL.md`, parses YAML frontmatter, and asserts that each skill `name:` referenced by CSCR's "see also" blocks exists in RCS. Same in reverse. The contract is the frontmatter `name:` field, which is stable by Anthropic Skills format definition. README-scraping is explicitly NOT used.

**Canonical slugs.** RCS's `applying-secure-coding-rules` skill specifies the exact plugin slug to install: `tikitribe-secure-coding-rules`, no abbreviations. CSCR's cross-pointer to RCS specifies `rocklambros/rcs` as the canonical repo. Both documented in `docs/explanation/relationship-to-rcs.md`. README's install section gives the marketplace slug with a sigstore identity to mitigate typo-squat risk.

**Content-hash check** is a v2.1 deliverable, not v2.0.0 — once the frontmatter `version:` contract stabilizes across both repos.

## Migration plan

**Branch model:** `v2/` branch hosts the rebuild. `main` stays on the current `rules/` layout until v2 is tagged. After v2.0.0 release, `main` switches to the v2 layout; the pre-v2 `main` head gets a `v1.x` tag for users who pin to it.

### Phased build on `v2/`

1. **P0 — Scaffolding.** `.claude-plugin/plugin.json` (with `hookScriptHashes`), repo restructure (`skills/`, `hooks/`, `evals/`), settings template, `tools/rule-to-skill-converter.py` (with `--strict` mode and golden tests), `SECURITY.md`, `docs/governance.md`, `docs/standards-pin.yaml`. CI updated.
2. **P0.5 — Corpus quality audit (M6).** Run every `Do` example through Tier A hooks (must pass); every `Don't` example through Tier A hooks (must block on the relevant rule). Failures get a manual review pass: fix the example or move the rule to Tier B / Layer 3. Acceptance: zero contradictions.
3. **P0.6 — Standards-currency audit (M7).** Verify every OWASP LLM Top 10 reference against the 2025 publication. Update `tests/coverage/test_coverage.py` to the 2025 list. Update rules citing deprecated mitigations (e.g., the FastAPI denylist-based prompt-injection defense at `rules/backend/fastapi/CLAUDE.md:440-451`).
4. **P1 — Core skills.** Convert `_core/*.md` to 6 skills (`applying-owasp-top-10`, `applying-ai-ml-security`, `applying-agentic-ai-security`, `applying-mcp-security`, `applying-rag-security`, `applying-graph-db-security`). Each with 4 evals (n≥5 adversarial probes per skill per M14 in the implementation plan). Converter runs in `--strict` mode.
5. **P2 — Language skills.** Convert `languages/**` to 12 skills. Each with 4 evals.
6. **P3 — Framework skills.** Convert `backend/**`, `frontend/**` to ~16 skills.
7. **P4 — Infra & RAG skills.** Convert `iac/**`, `containers/**`, `cicd/**`, `rag/**` to ~12 skills.
8. **P5 — Tier A hooks (AST-based per M3).** Author the 11 enumerated strict hook scripts (#4 merged into #3) with AST detection for language-aware patterns and regex floor for partial-edit fallback. pytest fixtures include known-FN payloads per hook. Per-hook ≤150ms, aggregate ≤750ms; CI benchmark gates. Per-hook coverage docs at `hooks/enforcement/coverage/<hook>.md` and aggregate `docs/explanation/enforcement-coverage.md`. Hook script hashes added to `.claude-plugin/plugin.json` `hookScriptHashes`. Escape-hatch mechanism (`# cscr:allow N:HASH` + `.cscr-allowlist.json`) implemented.
9. **P6 — Tier B hooks.** Add `hooks:` frontmatter to skills that warrant warnings (estimate ~15 skills, not all 42).
10. **P6.5 — Third-party held-out review (M11).** Hand a held-out vulnerable-code corpus (e.g., OWASP Benchmark v1.2 + curated CWE Top 25 set) to a named external reviewer. Test with and without CSCR loaded. Pre-register numerical claims. Publish results.
11. **P7 — Marketplace submission.** Submit to `claude-plugins-community`. Sigstore-attest the release; co-sign with the second key holder (or document why v2.0.0 ships with single-key signing as accepted residual risk). Update README. Tag v2.0.0.

### Backward compatibility

The `rules/` tree stays accessible from the `v1.x` git tag. The v2 README has a clear "Migrating from v1" section pointing to `/plugin install tikitribe-secure-coding-rules` and warning that the old `cp` flow is no longer maintained.

### Estimated scope

~42 skills × (SKILL.md + 4 evals + frontmatter) + 11 hook scripts + 11 hook test files (with known-FN fixtures) + 11 per-hook coverage docs + aggregate enforcement-coverage.md + plugin scaffolding + converter tool with golden tests + SECURITY.md + standards-pin.yaml + governance.md + third-party held-out review + sigstore release pipeline + CI updates. This is a multi-week project, not a single PR. The implementation plan (separate document) will name the work items so it is plannable.

## Risk register

| Risk | Mitigation |
|---|---|
| Converter produces low-quality SKILL.md (rule text was written for prose, not skill activation) | `--strict` mode (P0); golden-file tests; mechanical convert + manual `description`/`when_to_use` pass per skill. Use RCS-quality descriptions as the bar. |
| Tier A false positives on legitimate test fixtures | M2-hardened escape hatch (`# cscr:allow N:HASH` + `.cscr-allowlist.json`); advisory-by-default for 30 days post-release (M10); evals include FP cases. |
| Skill description truncation at 1,536 chars | Convention: first sentence = trigger phrase, second = the controls. Lint check in CI. |
| Community-marketplace review delay | Submit early on `v2/` branch with a preview tag; users can install via `--plugin-dir` while waiting. |
| Drift between RCS and CSCR cross-references | CI drift-check, frontmatter-parsed, pinned-SHA per M9. |
| Hook script performance overhead | AST hooks per M3; per-hook ≤150ms, aggregate ≤750ms across 6 Write/Edit hooks. CI benchmark gates end-to-end aggregate, not per-hook isolated. |
| Plugin enabling hooks by default surprises users | M10 staged rollout: advisory in v2.0.0, strict in v2.1.0 after public FP postmortem. First-run notice via SessionStart. |
| **(NEW) Marketplace push or maintainer-credential compromise** | M4: sigstore-attested releases; `hookScriptHashes` in plugin manifest verified at load; `docs/how-to/audit-cscr-pre-trust.md` six-check audit; second-key-holder requirement for releases. |
| **(NEW) Outcome metric refutation in third-party review** | M11: honest release-note language documenting what was measured AND what was NOT improved; README claims updated to match the measured uplift. Refutation does not block release. |
| **(NEW) Escape-hatch bypass via model-emitted comment** | M2: three-condition bypass (inline marker with line-hash + out-of-band allowlist registry + non-bypassable rule deny-list for #8 and #12); SessionEnd bypass logging. |
| **(NEW) Multi-statement dataflow false negatives in AST hooks** | M3: explicitly named as out-of-scope for Tier A; documented in `enforcement-coverage.md`; Layer 3 skill + recommended Semgrep rule covers the gap. |
| **(NEW) Standards drift (OWASP / NIST / MITRE rev superseded)** | M7: `docs/standards-pin.yaml` machine-readable version pins; monthly CI check opens issue on supersession; 90-day update SLA documented in governance.md. |

## Open questions for implementation phase

None blocking the design. Items deferred to implementation:

- Exact `paths:` glob per skill (TS/TSX overlap, monorepo-friendly patterns).
- Whether the converter tool runs at CI-time (deterministic build) or only as a one-shot migration helper (looser).
- Whether to ship a `--cscr-baseline` Bash flag wrapper that pre-pipes existing `npx`/`uvx` commands through pin-checking — out of scope for v2.0.0, candidate for v2.1.

## Success criteria

v2.0.0 ships when ALL of the following are true:

1. Plugin is installable from the community marketplace as `/plugin install tikitribe-secure-coding-rules`.
2. All ~42 skills have 4 passing evals each (with n≥5 adversarial probes per skill per the implementation plan).
3. All 11 Tier A hooks have passing unit tests AND per-hook coverage docs at `hooks/enforcement/coverage/<hook>.md` enumerate covered call shapes and known bypass classes.
4. The CI drift-check against RCS passes (frontmatter-parsed, pinned-SHA).
5. README's "Migrating from v1" section is in place.
6. **(Revised)** Total p95 per-session loaded skill size, measured by a representative AI/ML+FastAPI test fixture, is less than the v1 baseline. Not a fuzzy "small factor."
7. **(New, M1+M11)** `docs/explanation/enforcement-coverage.md` exists and is reviewed by a named third party; README contains no enforcement verbs (`enforce`, `block`, `refuse`) outside Tier A scope; pre-registered third-party held-out review is complete with results published in release notes.
8. **(New, M5)** `SECURITY.md` exists, has been smoke-tested by an external reporter, and the contact channel works.
9. **(New, M4)** Release is sigstore-attested; hook-script hashes are pinned in `.claude-plugin/plugin.json`; `docs/how-to/audit-cscr-pre-trust.md` documents the six-check audit applied to CSCR itself.
