# tikitribe-secure-coding-rules v2 Modernization Design

**Status:** Approved design with Amendments 01 and 02 applied, ready for implementation planning (pending Rock's decision on Round 3 vs design retrospective)
**Date:** 2026-05-24 (Amendments 01 and 02 applied 2026-05-24)
**Author:** Rock Lambros
**Plugin name:** `tikitribe-secure-coding-rules`
**Target version:** v2.0.0
**Amendment history:**
- Amendment 01 — resolved Round 1 premortem findings M1–M11 (false-confidence reframing, escape-hatch hardening, AST hooks, supply-chain controls, SECURITY.md+VDP, corpus-quality audit, standards pinning, converter contract, cross-pointer hardening, staged hook rollout, outcome metrics). See `2026-05-24-cscr-amendment-01.md`.
- Amendment 02 — resolved Round 2 Critical findings N1–N7 (AST→regex fail-secure, escape-hatch salt moved out of tree, allowlist moved out of tree, hash-pinning removed in favor of user-runnable `cscr verify`, sigstore single-signer disclosure, `cscr.enforcement` setting user-level only). Honest-framing constraint extended to supply-chain verbs. See `2026-05-24-cscr-amendment-02.md`.

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

**Honest-framing constraint.** The README and any user-facing copy may use enforcement verbs (`enforce`, `block`, `refuse`) only when describing Tier A hooks AND only for the bypass classes documented in `enforcement-coverage.md`. Layer 2 and Layer 3 use `advises`, `loads guidance for`, `documents`. Supply-chain verbs (`co-signed`, `attested`, `verified`, `hash-pinned`) require explicit per-release accuracy review — single-signer releases cannot claim "co-signed," releases without runtime verification cannot claim "verified," etc. A CI lint over README.md and docs/ flags both enforcement and supply-chain verbs in unsupported contexts.

## Repository layout (v2)

```
claude-secure-coding-rules/
├── .claude-plugin/
│   └── plugin.json                  # name, version, author, marketplace metadata,
│                                    # hookScriptHashes map (forward-compatible only — no
│                                    # runtime verification until Claude Code adds native
│                                    # support; see Amendment 02 N5)
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
│   ├── lint_skills.py               # frontmatter validation
│   ├── cscr-verify.py               # user-runnable supply-chain audit:
│   │                                # recompute hook hashes, fetch sigstore bundle,
│   │                                # compare. PASS/FAIL. (Amendment 02 N5)
│   ├── cscr-hash.py                 # generate line-hash for `cscr:allow` comments,
│   │                                # reads ~/.cscr/installation-salt (Amendment 02 N2)
│   └── cscr-allowlist.py            # CLI: add/remove/list entries in
│                                    # ~/.cscr/allowlists/<project-hash>.json
│                                    # (Amendment 02 N3)
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

**Out-of-tree state (Amendment 02 N2, N3, N7).** The plugin stores three categories of state outside the project tree to prevent the model from modifying its own enforcement parameters:

```
~/.cscr/                             # chmod 700, user-only
├── installation-salt                # 256-bit random, generated on first run
└── allowlists/
    └── <project-hash>.json          # per-project escape-hatch entries,
                                     # managed via `cscr allowlist` CLI
```

The plugin's `settings-template.json` includes deny rules `Read(~/.cscr/**)` and `Write(~/.claude/**)` — these are load-bearing for the bypass-prevention claim. Users who do not merge the template explicitly accept the residual risk that the model could read the salt or rewrite enforcement settings.

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

Each hook is one Python script under `hooks/enforcement/`. Stdin is the standard Claude Code hook JSON. Per-hook target ≤150ms; aggregate budget across 6 Write/Edit hooks ≤750ms, measured end-to-end by CI benchmark. (Note: this budget holds on GHA Linux runners; per-platform variance — Windows-with-Defender, M-series cold Python start, corporate EDR — is documented in `hooks/enforcement/coverage/latency.md` and deferred to Amendment 03 N9 for the cross-platform mitigation.)

**Per-hook coverage docs.** Each hook ships with `hooks/enforcement/coverage/<hook-name>.md` enumerating exactly which call shapes are caught, which bypass classes are documented, and which Layer 3 skill is the fallback. The aggregate is `docs/explanation/enforcement-coverage.md`.

**Edit-mode AST handling (Amendment 02 N1).** Edit calls deliver deltas (`old_string`/`new_string`), not full content. The hook reads the current file from disk, applies the diff in memory (`new_content = file_content.replace(old_string, new_string, 1)`), then parses the result. The TOCTOU window between hook read and Claude Code write is documented in each per-hook coverage doc.

**Fail-secure on AST regression (Amendment 02 N1).** If `ast.parse` fails on the post-edit content AND the pre-edit file parsed successfully, the hook blocks the edit with stderr: "CSCR cannot validate this edit: post-edit AST parse failed. Apply the edit in smaller fragments or fix the syntax error first." This converts the attacker's "introduce a parse error to fall through to weaker checks" technique into a self-DoS the user notices. For new files (no pre-edit state), AST failure plus any regex-floor match also blocks; the regex never silently passes.

### Escape hatch (Amendment 02 N2 + N3)

A bypass requires THREE conditions, none of which the model can satisfy unaided:

1. **Inline marker with line-hash:** `# cscr:allow <rule-id>:<sha256-prefix-8>` (or `// cscr:allow N:HASH` / `<!-- cscr:allow N:HASH -->`) where the SHA-prefix is computed over the offending line plus a **per-installation salt** stored at `~/.cscr/installation-salt` (chmod 600, user-only). The hook computes the same hash; mismatch = block. The user generates the hash by running `cscr-hash <line>` from their terminal — the salt is never read by code the model controls.
2. **Out-of-tree allowlist registry:** The allowlist lives at `~/.cscr/allowlists/<project-hash>.json`, NOT at the project root. The model has no default Read or Write to `~/.cscr/`. Entries are added via `cscr allowlist add <rule-id> <file> <line>` run by the user in their terminal.
3. **Non-bypassable rule deny-list:** Rules #8 (hardcoded secrets) and #12 (force-push to protected branches) are non-bypassable. The hook ignores `cscr:allow` for these.

**Settings-template deny rules are load-bearing.** The plugin's `settings-template.json` includes `Read(~/.cscr/**)`. Users who merge the template get the rule. Users who don't merge accept the residual risk that a permission-rule-light Claude Code session could grant the model Read access to the salt and the allowlist, at which point the bypass-prevention claim degrades.

**Honest claim narrowing.** The bypass is defeated against a model running in default-permission Claude Code sessions where `~/.cscr/` is not in the model's Read scope. A model with global Read (e.g., `bypassPermissions` mode, or a project granting `Read(~/**)`) can still compute the hash. This is documented in `docs/explanation/three-layers.md`.

**PR-diff gate (optional, now hygiene rather than load-bearing).** A GitHub Action `cscr-allowlist-gate` flags PRs that modify the local `.cscr-allowlist-changes.log` (audit log of allowlist edits made via the CLI). Opt-in per consuming project. With the out-of-tree allowlist (item 2), this gate is now documentation hygiene rather than the only defense against in-tree injection.

**Bypass logging (Amendment 02 N5).** SessionEnd hook in the plugin writes any `cscr:allow` comments introduced during the session to `~/.cscr/logs/<project-hash>.jsonl`. The same out-of-tree permission discipline applies. (Amendment 03 N8 will further harden against abnormal termination via a heartbeat write at SessionStart.)

### Default posture (Amendment 02 N7)

v2.0.0 ships `cscr.enforcement: "advisory"` by default. Hooks run in advisory mode (exit 0 with stderr warning) for the 30-day post-release window. v2.1.0 flips the default to `"strict"` (exit 2 = block) AFTER the strict-flip threshold is met (Amendment 03 N18 will define the threshold concretely; the v2.0.0 placeholder is "after the project has received and addressed real-world false-positive reports").

**`cscr.enforcement` setting is honored only from user-level settings** (`~/.claude/settings.json`), NOT from project-level settings. The model has no default `Write(~/.claude/**)` permission, so it cannot flip a project from strict to advisory by writing project settings. When the hook detects a project-level `cscr.enforcement` setting, it emits stderr: "CSCR enforcement mode is set at the user level, not the project level. Project-level setting ignored." This is load-bearing for the non-bypassable claim on rules #8 and #12.

The `settings-template.json` includes `Write(~/.claude/**)` as a deny rule. Users who don't merge the template, or who explicitly grant the model that permission, accept the residual risk.

First-run notice via SessionStart hook displays: "CSCR is in advisory mode. To enable blocking, set `cscr.enforcement: \"strict\"` in your user-level `~/.claude/settings.json`. See docs/how-to/enable-hooks.md."

Per-rule disable: users can set `cscr.rules.<rule-id>.enabled: false` in user-level settings to disable individual hooks while keeping the rest. The non-bypassable deny-list (rules #8 and #12) ignores this setting AND ignores `cscr.enforcement: "advisory"` — they always block.

**Honest claim narrowing for non-bypassable.** Rules #8 and #12 cannot be disabled by a model with default permissions in a Claude Code session. They can be disabled by a user with shell access to `~/.claude/settings.json` AND who has merged the CSCR settings template. Users who have not merged the template, or who have granted the model `Write(~/.claude/**)`, accept the residual risk.

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
11. **P7 — Marketplace submission.** Submit to `claude-plugins-community`. Sigstore-attest the release with the single maintainer key. Co-signing is a v2.x.0 milestone, explicitly disclosed in release notes and `docs/governance.md` as not-yet-implemented. Publish `cscr verify` CLI for user-runnable supply-chain audit. Update README per honest-framing constraint (no claims of "co-signed" or "verified" without per-release accuracy review). Tag v2.0.0.

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
| **(NEW) Marketplace push or maintainer-credential compromise** | M4 + Amendment 02 N5/N6: sigstore-attested releases (single-signer at v2.0.0, co-signed in a v2.x milestone); user-runnable `cscr verify` CLI for post-install hash audit; `docs/how-to/audit-cscr-pre-trust.md` six-check audit. No runtime hash verification until Claude Code adds native support — disclosed explicitly. |
| **(NEW) Outcome metric refutation in third-party review** | M11: honest release-note language documenting what was measured AND what was NOT improved; README claims updated to match the measured uplift. Refutation does not block release. |
| **(NEW) Escape-hatch bypass via model-emitted comment** | M2 + Amendment 02 N2/N3: three-condition bypass with per-installation salt (`~/.cscr/installation-salt`) and out-of-tree allowlist (`~/.cscr/allowlists/<project-hash>.json`); model has no default Read to `~/.cscr/` when settings-template is merged. SessionEnd bypass logging written to `~/.cscr/logs/`. Defeated only against models in default-permission sessions; documented residual risk for `bypassPermissions` or `Read(~/**)` configurations. |
| **(NEW, Amendment 02 N7) Model rewrites `cscr.enforcement` to advisory in project settings** | `cscr.enforcement` honored only from `~/.claude/settings.json` (user-level); project-level setting ignored with stderr warning. Settings template includes `Write(~/.claude/**)` deny rule. Non-bypassable rules (#8, #12) ignore advisory mode entirely. |
| **(NEW, Amendment 02 N1) Attacker controls AST→regex fallback via mid-edit syntax errors** | Fail-secure on AST regression: if pre-edit file parsed but post-edit does not, block with stderr explanation. Read-file-apply-diff-parse pattern for Edit calls. Regex floor never silently passes; blocks plus emits match as hint. |
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
7. **(Revised, M1+M11+Amendment 02 N6)** `docs/explanation/enforcement-coverage.md` exists and is reviewed by a named third party; README contains no enforcement verbs (`enforce`, `block`, `refuse`) outside Tier A scope AND no supply-chain verbs (`co-signed`, `attested`, `verified`, `hash-pinned`) without explicit per-release accuracy review; pre-registered third-party held-out review is complete with results published in release notes.
8. **(New, M5)** `SECURITY.md` exists, has been smoke-tested by an external reporter, and the contact channel works.
9. **(Revised, Amendment 02 N5+N6)** Release is sigstore-attested with a single maintainer key; `cscr verify` CLI command exists and produces clear PASS/FAIL output; `docs/how-to/audit-cscr-pre-trust.md` documents the six-check audit applied to CSCR itself. Co-signing is a v2.x.0 milestone, explicitly disclosed as not-yet-implemented in release notes.
10. **(New, Amendment 02 N2+N3+N7)** `settings-template.json` includes deny rules for `Read(~/.cscr/**)` and `Write(~/.claude/**)`; `cscr-hash` and `cscr allowlist` CLIs exist; the README and SECURITY.md document these as load-bearing for the bypass-prevention and non-bypassable claims; users who do not merge the template are explicitly told they accept the residual risk.
