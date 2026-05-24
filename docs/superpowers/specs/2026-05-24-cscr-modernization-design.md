# tikitribe-secure-coding-rules v2 Modernization Design

**Status:** Approved design (post-retrospective), ready for fresh single-round premortem, then implementation planning
**Date:** 2026-05-24 (architecture revised 2026-05-24 after two-round premortem)
**Author:** Rock Lambros
**Plugin name:** `tikitribe-secure-coding-rules`
**Target version:** v2.0.0
**Architecture:** Option B with BYOH (Bring-Your-Own-Hooks) per `2026-05-24-cscr-design-retrospective.md`
**Prior documents (superseded but retained for context):**
- `2026-05-24-cscr-amendment-01.md` — resolved Round 1 findings (catalog quality, RCS congruence, governance, supply chain) — most resolutions carry forward
- `2026-05-24-cscr-amendment-02.md` — resolved Round 2 Critical findings against the hooks-shipped-in-plugin architecture — superseded by the architectural shift to BYOH
- `2026-05-24-cscr-design-retrospective.md` — step-back analysis and B+BYOH decision

## Purpose

Convert `claude-secure-coding-rules` (CSCR) from a `cp`-distributed library of always-on CLAUDE.md rule files into a Claude Code plugin built on the 2026-era platform primitives: skills (description-matched, path-scoped, on-demand loading), permission rules (declarative deny), and the community plugin marketplace.

The v1 problems v2 fixes:
1. **`Level: strict` was advisory prose, not enforcement.** v2 is honest about this: enforcement comes from the platform's permission rules and (optionally) from user-installed hooks the user adopts after reading their coverage docs.
2. **8,800+ lines in `_core/` alone** burned the user's context window on every session. v2 path-scopes skills so most sessions load only 2-4 of the 42 skills.
3. **`cp`-based distribution.** v2 ships via the community marketplace as a single `/plugin install` command.

## Non-goals

- v2 is not a deterministic enforcement plugin. The two-round adversarial premortem demonstrated that a plugin layer cannot reliably enforce against an agent that controls the inputs to the enforcement check. v2 ships an optional hooks reference library for users who want to operate enforcement on their own infrastructure with their own threat model — but the *plugin itself* does not run code in the user's session by default.
- v2 is not a methodology repo. RCS owns that lane. CSCR stays a catalog of framework-specific controls.
- v2 does not bundle SAST runners. Existing `tests/` Semgrep/Bandit integration validates rule examples; production SAST stays the user's responsibility.

## Architecture

Three layers, ranked by where enforcement actually lives:

| Layer | Mechanism | Who runs it | What it covers |
|---|---|---|---|
| 1. Platform-level enforcement | Claude Code permission rules in user/project `settings.json` | The Claude Code harness, deterministically | File paths (`.env`, `secrets/**`), command patterns (`curl \| sh`, force-push targeting `main`/`master`), MCP allow/deny, sandbox config |
| 2. Optional user-installed hooks | Reference Python scripts in `hooks/optional/`, installed into user's `~/.claude/hooks/cscr/` via `cscr hooks install` | The user's own Claude Code session, after explicit opt-in | Documented per-script: Bash-level patterns (force-push, curl-pipe-sh, chmod 777, unpinned installs), with per-script bypass-class docs |
| 3. Skills (advisory) | `SKILL.md` loaded on description match and `paths:` glob | Claude during a session | Framework idioms, defense-in-depth, the rest of the catalog |

The plugin itself ships:
- Layer 1: `settings-template.json` users merge into their own settings
- Layer 2: inert reference scripts in `hooks/optional/` (the user copies the ones they want into their own config; nothing CSCR ships runs automatically)
- Layer 3: ~42 skills

**Honest-framing constraint.** The README and user-facing copy may use enforcement verbs (`enforce`, `block`, `refuse`) only in two contexts: (a) describing Claude Code's permission rules (the platform enforces, not CSCR), or (b) describing a specific hook in the optional library when paired with that hook's documented coverage. Layer 3 uses `advises`, `loads guidance for`, `documents`. A CI lint over README.md and docs/ flags violations.

## Repository layout

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
├── settings-template.json           # platform-level permission rules,
│                                    # merged into user/project settings via cscr-configure
├── hooks/optional/                  # reference implementations — NOT loaded by default
│   ├── README.md                    # WHEN to adopt, WHY each is opt-in,
│   │                                # what each does NOT catch
│   ├── _examples/                   # escape-hatch patterns, allowlist patterns
│   ├── block-force-push-protected.py
│   ├── block-curl-pipe-sh.py
│   ├── block-chmod-777.py
│   ├── block-unpinned-installs.py
│   ├── block-hardcoded-secrets.py
│   ├── block-eval-failsecure.py
│   ├── block-pickle-loads.py
│   ├── ...                          # ~11-15 reference scripts
│   ├── coverage/                    # per-hook bypass-class docs
│   │   ├── block-force-push-protected.md
│   │   ├── block-curl-pipe-sh.md
│   │   └── ...
│   └── bundles/                     # curated install groups
│       ├── bash-only.json           # only Bash-side patterns the model can't easily route around
│       ├── ai-ml-stack.json         # hooks relevant to LangChain/RAG/MCP work
│       └── full.json                # everything, with documented residual risk
├── SECURITY.md                      # VDP, reporting channel, disclosure policy
├── tests/
│   ├── hooks/                       # pytest unit tests for each reference hook script
│   ├── structural/                  # rule-format tests, adapted to SKILL.md
│   ├── semantic/                    # Do/Don't examples evaluated against the reference
│   │                                # hooks, validates corpus-to-hook consistency
│   └── coverage/                    # OWASP/CWE coverage analysis (semantic check)
├── tools/
│   ├── rule-to-skill-converter.py   # mechanical v1 → v2 first pass; --strict mode
│   ├── tests/converter/golden/      # golden-file converter tests
│   ├── run_evals.py                 # RCS-compatible eval harness
│   ├── lint_skills.py               # frontmatter validation
│   ├── cscr-configure.py            # interactive: merge settings-template into user/project
│   ├── cscr-hooks.py                # install / update / list / remove user-local hooks
│   └── cscr-verify.py               # verify plugin install: sigstore signature + skill hashes
├── docs/
│   ├── standards-pin.yaml           # external standards version pins
│   ├── governance.md                # ownership, dispute resolution, update SLA,
│   │                                # release co-signing roadmap
│   ├── superpowers/specs/           # design docs, amendments, retrospective
│   ├── how-to/
│   │   ├── install.md
│   │   ├── enable-optional-hooks.md # CENTRAL doc for BYOH adoption
│   │   ├── write-your-own-hook.md   # teaches hook authorship
│   │   ├── audit-cscr-pre-trust.md  # six-check audit applied to CSCR itself
│   │   ├── handle-rule-conflicts.md # org-wide carve-outs for regulated environments
│   │   └── contribute-a-skill.md
│   └── explanation/
│       ├── three-layers.md          # catalog + template + opt-in user-hooks
│       ├── why-hooks-are-opt-in.md  # references the two premortem rounds
│       ├── enforcement-coverage.md  # per-mechanism coverage and bypass classes
│       ├── converter-contract.md
│       ├── sigma-score.md           # vendored from RCS
│       └── relationship-to-rcs.md
├── CLAUDE.md                        # project instructions
└── README.md                        # honest-framing constraint; positions CSCR as
                                     # catalog + platform-configurator + reference hooks
```

## Skills catalog

The catalog is the primary value of v2. Each rule domain becomes one skill directory. The conversion principle: a CLAUDE.md rule file becomes a SKILL.md with frontmatter that scopes loading (`paths:`, `description`, `when_to_use`), a body that teaches the patterns, and bundled `reference/` files for deep dives.

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
    └── 04-adversarial/        # multiple adversarial probes per skill
        ├── 01.json
        ├── 02.json
        ├── 03.json
        ├── 04.json
        └── 05.json
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

The `paths:` field is the key context-budget win. The python skill no longer loads when editing Terraform. Most sessions load 2-4 skills, not all 42.

### Catalog mapping (current → v2)

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
| `languages/{go,rust,java,csharp,ruby,r,cpp,julia,sql}/CLAUDE.md` | one skill each | 12-16 |
| `backend/fastapi/CLAUDE.md` | `fastapi-security` | 17 |
| `backend/{express,django,flask,nestjs}/CLAUDE.md` | one skill each | 14-17 |
| `backend/{langchain,crewai,autogen,transformers,vllm,triton,torchserve,ray-serve,bentoml,mlflow,modal}/CLAUDE.md` | one skill each | 13-18 |
| `frontend/{react,nextjs,vue,angular,svelte}/CLAUDE.md` | one skill each | 14-17 |
| `rag/**` | grouped: `rag-orchestration-security`, `rag-vector-store-security`, `rag-graph-security`, `rag-document-processing-security`, `rag-embeddings-security`, `rag-chunking-security`, `rag-observability-security` | 14-18 |
| `iac/{terraform,pulumi}/CLAUDE.md` | one skill each | 17 |
| `containers/{docker,kubernetes,helm}/CLAUDE.md` | one skill each | 17 |
| `cicd/{github-actions,gitlab-ci}/CLAUDE.md` | one skill each | 16 |

Total: ~42 skills.

### Naming convention

- Active-voice gerund (`applying-owasp-top-10`) where the skill *does* something or applies a standard
- `<domain>-security` (`python-security`, `fastapi-security`) where the skill encodes a reference catalog for that domain

The split is the seam between RCS (methodology, verb-first) and CSCR (catalog, domain-first).

### Namespacing

Skills are invoked as `/tikitribe-secure-coding-rules:python-security`. They auto-load via description match without users typing the namespace; explicit invocation uses the full path.

## Layer 1: Platform-level permission rules

CSCR ships `settings-template.json` containing permission rules the user merges into their own `~/.claude/settings.json` (or project-level `.claude/settings.json`). The template is the *only* layer of CSCR-shipped enforcement that runs by default — and it runs in the platform, not in a CSCR-shipped hook.

### What the template covers

```json
{
  "permissions": {
    "deny": [
      "Read(./.env)",
      "Read(./.env.*)",
      "Read(**/secrets/**)",
      "Read(**/.aws/credentials)",
      "Read(**/.ssh/id_*)",
      "Read(**/.ssh/*_rsa)",
      "Edit(./.env)",
      "Edit(./.env.*)",
      "Write(./.env)",
      "Write(./.env.*)",
      "Bash(curl * | sh)",
      "Bash(curl * | bash)",
      "Bash(wget * | sh)",
      "Bash(wget * | bash)",
      "Bash(git push --force main)",
      "Bash(git push --force master)",
      "Bash(git push --force-with-lease main)",
      "Bash(git push --force-with-lease master)",
      "Bash(rm -rf /)",
      "Bash(rm -rf ~)",
      "Bash(rm -rf $HOME)"
    ]
  }
}
```

These are deterministic at the platform level. The user merges them once via `cscr configure --interactive` (which explains each rule and lets the user opt out per-rule).

### What the template does NOT cover

Permission rules can express file paths and command shapes, but not Python AST patterns or content inspection. The template cannot block `eval(user_input)` in a Write payload — that requires content inspection, which lives in Layer 2 (optional user hooks) or Layer 3 (skill text). The `enforcement-coverage.md` doc enumerates this honestly.

## Layer 2: Optional reference hooks (BYOH)

The plugin ships ~11-15 reference Python scripts in `hooks/optional/`. They are inert files until the user adopts them. The user opts in per-script or per-bundle.

### What ships in the reference library

Each script has a one-purpose name and a per-script coverage doc. Examples:

| Reference script | What it catches | What it does NOT catch (per coverage doc) |
|---|---|---|
| `block-force-push-protected.py` | Bash `git push --force` / `--force-with-lease` to `main`/`master`/`release/*` | Force push via shell function alias; modified `push.default` config |
| `block-curl-pipe-sh.py` | Bash `curl ... \| sh`, `wget ... \| bash`, `iex (irm ...)` | Download-then-chmod-exec sequence; tee-then-exec |
| `block-chmod-777.py` | `chmod 777`, `chmod a+rwx` | `chmod 0777` octal alias (caught by extended variant) |
| `block-unpinned-installs.py` | `pip install <pkg>` without `==`, `npm install <pkg>@latest`, `uvx --from git+` without `@<ref>` | Offline install from cached package; manual download then install |
| `block-hardcoded-secrets.py` | AWS keys, OpenAI keys, GitHub PATs, Stripe keys, private-key blocks (regex + entropy) | Base64-encoded; concatenation `"sk-" + "abcd..."`; loaded from a separately-written file |
| `block-eval-failsecure.py` | Python `eval(...)` / `exec(...)` / `compile(...)` on non-literal args, with fail-secure on AST parse regression | Obfuscation via `getattr(builtins, 'e'+'val')(...)` |
| `block-pickle-loads.py` | `pickle.loads`, `marshal.loads`, `yaml.load` without `SafeLoader`, `dill.loads` | Custom deserialization wrappers; module-aliased imports |

Each script's coverage doc is the trust artifact. The user reads it before opting in.

### Bundles

`hooks/optional/bundles/` provides curated install groups:

- **`bash-only.json`** — the Bash-level patterns the model can't easily route around (force-push, curl-pipe-sh, chmod 777, unpinned installs). Lowest false-positive risk. Recommended starting point.
- **`ai-ml-stack.json`** — hooks relevant to LangChain/RAG/MCP work (pickle, hardcoded API keys, trust_remote_code variants).
- **`full.json`** — everything, with explicit documentation of residual risk per script.

### The `cscr hooks` CLI

```bash
# List available reference hooks with coverage summaries
cscr hooks list

# Install a single hook (copies script to ~/.claude/hooks/cscr/,
# adds entry to ~/.claude/settings.json, prints coverage doc inline)
cscr hooks install block-force-push-protected

# Install a bundle
cscr hooks install --bundle bash-only

# Update installed hooks (diff-review before overwrite)
cscr hooks update

# Remove a hook
cscr hooks remove block-force-push-protected

# Show currently installed and where they came from
cscr hooks status
```

### Trust model under BYOH

The user owns runtime trust:

1. **Plugin install** (sigstore-attested, single-signer at v2.0.0) ships inert reference scripts the user can read. Compromise window for the plugin is adoption-time, not every PreToolUse.
2. **`cscr hooks install`** is an explicit user action. The user reads the coverage doc inline before the script is copied into their config.
3. **User-local hooks** live in `~/.claude/hooks/cscr/`. The user can audit, modify, or remove them at any time. Updates are diff-reviewed before overwrite.
4. **CSCR cannot make claims** about what the user's hooks do, because the user owns them. CSCR's coverage docs describe the *reference implementation*; the user's modified copy may differ.

### Why hooks are opt-in (referenced in `docs/explanation/why-hooks-are-opt-in.md`)

Two adversarial premortem rounds against an earlier design that shipped hooks as active components surfaced 11 cumulative Critical findings. The pattern: each cryptographic or operational hardening of the hook layer introduced a new attack surface inside the same threat model. The root cause is structural — a plugin layer cannot deterministically enforce against an agent that controls the inputs to the enforcement check. BYOH moves the trust decision to the user, who knows their threat model better than CSCR can.

## Eval discipline

Every shipped skill carries 4 evals under `skills/<name>/evals/`. The eval count is concrete:

```
evals/
├── 01-happy-path.json          # 1 scenario
├── 02-edge-case.json           # 1 scenario
├── 03-anti-trigger.json        # 1 scenario
└── 04-adversarial/             # ≥5 scenarios per skill
    ├── 01.json
    ├── 02.json
    ├── 03.json
    ├── 04.json
    └── 05.json
```

The total per skill is 8 eval scenarios (1 + 1 + 1 + 5). Each adversarial scenario is scored independently. The "shipped" bar is: all 8 pass.

| File | Purpose | Pass condition |
|---|---|---|
| `01-happy-path.json` | User asks for the secure pattern in-scope | Model produces canonical secure pattern and cites the rule |
| `02-edge-case.json` | Ambiguous / boundary scenario | Model flags the gating rule and applies it or asks the user to disambiguate |
| `03-anti-trigger.json` | Adjacent but unrelated request | Skill stays dormant |
| `04-adversarial/0N.json` | Prompt-injection-flavored request to produce the insecure pattern (N=5 variants per skill) | Model refuses and cites the rule (or the user has installed the relevant optional hook, in which case the hook blocks AND the model cites the rule) |

Hook reference scripts get separate pytest unit tests under `tests/hooks/` with malicious-payload fixtures, including documented bypass-class probes (so the test confirms what the coverage doc says).

Schema mirrors RCS so RCS's `tools/run_evals.py` harness is reusable. PRAGMATIC discipline applies: Sonnet-only by default, full 3-model optional. Implementation plan covers Haiku stratification for top-Σ skills.

## Relationship to RCS

| Dimension | RCS | CSCR v2 |
|---|---|---|
| Content lane | Methodology (verb-named, decision-tree) | Catalog (framework-specific, reference) |
| Skill naming | `verb-noun` (`enforcing-seed-hygiene`) | `<domain>-security` for catalog + `applying-<standard>` for core |
| Skill format | Anthropic Skills format | Identical |
| Install path | Symlink from clone or community marketplace | `/plugin install` from marketplace |
| Eval shape | 3 JSON evals | 3 + adversarial (n≥5) |
| Sigma scoring | Yes (1-20) | Yes (vendored rubric) |
| Plugin-shipped executable code | None | None (reference hooks are inert files; user opts in) |
| Governance | Per-skill SemVer + repo integration tags | Same |

### The cross-pointer

RCS's `applying-secure-coding-rules` skill names CSCR as the corpus. CSCR's AI/ML skills (`applying-ai-ml-security`, `langchain-security`, `applying-mcp-security`) cite RCS skills like `auditing-train-test-split`, `threat-modeling-llm-app`, and `auditing-mcp-server-pre-trust` for the methodology side.

### Drift check

CI job clones RCS at a pinned commit SHA, walks `skills/*/*/SKILL.md`, parses YAML frontmatter, asserts that each skill `name:` referenced by CSCR's "see also" blocks exists in RCS. Same in reverse. README scraping is explicitly NOT used.

## Migration plan

**Branch model:** `v2/` branch hosts the rebuild. `main` stays on the current `rules/` layout until v2 is tagged. After v2.0.0 release, `main` switches to the v2 layout; pre-v2 head gets a `v1.x` tag for users who pin to it.

### Phased build on `v2/`

1. **P0 — Scaffolding.** `.claude-plugin/plugin.json`, repo restructure, `tools/rule-to-skill-converter.py` (with `--strict` mode and golden tests), `SECURITY.md`, `docs/governance.md`, `docs/standards-pin.yaml`. CI updated.
2. **P0.5 — Corpus quality audit.** Every `Do` example in `rules/` is reviewed against current standards. Every `Don't` example is verified to actually contain the vulnerable pattern. Deprecated mitigations (e.g., the FastAPI denylist-based prompt-injection defense at `rules/backend/fastapi/CLAUDE.md:440-451`) are rewritten before conversion. The converter `--strict` mode refuses to process any rule whose audit fails.
3. **P0.6 — Standards-currency audit.** OWASP LLM Top 10 references updated from v1.1 (2023) to 2025 numbering. `tests/coverage/test_coverage.py` updated to 2025 list. `docs/standards-pin.yaml` populated with version, publication date, canonical URL for each cited standard.
4. **P1 — Core skills.** Convert `_core/*.md` to 6 skills (`applying-owasp-top-10`, `applying-ai-ml-security`, `applying-agentic-ai-security`, `applying-mcp-security`, `applying-rag-security`, `applying-graph-db-security`). Each with 8 evals (1+1+1+5).
5. **P2 — Language skills.** Convert `languages/**` to 12 skills.
6. **P3 — Framework skills.** Convert `backend/**`, `frontend/**` to ~16 skills.
7. **P4 — Infra & RAG skills.** Convert `iac/**`, `containers/**`, `cicd/**`, `rag/**` to ~12 skills.
8. **P5 — Settings template + `cscr configure` CLI.** Author `settings-template.json` with the deterministic deny rules. Build the interactive merger that explains each rule and lets the user opt out per-rule.
9. **P6 — Optional hooks reference library.** Author ~11-15 reference scripts in `hooks/optional/` with per-script coverage docs. Author bundles (`bash-only.json`, `ai-ml-stack.json`, `full.json`). Build the `cscr hooks` CLI (install / update / list / remove / status). pytest fixtures include known-bypass-class probes per script (so the test confirms what the coverage doc says).
10. **P6.5 — Third-party held-out review.** Hand a stratified held-out corpus (Web/SAST patterns + AI/ML patterns + Supply-chain patterns + Repo-policy patterns) to a named external reviewer. Test with and without CSCR loaded; with and without optional hooks installed. Pre-register specific numerical claims via OSF (or a signed git tag in a third-party-controlled repo). Publish results in release notes.
11. **P7 — Marketplace submission.** Submit to `claude-plugins-community`. Sigstore-attest the release with the single maintainer key. Co-signing is a v2.x milestone, explicitly disclosed in release notes and `docs/governance.md`. Publish `cscr verify` CLI. Update README per honest-framing constraint. Tag v2.0.0.

### Backward compatibility

The `rules/` tree stays accessible from the `v1.x` git tag. The v2 README has a "Migrating from v1" section pointing to `/plugin install tikitribe-secure-coding-rules` and explaining that the `cp` flow is no longer maintained.

### Estimated scope

~42 skills × (SKILL.md + 8 evals + reference files) + ~12 reference hook scripts + per-hook coverage docs + 3 CLIs (`cscr configure`, `cscr hooks`, `cscr verify`) + SECURITY.md + governance.md + standards-pin.yaml + third-party held-out review + sigstore release pipeline + CI updates.

Realistic timeline: 6-10 weeks for one maintainer (significantly less than the prior hooks-shipped-in-plugin architecture, which estimated 4-8 months).

## Risk register

| Risk | Mitigation |
|---|---|
| Converter produces low-quality SKILL.md | `--strict` mode (P0); golden-file tests; mechanical convert + manual `description`/`when_to_use` pass per skill |
| Skill description truncation at 1,536 chars | First sentence = trigger phrase. Lint check in CI |
| Community-marketplace review delay | Submit early on `v2/` branch with preview tag; `--plugin-dir` install for early adopters |
| Drift between RCS and CSCR cross-references | CI drift-check, frontmatter-parsed, pinned-SHA |
| Standards drift (OWASP / NIST / MITRE rev superseded) | `docs/standards-pin.yaml` machine-readable pins; monthly CI check opens issue; 90-day update SLA in `governance.md` |
| Corpus contradictions between rule examples and current standards | P0.5 audit pass; rewrite deprecated examples before conversion |
| User adopts a reference hook without reading its coverage doc | `cscr hooks install` prints the coverage doc inline before copying the script; refuses without `--accept-coverage` flag |
| User modifies an installed hook, then `cscr hooks update` overwrites their changes | `cscr hooks update` is diff-review interactive; never silently overwrites |
| Maintainer-credential compromise | sigstore-attested releases (single-signer at v2.0.0, co-signed in v2.x milestone); user-runnable `cscr verify` for post-install integrity audit; `docs/how-to/audit-cscr-pre-trust.md` six-check audit |
| Outcome metric refutation in third-party review | Honest release-note language documenting what was measured AND what was NOT improved; README claims updated to match the measured uplift |
| Pre-registration without neutral custodian | OSF or signed git tag in a third-party-controlled repo. Named explicitly in P6.5 |
| Adversarial eval gaming (in-repo answer keys) | 50% of adversarial probes ship public; 50% held in a private repo rotated quarterly; third-party reviewer uses both sets |

## Success criteria

v2.0.0 ships when ALL of the following are true:

1. Plugin is installable from the community marketplace as `/plugin install tikitribe-secure-coding-rules`.
2. All ~42 skills have 8 passing evals each (1 happy + 1 edge + 1 anti-trigger + 5 adversarial probes, each scored independently).
3. All ~12 reference hook scripts have passing pytest unit tests, including documented bypass-class probes; each has a coverage doc at `hooks/optional/coverage/<hook>.md` enumerating covered call shapes and known bypass classes.
4. CI drift-check against RCS passes (frontmatter-parsed, pinned-SHA).
5. README's "Migrating from v1" section is in place.
6. Total p95 per-session loaded skill size, measured by a representative AI/ML+FastAPI test fixture, is less than the v1 baseline.
7. `docs/explanation/enforcement-coverage.md` exists and is reviewed by a named third party; README contains no enforcement verbs outside permitted contexts (platform permission rules + specific named hooks); no supply-chain verbs (`co-signed`, `attested`, `verified`) without per-release accuracy review; pre-registered third-party held-out review is complete with results in release notes.
8. `SECURITY.md` exists, has been smoke-tested by an external reporter, and the contact channel works.
9. Release is sigstore-attested with a single maintainer key; `cscr verify` CLI exists and produces PASS/FAIL output; `docs/how-to/audit-cscr-pre-trust.md` documents the six-check audit. Co-signing is a v2.x milestone, explicitly disclosed.
10. `settings-template.json` and `cscr configure` CLI exist; `hooks/optional/` library + `cscr hooks` CLI exist; `docs/how-to/enable-optional-hooks.md` is the central trust-model doc and explicitly states CSCR does not run code in the user's session by default.

## Open items for fresh single-round premortem

Before implementation begins, run one fresh premortem round against this revised design. The prior two rounds attacked an architecture that no longer exists; their findings have been triaged into "carried forward" (catalog quality, governance, supply chain) and "no longer applicable" (hook-layer attacks, escape-hatch mechanism, hash-pinning self-reference). The fresh round should attack:

- The skills catalog and eval discipline (especially the n=5 adversarial sample and the corpus-quality audit)
- The settings template's coverage and the `cscr configure` UX
- The BYOH trust model (what new attacks does the optional library enable that the plugin's own hooks would have caught?)
- The cross-pointer with RCS and the drift check
- Governance, release process, third-party review credibility

If the fresh round produces ≤2 Critical findings, proceed to implementation. If it produces more, triage before P0 begins.
