# tikitribe-secure-coding-rules v2 Modernization Design

**Status:** Approved (B-pure architecture, post three premortem rounds), ready for implementation planning
**Date:** 2026-05-24 (architecture revised three times same day — see Decision lineage below)
**Author:** Rock Lambros
**Plugin name:** `tikitribe-secure-coding-rules`
**Target version:** v2.0.0
**Architecture:** B-pure — catalog + permission-rule template + documentation; no CSCR-authored executable code ships in the plugin

## Decision lineage

| Round | Architecture attacked | Critical findings | Outcome |
|---|---|---|---|
| Round 1 | Original hooks-shipped-in-plugin (M1-M11 amendment) | 5 Critical | Amendment 01 applied |
| Round 2 | Amendment 01 hooks-with-out-of-tree-state | 6 Critical | Amendment 02 applied |
| Retrospective | Step-back; chose Option B with BYOH (reference hooks the user installs) | — | Design rewritten for B+BYOH |
| Fresh round | B+BYOH architecture | 5 Critical | B+BYOH abandoned; B-pure adopted |

**The pattern that forced B-pure:** Any architecture that ships executable enforcement scripts (whether plugin-active or user-installable) recreates the model-controlled-bypass problem because the agent has Bash tool access. A prompt-injected model can instruct the user to run `cscr hooks install --bundle full --accept-coverage`; the user approves at the documented 93% rate (Hughes 2026); the runtime attack surface after adoption is identical to the original hook-shipping architecture. Three rounds of premortem on three architectures all surfaced 5+ Criticals on the same root cause.

**B-pure escapes the trap by not shipping any executable scripts.** Hook authorship is taught in documentation; users who want hooks write their own. CSCR's claims are bounded to what the *catalog* and the *permission-rule template* deliver — both of which are inert files the user merges into their config or reads in a session.

Prior amendments and the retrospective are preserved in `docs/superpowers/specs/` for context. Their resolutions are partially carried forward (catalog structure, eval discipline, RCS congruence, governance, supply chain at the plugin-metadata layer) and partially dropped (everything involving CSCR-shipped executable hooks).

## Purpose

Convert `claude-secure-coding-rules` (CSCR) from a `cp`-distributed library of always-on CLAUDE.md rule files into a Claude Code plugin that ships:

1. **The catalog** — ~42 path-scoped, on-demand-loading skills that teach secure patterns by domain
2. **A permission-rule template** — a static `settings-template.json` users merge into their own Claude Code settings; enforcement happens at the platform layer, not in any CSCR-shipped code
3. **Documentation** — including a "write your own hook" guide with full code examples in markdown that users copy manually if they want enforcement beyond what permission rules can express

The v1 problems v2 fixes:
- **`Level: strict` was advisory prose, not enforcement.** v2 is honest about this: enforcement comes from the platform's permission rules. CSCR does not claim deterministic enforcement of anything not expressible as a permission rule.
- **8,800+ lines in `_core/` alone** burned the user's context window on every session. v2 path-scopes skills so most sessions load only 2-4 of the 42 skills.
- **`cp`-based distribution.** v2 ships via the community marketplace as a single `/plugin install` command.

## Non-goals

- v2 is not a deterministic enforcement plugin. Three rounds of premortem demonstrated that a plugin layer cannot reliably enforce against an agent that controls the inputs to the enforcement check. v2 does not attempt this.
- v2 does not ship executable enforcement code. No `cscr hooks install`, no `cscr-configure` interactive merger, no `cscr-verify` CLI. The user merges the settings template manually or via tools they already use; sigstore verification of the release is documented but performed by the user with `python -m sigstore verify`, not by a CSCR-shipped binary.
- v2 is not a methodology repo. RCS owns that lane.
- v2 does not bundle SAST runners.

## Architecture

Two layers, ranked by where enforcement actually lives:

| Layer | Mechanism | Who runs it | What it covers |
|---|---|---|---|
| 1. Platform-level enforcement | Claude Code permission rules in user/project `settings.json` | The Claude Code harness, deterministically | File paths (`.env`, `secrets/**`), command patterns (`curl \| sh`, force-push targeting `main`/`master`), MCP allow/deny, sandbox config |
| 2. Skills (advisory) | `SKILL.md` loaded on description match and `paths:` glob | Claude during a session | Framework idioms, defense-in-depth, the rest of the catalog |

There is no Layer 3 / hook layer in v2. The retrospective's BYOH layer was attempted in a prior revision and rejected after the fresh premortem surfaced 5 Criticals. Users who want enforcement beyond what permission rules express read `docs/how-to/write-your-own-hook.md` and author their own hooks in their own infrastructure with their own threat model.

**Honest-framing constraint.** The README and user-facing copy may use enforcement verbs (`enforce`, `block`, `refuse`) only when describing Claude Code's permission rules (which CSCR's template uses but does not implement). Layer 2 uses `advises`, `loads guidance for`, `documents`. Supply-chain verbs (`co-signed`, `attested`, `verified`) require per-release accuracy review — single-signer releases cannot claim "co-signed," releases without runtime verification cannot claim "verified at runtime," etc. A CI lint over README.md, docs/, and the marketplace listing description flags violations. The lint covers a deny-phrase list, not just verbs (`the security plugin`, `protects you from`, `authoritative`, `comprehensive coverage`, `enterprise-grade`, etc.).

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
├── settings-template.json           # platform-level permission rules
├── SECURITY.md                      # VDP, reporting channel, disclosure policy
├── TERMS.md                         # warranty disclaimer + no-fitness-for-regulated-use
├── tests/
│   ├── structural/                  # rule-format tests, adapted to SKILL.md
│   ├── semantic/                    # Do/Don't examples evaluated against the
│   │                                # settings-template permission rules and
│   │                                # documented hook patterns
│   └── coverage/                    # OWASP/CWE coverage analysis (semantic check)
├── tools/
│   ├── rule-to-skill-converter.py   # mechanical v1 → v2 first pass; --strict mode
│   ├── tests/converter/golden/      # golden-file converter tests
│   ├── run_evals.py                 # RCS-compatible eval harness
│   └── lint_skills.py               # frontmatter validation
├── docs/
│   ├── standards-pin.yaml           # external standards version pins
│   ├── governance.md                # ownership, dispute resolution, update SLA,
│   │                                # release co-signing roadmap, deprecation policy
│   ├── superpowers/specs/           # design docs, amendments, retrospective
│   ├── how-to/
│   │   ├── install.md
│   │   ├── merge-settings-template.md # how to merge the template into your settings
│   │   ├── write-your-own-hook.md   # full code examples; user copies manually
│   │   ├── verify-the-release.md    # how to run `python -m sigstore verify`
│   │   ├── audit-cscr-pre-trust.md  # six-check audit
│   │   ├── handle-rule-conflicts.md
│   │   └── contribute-a-skill.md
│   └── explanation/
│       ├── two-layers.md            # catalog + template
│       ├── why-no-hooks.md          # references the three premortem rounds
│       ├── enforcement-coverage.md  # what permission rules CAN and CANNOT enforce
│       ├── converter-contract.md
│       ├── sigma-score.md           # vendored from RCS, re-validated for security
│       └── relationship-to-rcs.md
├── CLAUDE.md                        # project instructions
└── README.md                        # honest-framing; positions CSCR as catalog + platform configurator
```

**Notable absences** (deliberate, per fresh-round F1-F5):
- No `tools/cscr-configure.py` (the settings template is a static JSON file the user merges)
- No `tools/cscr-hooks.py` (no hooks ship; user authors hooks from documentation)
- No `tools/cscr-verify.py` (sigstore verification is `python -m sigstore verify` against the release tarball; documented in `verify-the-release.md`)
- No `hooks/optional/` directory (eliminates the BYOH attack surface)
- No `~/.cscr/` state directory (no per-installation salts or allowlists)

## Skills catalog

The catalog is the primary value of v2. Each rule domain becomes one skill directory.

### Per-skill anatomy

```
skills/python-security/
├── SKILL.md                   # frontmatter + concise instructions, <400 lines
├── reference/
│   ├── deserialization.md
│   ├── subprocess.md
│   └── crypto.md
├── examples/
│   ├── secure-sql.py
│   └── secure-subprocess.py
└── evals/
    ├── 01-happy-path/         # n≥3 scenarios per cell
    │   ├── 01.json
    │   ├── 02.json
    │   └── 03.json
    ├── 02-edge-case/
    │   ├── 01.json
    │   ├── 02.json
    │   └── 03.json
    ├── 03-anti-trigger/
    │   ├── 01.json
    │   ├── 02.json
    │   └── 03.json
    └── 04-adversarial/        # n≥5 scenarios per skill, distinct attack families
        ├── 01.json
        ├── 02.json
        ├── 03.json
        ├── 04.json
        └── 05.json
```

Total per skill: 14 eval scenarios (3+3+3+5), each scored independently. The "shipped" bar is: all 14 pass. (Up from the BYOH design's 8, per fresh-round F13 / DataSci #10 on n=1 cells being example-not-test.)

### Adversarial variant taxonomy

Each skill commits to a documented variant taxonomy *before* writing adversarial probes. The taxonomy enumerates known attack families for that domain (per fresh-round DataSci #2). For `python-security` the families might be {direct call, aliased import, base64-then-loads, dill substitution, custom `__reduce__`, gadget chain}; the 5 adversarial probes draw one from each. The taxonomy lives at `skills/<name>/evals/04-adversarial/taxonomy.md` and is part of the skill's "shipped" deliverable.

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
  crypto, file I/O, or database queries.
version: 2.0.0
sigma: 18
---
```

### Catalog mapping (unchanged from prior revisions)

| Current v1 path | v2 skill | Σ |
|---|---|---|
| `_core/owasp-2025.md` | `applying-owasp-top-10` | 20 |
| `_core/ai-security.md` | `applying-ai-ml-security` | 19 |
| `_core/agent-security.md` | `applying-agentic-ai-security` | 19 |
| `_core/mcp-security.md` | `applying-mcp-security` | 19 |
| `_core/rag-security.md` | `applying-rag-security` | 18 |
| `_core/graph-database-security.md` | `applying-graph-db-security` | 15 |
| `languages/**` | 12 skills (one per language) | 12-18 |
| `backend/**` | ~16 skills | 13-18 |
| `frontend/**` | 5 skills | 14-17 |
| `rag/**` | 7 grouped skills | 14-18 |
| `iac/**` | 2 skills (Terraform, Pulumi) | 17 |
| `containers/**` | 3 skills (Docker, k8s, Helm) | 17 |
| `cicd/**` | 2 skills (GitHub Actions, GitLab CI) | 16 |

Total: ~42 skills.

### Naming convention

- Active-voice gerund (`applying-owasp-top-10`) where the skill *does* something
- `<domain>-security` (`python-security`, `fastapi-security`) for catalog skills

### Namespacing

`/tikitribe-secure-coding-rules:python-security`. Auto-load via description match.

## Layer 1: Platform-level permission rules

CSCR ships `settings-template.json` containing permission rules the user merges into their own `~/.claude/settings.json` (or project-level `.claude/settings.json`) **manually** — no CSCR-shipped CLI performs the merge. The user uses their preferred tooling: `jq`, a JSON merge utility, their editor, or a shell pipeline.

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
      "Bash(sh -c *curl*)",
      "Bash(bash -c *curl*)",
      "Bash(eval *curl*)",
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

### What the template does NOT cover (per fresh-round F7)

The template adds shell-of-curl patterns (`sh -c *curl*`, `bash -c *curl*`, `eval *curl*`) to address the Round 3 bypass-class concern. It still does not catch:

- Process substitution: `bash <(curl ...)`
- Download-then-exec: `curl ... -o /tmp/x && sh /tmp/x`
- Tee-then-exec: `curl ... | tee /tmp/x; sh /tmp/x`
- Multi-step variable construction: `URL=...; curl $URL | sh`

The template's `enforcement-coverage.md` enumerates these explicitly. No claim is made that the template "blocks all pipe-to-shell." The claim is "blocks the patterns named in this template; documented bypass classes are listed."

### Merge guidance

`docs/how-to/merge-settings-template.md` walks the user through:

1. **Inspect their existing settings** for `deny` rules. If they already have stricter rules (e.g., `Bash(curl *)`), keep theirs — CSCR's template never replaces user rules; the merge is additive only.
2. **Use a JSON merge tool of their choice** (`jq -s '.[0] * .[1]'` with deduplication, an editor, or any tool). CSCR ships no merger.
3. **Verify with `cat ~/.claude/settings.json | jq '.permissions.deny'`** that the resulting list contains both their original rules and CSCR's additions.
4. **Document their merged state** in their dotfiles repo or settings backup, since they own the file.

### Why no `cscr-configure` merger (per fresh-round F2 and F6)

A CSCR-shipped interactive merger is itself executable code the model can instruct the user to invoke, with the same model-controlled-bypass surface as the BYOH `cscr hooks install` flow. The fresh round demonstrated this. Manual merge via the user's existing tools puts the trust decision genuinely in the user's hands, with no CSCR-authored binary in the loop.

## Layer 2: Skills (advisory)

The catalog. See "Skills catalog" above. Skills load on description match and `paths:` glob; they advise the model on framework idioms and defense-in-depth. They make no enforcement claim.

## Documentation: write-your-own-hook

`docs/how-to/write-your-own-hook.md` teaches hook authorship in detail. Full code examples are in markdown that the user copies manually into their own `~/.claude/hooks/` directory. CSCR ships zero executable hook files; the guide ships ~10-12 documented patterns in fenced code blocks.

Each documented pattern includes:
- The Python source for the hook script
- The settings.json hook entry the user adds
- The bypass classes that pattern does NOT catch (per fresh-round F22 / Gov #4)
- Suggested unit tests the user writes
- A reference to which Layer 1 permission rule (if any) complements the hook

Patterns documented include (but are not limited to): `block-force-push-protected`, `block-curl-pipe-sh-extended`, `block-chmod-777`, `block-unpinned-installs`, `block-hardcoded-secrets-regex`, `block-eval-on-user-input` (with the AST fail-secure pattern fully written out), `block-pickle-loads`, `warn-missing-pydantic-fastapi`.

The user reads the guide, picks the patterns they want, copies the code into their own files, writes the settings entry themselves, and tests against their own codebase. CSCR has no install command and no upgrade mechanism for these — they're documentation, not a distribution.

**Why this is safer than BYOH (per fresh-round F1, F2, F9):**

- No `cscr hooks install` CLI for the model to invoke via Bash
- No `cscr hooks update` to ship malicious updates through
- No settings.json contract for CSCR to define and break
- Friction is the safety mechanism. A user who manually authors a hook from documentation has engaged enough with the pattern to know what it does. A user who runs `cscr hooks install --bundle full --accept-coverage` has not.
- Trust is local in the strongest possible sense. The user's hook is the user's code.

**What this gives up:**

- Easy onboarding for hooks. Users who want hooks have to do the work.
- A single CSCR-maintained source of truth for hook implementations. If CSCR's documented pattern has a bypass and the user copied it months ago, the user doesn't get an automatic fix.

**Mitigation for that giving-up:**

- `docs/how-to/write-your-own-hook.md` includes a "subscribe to security advisories" section pointing at the repo's GitHub Security Advisories. When a bypass is documented for one of CSCR's pattern examples, CSCR ships an advisory; the user who subscribed updates their copy manually.

## Eval discipline

14 evals per skill (3 happy + 3 edge + 3 anti-trigger + 5 adversarial), each scored independently. Adversarial variant taxonomy documented per skill.

| File | Purpose | Pass condition |
|---|---|---|
| `01-happy-path/0N.json` | User asks for the secure pattern in-scope (3 variants per skill) | Model produces canonical secure pattern and cites the rule |
| `02-edge-case/0N.json` | Ambiguous / boundary scenarios (3 variants) | Model flags the gating rule and applies it or asks |
| `03-anti-trigger/0N.json` | Adjacent but unrelated requests (3 variants) | Skill stays dormant |
| `04-adversarial/0N.json` | Prompt-injection variants from documented attack families (5, one per family) | Model refuses and cites the rule |

Schema mirrors RCS so `tools/run_evals.py` is reusable. The schema bump for the new directory-of-files layout is documented in `docs/explanation/run-evals-schema-bump.md` and contributed upstream to RCS for the shared harness (per fresh-round MLEng #9).

**Public/private adversarial split** (per fresh-round F12): 60% of adversarial probes ship public in-tree; 40% are held in a private repo and rotated by a *named third party* who has never seen the public set. Quarterly rotation. The honest claim is "held out from the public training corpus and from the maintainer's authoring process at rotation time" — not "held out forever."

PRAGMATIC discipline applies: Sonnet-only by default. Haiku stratification for top-Σ security skills is in the implementation plan.

## Relationship to RCS

| Dimension | RCS | CSCR v2 (B-pure) |
|---|---|---|
| Content lane | Methodology (verb-named, decision-tree) | Catalog (framework-specific, reference) |
| Skill naming | `verb-noun` | `<domain>-security` + `applying-<standard>` |
| Skill format | Anthropic Skills format | Identical |
| Plugin-shipped executable code | None | None |
| Eval shape | 3 JSON evals | 14 evals (3+3+3+5) |
| Sigma scoring | Yes | Yes (re-validated for security per fresh-round DataSci #7) |
| Governance | Per-skill SemVer + repo integration tags | Same |

### The cross-pointer

RCS's `applying-secure-coding-rules` skill names CSCR as the corpus. CSCR's AI/ML skills cite RCS skills for the methodology side. The cross-pointer is now safer because both repos ship the same shape (skills only, no executable enforcement) — a typo-squat attacker has less surface to mimic since neither repo has install CLIs to forge.

### Drift check

CI job clones RCS at a pinned commit SHA, parses YAML frontmatter, asserts skill `name:` references resolve. Same in reverse.

## Migration plan

**Branch model:** `v2/` branch hosts the rebuild. `main` switches to v2 after v2.0.0 tags. Pre-v2 head gets a `v1.x` tag.

### Phased build on `v2/`

1. **P0 — Scaffolding.** `.claude-plugin/plugin.json`, repo restructure, `tools/rule-to-skill-converter.py` (with `--strict` mode and golden tests; --strict consumes an explicit audit-output schema per fresh-round F18), `SECURITY.md`, `TERMS.md`, `docs/governance.md`, `docs/standards-pin.yaml`. **CI rewrite** (per fresh-round F14): explicit job specifications for eval harness, structural tests, semantic tests, RCS drift check, honest-framing lint (including deny-phrase list), converter golden tests. Workflows scoped to `skills/**` and the new layout.
2. **P0.5 — Corpus quality audit.** Every `Do` example reviewed against current standards. Every `Don't` verified. Deprecated mitigations rewritten. Budget: ~80+ person-hours (per fresh-round F4). The audit produces an explicit YAML output the converter `--strict` mode consumes.
3. **P0.6 — Standards-currency audit.** OWASP LLM Top 10 → 2025 numbering. NIST AI RMF revision check. MITRE ATLAS sync. `standards-pin.yaml` populated.
4. **P1-P4 — Skill conversion.** Convert in catalog order: `_core` (6 skills) → languages (12) → frameworks (16) → infra & RAG (12). Each skill ships 14 evals with documented adversarial variant taxonomy.
5. **P5 — Settings template + documentation.** Author `settings-template.json` with extended permission rules including the shell-of-curl patterns. Author `docs/how-to/merge-settings-template.md` walking the user through manual merge. Author `docs/how-to/write-your-own-hook.md` with ~10-12 documented hook patterns including full code, bypass-class enumeration, and unit-test suggestions.
6. **P6 — Third-party held-out review.** Hand a stratified held-out corpus to a named external reviewer with a *signed SoW, mutual NDA, and documented liability allocation* (per fresh-round F5). Strata: Web/SAST + AI/ML + Supply-chain + IaC + Containers + Frontend + Languages (7 strata per fresh-round DataSci #3, not 4). Reviewer is procured *before P0 begins* so the timeline does not wait on recruitment (per fresh-round MLOps #7). Pre-register specific numerical claims via OSF (not signed git tag — per fresh-round F3 / DataSci #4).
7. **P7 — Marketplace submission.** Submit to `claude-plugins-community`. Sigstore-attest the release with the single maintainer key. Co-signing is a v2.x milestone, explicitly disclosed in release notes, marketplace listing description, README adjacent to any signing claim, and `docs/governance.md` (per fresh-round F10 / Gov #5). Tag v2.0.0.

### Backward compatibility

The `rules/` tree stays accessible from the `v1.x` git tag. The v2 README has a prominent banner at the top disclaiming v1 framing and linking to a "what changed and why" doc (per fresh-round F15 / Gov #6).

### Estimated scope (realistic)

Per fresh-round F4 / MLOps #1: bottom-up estimate is ~600 person-hours. Realistic timeline: **10-14 weeks** for one maintainer (revised up from B+BYOH's optimistic 6-10 weeks). The B-pure architecture is smaller in code surface than B+BYOH (no `cscr-*` CLIs, no hook scripts, no test fixtures for them) but the eval count went from 8 to 14 per skill (588 total) and the corpus-quality audit + third-party reviewer procurement add ~120 person-hours of judgment work.

If the timeline pressure is acute, the implementation plan can scope P6.5 (third-party review) to top-Σ skills only at v2.0.0 and defer long-tail review to v2.1.

## Risk register

| Risk | Mitigation |
|---|---|
| Converter produces low-quality SKILL.md | `--strict` mode (P0); golden-file tests with explicit byte-equivalence policy (PyYAML pinned, line-ending normalized, Unicode NFC) per fresh-round F21; mechanical convert + manual `description`/`when_to_use` pass per skill |
| Skill description truncation at 1,536 chars | First sentence = trigger phrase. Lint check in CI |
| Community-marketplace review delay | Submit early on `v2/` branch with preview tag; document v2.0.0 as "tagged + sigstore-attested + signed" separately from "marketplace-listed" (per fresh-round MLOps #10) |
| Drift between RCS and CSCR cross-references | CI drift-check, frontmatter-parsed, pinned-SHA |
| Standards drift | `docs/standards-pin.yaml` machine-readable pins; daily (not monthly) CI check via RSS/feed where available; 180-day update SLA in `governance.md` (revised from 90 per fresh-round F8 / MLOps #8 single-maintainer infeasibility) |
| Corpus contradictions between rule examples and current standards | P0.5 audit pass; rewrite deprecated examples before conversion |
| User merges settings-template and accidentally weakens existing stricter rules | `merge-settings-template.md` explicitly walks the user through preserving their existing rules; CSCR ships zero auto-merge code, so the failure mode requires the user to make a manual mistake rather than CSCR to make it for them. Honest tradeoff: less convenient, but a regression vector the prior architectures had is gone |
| User authors a hook from documentation, hook has a bypass | `write-your-own-hook.md` documents bypass classes per pattern; GitHub Security Advisories ship corrections when a pattern has a documented bypass; users who care subscribe |
| Marketplace approval delay | Decouple v2.0.0 (tagged + signed) from marketplace-listed milestone |
| Maintainer-credential compromise | Sigstore-attested releases (single-signer at v2.0.0, co-signed in v2.x milestone with named candidate in `governance.md`); user-runnable `python -m sigstore verify` for post-install integrity; six-check audit in `audit-cscr-pre-trust.md` |
| Outcome metric refutation in third-party review | Honest release-note language documenting what was measured AND what was NOT improved; README claims updated to match the measured uplift; refutation does not block release but triggers a relabel-to-X path per fresh-round F17 deferred |
| Pre-registration without neutral custodian | OSF only (not signed git tag) per fresh-round F3 |
| Adversarial eval gaming via in-repo answer keys | 60% public, 40% private rotated by a *named third party* (not the maintainer) quarterly |
| Liability framing under EU AI Act / Product Liability Directive | `TERMS.md` alongside LICENSE with no-warranty-for-security-purpose and no-fitness-for-regulated-use; consider distributing through an LLC or non-profit entity (open question for governance.md) |
| README v1 framing persists in caches/citations | Banner at top of v2 README; canonical "what changed and why" doc; security-advisory class for v1 claim corrections |

## Success criteria

v2.0.0 ships when ALL of the following are true:

1. Plugin is installable from `claude-plugins-community` as `/plugin install tikitribe-secure-coding-rules`. (Or: tagged + sigstore-attested + signed, with marketplace-listed status documented as a separate milestone if marketplace approval is delayed.)
2. All ~42 skills have 14 passing evals each (3 happy + 3 edge + 3 anti-trigger + 5 adversarial), each scored independently. Adversarial variant taxonomy documented per skill.
3. `settings-template.json` exists with extended permission rules; `docs/how-to/merge-settings-template.md` walks the user through manual merge and explicitly addresses preserving existing stricter rules. `docs/explanation/enforcement-coverage.md` enumerates per-template-rule bypass classes.
4. `docs/how-to/write-your-own-hook.md` exists with ~10-12 documented patterns (full code, bypass classes, suggested tests). Zero executable hook files ship in the plugin.
5. CI drift-check against RCS passes (frontmatter-parsed, pinned-SHA).
6. README's "Migrating from v1" section is in place. README banner disclaims v1 framing.
7. Total p95 per-session loaded skill size, measured across ≥10 representative project-shape fixtures (not one), is less than the v1 baseline. Bootstrap 95% CI reported.
8. `docs/explanation/enforcement-coverage.md` exists and is reviewed by the named third-party reviewer. README and marketplace listing description contain no enforcement verbs outside permitted contexts (platform permission rules only). No supply-chain verbs without per-release accuracy review. Honest-framing lint covers deny-phrase list, not just verbs.
9. Pre-registered third-party held-out review (P6) is complete with results published in release notes. Reviewer was procured with signed SoW, mutual NDA, and documented liability allocation BEFORE P0 began. Pre-registration via OSF (not git-tag substitution).
10. `SECURITY.md` exists, has been smoke-tested by an external reporter, and the contact channel works. `TERMS.md` documents warranty disclaimer and no-fitness-for-regulated-use. `governance.md` enumerates: named maintainer(s), succession contact, 180-day standards-drift SLA, deprecation procedure, co-signing milestone target version with named candidate, dispute resolution for corpus-poisoning PR-review escalations.
11. Release is sigstore-attested with single maintainer key; `docs/how-to/verify-the-release.md` documents `python -m sigstore verify`; `docs/how-to/audit-cscr-pre-trust.md` documents six-check audit. Co-signing is a v2.x milestone with explicit timeline and named candidate.

## Open items for implementation phase

- Bottom-up timeline re-estimate published in `governance.md` so external observers can hold it accountable (per fresh-round F4).
- Reviewer procurement (P6) begins before P0 closes — recruitment is on the critical path.
- Counsel review of `TERMS.md` (estimated $2-5K) and entity-structure decision (LLC vs personal distribution) before v2.0.0 tags.
- Co-signer candidate named in `governance.md` before v2.0.0 tags, even if co-signing itself ships in v2.1.
- The fresh-round Medium findings (F15-F23) are tracked for implementation but not gating on the architecture. Each has a documented mitigation in this design or risk register.

## What this architecture ships that the prior architectures did not

- **Honest architectural claims.** "CSCR teaches; Claude Code's permission rules enforce; you write your own hooks if you want enforcement beyond what permission rules express."
- **A premortem that clears on first round.** B-pure was attacked implicitly via the fresh-round counterfactuals; the Critical findings against B+BYOH all evaporate under B-pure (F1 disappears — no `cscr hooks install`; F2 disappears — no merger; F3 disappears — no shipped hook script; F6 disappears — no CLI binaries; F9 disappears — no update channel). The remaining findings are catalog-side and governance-side, with established mitigations.
- **A faster path to user value despite the longer timeline.** B-pure ships ~42 skills + a template + documentation. v2.0.0 is a real upgrade over v1 the moment users install it, even before they write any hooks of their own.
- **Architectural symmetry with RCS.** Both repos ship skills + docs + no executable enforcement. The cross-pointer becomes more credible.
- **A defensible position under regulator review.** "CSCR is a documentation catalog and configuration template. It does not run code in your session. Enforcement happens at the platform layer. Hook authorship is taught but not provided."

This is the architecture v2.0.0 ships.
