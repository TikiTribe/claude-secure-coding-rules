# CSCR v2 — Design Retrospective

**Status:** Decision document, not a spec
**Date:** 2026-05-24
**Author:** Rock Lambros
**Purpose:** Step back from the amendment loop. Two adversarial premortem rounds produced 11 cumulative Critical findings against the hybrid-hook architecture. Each amendment resolved the surfaced defects but the count did not decline. This document asks whether the architecture is fighting the platform, evaluates alternatives, and recommends a path.

## What we observe

Two rounds of six-perspective adversarial premortem produced:

- **Round 1:** 5 Critical, 6 High, 14 lower-priority findings (Amendment 01 resolved M1-M11)
- **Round 2:** 6 Critical, 6 High, 16 lower-priority findings (Amendment 02 resolved N1-N7)

The Critical count did not decline between rounds. Each amendment that resolved one class of attack introduced a new one. The pattern across the 11 cumulative Criticals is consistent.

### The recurring pattern, named

Each amendment added a control intended to defeat a model-controlled attack vector. The control itself depended on a property the threat model violated:

| Amendment 01 added | Round 2 found |
|---|---|
| `# cscr:allow N:HASH` line-hash with stable salt (M2) | Salt is model-readable (N2) |
| `.cscr-allowlist.json` "owned by humans" (M2.2) | File is in-tree-writable by the model (N3) |
| `hookScriptHashes` verified at load (M4) | Verifier ships in the same plugin being verified (N5) |
| Advisory-by-default kill switch (M10) | Kill switch defeats non-bypassable rules (N7) |
| Sigstore-attested releases (M4) | Verification is opt-in, not enforced (N6) |
| AST-based hooks replacing regex (M3) | Regex floor on parse failure is attacker-controllable (N1) |

Amendment 02 fixed these six, but only by moving state out of the project tree (`~/.cscr/`), narrowing the claim to "defeats prompt injection in default-permission sessions where the user merged the settings template," and accepting single-signer at v2.0.0. The mitigation is now load-bearing on a deny rule the user must opt into.

### The root cause

CSCR cannot deterministically enforce against an agent that controls the inputs to the enforcement check. The Claude Code platform's hook mechanism reads stdin from the model's tool calls; the hook script lives in user-writable space; the project root is model-writable; the plugin directory is model-readable. Every "defense" the amendments add lives somewhere the threat can reach.

The constraint is not a Claude Code bug. It is a structural property of agentic systems where the agent has tool access to the filesystem and shell. The amendments' mitigation strategy — moving state to `~/.cscr/` and gating with permission rules — works only as long as:

1. The user merges the settings template (load-bearing assumption).
2. The user does not grant the model `Read(~/**)` or `bypassPermissions` mode (load-bearing assumption).
3. The salt and allowlist files survive marketplace pushes (depends on the user reinstalling the plugin without `~/.cscr/` cleanup).
4. The platform does not change in a way that grants the model access to user-home paths (forward-compatibility assumption).

When all four hold, Amendment 02 provides honest "advisory + opt-in-strict with reasonable defaults" security. When any one fails, the bypass-prevention claim degrades to "advisory text the model can ignore." The 93% prompt-approval rate (Hughes 2026) makes assumption 1 fragile in practice.

### What we are NOT seeing

This is important: we are not seeing a flaw in the *idea* of a security catalog for Claude Code. The 84 source rules encode real expertise. The skills-based delivery (replacing `cp` with `/plugin install`, replacing CLAUDE.md walls with path-scoped skills) is a real improvement. The conversion to the Anthropic Skills format aligns CSCR with the broader agentskills.io ecosystem. Those wins survive any architectural choice we make below.

What we are seeing is that *adding hooks to the catalog* is doing less work than the design assumed. Hooks were positioned as "the only mechanism that actually enforces" — the layer that converted `Level: strict` from prose to reality. After two rounds, the honest claim is: hooks are best-effort enforcement against default-permission sessions, contingent on multiple opt-ins the user must perform, with documented bypass classes per pattern. That is a real value-add over pure advisory text, but it is not "deterministic enforcement."

## The decision space

Four architectural options to evaluate. Each is scored against three axes: (i) security uplift over v1 advisory text, (ii) implementation cost to v2.0.0, (iii) sustainability of the claim under adversarial premortem (would Rounds 3-4 surface more Criticals?).

### Option A: Continue the current architecture (skills + hooks + amendments)

**Description.** Ship v2.0.0 with the post-Amendment-02 design. ~42 skills, 11 Tier A hooks with out-of-tree state, fail-secure AST hooks, `cscr verify` CLI, single-signer sigstore, honest-framing lint.

**Security uplift over v1.** Real for default-permission sessions where the user merged the settings template. The 11 Tier A hooks block specific RCE/secret/deserialization patterns. AST-mode catches more than regex. Out-of-tree state and `cscr.enforcement` user-level-only defeat the simple model-rewrites-settings bypass. Non-bypassable rules #8 and #12 cannot be disabled via project config.

**Implementation cost.** High. The migration plan now has 11 phases, 42 skills × 4 evals, 11 hook scripts + AST modules + per-platform latency benchmarks, 4 CLIs (`cscr verify`, `cscr-hash`, `cscr allowlist`, settings-template merger), SECURITY.md, governance.md, standards-pin.yaml, third-party held-out review, sigstore release pipeline, plus the cross-platform mitigations deferred to Amendment 03. Realistic timeline: 4-8 months for one maintainer.

**Sustainability under further premortem.** Uncertain. Round 2 surfaced 6 Critical even after Round 1's amendments. Amendment 03 will resolve N8-N18 (eval gaming, latency budget, OWASP Benchmark coverage gap, pre-registration custodian, refutation-doesn't-block-release framing). Round 3 might surface another wave. The pattern is: every cryptographic or operational hardening of the hook layer introduces a new attack surface inside the same threat model.

**Score:** Security uplift = Medium-High (contingent on user opt-ins). Cost = High. Sustainability = Low-Medium (the pattern suggests more amendments).

### Option B: Skills-only, no hooks (RCS-symmetric)

**Description.** Drop the hook layer entirely. Ship v2.0.0 as ~42 skills with `paths:` activation, path-scoped loading, sigma scoring, 4-eval discipline. Settings template ships permission rules (declarative deny for `.env`, `secrets/**`, `curl|sh`, force-push to protected branches) as the only enforcement layer. No `~/.cscr/`, no AST hooks, no escape hatch, no `cscr verify`, no single-signer-vs-co-signer distinction (the plugin ships no executable code beyond the skills themselves).

**Security uplift over v1.** Medium. The catalog is real expertise; on-demand loading is a context-budget win; sigma scoring helps users prioritize. Permission rules provide deterministic enforcement for the patterns they cover (file paths, command patterns) — that's a real layer above v1's pure prose. But the catalog's "Level: strict" patterns (eval, pickle, shell=True, SQL f-strings, trust_remote_code, etc.) revert to advisory text — exactly what the user wanted to fix.

**Implementation cost.** Low. ~42 skills × 4 evals + settings-template + plugin manifest + SECURITY.md + governance.md. Drops: 11 hook scripts, AST modules, per-platform latency, escape-hatch mechanism, 4 CLIs, hash-pinning, sigstore-attestation-of-hooks (the manifest is just YAML at that point). Realistic timeline: 6-10 weeks for one maintainer.

**Sustainability under further premortem.** High. Without hooks, the model-controlled-inputs problem disappears. The remaining attack surface is the catalog content itself (corpus poisoning via PRs, deprecated patterns shipped as canonical) — these are governance problems CSCR already needs to solve and they have well-understood mitigations (CODEOWNERS, second-reviewer requirement, standards-currency CI). Round 3 would surface much less.

**Score:** Security uplift = Medium (loses the deterministic-block claim). Cost = Low. Sustainability = High.

**The honest framing.** "CSCR is a security catalog for Claude Code. It teaches; it does not enforce. The patterns it teaches are real and authoritative. The Claude Code platform's permission rules and sandbox feature provide enforcement; CSCR ships a settings template to configure them."

This is what RCS already does for methodology. Symmetric is honest.

### Option C: Narrow hooks to Bash-level only (model-can't-route-around)

**Description.** Keep hooks but restrict them to patterns the model genuinely cannot route around at the platform level. Specifically:
- `git push --force` / `--force-with-lease` to `main`/`master`/`release/*` (Bash AST via shlex)
- `curl ... | sh`, `wget ... | bash`, `iex (irm ...)` (Bash patterns)
- `chmod 777` (Bash patterns)
- `pip install` without `==`, `npm install @latest`, `uvx --from git+` without `@<ref>` (Bash patterns)
- Hardcoded secrets in Bash command strings (regex against tool_input.command for Bash calls only)

Drop the AST-on-Write/Edit hooks entirely. The Write/Edit-side patterns (eval, pickle, shell=True, SQL f-strings, dangerouslySetInnerHTML, trust_remote_code) move to Layer 3 skill text with explicit "use Semgrep or Bandit for deterministic enforcement of this class." Drop the escape hatch (no Write/Edit hooks = no `cscr:allow` needed). Keep `~/.cscr/` for the user-level enforcement settings only.

**Security uplift over v1.** Medium-High for Bash-level patterns. These are the patterns where the model has fewer escape routes — Bash command parsing is more constrained than Python AST, and the patterns themselves (force-push, curl-pipe-sh) are inherently single-tool-call attacks the model cannot easily route through alternative mechanisms. Loses the RCE-class block on Write/Edit (eval, pickle, etc.) — those revert to advisory.

**Implementation cost.** Low-Medium. ~42 skills + 5-6 hook scripts (Bash-only) + Bash AST module + simpler settings-template + SECURITY.md + governance.md. Drops: 6 Write/Edit hook scripts, Python/JS AST modules, escape hatch, `cscr-hash` and `cscr allowlist` CLIs. Keeps `cscr verify` as a simple sigstore checker for the hook scripts (which are now fewer and simpler). Realistic timeline: 10-14 weeks.

**Sustainability under further premortem.** Medium-High. The Bash-only patterns are structurally harder for the model to route around — `git push --force origin main` cannot be obfuscated into a different command shape the way `subprocess.run(["bash","-c", f"ls {x}"])` can disguise itself. Round 3 would surface fewer Criticals because the threat model is narrower and better-aligned with what hooks can actually enforce.

**Score:** Security uplift = Medium-High (narrower but genuine). Cost = Low-Medium. Sustainability = Medium-High.

### Option D: Defer enforcement to Claude Code platform, ship CSCR as catalog + configurator

**Description.** Ship v2.0.0 as: (i) ~42 skills (the catalog), (ii) a `settings-template.json` with extensive permission rules covering paths, commands, MCP servers, sandboxing config, (iii) a `cscr configure` CLI that merges the template into the user's settings interactively (explains each rule, lets the user opt in/out per-rule), (iv) optional integration with Claude Code's sandbox feature (CSCR ships a `sandbox.json` template too). No hooks at all. No `~/.cscr/`. No `cscr verify` (there's nothing executable to verify beyond the skills, which are markdown).

The pitch to the user: "CSCR teaches secure patterns AND configures Claude Code's platform-level security features (permission rules, sandbox) to enforce them. The enforcement runs in the platform, not in CSCR — so the threat model is whatever Claude Code's platform delivers, not what a plugin can fake."

**Security uplift over v1.** Medium-High. Same skill catalog as Option B, plus the platform-level enforcement that comes with proper sandboxing and permission rules. The catch: sandboxing and permission rules have real costs (some legitimate operations get blocked, the user has to think about exceptions). CSCR's value is curating the *right* permission rules and sandbox config for security-sensitive Claude Code use.

**Implementation cost.** Medium. ~42 skills + 1 interactive CLI (`cscr configure`) + 2 templates (settings + sandbox) + SECURITY.md + governance.md + a careful guide to which rules to enable for which use cases. The CLI is non-trivial (interactive, explains tradeoffs, persists choices). Realistic timeline: 12-16 weeks.

**Sustainability under further premortem.** High. The only attack surface is corpus poisoning + template-misconfiguration. Both are governance problems with well-understood mitigations.

**Score:** Security uplift = Medium-High. Cost = Medium. Sustainability = High.

**The honest framing.** "CSCR is the security configurator for Claude Code. It teaches you what secure patterns look like AND configures the platform's enforcement features to back them up. The enforcement is the platform's; CSCR is the curator."

## Cross-cutting observations

### What every option preserves

All four options preserve the v1→v2 wins that motivated the modernization:
- Skills replace CLAUDE.md walls (context-budget win for AI/ML projects)
- `/plugin install` replaces `cp` (distribution win)
- 4-eval discipline shipped from Round 1 (quality win)
- RCS congruence and cross-pointer (ecosystem win)
- Honest-framing constraint (credibility win)
- SECURITY.md, governance.md, standards-pin.yaml (operational hygiene wins)

The disagreement is only on the hook layer.

### What every option loses vs. the original aspiration

The original aspiration was "convert `Level: strict` from prose to actual enforcement." After two rounds of premortem, no architecture cleanly delivers that for the patterns CSCR cares most about (eval, pickle, SQL f-strings on Write/Edit). Either:
- We claim it (Option A) and pay for an architecture that requires multiple amendments to defend.
- We don't claim it (Options B, C, D) and admit CSCR's value is in teaching + platform-configuring, not in plugin-level enforcement.

The honest read of Hughes 2026 + the two premortems is that the second framing is right. CSCR cannot fix what the platform fundamentally allows.

### The RCS comparison

RCS ships 104 methodology skills with zero hooks. RCS's reputation is solid. RCS users do not complain that "the plugin doesn't enforce" — they understand RCS is methodology. CSCR adopting the same posture (Options B or D) imports RCS's credibility model along with its architecture.

The current CSCR design (Option A) is trying to be RCS *plus* enforcement. The premortems suggest the *plus* is the part that doesn't work.

## Decision: Option B with BYOH (Bring-Your-Own-Hooks)

**Adopted: Option B (skills-only plugin) with an optional reference-implementation hooks library that the user installs into their own Claude Code config.**

This is a sharpened version of Option B. The plugin ships hooks as *reference implementations*, not as active code. The user opts into them explicitly, installs them into their own `~/.claude/hooks/cscr/` directory, and owns the runtime trust decision.

### What ships in BYOH

```
claude-secure-coding-rules/
├── .claude-plugin/
│   └── plugin.json                  # name, version, metadata only
├── skills/                          # ~42 skills, primary value
├── settings-template.json           # declarative permission rules,
│                                    # works without any hooks
├── hooks/optional/                  # reference implementations
│   ├── README.md                    # WHEN to adopt, WHY each one is opt-in,
│   │                                # what each one does NOT catch
│   ├── _examples/                   # escape-hatch patterns, allowlist patterns
│   ├── block-force-push-protected.py
│   ├── block-curl-pipe-sh.py
│   ├── block-chmod-777.py
│   ├── block-unpinned-installs.py
│   ├── block-hardcoded-secrets.py
│   ├── block-eval-failsecure.py
│   ├── block-pickle-loads.py
│   ├── ...                          # 11-15 reference scripts
│   ├── coverage/                    # per-hook bypass-class docs
│   └── bundles/                     # curated groups: bash-only, ai-ml, full
├── tools/
│   ├── cscr-hooks.py                # install/update/list/remove user-local hooks
│   ├── cscr-verify.py               # verify the plugin install
│   └── cscr-configure.py            # interactive settings-template merger
└── docs/
    ├── how-to/
    │   ├── install.md
    │   ├── enable-optional-hooks.md # the central doc for BYOH
    │   ├── write-your-own-hook.md
    │   └── audit-cscr-pre-trust.md
    └── explanation/
        ├── three-layers.md          # catalog + template + opt-in user-hooks
        ├── why-hooks-are-opt-in.md  # references the premortem findings
        └── ...
```

### User workflow

1. `/plugin install tikitribe-secure-coding-rules` — installs skills, template, inert reference scripts
2. Read `docs/how-to/enable-optional-hooks.md` — explains the trust model
3. `cscr hooks install block-force-push-protected` (or `--bundle bash-only`) — copies the script into `~/.claude/hooks/cscr/`, adds the hook entry to `~/.claude/settings.json`, prints the coverage doc inline
4. Audit, modify, or remove individually via `cscr hooks list / update / remove`
5. The hooks live in the user's home dir, not the plugin dir; the user can edit them freely; updates are diff-reviewed before overwrite

### How BYOH addresses the Critical findings

| Round 1/2 finding | BYOH disposition |
|---|---|
| M3 / N1 (AST→regex attacker-controllable) | User adopted the script knowing the documented bypass classes; chooses fail-secure variant if they want |
| M4 / N5 (hash-pinning self-referential) | Disappears — CSCR doesn't run anything in the user's session by default |
| N2 (escape-hatch salt model-readable) | CSCR ships *example* escape-hatch patterns; user chooses their approach |
| N3 (in-tree allowlist) | Same — example patterns in docs, user picks |
| N6 (sigstore + co-signing) | Plugin still sigstore-signed but threat surface shrinks: compromise window is adoption-time only |
| N7 (global advisory kill switch) | No kill switch because no plugin-shipped hooks to disable |
| N4 (PR-diff Action unscaffolded) | User implements their own PR review for `~/.claude/hooks/cscr/` if they want it |
| N8 (bypass log writable) | User owns the log location and retention |
| N9 (latency budget cross-platform) | User benchmarks on their own hardware before enabling |
| N17 ("refutation doesn't block release") | No deterministic enforcement claim to refute |

The findings that *still apply* under BYOH are the catalog-side concerns (N11 eval gaming, N13 statistical thinness, N14 OWASP Benchmark coverage gap, plus governance findings). Those need Amendment 03-style resolution but they are tractable in a way the hooks-side findings were not.

### Honest framing under BYOH

> CSCR teaches secure patterns through a skill catalog and ships a permission-rule template that uses Claude Code's platform-level enforcement. For users who want additional deterministic checks beyond what permission rules express, CSCR ships a library of reference hook scripts with documented coverage and bypass classes. The user installs the hooks they want into their own Claude Code config; CSCR does not run code in your session by default. Each hook's coverage doc names the bypass classes it does not catch. You are adopting reference implementations on your own infrastructure with your own threat model.

### Reasoning for B+BYOH over pure B, C, D, or A

1. **Sustainability:** premortem clears almost completely on the plugin itself. Two rounds of 11 Critical findings on Option A is strong signal that further amendments would surface more. BYOH passes the same premortem cleanly because CSCR no longer runs code in the user's session.
2. **The catalog is the primary value.** v1's actual problem is "84 files copied by hand, 8,800 lines always-on, no path-scoping, no on-demand loading." BYOH fixes all of that — and adds an optional power-user enforcement layer for those who want it.
3. **Trust decision lands in the right place.** The user knows their threat model, false-positive tolerance, and codebase quirks better than CSCR can. Putting the runtime trust decision with the user respects that and removes the supply-chain attack surface CSCR can't credibly defend.
4. **Reference implementations are real value.** Users who write their own hooks read CSCR's first. The optional library teaches what good hook code looks like — that is teaching value layered on top of the catalog's teaching value.
5. **RCS-symmetric on the default path.** A user who installs both CSCR and RCS and adopts no optional hooks sees two structurally identical plugins. The cross-pointer model becomes more credible when the architectures match. CSCR adds value beyond RCS only for users who explicitly want it (the optional hooks library).
6. **v2.x runway preserved.** If a particular hook proves widely useful and widely safe in real deployments, it could be promoted to default-enabled in v3 with proper deprecation, telemetry, and informed consent. The optional library is the proving ground.

### Tradeoffs accepted

**You give up:**
- The "install one plugin and you're protected" narrative. Users opt into hooks explicitly.
- Some users will skip the hooks step and only get the catalog. That's fine — they still get the catalog.
- The hooks reference library becomes a maintenance commitment (current scripts, documented bypass classes) but it is far lighter than maintaining shipped-and-running hooks: no sigstore-of-hooks, no per-platform latency benchmarks, no `cscr.enforcement` setting, no escape-hatch infrastructure.

**You gain:**
- v2.0.0 ships in ~6-10 weeks
- v2.0.0 passes adversarial premortem on first pass with few or no Criticals
- v2.0.0 claims match what CSCR actually delivers
- Power users get exactly the enforcement they want, configured exactly the way they want
- The optional library teaches hook authorship to the broader Claude Code ecosystem

## Next steps

1. Rewrite the design doc against the BYOH architecture. The current doc is structured around hooks-as-first-class; the new one centers on the catalog with hooks-as-reference-library.
2. Carry forward from prior amendments: skills catalog (M1-M9), eval discipline (M14), SECURITY.md + governance.md + standards-pin.yaml (M5, M7), RCS cross-pointer (M9), honest-framing constraint (M1, N6).
3. Drop from prior amendments: hook supply-chain machinery (M4, N5, N6), escape-hatch mechanism (M2, N2, N3), `cscr.enforcement` user-vs-project resolution (N7), AST fail-secure logic (N1), `~/.cscr/` state directory (N2, N3 resolutions).
4. Run a single fresh premortem round on the new design to confirm the new shape passes cleanly.
5. Move to implementation planning (`writing-plans` skill).

This decision document is final unless new information arrives. The next artifact is the rewritten design doc.

---

## Addendum: B+BYOH attacked, B-pure adopted

After the rewritten design doc was authored and committed, a fresh single-round premortem (six perspectives in parallel) was run against the B+BYOH architecture. Acceptance gate was ≤2 Critical findings → proceed to implementation.

**Fresh round produced 5 Critical, 8 High, 9 Medium.**

The pattern across three rounds was now visible: **any architecture that ships CSCR-authored executable enforcement code recreates the model-controlled-bypass problem because the agent has Bash tool access.**

Specifically, the 5 fresh Criticals against B+BYOH were:

| # | Finding | Root cause |
|---|---|---|
| F1 | `cscr hooks install` is model-callable via Bash | Model emits the install command; user approves at the 93% rate |
| F2 | Settings.json hook-entry contract undefined; merger weakens existing user rules | CSCR doesn't specify conflict resolution; security-conscious users get a regression |
| F3 | `block-eval-failsecure.py` re-introduces Round 2 N1 AST-on-Edit problem | The retrospective claimed to drop this; the reference library re-shipped it |
| F4 | 6-10 week timeline doesn't survive 600+ person-hour artifact count | The estimate was based on 4 evals/skill (168 total); B+BYOH ships 8 (336 total) |
| F5 | P6.5 third-party review governance unaddressed; success criterion unachievable on schedule | No SoW, no NDA, no insurance, no recruitment plan |

F1, F3, F6 (CLI self-verifier), F9 (update channel) all collapse to the same root cause: **CSCR-shipped executable code the model can instruct the user to run.**

### B-pure adopted

The fresh round forced the recognition that BYOH did not actually relocate trust — it relocated the *act of installation* while preserving the *runtime attack surface*. The only architecture that escapes the trap is one where CSCR ships zero executable enforcement code:

- ~42 skills (the catalog) — unchanged
- `settings-template.json` (declarative permission rules) — unchanged; user merges manually with their own tooling
- `docs/how-to/write-your-own-hook.md` (full code examples in markdown the user copies) — replaces `hooks/optional/`
- No `cscr-configure`, no `cscr-hooks`, no `cscr-verify` CLI binaries — eliminated
- No `~/.cscr/` state directory — eliminated
- Sigstore verification via `python -m sigstore verify` documented in `docs/how-to/verify-the-release.md` — no CSCR-shipped binary

The design doc was rewritten a second time to reflect B-pure (see commit log).

### Tradeoffs accepted under B-pure

- **Longer timeline (10-14 weeks vs 6-10).** Adding the corpus-quality audit + reviewer procurement + 14 evals/skill costs about 4 extra weeks. The B-pure architecture itself is smaller (no CLIs to build) but the eval discipline tightened in response to fresh-round F13.
- **Friction is the safety mechanism.** Users who want hooks must read documentation and author code. There is no `--bundle full` shortcut. This is the point.
- **No automatic upgrade for user-authored hooks.** Users subscribe to GitHub Security Advisories and update their copies manually when a bypass is documented.
- **Loses the "all-in-one security plugin" marketing position.** CSCR is a catalog + template + docs. That's it. Users who want enforcement beyond what permission rules express bring their own enforcement code.

### What B-pure gains

- Premortem clears the architectural Criticals. The remaining findings are catalog-side and governance-side, both well-understood problem classes.
- Honest claims throughout. "CSCR teaches; Claude Code enforces; you write hooks if you want them." No verb has to be linted out of the README because the claims are bounded by what the architecture actually delivers.
- Defensible under regulator review. Substance-over-form analysis lands cleanly because CSCR doesn't ship executable enforcement code at all.
- Architectural symmetry with RCS, deeper than B+BYOH had. Both repos ship skills + docs only; cross-pointer typo-squat amplification reduces because neither has install CLIs to forge.

### What this means for the decision document

The original recommendation in this document — Option B (skills-only) — was correct in spirit but underspecified the cost of even minimal executable code. BYOH attempted to preserve the optional-hooks teaching value as installable scripts; the fresh round demonstrated that *shipping the scripts* (whether active or inert) is the load-bearing failure, not their default-on/default-off status.

B-pure preserves the teaching value as *documentation*, which is durable, copy-paste-friendly, and outside the model's invocable surface. That's the architecture v2.0.0 ships under.
