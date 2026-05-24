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

## Recommendation

**Adopt Option B (skills-only) for v2.0.0. Reserve Option C or D for v2.x if the hook layer is genuinely needed.**

Reasoning:

1. **Sustainability matters more than feature completeness for v2.0.0.** Two rounds of 11 Critical findings on Option A is a strong signal that further premortems will surface more. Option B passes the same premortem cleanly because the threat model is much narrower.
2. **The catalog is the primary value.** v1's actual problem is not "no enforcement" — it is "84 files copied by hand, 8,800 lines always-on in `_core/` alone, no path-scoping, no on-demand loading." Option B fixes those completely. The enforcement-via-hooks layer was the ambitious goal added on top; the ambitious goal is the part with the recurring Critical findings.
3. **Option B can be shipped in 6-10 weeks vs Option A's 4-8 months.** The faster ship lets CSCR users get the catalog wins quickly. If demand for hook-based enforcement is strong post-v2.0.0, Option C (Bash-only hooks) is a natural v2.x expansion that builds on a stable v2.0.0 foundation.
4. **Honest framing is easier to maintain when claims are smaller.** Option A's honest-framing constraint (no `enforce`, `block`, `refuse` outside Tier A; no `co-signed` without per-release review) is real but adds CI lint complexity and PR-review burden. Option B has no enforcement claims to police — the framing is naturally honest.
5. **RCS-symmetric is a strong default.** Two repos with the same architecture (skills + evals + settings-template, no hooks) reduces cognitive load for users who install both. The cross-pointer model already in the design becomes more credible when the architectures match.

**What we lose by choosing B:**

- The "Tier A hooks block 12 RCE-class patterns" claim. This was the headline that motivated Round 1's "yes go big" decision. Replacing it with "the catalog teaches you to avoid these patterns and configures permission rules to deny the worst" is a downgrade in marketing terms, an honest narrowing in security terms.
- The political/competitive position of "the security plugin that actually enforces." CSCR would not occupy that niche. Whether anyone else can is an open question — the premortem suggests no.

**What we gain:**

- A v2.0.0 that ships in ~2 months instead of ~6 months.
- A v2.0.0 that passes adversarial premortem on first pass with few or no Criticals.
- A v2.0.0 whose claims match what the platform actually delivers.
- Architectural symmetry with RCS that strengthens both repos.
- Capacity preserved for v2.x to add narrowly-scoped Bash hooks (Option C) once the v2.0.0 catalog is shipped and stable.

## Decision required from Rock

This document is a decision support memo, not a spec. The architectural choice is yours.

**(A)** Continue current architecture. Write Amendment 03 for N8-N18, run Round 3, accept the continued amendment cycle. v2.0.0 in 4-8 months with the "Tier A hooks enforce" claim narrowed and caveated.

**(B)** Skills-only. Rewrite the design doc to remove the hook layer entirely. ~42 skills + permission-rule template + governance. v2.0.0 in 6-10 weeks with honest "catalog + platform configurator" framing.

**(C)** Bash-only hooks. Keep hooks but narrow to the 5-6 patterns the model can't route around at the Bash layer. Drop the Write/Edit hooks. v2.0.0 in 10-14 weeks with "narrow but genuine" enforcement claim.

**(D)** Catalog + configurator. Ship the skills plus an interactive `cscr configure` CLI that drives Claude Code's platform-level enforcement (permission rules, sandbox). v2.0.0 in 12-16 weeks with "the enforcement is the platform's; CSCR is the curator" framing.

My recommendation is **B** with **C as a deliberate v2.x expansion** once v2.0.0 is shipped and the catalog's adoption is measured. The 11 Critical findings across two rounds are strong evidence that the hook layer in its current form is fighting the platform. Option B accepts that constraint instead of fighting it further.

If you disagree and want to continue with Option A, the next step is Amendment 03 for N8-N18 and Round 3. If you choose C or D, the next step is rewriting the design doc against the new architecture and running a fresh single-round premortem on it (the changes are large enough that the prior premortems' findings won't all carry over).
