# CSCR v2 Design — Amendment 02

**Status:** Approved, applied to design doc 2026-05-24-cscr-modernization-design.md
**Date:** 2026-05-24
**Author:** Rock Lambros
**Source:** Round 2 adversarial premortem (six-perspective multi-agent), surfaced 6 Critical and 6 High findings after Amendment 01. This amendment resolves the six Critical findings (N1–N7). High-severity findings (N8–N18) and lower-priority findings (N19–N34) are deferred to Amendment 03 or the implementation plan; the deferral list is at the bottom of this document.

This amendment is a delta document, structured the same way as Amendment 01. The main design doc is revised in place alongside it.

## Meta-observation that shapes this amendment

Round 2 found that Amendment 01's cryptographic hardening (line-hashes, hash-pinned hooks) and operational hardening (advisory-by-default, allowlist registry) each introduced a new attack surface inside the threat model the hardening was supposed to address. The pattern repeats across N1, N2, N3, N5, N6, N7: a control was added to defeat a model-controlled attack vector, but the control itself depends on a property (a secret the model can't read, a file the model can't write, a verifier the attacker hasn't compromised) that doesn't hold when the model is the threat.

The root cause is structural: **CSCR cannot deterministically enforce against an agent that controls the inputs to the enforcement check**. The Claude Code platform's hook mechanism reads stdin from the model's tool calls; the hook script lives in user-writable space; the project root is model-writable; the plugin directory is model-readable. Every "defense" the amendment adds lives somewhere the threat can reach.

Amendment 02 accepts this constraint instead of pretending to defeat it. The resolutions below narrow CSCR's enforcement claim to what is actually defensible, push the rest to advisory layers with honest framing, and add platform-level controls (deny rules, sandbox config, OS-level guards) where the plugin-level controls were doing work they couldn't do.

---

## N1. AST→regex fallback is attacker-controllable

**Finding (Round 2).** Hooks parse with AST; on parse failure (mid-edit syntax errors, partial-file deltas) fall through to regex. Attacker controls when parse fails by writing a single unbalanced delimiter elsewhere in the file. Edit's `tool_input` is `old_string`/`new_string` deltas, not full content — AST can't parse the delta alone; hook must read-file-apply-diff-parse, which the spec never specifies. Fail-open on parse failure is a security anti-pattern.

**Resolution.**

1. **Fail-secure on parse failure for files that previously parsed.** If `ast.parse` fails on the post-edit file content AND the pre-edit file parsed successfully, the hook blocks the edit with a stderr message "CSCR cannot validate this edit: post-edit AST parse failed. Apply the edit in smaller fragments or fix the syntax error first." This converts the attacker's bypass technique (introduce a parse error) into a self-DoS that the user notices.
2. **Read-file-apply-diff-parse pattern specified.** For Edit calls, the hook reads the current file from disk, applies the diff in memory (`new_content = file_content.replace(old_string, new_string, 1)`), then parses the result. The spec names this pattern explicitly; per-hook coverage docs document the TOCTOU window (the hook reads the file before Claude Code applies the edit; if the file changes between hook read and Claude Code write, the AST check ran against stale content).
3. **Two-stage edits not detected.** A model that writes a benign Python file (Write, passes AST) then edits in the malicious one-liner (Edit, AST applies fine to the resulting file and flags it) IS caught by the Edit-time AST check. A model that writes benign + edits with a syntax error to force parse failure IS caught by the fail-secure rule above. The remaining case — model writes benign, then writes a *new* file with the payload — is caught by the new file's own Write hook. The hook is per-call, not per-session, so each call is checked.
4. **Regex floor explicitly scoped.** The regex floor only fires when (a) the file is a new file (no pre-edit state to compare) AND (b) AST parse fails on the new content. In that case, the hook blocks (fail-secure) AND emits the regex match as a hint for the user. The regex never silently passes.

**Spec changes:**
- §Hybrid hook architecture → Tier A: add subsection "Edit-mode AST handling: read-file-apply-diff-parse with fail-secure on regression."
- §Risk register: row "Multi-statement dataflow false negatives in AST hooks" updates to note Edit-mode is now AST-equivalent to Write-mode.

---

## N2. Escape-hatch salt is model-readable

**Finding.** Salt published with plugin lives at a path the model can Read via `${CLAUDE_PLUGIN_DIR}`. The model computes `sha256(line + salt)[:8]` and emits the matching `# cscr:allow N:HASH`. The line-hash collapses to a checksum. Preimage attack is trivial when the salt is public.

**Resolution.**

The line-hash mechanism is removed entirely. It does not survive contact with the threat model.

The replacement is a **per-installation user secret** stored outside the project tree:

1. **Per-installation salt.** On first plugin invocation, the plugin generates a 256-bit random salt and stores it at `~/.cscr/installation-salt` (chmod 600, user-only readable). The model running in a project context does not have Read access to `~/.cscr/` unless the user explicitly grants it via permission rules — and the design explicitly documents that granting Read access to `~/.cscr/` defeats the bypass-prevention mechanism.
2. **Hash computed inside the hook, never serialized.** The hook computes `sha256(line + installation-salt)` at hook-time. The result is compared to the hash the user typed in the `# cscr:allow N:HASH` comment. The hash the user types must be generated by running a separate command `cscr-hash <line>` from outside the model's session (e.g., in the user's terminal), which reads the per-installation salt. The model has no path to compute the same hash.
3. **Plugin manifest documents the deny rule.** The plugin ships with a `settings-template.json` deny rule: `Read(~/.cscr/**)`. Users who merge the template get the rule. Users who don't merge accept the residual risk.
4. **Out-of-band registry kept (Amendment 01 M2.2).** `.cscr-allowlist.json` at the project root remains as the second mechanism, but is no longer the primary defense — see N3 for why.

**Honest claim narrowing.** Even with the per-installation salt, the bypass is defeated only against a model that does not have Read access to `~/.cscr/`. A model with global Read (e.g., a session run in `bypassPermissions` mode, or a project whose permission rules grant `Read(~/**)`) can still compute the hash. The spec documents this explicitly. The bypass-prevention claim is "defeats prompt-injection attacks in default-permission Claude Code sessions where `~/.cscr/` is not in the model's Read scope."

**Spec changes:**
- §Hybrid hook architecture → Escape hatch: replace the entire subsection. Line-hash mechanism removed. Per-installation salt + out-of-tree storage substituted.
- §Repository layout: remove the `<salt>` location from the plugin tree; document `~/.cscr/installation-salt` as the storage path.
- §Default posture: add the `Read(~/.cscr/**)` deny rule to the settings-template.

---

## N3. `.cscr-allowlist.json` is in-tree-writable

**Finding.** The "owned by humans (not the model)" claim has no enforcer. Model has Write to project root. Hook reads the file the model just wrote. PR-diff Action is opt-in.

**Resolution.**

The in-tree allowlist is moved out of tree, with the same per-installation discipline as the salt:

1. **Allowlist registry moves to `~/.cscr/allowlists/<project-hash>.json`.** The `<project-hash>` is a deterministic hash of the project's git remote URL (or, for non-git projects, of the absolute path). The hook reads from this location, not from the project root. The model has no default Read or Write to `~/.cscr/`.
2. **Allowlist entries are managed via a CLI command, not by file edit.** `cscr allowlist add <rule-id> <file> <line>` reads the salt from `~/.cscr/installation-salt`, computes the line-hash, and writes the entry to the per-project allowlist file. The user runs this command in their terminal, outside the model's session.
3. **Plugin ships a Read deny rule for `~/.cscr/allowlists/**`.** Same template-merge model as the salt. Users who don't merge accept the residual risk.
4. **PR-diff gate remains as an additional layer.** It's opt-in for consuming projects, but no longer load-bearing — the out-of-tree allowlist is the primary defense. The PR gate is now documentation hygiene (review CHANGES to the allowlist commits) rather than the only defense.

**Honest claim narrowing.** Same caveat as N2 — defeats prompt injection in default-permission sessions; bypassable if the model has Read access to `~/.cscr/`. Documented.

**Spec changes:**
- §Hybrid hook architecture → Escape hatch §2: rewrite to point at `~/.cscr/allowlists/<project-hash>.json`.
- §Repository layout: remove `.cscr-allowlist.json.example` from the plugin tree.
- §Migration plan P5: add CLI tool `cscr allowlist <add|remove|list>` as a deliverable.

---

## N5. `hookScriptHashes` verifier is self-referential

**Finding.** "Claude Code (where possible) or a SessionStart hook (where not)" — the SessionStart hook is shipped in the same plugin being verified. Marketplace-push attacker compromises both hooks and verifier in one commit. Sigstore-on-manifest verifies the manifest, not the hook scripts at runtime.

**Resolution.**

Plugin-level hash verification is removed. It cannot work without platform support, and the platform does not support it as of Claude Code's current version.

The replacement is **explicit reliance on the platform's plugin trust model + a documented out-of-band audit workflow**:

1. **Hash-pinning claim is removed.** The plugin manifest no longer claims `hookScriptHashes` as a runtime control. The field stays in the manifest as forward-compatible metadata for a future Claude Code version that natively verifies it, but the design no longer asserts current enforcement.
2. **`docs/how-to/audit-cscr-pre-trust.md` becomes the primary supply-chain control.** The doc walks users through computing the SHA-256 of every hook script post-install and comparing against the sigstore-attested release bundle. The user runs this command once at install, and again on each plugin update. Output is a simple PASS/FAIL.
3. **A `cscr verify` CLI command automates the check.** Reads the local plugin install, fetches the sigstore bundle from the release URL, recomputes hashes, reports any drift. Users with high security requirements add `cscr verify` to their CI pre-deploy step (consuming-project responsibility).
4. **SessionStart hook is removed from the verification path.** Its previous role (run `hookScriptHashes` check at session start) was self-referential; it's deleted. The plugin still has a SessionStart hook for first-run notice and per-installation salt generation, but it does no security verification.
5. **README claim updated.** From "hash-pinned hooks verified at load" to "sigstore-attested releases; user-runnable `cscr verify` for hash audit; no runtime verification at this time."

**Spec changes:**
- §Repository layout: `hookScriptHashes` retained but documented as forward-compatible only.
- §Risk register: row "Marketplace push or maintainer-credential compromise" updates mitigation language: "sigstore-attested releases + user-runnable `cscr verify` + documented six-check audit. No runtime hash verification until Claude Code adds native support."
- §Migration plan P5: add `cscr verify` CLI tool as a deliverable.

---

## N6. Sigstore verification opt-in; second-key requirement contradicts itself

**Finding.** Release-side artifact + README docs page = no load-time check. Second-key requirement contradicts itself across M4 §4 (mandatory) and P7 (optional with documented residual risk). The implementation team takes the path that ships.

**Resolution.**

The contradiction is resolved by lowering the v2.0.0 claim, not by raising the gate:

1. **v2.0.0 ships single-signer with explicit disclosure.** The release notes, README, and `docs/governance.md` all state: "v2.0.0 releases are signed by a single maintainer key (Rock Lambros). Co-signing requires a second maintainer who has not yet been recruited. Until co-signing is in place, the supply-chain attack surface is single-key compromise. See `docs/governance.md` for the recruitment status."
2. **Second-key requirement is a v2.x.0 milestone, not a v2.0.0 gate.** Documented as such. Removes the contradiction by being explicit that the control is not yet live.
3. **Sigstore verification gets a user-facing hook.** The `cscr verify` command (see N5) checks the sigstore signature, not just the hash. Users who care about supply-chain integrity run this at install and after every update. This is the only verification the design promises at v2.0.0.
4. **Honest-framing constraint extended.** Amendment 01's honest-framing lint (covering `enforce`, `block`, `refuse`) is extended to cover supply-chain claims: `co-signed`, `attested`, `verified`, `hash-pinned`. A CI lint over README.md and docs/ flags any of these terms; the maintainer must confirm in PR review that the claim is accurate at the current release.

**Spec changes:**
- §Migration plan P7: rewrite to remove the "or document why v2.0.0 ships with single-key signing as accepted residual risk" escape hatch; replace with explicit single-key disclosure as the v2.0.0 posture.
- §Architecture overview → Honest-framing constraint: extend the lint to supply-chain verbs.

---

## N7. Non-bypassable rules defeated by global advisory kill switch

**Finding.** Model can Write `cscr.enforcement: "advisory"` to project `.claude/settings.json`. All Tier A hooks now exit 0 with stderr warning. Rules #8 and #12 — declared non-bypassable per-rule — are bypassable per-suite via the kill switch that M10 introduced.

**Resolution.**

The kill switch is moved out of the model's reach:

1. **`cscr.enforcement` setting only honored from user settings, not project settings.** The plugin reads `cscr.enforcement` from `~/.claude/settings.json` (user-level, outside the project tree, requires explicit `Write(~/.claude/**)` permission the model does not have by default). Project-level `cscr.enforcement` settings are ignored with a stderr warning: "CSCR enforcement mode is set at the user level, not the project level. Project-level setting ignored."
2. **`Write(~/.claude/**)` deny rule added to `settings-template.json`.** Documented as load-bearing for the non-bypassable claim. Users who don't merge accept the residual risk.
3. **Non-bypassable rules ignore `cscr.enforcement: "advisory"`.** Even if the user sets advisory mode globally, rules #8 (hardcoded secrets) and #12 (force-push) still exit 2. The user can disable them only by uninstalling the plugin or by running with `bypassPermissions` mode (which the plugin can detect via env var and refuse to load).
4. **Per-rule disable is similarly user-level only.** `cscr.rules.<rule-id>.enabled: false` is honored only from user settings. Project-level per-rule disable is ignored.
5. **UX for the conflict.** When the model tries to set `cscr.enforcement: "advisory"` in project settings (or when the hook detects a project-level setting), the hook emits stderr: "Rule #N attempted to be disabled via project-level config. CSCR honors enforcement settings only from user-level config. Block stands. See docs/how-to/handle-rule-conflicts.md."

**Honest claim narrowing.** The non-bypassable claim is now: "Rules #8 and #12 cannot be disabled by a model with default permissions in a Claude Code session. They can be disabled by a user with shell access to `~/.claude/settings.json` AND who has merged the CSCR settings template. Users who have not merged the template, or who have granted the model `Write(~/.claude/**)`, accept the residual risk."

**Spec changes:**
- §Hybrid hook architecture → Default posture: rewrite per above.
- §Settings template (new subsection in repo layout): document the required deny rules (`Read(~/.cscr/**)`, `Write(~/.claude/**)`, plus the existing N2/N3 deny rules) as a single coherent block.
- §Risk register: add row "Model writes `cscr.enforcement: advisory` to project settings" with mitigation "Project-level setting ignored; user-level only."

---

## What this amendment does NOT cover

Round 2 surfaced 18 surviving findings at Plausible-or-above. This amendment resolves the 6 Critical (N1, N2, N3, N5, N6, N7). The following High and Medium-High findings are deferred:

- **N4** (PR-diff Action unscaffolded) — Amendment 02's resolution of N3 reduces N4's load-bearing role; the PR gate is now optional documentation hygiene. Scaffolding the Action is implementation-plan work.
- **N8** (Bypass log writable/erasable) — Amendment 03 candidate. Resolution shape: move log to `~/.cscr/logs/`, same permission model as the salt; SessionStart hook also writes a heartbeat (catches abnormal-termination gap); structured content schema (no source snippets — hash only).
- **N9** (150ms × 6 budget fiction outside GHA Linux) — Amendment 03 candidate. Resolution shape: hook daemon (single long-lived process, six rules in one) eliminates per-hook process spawn; benchmark on Linux + macOS + Windows + Windows-with-Defender; document per-platform p95 latency.
- **N10** (ReDoS / catastrophic backtracking) — Implementation plan. Use `re2` or set a `signal.alarm` timeout per regex; fail-secure on timeout.
- **N11** (Adversarial eval gaming via in-repo answer keys) — Amendment 03 candidate. Resolution shape: hold out 50% of adversarial probes in a private repo; only the public 50% ship with the plugin; private set is rotated quarterly and the third-party reviewer uses both.
- **N12** (Eval count contradiction) — Implementation plan. One sentence in §Eval discipline naming the canonical layout.
- **N13** (n=5 adversarial probes statistically thin) — Amendment 03 candidate. Resolution shape: stratify per-pattern, raise floor to n≥30 per pre-registered claim, commit to McNemar's test with Bonferroni correction across 42 strata.
- **N14** (OWASP Benchmark v1.2 doesn't cover AI/ML surface) — Amendment 03 candidate. Resolution shape: stratify the held-out corpus into (Web/SAST, AI/ML, Supply-chain, Repo-policy); use OWASP Benchmark only for the Web/SAST stratum; commission MITRE ATLAS-derived probes for AI/ML stratum.
- **N15** (P0.5 ↔ P5 circular dependency) — Implementation plan. Reorder: P5 (hooks) before P0.5 (corpus audit). Trivial fix.
- **N16** (Pre-registration has no neutral custodian) — Implementation plan. Use OSF or sign a git tag in a third-party-controlled repo (e.g., a public scratch repo of the named reviewer).
- **N17** (Refutation-doesn't-block-release is a quotable defect line) — Amendment 03 candidate. Resolution shape: replace "refutation does not block release" with "refutation triggers a relabel-to-X path (catalog-only framing) before release"; commit to specific relabel language in advance.
- **N18** (v2.0.0 → v2.1.0 strict flip threshold undefined) — Amendment 03 candidate. Resolution shape: commit to threshold "≥10 distinct installs reported any FP AND ≥30 days elapsed AND ≥80% of reported FPs closed."
- **N19–N34** (lower priority) — Implementation plan.

The deferral logic: Amendment 02 must resolve the Critical findings before Round 3 can run productively. The High findings (N8, N9, N11, N13, N14, N17, N18) are real and should be resolved in Amendment 03, but they don't change the spec's architectural soundness the way the Criticals did.

---

## Success criteria after this amendment (v2.0.0)

The Amendment 01 success criteria are revised. The honest-framing constraint expands (N6). New criteria are added for the moved-out-of-tree files (N2, N3, N7).

1. Plugin is installable from the community marketplace as `/plugin install tikitribe-secure-coding-rules`.
2. All ~42 skills have 4 passing evals each (Amendment 03 may revise the per-skill adversarial probe count and schema).
3. All 11 Tier A hooks have passing unit tests AND per-hook coverage docs at `hooks/enforcement/coverage/<hook>.md` enumerate covered call shapes and known bypass classes.
4. CI drift-check against RCS passes (frontmatter-parsed, pinned-SHA).
5. README's "Migrating from v1" section is in place.
6. Total p95 per-session loaded skill size, measured by a representative AI/ML+FastAPI test fixture, is less than the v1 baseline.
7. `docs/explanation/enforcement-coverage.md` exists and is reviewed by a named third party; README contains no enforcement verbs (`enforce`, `block`, `refuse`) outside Tier A scope **AND no supply-chain verbs (`co-signed`, `attested`, `verified`, `hash-pinned`) without explicit per-release accuracy review**; pre-registered third-party held-out review is complete with results published in release notes.
8. `SECURITY.md` exists, has been smoke-tested by an external reporter, and the contact channel works.
9. **(Revised, N5+N6)** Release is sigstore-attested with a single maintainer key; `cscr verify` CLI command exists and produces clear PASS/FAIL output; `docs/how-to/audit-cscr-pre-trust.md` documents the six-check audit. Co-signing is a v2.x.0 milestone, explicitly disclosed as not-yet-implemented in release notes.
10. **(New, N2+N3+N7)** `settings-template.json` includes deny rules for `Read(~/.cscr/**)` and `Write(~/.claude/**)`; the README and SECURITY.md document these as load-bearing for the bypass-prevention and non-bypassable claims; users who do not merge the template are explicitly told they accept the residual risk.

## Resume condition for the premortem

Round 3 (security and adversarial robustness, lead perspectives Red Teamer + Security Architect) can resume after this amendment lands in the design doc. **However**, the recommendation from Round 2 was to consider whether the architectural pattern is sound before continuing. After applying Amendment 02, Rock should decide:

- **(A)** Continue to Round 3 — the amendments have stabilized the design enough to attack the next layer.
- **(B)** Step back and write a "design retrospective" — two rounds with 11 cumulative Critical findings (5 in Round 1, 6 in Round 2) suggests the hybrid-hook architecture is fighting the platform. A simpler architecture (skills-only, no hooks; or hooks limited to Bash-level patterns the model cannot route around like force-push and curl-pipe-sh) might land more honest claims with less moving parts.
- **(C)** Stop the premortem entirely — Amendment 02 is sufficient triage; ship v2.0.0 against the narrowed claims and accept that further premortems hit diminishing returns.

This decision is on Rock, not in the spec.
