# CSCR v2 Design — Amendment 01

**Status:** Approved, applied to design doc 2026-05-24-cscr-modernization-design.md
**Date:** 2026-05-24
**Author:** Rock Lambros
**Source:** Round 1 adversarial premortem (six-perspective multi-agent), surfaced 25 Plausible-or-above findings and 1 parked tail risk. This amendment resolves the eleven highest-priority findings (M1–M11). Lower-priority findings (M12–M28) are tracked for the implementation plan, not for the spec.

This amendment is a delta document. It states each finding, the resolution that lands in the design, and the spec passages that change. The main design doc is revised in place alongside this amendment.

---

## M1. Layer-1 false-confidence reframing

**Finding (Round 1).** The design declares a three-layer architecture and labels Layer 1 "model cannot bypass," but Layer 1 covers ~12 patterns out of the ~250 `Level: strict` rules in the corpus. README/marketing reads as covering all strict rules; coverage is ~1–2%. Replicates the v1 false-confidence pattern at a new layer.

**Resolution.**

1. **Coverage table is mandatory artifact, gated by Success Criterion 7.** A new artifact `docs/explanation/enforcement-coverage.md` lists, for each of the 12 Tier A hooks, the CWE class it targets, the explicit bypass classes it does NOT catch, and the layer (Tier B or Layer 3 skill) that picks up the gap. Same table generated for Tier B and Layer 3 with explicit "this is advisory, not enforcement."
2. **Marketing language constraint.** The README cannot use "enforce," "block," or "refuses" outside the Tier A section. Layer 2 and Layer 3 use "advises," "loads guidance for," "documents." Lint check in CI: a regex-based grep over README.md and docs/ that flags marketing verbs in non-Tier-A contexts. Soft warning, not blocking — but it generates a review comment.
3. **Third-party review gate.** Before v2.0.0, a held-out vulnerable-code review (see M11) confirms that the README's enforcement claims match a reviewer's read of the actual coverage. The reviewer is named in the release notes.

**Spec changes:**
- §Architecture overview, layer table: each layer's "Strength" column rewrites to name what is covered, NOT a global claim. Layer 1: "Deterministic block of 12 explicit patterns; see enforcement-coverage.md for bypass classes." Layer 2: "Declarative file-path and command deny rules; ineffective against process-internal writes." Layer 3: "Advisory model guidance, conditional on skill activation."
- §Success criteria: add criterion 7 "enforcement-coverage.md exists and is reviewed by a named third party; README contains no enforcement verbs outside Tier A scope."

---

## M2. `# cscr:allow` escape hatch is model-controllable

**Finding.** A prompt-injected model can write `# cscr:allow N` next to a payload and the hook passes. The bypass token lives in the same input stream the model controls. The "comment is the audit trail" claim relies on PR review at the 93% approval rate.

**Resolution.**

1. **Out-of-band allowlist registry, hash-bound.** `# cscr:allow N` is no longer sufficient on its own. The full bypass form is `# cscr:allow N:<sha256-prefix-8>` where the SHA-prefix is computed over the offending line plus a stable salt. Hook computes the same hash; mismatch = block. A second file `.cscr-allowlist.json` at the project root, owned by humans, lists permitted (rule-id, file-path, line-hash) tuples. A bypass that's NOT in `.cscr-allowlist.json` AND not matching its line-hash gets blocked.
2. **Rule deny-list (rules that cannot be bypassed).** Rule #8 (hardcoded secrets) and Rule #12 (force-push to protected branches) are non-bypassable. The hook ignores `# cscr:allow` for these rules. Documented in `docs/explanation/three-layers.md`.
3. **PR diff gate.** A required CI check on consuming projects (provided as an optional GitHub Action `cscr-allowlist-gate`) blocks PRs that introduce new `cscr:allow` entries without a matching diff in `.cscr-allowlist.json`. This is opt-in for consuming projects, not enforced by CSCR itself.
4. **Logging.** SessionEnd hook in the plugin writes any `cscr:allow` comments introduced during the session to `~/.claude/projects/<project>/cscr-bypass-log.jsonl`. The user reviews via `/cscr:audit-bypasses` skill.

**Spec changes:**
- §Hybrid hook architecture → Escape hatch: replace the entire subsection with the four-mechanism resolution above.
- §Threat coverage by layer: add row "Hardcoded API key written to source" → "Tier A, non-bypassable (escape hatch rejected for rule #8)."

---

## M3. Regex hooks don't reach the threat class they claim

**Finding.** Hooks described as "f-string SQL," "subprocess shell=True with interpolation," "dangerouslySetInnerHTML" are matched as regex over source text. Trivially bypassed by `engine.execute(f"...")`, `subprocess.run(["bash","-c", f"ls {x}"])`, `v-html`/`[innerHTML]`/`{@html}`, secret-splitting, etc. The "deterministic" claim holds for the regex, not for the threat class.

**Resolution.**

1. **AST-based hooks for language-aware patterns.** Patterns 1, 2, 3, 4, 5, 7 (the language-specific code patterns) use Python's `ast.parse` for Python and `babel-parser` or `acorn` for JS/TS where available. Regex remains the floor (when AST parse fails — partial-file edits, syntax errors mid-edit), but the AST path is the primary detector. The performance budget is rewritten: per-hook target raised to 150ms, aggregate to 750ms across 6 hooks on a Write/Edit call. CI benchmark gate measures end-to-end aggregate.
2. **Broadened call-shape detection.** Pattern 5 (SQL) matches any callable named `execute`, `executemany`, `text`, `raw`, `query`, plus SQLAlchemy `sql.SQL` family, on any receiver. Pattern 3 (subprocess) matches `subprocess.*`, `os.system`, `os.popen`, `os.exec*`, `pty.spawn`, `commands.getoutput`. Pattern 6 (HTML injection) matches `dangerouslySetInnerHTML` (React), `v-html` directive (Vue), `[innerHTML]` binding (Angular), `{@html}` (Svelte). Each hook's `docs/explanation/enforcement-coverage.md` row enumerates the call shapes covered AND the call shapes known to bypass (multi-statement dataflow, dynamic attribute access).
3. **Multi-statement dataflow is named out of scope.** The design honestly states: "f-string SQL where the f-string is assigned to a variable and the variable is passed to `execute` on a subsequent line is NOT caught by Tier A. This requires interprocedural taint analysis the hook cannot do. Use Layer 3 skills + linters (Semgrep with `python.lang.security.audit.formatted-sql-query`)."

**Spec changes:**
- §Hybrid hook architecture → Tier A patterns table: each row expands to specify call shapes covered AND explicit bypass classes documented.
- §Risk register: row 6 (hook performance overhead) updates to 150ms per-hook / 750ms aggregate, with CI benchmark.
- §Implementation plan P5: add deliverable "hooks/enforcement/ast/*.py modules" and "hooks/enforcement/coverage/<hook>.md" companion docs.

---

## M4. Hook supply-chain attack against the plugin itself

**Finding.** Hook scripts are Python that runs on every PreToolUse with full `tool_input` access (including source content the user is writing). The plugin is distributed via marketplace. No signing, no hash-pinning, no audit-hash registry analog to the user's MCP-server pre-trust pattern. CVE-2025-59536 / CVE-2026-21852 class, named in Rock's own CLAUDE.md, not adopted as mitigation.

**Resolution.**

1. **Hash-pinned hook scripts.** The plugin manifest (`.claude-plugin/plugin.json`) gets a new optional field `hookScriptHashes`: a map of relative paths to SHA-256 hashes. On plugin load, Claude Code (where possible) or a SessionStart hook (where not) verifies each hook script's hash against the manifest. Mismatch = plugin disabled with a user-visible error. The manifest is signed (see point 2).
2. **Sigstore-attested releases.** Every tagged release publishes a sigstore bundle. The plugin's README documents how to verify the bundle. The marketplace listing links the public key (or the sigstore identity). The README has a copy-paste verification command.
3. **MCP-style pre-trust check pre-published.** A new docs page `docs/how-to/audit-cscr-pre-trust.md` walks the six checks from Rock's `auditing-mcp-server-pre-trust` skill applied to CSCR itself. The plugin's marketplace listing links it. Anyone installing CSCR can audit it the same way they'd audit any MCP server.
4. **Second key holder.** Releases require co-signing from a second sigstore identity (a co-maintainer to be named). Until a second maintainer is in place, releases are NOT auto-pushed to the marketplace — they are gated on a manual Rock-side check. This is documented in `docs/governance.md`.

**Spec changes:**
- §Repository layout: add `.claude-plugin/plugin.json` `hookScriptHashes` field, add `docs/how-to/audit-cscr-pre-trust.md`, add `docs/governance.md`.
- §Migration plan, P5: add deliverable "hook script hash generation + manifest signing pipeline."
- §Risk register: add row "Marketplace push or maintainer-credential compromise" with mitigation "sigstore-attested releases, hash-pinned hooks, second-key-holder requirement."

---

## M5. No SECURITY.md / VDP / placeholder email

**Finding.** `README.md:766` lists `security@example.com` as the vulnerability-reporting address. No `SECURITY.md` exists. Violates Rock's own QC.1 (NIST SP 800-218 mandate for VDP on public projects).

**Resolution.**

1. **Author `SECURITY.md` before any further premortem rounds.** Use the GitHub-recommended template adapted for an open-source security-tooling project. Names a real reporting channel (PGP-protected email or a security-only GitHub advisory submission). Lists in-scope and out-of-scope. References the 90-day coordinated-disclosure policy.
2. **README contact line update.** Replace the placeholder email with a link to `SECURITY.md`.
3. **Pre-v2.0.0 check.** Success criterion 8 (new): `SECURITY.md` exists, links resolve, and at least one external test report has been received and acknowledged via the documented channel before release.

**Spec changes:**
- §Repository layout: add `SECURITY.md` at repo root.
- §Success criteria: add criterion 8 (SECURITY.md exists and has been smoke-tested by an external reporter).

---

## M6. Source corpus contains examples that contradict v2 hooks and contain anti-patterns

**Finding.** Concrete instances:
- `rules/languages/python/CLAUDE.md:70-71` — "Do" example uses `subprocess.run(f'process {shlex.quote(filename)}', shell=True)`, which Tier A pattern #3 blocks.
- `rules/backend/fastapi/CLAUDE.md:440-451` — `Level: strict` "Do" example uses a substring denylist (`"ignore previous instructions"`) for prompt-injection defense, a technique OWASP LLM01 explicitly deprecates.

Mechanical converter would propagate these into v2 SKILL.md files.

**Resolution.**

1. **Corpus quality audit before P1 begins.** A new task in P0: run every "Do" example through Tier A hooks (must pass) and every "Don't" example through Tier A hooks (must block on the relevant rule). Failures get a manual review pass: either the example is fixed, or the rule's classification moves from Tier A to Tier B / Layer 3.
2. **Standards-currency audit before P1.** Every rule citing OWASP LLM Top 10 has its taxonomy verified against the current public version (2025 LLM Top 10 at time of writing — see M7). Rules citing deprecated mitigations are flagged and rewritten before conversion.
3. **Converter has a `--strict` mode** that refuses to convert any rule whose code examples don't pass the audit. P1–P4 require `--strict`.

**Spec changes:**
- §Migration plan, P0: add "P0.5 — corpus quality + standards-currency audit. Acceptance: zero contradictions between rule examples and Tier A hooks; zero references to deprecated mitigations."
- §Risk register: row "Converter produces low-quality SKILL.md" updates with the strict-mode mitigation.

---

## M7. Standards drift — OWASP LLM Top 10 pinned to 2023 v1.1, 2025 revision not reflected

**Finding.** Corpus cites "OWASP LLM Top 10 v1.1 (2023)"; `tests/coverage/test_coverage.py:153-164` encodes 2023 numbering. The 2025 revision reorganized categories (LLM02 changed from "Insecure Output Handling" to "Sensitive Information Disclosure"; new categories like "System Prompt Leakage" and "Vector and Embedding Weaknesses" added). Auditors will see name collisions across LLM01–LLM10 revisions.

**Resolution.**

1. **Standards pinning is explicit and machine-readable.** A new artifact `docs/standards-pin.yaml` lists every external standard CSCR cites, with version, publication date, and canonical URL. Rules cite by `<standard>:<version>:<id>` (e.g., `OWASP-LLM-Top-10:2025:LLM01`). The skill body shows the human-readable name; the machine-readable form lives in frontmatter.
2. **Standards-drift CI check.** A monthly scheduled CI job fetches the publishers' canonical lists (OWASP, NIST AI RMF, MITRE ATLAS) and checks whether any cited version is superseded. Job opens an issue rather than failing CI — drift is not a release-blocker but a tracked task.
3. **Update SLA.** `docs/governance.md` states: when a referenced standard publishes a major revision, CSCR ships an updated skill within 90 days OR documents why the prior version is retained.
4. **v2.0.0 reset.** Before release, every reference to LLM Top 10 is updated to 2025 numbering. Tests in `tests/coverage/test_coverage.py:153-164` updated to 2025 list.

**Spec changes:**
- §Repository layout: add `docs/standards-pin.yaml`, add `docs/governance.md`.
- §Migration plan, P0: add "P0.6 — standards refresh pass. All OWASP LLM Top 10 refs updated to 2025; tests/coverage updated."

---

## M8. Converter contract undefined

**Finding.** `tools/rule-to-skill-converter.py` is named in the spec without a contract: what's parsed, how `paths:` is derived, how multi-rule files split into SKILL.md files, how `Level: strict` translates. Two contributors produce two different outputs.

**Resolution.**

1. **Converter specification document.** New artifact `docs/explanation/converter-contract.md` defines: input grammar (markdown-AST via `markdown-it-py`), output schema (frontmatter fields, body structure), `paths:` derivation rules (filename pattern → glob), multi-rule splitting policy (one SKILL.md per filename; multiple rules in the same file become multiple H2 sections), `Level:` translation (`strict` → Tier A candidate if pattern matches one of the 12 enumerated, else flagged for manual review; `warning` → Tier B candidate; `advisory` → Layer 3 prose).
2. **Golden-file tests.** `tools/tests/converter/golden/` contains input rule files and expected output SKILL.md files. CI fails on byte-mismatch. Re-running the converter on the same input produces byte-identical output.
3. **Idempotence requirement.** Running the converter twice in a row produces no diff on the second run.

**Spec changes:**
- §Repository layout: add `docs/explanation/converter-contract.md`, add `tools/tests/converter/golden/`.
- §Migration plan, P0: P0 deliverable "rule-to-skill-converter.py" gains acceptance criteria: golden tests pass, idempotence verified, runs with `--strict` mode (see M6).

---

## M9. RCS↔CSCR cross-pointer is a trust-amplification surface

**Finding.** The cross-pointer is "load-bearing." Bidirectional vouching forms a social-engineering substrate. Typo-squat plugin can inherit the credibility. Drift check verifies existence, not content.

**Resolution.**

1. **Drift check parses frontmatter, not README.** As already noted in the design's risk register (row 4). The amendment makes this concrete: the CI job clones RCS at a pinned commit SHA (not a tag), walks `skills/*/*/SKILL.md`, parses YAML frontmatter, asserts the cited skill `name:` exists. Same in reverse.
2. **Cross-pointer uses canonical plugin slug.** RCS's `applying-secure-coding-rules` skill specifies the exact plugin slug to install: `tikitribe-secure-coding-rules`, no abbreviations. CSCR's cross-pointer to RCS specifies `rocklambros/rcs` as the canonical repo. Both documented in `docs/explanation/relationship-to-rcs.md`.
3. **Content-hash check (optional, v2.1).** The drift check can be extended to verify that the cited skill's frontmatter `version:` matches an expected value. Out of scope for v2.0.0 but listed as v2.1 work.
4. **Typo-squat mitigation.** README's install section gives the exact marketplace plugin slug with a checksum or sigstore identity. Documented in `docs/how-to/install.md`.

**Spec changes:**
- §Relationship to RCS → Drift check: rewrite to specify frontmatter parsing and pinned-SHA cloning.
- §Repository layout: ensure `docs/explanation/relationship-to-rcs.md` exists.

---

## M10. Install consent ≠ execution consent (staged rollout)

**Finding.** Plugin's `settings.json` enabling hooks by default conflates installation consent with execution consent. The user did not evaluate the Python that runs on every Write/Edit.

**Resolution.**

1. **Staged rollout.** v2.0.0 ships with `cscr.enforcement: "advisory"` by default. Hooks run in advisory mode (exit 0, stderr warning to the user) for 30 days post-release. v2.1.0 flips the default to `"strict"` (exit 2, block) after the project has received and addressed false-positive reports from real installs.
2. **First-run notice.** SessionStart hook on first install displays a notice: "CSCR is in advisory mode. To enable blocking enforcement, set `cscr.enforcement: \"strict\"` in your project settings. See docs/how-to/enable-hooks.md."
3. **Per-rule enable/disable.** Users can set `cscr.rules.<rule-id>.enabled: false` to disable individual hooks while keeping the rest. Documented.
4. **Telemetry-free FP feedback channel.** A `/cscr:report-false-positive` skill collects the offending pattern (anonymized — no source content) and opens a pre-filled GitHub issue. No silent telemetry.

**Spec changes:**
- §Hybrid hook architecture → Default posture: rewrite to specify advisory-by-default for v2.0.0, strict in v2.1.0+.
- §Risk register: row "Plugin's settings.json enabling hooks by default surprises users" updates with the staged-rollout mitigation.

---

## M11. Success criteria measure shipping, not security uplift

**Finding.** All six success criteria are operational. None measure whether developers using CSCR produce more secure code. v2.0.0 can ship green with zero security uplift.

**Resolution.**

1. **Third-party held-out review.** Before v2.0.0, a named third-party reviewer is given a held-out vulnerable-code corpus (e.g., OWASP Benchmark v1.2, a curated set of CWE Top 25 violations) and tested with and without CSCR loaded. The review reports detection rate and false-positive rate per category. The numbers ship in the v2.0.0 release notes. This is a one-shot exercise, not ongoing telemetry.
2. **Pre-registered hypotheses.** Before the review, the project commits to specific numerical claims (e.g., "CSCR-loaded models will flag CWE-89 in ≥X% of OWASP Benchmark cases where they would otherwise miss it; false-positive rate on the OWASP Benchmark NEUTRAL set will be ≤Y%"). The review either confirms or refutes.
3. **Refutation does not block release.** If the review fails to confirm uplift, v2.0.0 ships with honest release-note language stating what was measured and what was NOT improved. The "secure by default" README claim is removed or qualified.
4. **Success criterion 9 (new):** "Pre-registered third-party held-out review is complete, results are published in the release notes, README claims match the measured uplift."

**Spec changes:**
- §Success criteria: add criteria 7, 8, 9 (M1 coverage table, M5 SECURITY.md, M11 third-party review).
- §Risk register: add row "Outcome metric refutation" with mitigation "honest release-note language; do not block release."

---

## What this amendment does NOT cover

The following Round 1 findings are tracked for the implementation plan, not for the spec. They are not blocking spec approval:

- **M12** (PRAGMATIC Sonnet-only generalizes worse for security) — implementation plan adds Haiku-stratified eval for the top-Σ security skills.
- **M13** (OWASP category imbalance, A04/A10 thin) — implementation plan P1 adds explicit rule-count balancing for `applying-owasp-top-10`.
- **M14** (n=1 adversarial eval) — implementation plan raises per-skill adversarial eval count to ≥5 with documented variant taxonomy.
- **M15** (CWE/OWASP refs unverified) — implementation plan adds CI gate that resolves cited IDs against MITRE/OWASP canonical lists.
- **M16** (coverage test is string-match) — implementation plan replaces with semantic check.
- **M17** (CI pip install unpinned) — implementation plan moves to `tests/requirements.txt` with pinned versions.
- **M18** (aggregate payload growth for AI/ML) — implementation plan adds session-load-size benchmark.
- **M19** (sigma scoring undefined) — implementation plan vendors the rubric from RCS.
- **M21** (regulator conflict-resolution) — implementation plan adds `docs/how-to/handle-rule-conflicts.md` with org-wide carve-out mechanism via `.cscr-allowlist.json` (built on M2 infrastructure).
- **M22** (single CODEOWNER) — implementation plan adds `/hooks/**` second-reviewer rule, names co-maintainer search as a v2.1 milestone.
- **M25** (README marketing outruns LICENSE disclaim) — implementation plan adopts RCS "tooling, not advice" disclaimer in README and per-SKILL.md footer.
- **M26** (no governance model) — implementation plan adds `docs/governance.md`.
- **M27** (settings-template upgrade path) — implementation plan adds `tools/cscr-settings-diff` for v2.1.
- **M28** (hook aggregate latency unmeasured) — implementation plan adds CI benchmark gate (see M3).

**Tail risk TR1** (marketplace pipeline compromise) — parked. M4's sigstore mitigation reduces blast radius. Re-evaluate if a marketplace-pipeline incident occurs in the broader ecosystem.

---

## Success criteria after this amendment (v2.0.0)

The original six are revised; three new criteria are added.

1. Plugin is installable from the community marketplace as `/plugin install tikitribe-secure-coding-rules`.
2. All ~42 skills have 4 passing evals each (per the revised eval discipline, with n≥5 adversarial probes per skill where M14 lands in the implementation plan).
3. All 12 Tier A hooks have passing unit tests AND the enforcement-coverage.md table documents bypass classes per hook.
4. The CI drift-check against RCS passes (frontmatter-parsed, pinned-SHA per M9).
5. README's "Migrating from v1" section is in place.
6. **(Revised)** Total p95 per-session loaded skill size measured by a representative AI/ML+FastAPI test fixture is less than the v1 baseline. Not a fuzzy "small factor."
7. **(New, from M1+M11)** `docs/explanation/enforcement-coverage.md` exists; README contains no enforcement verbs outside Tier A scope; pre-registered third-party held-out review is complete and published.
8. **(New, from M5)** `SECURITY.md` exists, has been smoke-tested by an external reporter, and the contact channel works.
9. **(New, from M4)** Release is sigstore-attested; hook-script hashes are pinned in the plugin manifest; `docs/how-to/audit-cscr-pre-trust.md` documents the six-check audit.

## Resume condition for the premortem

Once the design doc is revised in place to incorporate this amendment, Round 2 (methodology and modeling — hybrid hook architecture and skill activation semantics) can resume. Skip the resume if Rock decides Round 1 + amendment is sufficient triage.
