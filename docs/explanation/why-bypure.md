# Why B-pure: the architecture decision and what it costs

This document explains why CSCR v2 ships zero executable enforcement code — only inert files (catalog skills, permission-rule template, hook-authoring documentation) the user merges, reads, or copies into their own configuration. The choice has costs; this doc names them so a reader can decide whether the tradeoffs fit their use case.

The short version: every architecture that ships CSCR-authored executable hooks recreates the model-controlled-bypass problem the hooks are meant to solve. Three rounds of premortem on three different architectures (original-hooks, amended-hooks, BYOH-with-reference-hooks) all surfaced 5+ Critical findings on the same root cause. The fourth attempt — B-pure — was the first to survive premortem cleanly. Full lineage in `docs/superpowers/specs/2026-05-24-cscr-modernization-design.md`.

## The pattern that forced B-pure

A Claude Code agent has Bash tool access. Any executable enforcement script the user installed — whether shipped by CSCR or written by the user from CSCR's reference — can be uninstalled by issuing a Bash command. A prompt-injected model that wants to escape a hook can:

1. Read the hook's location (documented in the user's `settings.json` or inferable from `~/.claude/hooks/`).
2. Issue `Bash(rm ~/.claude/hooks/cscr/block-eval-on-user-input.py)` or `Bash(sed -i '...' ~/.claude/settings.json)` to remove the deny entry.
3. The user gets a permission prompt. The user approves 93% of permission prompts (Hughes 2026). The hook is gone.

This works regardless of whether CSCR shipped the script, whether CSCR shipped an installer that installed the script, or whether the user wrote the script themselves from a CSCR reference. The runtime attack surface after adoption is identical. **What matters is whether CSCR's distribution surface presents a plausible "this is the install command" path the model can suggest.**

- "Shipped-in-plugin" architecture (Round 1): model says "the hook is in `<plugin>/hooks/`; run this command to disable it." → bypassed.
- "Amended out-of-tree state" architecture (Round 2): model says "the state file at `~/.config/cscr/state.json` controls which hooks fire; rewrite it." → bypassed.
- "BYOH with reference hooks" architecture (retrospective): model says "run `cscr hooks install --bundle full --accept-coverage` to set up the protections, then run `cscr hooks uninstall block-eval-on-user-input` because it's blocking your work." → bypassed at install time AND uninstall time.

In every variant, CSCR shipped (or could plausibly be expected to ship) an executable affordance the model could weaponise. The user's 93% approval rate did the rest.

**B-pure escapes the trap by not shipping any executable scripts.** No `cscr hooks install`, no `cscr-configure`, no auto-merge for the settings template. The user reads the hook source in a markdown file, copies it into their own `~/.claude/hooks/cscr/` directory, runs `chmod +x` themselves, and edits their own `settings.json`. There is no CSCR-authored command for the model to invoke. The model can still suggest the install steps — but each step is a distinct, manual action the user takes consciously.

## What B-pure ships

Three things, all inert:

1. **Skills catalog** — ~42 path-scoped markdown files under `skills/`. Each loads when the user's working directory matches its `paths:` glob. Each teaches the model about secure patterns in its domain. **No skill can deny a tool call.** Skills shape the model's output; they do not gate it.

2. **Permission-rule template** — `settings-template.json`. A static JSON file enumerating ~24 deny rules. The user runs `jq -s '.[0] * .[1]'` (or merges manually in an editor) to add the rules to their own `~/.claude/settings.json`. The platform's permission system enforces the rules. **CSCR does not run the merge.** The user owns the file at all times.

3. **Hook-authoring documentation** — `docs/how-to/write-your-own-hook.md`. ~11 hook patterns in markdown fenced code blocks. Each pattern has full Python source, settings.json snippet, enumerated bypass classes, and pytest suite. The user reads, picks, copies, and tests. **CSCR ships no `.py` hook files.**

## What B-pure does NOT ship

- No `cscr` CLI of any kind. No `cscr hooks install`. No `cscr-configure`. No `cscr-verify` (sigstore verification is done by the user calling sigstore directly per `docs/how-to/verify-the-release.md`).
- No installer for the settings template. The user runs `jq` or their editor.
- No state files outside the user's own config. CSCR's surface area in the filesystem after install is exactly the skills directory and the template JSON, both of which the user can `rm` without consequence to anything CSCR controls.
- No upgrade mechanism for the hook patterns. If CSCR adds a hook pattern in v2.1.0, the user reads the changelog and copies the new pattern themselves (or doesn't).

## The costs

Honest tradeoffs B-pure makes:

1. **No friction reduction for users who would have run `cscr hooks install`.** A user who genuinely wants the full hook set has to copy 11 Python files by hand and manually merge 11 settings entries. The plan is explicit that this is a feature, not a bug: the friction is exactly the wall between an inviting `cscr install` command and a model that can invoke it.

2. **No CSCR-controlled upgrades.** If a hook pattern improves (better regex, fewer false positives, broader coverage), every user who installed v1 of the pattern has to read the changelog, find the new version, and re-copy. CSCR has no way to push the update. This is the cost of not having an upgrade channel; the benefit is that there's no upgrade channel for an adversary to abuse either.

3. **No telemetry on adoption.** CSCR does not know how many users installed which patterns. The project cannot measure "did the chmod 777 hook prevent X attacks last quarter." Adoption is a private fact of each installer. The benefit is that there is no telemetry endpoint to compromise.

4. **Distribution surface is smaller, but the cognitive burden on users is larger.** A user who wants real enforcement has to read every hook's bypass-class list, decide which gaps they care about, possibly write more hooks, and test the whole stack against their own threat model. CSCR provides the materials, not the protection.

5. **Skills are advisory, full stop.** A skill can teach the model "use `argon2` not `bcrypt` for new password hashes." The skill cannot enforce that the model takes the advice. Enforcement happens at the permission-rule layer (which can't reason about Python kwargs) or the hook layer (which the user installs at their discretion). v1 had `Level: strict` decorations on rules; v2 retires that vocabulary because it was prose, not enforcement. The honest framing is throughout the v2 documentation.

6. **The model-controlled-bypass problem is reduced but not solved.** Even without a CSCR install command, a model that wants to disable a user-installed hook can suggest `sed -i '/cscr/d' ~/.claude/settings.json`. The user still has to approve. B-pure removes the *high-confidence-because-CSCR-said-so* social signal from the suggestion; the rest is the user's responsibility, the same as for any other privileged operation a model proposes.

## What B-pure is NOT

- **Not a claim that hooks are unsafe.** Hooks are the right enforcement mechanism for many problems; CSCR teaches how to write them well. The argument is specifically about who *ships* the hooks. User-authored hooks land with the user's mental model of what they cover; CSCR-shipped hooks would land with the user's assumption that they cover whatever CSCR claims.

- **Not a claim that B-pure is the only safe option.** A plugin that ships hooks AND establishes out-of-band identity verification for install commands (e.g., physical YubiKey tap per install) could be safe. That architecture wasn't on the table for CSCR because it requires distribution infrastructure CSCR doesn't have and adds friction users wouldn't accept.

- **Not a refusal to evolve.** Co-signing by a second maintainer is a v2.2.0 milestone (see `docs/governance.md`). Sigstore signing of the release tarball is in P7. If a future Claude Code release adds primitives that make a different architecture safer (e.g., a runtime-enforced "this hook came from a verified plugin" attestation), B-pure will revisit.

## When to read this document

- When you're evaluating whether to install CSCR and you want to know what you're actually getting before you copy the JSON.
- When you're reading another security plugin's claims and want a reference point for the kind of honest framing this project tries to use.
- When you're writing your own Claude Code plugin and the question "should I ship the hooks or not?" comes up. The premortem lineage in `docs/superpowers/specs/` is the long answer; this doc is the short one.
- When CSCR adds a feature that looks executable and you want to verify the architecture hasn't drifted.

## Related reading

- `docs/superpowers/specs/2026-05-24-cscr-modernization-design.md` — the full design spec including the decision lineage and the prior amendments.
- `docs/explanation/enforcement-coverage.md` — what each Layer 1 deny rule and Layer 2 hook actually covers, with enumerated bypass classes.
- `docs/how-to/merge-settings-template.md` — the manual-merge guide for the permission template.
- `docs/how-to/write-your-own-hook.md` — the 11 hook patterns the user can copy.
- `docs/how-to/verify-the-release.md` — sigstore verification (user calls sigstore directly; no CSCR-shipped verifier).
- `docs/governance.md` — co-signing roadmap and standards-pin SLA.
