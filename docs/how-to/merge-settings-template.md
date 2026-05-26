# How to merge the CSCR settings template

CSCR ships zero merge code. You merge the permission-rule template into your own Claude Code settings using your preferred tooling. This guide shows three approaches.

## Before you start

Read `settings-template.json` end to end. Understand each rule. The template denies file reads of common secret locations (`.env`, `**/secrets/**`, AWS credentials, SSH private keys) and denies several Bash patterns (`curl | sh` and variants, `chmod 777`, force-push to protected branches).

**If you already have stricter rules in your `~/.claude/settings.json`, keep them.** CSCR's template is additive — it should never replace a rule you already have. Document this explicitly during your merge.

## Approach 1: jq merge with deduplication

```bash
# Inspect current state
cat ~/.claude/settings.json | jq '.permissions'

# Merge with deduplication
jq -s '
  .[0] as $current
  | .[1] as $template
  | $current
  | .permissions.deny = (($current.permissions.deny // []) + ($template.permissions.deny // []) | unique)
' ~/.claude/settings.json settings-template.json > ~/.claude/settings.json.new

# Diff
diff ~/.claude/settings.json ~/.claude/settings.json.new

# Apply
mv ~/.claude/settings.json.new ~/.claude/settings.json
```

## Approach 2: Manual editor merge

Open `~/.claude/settings.json` in your editor. Copy each entry from `settings-template.json`'s `permissions.deny` array. For each entry, before pasting, check whether you already have an equivalent or stricter rule. Skip the entry if so. Paste the entry if you don't already have it or anything stricter.

## Approach 3: Project-level only

If you only want CSCR's rules in a specific project, merge into `.claude/settings.json` at the project root instead of `~/.claude/settings.json`. Use the same approach (jq or editor).

## Verification

```bash
cat ~/.claude/settings.json | jq '.permissions.deny | length'
```

Expected: a count that increased by the number of CSCR rules you accepted (subtract any you already had).

```bash
cat ~/.claude/settings.json | jq '.permissions.deny[] | select(contains("curl"))'
```

Expected: at least the four `curl` patterns from the template, plus any you had before.

## What this template does NOT cover

See `docs/explanation/enforcement-coverage.md` for the per-rule bypass classes. The template catches the specific patterns enumerated; it does not catch every variant. For enforcement beyond what permission rules can express, see `docs/how-to/write-your-own-hook.md`.
