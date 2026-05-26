# How to verify a CSCR release

CSCR ships sigstore-attested releases. You verify the release tarball before trusting the plugin. CSCR does NOT ship a `cscr-verify` binary — you call sigstore directly.

## Prerequisites

```bash
pip install sigstore
```

## Verify a release

```bash
# Download the release tarball + bundle from GitHub
gh release download v2.0.0 -R TikiTribe/claude-secure-coding-rules

# Verify the sigstore bundle
python -m sigstore verify identity \
  --bundle tikitribe-secure-coding-rules-2.0.0.tar.gz.sigstore.json \
  --cert-identity 'rock@rockcyber.com' \
  --cert-oidc-issuer 'https://github.com/login/oauth' \
  tikitribe-secure-coding-rules-2.0.0.tar.gz
```

Expected output: `OK: verified <filename>`

## What this verifies

- The release tarball was signed by Rock Lambros's GitHub identity (rock@rockcyber.com).
- The signature is valid against sigstore's transparency log (Rekor).
- The tarball has not been modified since signing.

## What this does NOT verify

- That Rock's GitHub account was not compromised at signing time. (Mitigated by sigstore's transparency log — a compromised signing is detectable post-hoc via Rekor.)
- That the skill content is accurate. (No mechanism can verify accuracy; see `docs/how-to/audit-cscr-pre-trust.md` for the manual six-check audit.)
- The user-authored hooks you wrote from `docs/how-to/write-your-own-hook.md`. (Those are your code; verify them yourself.)

## Co-signing roadmap

v2.0.0 ships single-signer. Co-signing by a second maintainer is a v2.2.0 milestone — see `docs/governance.md`.
