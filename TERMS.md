# Additional Terms

This file supplements the MIT LICENSE. It does not modify the LICENSE's grant or restrictions — it documents additional disclaimers specific to this project's nature as a security catalog.

## No warranty for security purposes

The MIT LICENSE disclaims all warranties. This file reiterates and clarifies for the avoidance of doubt that:

- CSCR is a documentation catalog of security patterns and a configuration template.
- CSCR does NOT enforce security in your environment. Enforcement, where it occurs, is provided by the Claude Code platform's permission rules (which CSCR's `settings-template.json` configures) and by hooks you author yourself from the documentation in `docs/how-to/write-your-own-hook.md`.
- The patterns documented in CSCR are best-effort distillations of public standards (OWASP, NIST, MITRE ATLAS, etc.). They may be incomplete, outdated, or wrong for your specific use case.
- The reference hook patterns in `docs/how-to/write-your-own-hook.md` include documented bypass classes for each pattern. Patterns you author from those examples WILL have failure modes you did not anticipate.

## No fitness for regulated use

CSCR is not designed for, validated against, or warranted to satisfy any specific regulatory regime. This includes (without limitation):

- HIPAA / HITECH
- SOC 2 (any type)
- PCI-DSS
- FedRAMP (any level)
- EU AI Act
- ISO 27001 / 27017 / 27018
- NIST SP 800-53 / 800-171

If you use CSCR in a regulated environment, the responsibility for demonstrating compliance is entirely yours. CSCR does not provide assurance artifacts (control mappings, evidence packages, attestations) for any regulatory regime.

## Vendor responsibility

The author of this project is an individual. The author distributes through the Claude Code community marketplace, which itself is a third-party service. The author does not carry product-liability insurance for this project. By installing CSCR, you accept that any failure mode resulting from your reliance on CSCR is your own to bear.

If your use case requires a vendor with insurance, contractual SLAs, or regulated-compliance attestations, do not use CSCR. Use a commercial vendor with the appropriate contractual posture.
