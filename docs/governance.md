# Governance

## Maintainership

**Primary maintainer:** Rock Lambros (rock@rockcyber.com)
**Succession contact:** TBD before v2.0.0 tag — see Task 138.
**Bus factor:** 1. The co-maintainer recruitment milestone is v2.x (see Co-signing roadmap below).

## Standards-drift update SLA

When a referenced standard in `docs/standards-pin.yaml` publishes a major revision, CSCR ships an updated skill within **180 days** OR documents in `docs/governance.md` why the prior version is retained.

180 days reflects single-maintainer realism. The original 90-day target was infeasible per fresh-round premortem F8.

Standards drift is detected by `tools/standards-check.py`, which runs daily via GitHub Actions and opens an issue when a pinned standard's canonical URL returns evidence of a superseding revision (RSS feed where available, page-content diff otherwise).

## Reference-hook bypass-fix SLA

Hook patterns documented in `docs/how-to/write-your-own-hook.md` are maintained best-effort, no SLA. Documented bypasses are tracked in this repo's GitHub issues with the `bypass-class` label. Users who installed a documented pattern should subscribe to GitHub Security Advisories on this repo to learn when a bypass becomes known.

## Co-signing roadmap

v2.0.0 ships sigstore-attested with a single maintainer key (Rock Lambros's). Co-signing requires a second maintainer with a credible reputation in AI/security willing to (a) review every release, (b) hold a signing key with the operational discipline that implies, (c) accept the liability framing of attesting to releases they did not author.

**Co-signing target version:** v2.2.0
**Co-signing target date:** Q1 2027
**Named candidate:** TBD before v2.0.0 tag — see Task 138.

Until co-signing is in place, the supply-chain attack surface is single-key compromise. Disclosed in release notes, README adjacent to any signing claim, marketplace listing description, and SECURITY.md.

## Deprecation policy

Skills or documented hook patterns are deprecated by:

1. Adding a `deprecated: true` field to the SKILL.md frontmatter, with `deprecated_reason` and `replaced_by` (if applicable).
2. Marking the skill in `skills/README.md` cross-index with a strikethrough and a footnote.
3. Logging the deprecation in `CHANGELOG.md` under the release that ships the deprecation.

Deprecated skills are removed from the catalog two minor versions after deprecation (e.g., deprecated in v2.1 → removed in v2.3).

## Dispute resolution for corpus-poisoning PR escalations

Pull requests modifying skill content (the `skills/**` tree) that touch a `Level: strict` pattern or add a new `Do`/`Don't` example require review by the primary maintainer. PRs from new contributors that touch the corpus require two reviewers when a co-maintainer exists; until then, the primary maintainer reviews and explicitly documents any conflict-of-interest disclosures in the PR conversation.

Dispute escalation path: if a contributor disagrees with a maintainer review decision, the dispute is logged as a GitHub Discussion in the `Governance` category. Disputes that cannot be resolved in 30 days result in the contested change being deferred to the next minor version with explicit "deferred for governance review" labeling.

## Update cadence for this document

`docs/governance.md` is reviewed and updated:
- At each minor version release (v2.1, v2.2, etc.)
- When a maintainer change occurs
- When a standards-drift SLA is breached (post-mortem entry added)
- When the co-signing milestone is hit (the relevant sections updated)
