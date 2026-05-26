"""Held-out adversarial corpus runner.

Reads probe JSON files, sends each prompt to Claude via the Anthropic SDK,
evaluates the response against the structured assertions, and reports
per-stratum and overall metrics.

Usage:
    python -m tests.held_out_corpus._lib.runner --all
    python -m tests.held_out_corpus._lib.runner --stratum web-sast
    python -m tests.held_out_corpus._lib.runner --stratum web-sast --no-skills
    python -m tests.held_out_corpus._lib.runner --stratum web-sast --model opus-4-7
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from tests.held_out_corpus._lib.schema import Probe


CORPUS_ROOT = Path(__file__).parent.parent
PROJECT_ROOT = CORPUS_ROOT.parent.parent

MODEL_ALIASES = {
    # Default. Balances cost (~$4-5 per full run) and accuracy.
    "sonnet": "claude-sonnet-4-6",
    "sonnet-4-6": "claude-sonnet-4-6",
    # Spot-check / contested probes. ~$20-25 per full run.
    "opus": "claude-opus-4-7",
    "opus-4-7": "claude-opus-4-7",
    # Cost floor for sanity checks. Accuracy gap on adversarial probes is
    # documented in the README; not the default.
    "haiku": "claude-haiku-4-5-20251001",
    "haiku-4-5": "claude-haiku-4-5-20251001",
}


@dataclass
class ProbeResult:
    """Outcome of running one probe."""

    probe: Probe
    response: str
    must_not_contain_passed: bool
    must_contain_any_passed: bool
    must_cite_passed: bool

    @property
    def fully_passed(self) -> bool:
        return (
            self.must_not_contain_passed
            and self.must_contain_any_passed
            and self.must_cite_passed
        )

    @property
    def partial_credit(self) -> bool:
        """Avoided the insecure pattern but didn't cite or didn't produce
        the named safe pattern."""
        return self.must_not_contain_passed and not self.fully_passed


def load_probes(stratum: str | None) -> list[Probe]:
    """Load every probe under stratum/, or all strata if stratum is None.

    Skips any directory starting with `_` (e.g., `_lib/`).
    """
    probes: list[Probe] = []
    if stratum:
        roots = [CORPUS_ROOT / stratum]
    else:
        roots = [
            d for d in CORPUS_ROOT.iterdir()
            if d.is_dir() and not d.name.startswith("_")
        ]
    for root in roots:
        if not root.exists():
            print(f"warning: stratum directory missing: {root}", file=sys.stderr)
            continue
        for probe_path in sorted(root.glob("*.json")):
            with probe_path.open() as f:
                data = json.load(f)
            probes.append(Probe.model_validate(data))
    return probes


def build_system_prompt(skill_under_test: str | None, no_skills: bool) -> str:
    """Build the system prompt for one probe.

    When `no_skills` is True, returns an empty prompt — the baseline
    measurement that shows what Claude does without CSCR loaded.

    When `no_skills` is False and `skill_under_test` is set, returns the
    contents of that skill's SKILL.md body so the model behaves as if the
    skill were loaded by the harness. (Real Claude Code loads skills via
    path globs; the harness simulates by injection so the measurement is
    reproducible from a single API call.)
    """
    if no_skills or skill_under_test is None:
        return ""
    skill_md = PROJECT_ROOT / "skills" / skill_under_test / "SKILL.md"
    if not skill_md.exists():
        # Skill not yet built (P1-P4 in flight). Fall back to no-skill mode
        # but mark the prompt so a transcript reader can tell what happened.
        return (
            f"# NOTE: skill '{skill_under_test}' not yet built. "
            "Running without skill context. This probe's result reflects "
            "baseline model behaviour, not skills-on behaviour."
        )
    return skill_md.read_text()


def call_claude(prompt: str, system: str, model: str) -> str:
    """Send the probe prompt to Claude. Returns the response text."""
    try:
        import anthropic
    except ImportError:
        print(
            "error: anthropic SDK not installed. Run: uv add anthropic",
            file=sys.stderr,
        )
        sys.exit(2)
    client = anthropic.Anthropic()
    message = client.messages.create(
        model=model,
        max_tokens=2048,
        system=system or "You are a helpful coding assistant.",
        messages=[{"role": "user", "content": prompt}],
    )
    parts = []
    for block in message.content:
        if hasattr(block, "text"):
            parts.append(block.text)
    return "\n".join(parts)


def evaluate(probe: Probe, response: str) -> ProbeResult:
    """Run the structured assertions against the response."""
    must_not_contain_passed = not any(
        s in response for s in probe.expected.must_not_contain
    )
    must_contain_any_passed = (
        not probe.expected.must_contain_any
        or any(s in response for s in probe.expected.must_contain_any)
    )
    must_cite_passed = (
        not probe.expected.must_cite
        or any(s in response for s in probe.expected.must_cite)
    )
    return ProbeResult(
        probe=probe,
        response=response,
        must_not_contain_passed=must_not_contain_passed,
        must_contain_any_passed=must_contain_any_passed,
        must_cite_passed=must_cite_passed,
    )


def print_probe_result(result: ProbeResult) -> None:
    """One line per probe."""
    if result.fully_passed:
        verdict = "PASS"
    elif result.partial_credit:
        verdict = "PARTIAL"
    else:
        verdict = "FAIL"
    parts = []
    if not result.must_not_contain_passed:
        parts.append("contained-insecure")
    if not result.must_contain_any_passed:
        parts.append("missing-safe")
    if not result.must_cite_passed:
        parts.append("missing-citation")
    detail = f" ({', '.join(parts)})" if parts else ""
    print(f"  [{verdict:7s}] {result.probe.id}{detail}")


def print_stratum_summary(stratum: str, results: list[ProbeResult]) -> None:
    """Per-stratum tally."""
    n = len(results)
    if n == 0:
        return
    passed = sum(r.fully_passed for r in results)
    partial = sum(r.partial_credit for r in results)
    failed = n - passed - partial
    print(
        f"\n{stratum}: {passed}/{n} pass, {partial}/{n} partial, {failed}/{n} fail"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m tests.held_out_corpus._lib.runner",
        description="Run the CSCR held-out adversarial corpus.",
    )
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--all", action="store_true",
        help="Run every probe in every stratum.",
    )
    selection.add_argument(
        "--stratum", type=str,
        help="Run only the named stratum (e.g., web-sast).",
    )
    parser.add_argument(
        "--no-skills", action="store_true",
        help=(
            "Run without injecting skill content into the system prompt. "
            "Baseline measurement for paired comparison."
        ),
    )
    parser.add_argument(
        "--model", type=str, default="sonnet-4-6",
        choices=sorted(MODEL_ALIASES.keys()),
        help="Model to use. sonnet-4-6 is the default.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help=(
            "Don't call the API; print what would be sent and exit. Useful "
            "for verifying probe loading without spending tokens."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    model = MODEL_ALIASES[args.model]

    probes = load_probes(args.stratum if not args.all else None)
    if not probes:
        print("error: no probes found", file=sys.stderr)
        return 1

    print(
        f"loaded {len(probes)} probes "
        f"(skills={'OFF' if args.no_skills else 'ON'}, model={model})"
    )

    if args.dry_run:
        for p in probes:
            print(f"  would run: {p.id} (skill_under_test={p.skill_under_test})")
        return 0

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY env var not set", file=sys.stderr)
        return 2

    by_stratum: dict[str, list[ProbeResult]] = {}
    for probe in probes:
        system = build_system_prompt(probe.skill_under_test, args.no_skills)
        response = call_claude(probe.prompt, system, model)
        result = evaluate(probe, response)
        by_stratum.setdefault(probe.stratum, []).append(result)
        print_probe_result(result)

    print("\n=== SUMMARY ===")
    for stratum, results in sorted(by_stratum.items()):
        print_stratum_summary(stratum, results)
    all_results = [r for rs in by_stratum.values() for r in rs]
    n = len(all_results)
    passed = sum(r.fully_passed for r in all_results)
    partial = sum(r.partial_credit for r in all_results)
    print(
        f"\nOVERALL: {passed}/{n} pass, {partial}/{n} partial, "
        f"{n - passed - partial}/{n} fail"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
