"""Unit tests for the held-out corpus runner.

Tests the parts that don't call out to the Anthropic API: schema validation,
probe loading, evaluation logic, and the CLI's dry-run path.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.held_out_corpus._lib import runner, schema


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_accepts_minimal_probe():
    schema.Probe.model_validate({
        "id": "test/x",
        "stratum": "test",
        "category": "CWE-89",
        "prompt": "Write code.",
        "expected": {"must_not_contain": ["bad"]},
    })


def test_schema_rejects_unknown_top_level_field():
    with pytest.raises(ValidationError):
        schema.Probe.model_validate({
            "id": "test/x",
            "stratum": "test",
            "category": "CWE-89",
            "prompt": "Write code.",
            "expected": {"must_not_contain": ["bad"]},
            "unknown_field": "should fail",
        })


def test_schema_rejects_unknown_assertion_field():
    with pytest.raises(ValidationError):
        schema.Probe.model_validate({
            "id": "test/x",
            "stratum": "test",
            "category": "CWE-89",
            "prompt": "Write code.",
            "expected": {
                "must_not_contain": ["bad"],
                "must_contain_alternative": "typo",
            },
        })


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _probe(must_not_contain=None, must_contain_any=None, must_cite=None):
    return schema.Probe(
        id="t/1",
        stratum="test",
        category="CWE-0",
        prompt="p",
        expected=schema.ProbeAssertions(
            must_not_contain=must_not_contain or [],
            must_contain_any=must_contain_any or [],
            must_cite=must_cite or [],
        ),
    )


def test_evaluate_fully_passes():
    p = _probe(
        must_not_contain=["bad"],
        must_contain_any=["good"],
        must_cite=["CWE-89"],
    )
    r = runner.evaluate(p, "this is good and cites CWE-89")
    assert r.fully_passed
    assert not r.partial_credit


def test_evaluate_partial_credit_no_citation():
    p = _probe(
        must_not_contain=["bad"],
        must_contain_any=["good"],
        must_cite=["CWE-89"],
    )
    r = runner.evaluate(p, "this is good but never names the category")
    assert not r.fully_passed
    assert r.partial_credit


def test_evaluate_fails_on_insecure_pattern():
    p = _probe(must_not_contain=["eval("])
    r = runner.evaluate(p, "use eval(user_input) for flexibility")
    assert not r.fully_passed
    assert not r.partial_credit


def test_evaluate_empty_assertions_pass_by_default():
    p = _probe()
    r = runner.evaluate(p, "")
    assert r.fully_passed


# ---------------------------------------------------------------------------
# CLI dry-run
# ---------------------------------------------------------------------------


def test_cli_dry_run_loads_web_sast(capsys):
    """Smoke test: --dry-run on the real web_sast stratum loads probes
    without spending tokens. Locks in that the shipped corpus parses under
    the strict schema."""
    exit_code = runner.main(["--stratum", "web_sast", "--dry-run"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "loaded" in captured.out
    assert "probes" in captured.out


def test_cli_rejects_missing_stratum(capsys):
    """A nonexistent stratum should produce a warning and exit nonzero."""
    exit_code = runner.main(["--stratum", "does-not-exist", "--dry-run"])
    assert exit_code != 0


# ---------------------------------------------------------------------------
# Corpus shape
# ---------------------------------------------------------------------------


CORPUS_ROOT = Path(__file__).parent.parent


def test_every_shipped_probe_parses():
    """Every JSON under any stratum directory must round-trip through Probe.

    Single test that catches authoring drift across the whole corpus. If a
    new probe has a typo'd assertion field or missing required field, this
    fails loud.
    """
    errors: list[str] = []
    for stratum_dir in CORPUS_ROOT.iterdir():
        if not stratum_dir.is_dir() or stratum_dir.name.startswith("_"):
            continue
        for probe_path in sorted(stratum_dir.glob("*.json")):
            try:
                schema.Probe.model_validate(
                    json.loads(probe_path.read_text())
                )
            except (ValidationError, json.JSONDecodeError) as exc:
                errors.append(f"{probe_path.relative_to(CORPUS_ROOT)}: {exc}")
    assert not errors, "\n".join(errors)
