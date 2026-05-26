"""Probe JSON schema for the held-out adversarial corpus.

Each probe file matches the Probe model. The runner loads probes by
walking <corpus>/<stratum>/*.json and validating with Probe.model_validate.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ProbeAssertions(BaseModel):
    """Structured assertions evaluated against the model response."""

    model_config = ConfigDict(extra="forbid")

    must_not_contain: list[str] = Field(
        default_factory=list,
        description="Substrings that must NOT appear in the response. These "
        "are the insecure patterns the probe is trying to elicit. A response "
        "containing any of these strings fails the must_not_contain check.",
    )
    must_contain_any: list[str] = Field(
        default_factory=list,
        description="At least one of these substrings must appear. These are "
        "the safe patterns. An empty list means the safe-pattern check is "
        "skipped (e.g., when the only assertion is 'avoid the insecure form').",
    )
    must_cite: list[str] = Field(
        default_factory=list,
        description="Category IDs (e.g., 'A03', 'LLM01:2025', 'CWE-89') at "
        "least one of which must appear in the response. Empty list skips "
        "the citation check.",
    )


class Probe(BaseModel):
    """A single adversarial probe."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        description="Unique probe identifier, conventionally "
        "'<stratum>/<short-name>-<NNN>'.",
    )
    stratum: str = Field(
        description="One of: web-sast, ai-ml, supply-chain, iac, containers, "
        "frontend, languages.",
    )
    category: str = Field(
        description="The category this probe targets, e.g., 'CWE-89' or "
        "'LLM01:2025'. Informational; not asserted against.",
    )
    owasp: str | None = Field(
        default=None,
        description="The OWASP category id this probe maps to (e.g., "
        "'A03:2025' or 'LLM01:2025'). Optional.",
    )
    skill_under_test: str | None = Field(
        default=None,
        description="The CSCR skill name whose SKILL.md is injected into the "
        "system prompt when the harness runs in skills-on mode. None means "
        "no skill is injected — useful for control probes.",
    )
    prompt: str = Field(
        description="The exact user prompt sent to the model.",
    )
    expected: ProbeAssertions = Field(
        description="Structured assertions evaluated against the response.",
    )
    notes: str | None = Field(
        default=None,
        description="Optional context for the rotator (date authored, "
        "rationale, known limitations).",
    )
