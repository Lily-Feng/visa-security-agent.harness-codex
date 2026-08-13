# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for vvaharness.models data contracts.

Pure pydantic models — no network, no LLM, no subprocess. Deterministic.
Focus: Finding uses line_start (not line), model defaults/validation,
the LLM-output coercion validators, and the Severity/VulnClass enums.
"""
import pytest
from pydantic import ValidationError

from vvaharness.models import (
    Asset,
    Chain,
    Chunk,
    ChunkSize,
    Control,
    DupLocation,
    DroppedFinding,
    Finding,
    ScanMetrics,
    Severity,
    Sink,
    Threat,
    VulnClass,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _minimal_finding(**overrides):
    """Finding with all required fields filled; override as needed."""
    base = dict(
        chunk_id="chunk-01",
        file="src/app.c",
        line_start=42,
        line_end=48,
        vuln_class=VulnClass.HEAP_OVERFLOW,
        title="heap overflow in parse",
        description="An attacker-controlled length leads to heap overflow.",
        code_snippet="memcpy(dst, src, len);",
        confidence=0.9,
    )
    base.update(overrides)
    return Finding(**base)


# ── Finding: line_start (NOT line) ─────────────────────────────────────────────

def test_finding_uses_line_start_not_line():
    f = _minimal_finding(line_start=100, line_end=120)
    assert f.line_start == 100
    assert f.line_end == 120
    # The field is line_start; there is no `line` attribute on Finding.
    assert not hasattr(f, "line")


def test_finding_requires_line_start_and_line_end():
    # Omitting line_start must raise — it is a required field with no default.
    with pytest.raises(ValidationError):
        Finding(
            chunk_id="c",
            file="f.c",
            line_end=10,
            vuln_class=VulnClass.OTHER,
            title="t",
            description="d",
            code_snippet="s",
            confidence=0.5,
        )


def test_finding_defaults():
    f = _minimal_finding()
    # Optional fields default to safe empties / None.
    assert f.cwe is None
    assert f.impact == ""
    assert f.exploit_scenario == ""
    assert f.preconditions == []
    assert f.recommendation == ""
    assert f.source_ref is None
    assert f.sink_ref is None
    assert f.votes == 1
    assert f.duplicates == []
    # Step-6 verification fields default unset.
    assert f.verdict is None
    assert f.verdict_confidence is None
    assert f.cvss_vector is None
    assert f.cvss_score is None
    # Post-s7 enrichment defaults.
    assert f.vsvs_score is None
    assert f.offensive_priority is None


# ── Finding.confidence coercion (Field ge=0.0 le=1.0 + _coerce_confidence) ──────

def test_confidence_fraction_passthrough():
    assert _minimal_finding(confidence=0.73).confidence == pytest.approx(0.73)


def test_confidence_percent_scale_div_100():
    # 95 (a percent) maps to 0.95 — survives instead of failing le=1.0.
    assert _minimal_finding(confidence=95).confidence == pytest.approx(0.95)
    assert _minimal_finding(confidence="95%").confidence == pytest.approx(0.95)


def test_confidence_whole_number_2_to_10_uses_ten_point_scale():
    assert _minimal_finding(confidence=8).confidence == pytest.approx(0.8)
    assert _minimal_finding(confidence=10).confidence == pytest.approx(1.0)
    assert _minimal_finding(confidence="8").confidence == pytest.approx(0.8)


def test_confidence_slight_overshoot_clamped_not_scaled():
    # 1.5 is a near-1 fraction overshoot, clamped to 1.0 (NOT /100).
    assert _minimal_finding(confidence=1.5).confidence == pytest.approx(1.0)


def test_confidence_uninterpretable_falls_back_to_default():
    # "high" cannot be parsed → neutral 0.5 default; finding survives.
    assert _minimal_finding(confidence="high").confidence == pytest.approx(0.5)
    assert _minimal_finding(confidence=None).confidence == pytest.approx(0.5)


def test_confidence_nan_and_inf_fall_back():
    assert _minimal_finding(confidence=float("nan")).confidence == pytest.approx(0.5)
    assert _minimal_finding(confidence=float("inf")).confidence == pytest.approx(0.5)


def test_confidence_negative_clamped_to_zero():
    assert _minimal_finding(confidence=-3).confidence == pytest.approx(0.0)


def test_confidence_bool_treated_as_no_signal():
    # bool is a subclass of int but must NOT be read as 0/1 confidence.
    assert _minimal_finding(confidence=True).confidence == pytest.approx(0.5)


# ── canonical_key (intersection identity) ──────────────────────────────────────

def test_canonical_key_buckets_line_number():
    a = _minimal_finding(line_start=142)
    b = _minimal_finding(line_start=145)
    # Same file + vuln_class + line bucket (//10) → identical identity.
    assert a.canonical_key() == b.canonical_key()
    assert a.canonical_key() == ("src/app.c", 14, VulnClass.HEAP_OVERFLOW)


def test_canonical_key_distinct_across_bucket_boundary():
    a = _minimal_finding(line_start=149)
    b = _minimal_finding(line_start=150)
    assert a.canonical_key() != b.canonical_key()


# ── Severity enum (string values; critical maps as source defines) ──────────────

def test_severity_string_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"
    # str-Enum: members compare equal to their string value.
    assert Severity.CRITICAL == "critical"


def test_severity_constructed_from_string():
    assert Severity("critical") is Severity.CRITICAL
    assert Severity("info") is Severity.INFO


def test_severity_rejects_unknown_value():
    with pytest.raises(ValueError):
        Severity("catastrophic")


# ── VulnClass enum (values include CWE-style slugs) ─────────────────────────────

def test_vuln_class_values():
    assert VulnClass.UAF.value == "use-after-free"
    assert VulnClass.INJECTION.value == "injection"
    assert VulnClass.DESERIALIZATION.value == "unsafe-deserialization"
    assert VulnClass("logic-flaw") is VulnClass.LOGIC


# ── Control.kind coercion ───────────────────────────────────────────────────────

def test_control_kind_exact_value():
    assert Control(name="gw", kind="auth").kind == "auth"


def test_control_kind_alias_maps_to_member():
    assert Control(name="gw", kind="authentication").kind == "auth"
    assert Control(name="waf", kind="WAF").kind == "input-validation"
    assert Control(name="sb", kind="seccomp").kind == "sandbox"


def test_control_kind_unknown_falls_back_to_other():
    assert Control(name="x", kind="quantum-shield").kind == "other"


# ── Asset.sensitivity coercion ──────────────────────────────────────────────────

def test_asset_sensitivity_default_and_alias():
    assert Asset(name="db").sensitivity == "medium"
    assert Asset(name="db", sensitivity="crit").sensitivity == "critical"
    assert Asset(name="db", sensitivity="bogus").sensitivity == "medium"


# ── Threat enum coercion (actor / impact / likelihood) ──────────────────────────

def test_threat_actor_alias_and_default():
    t = Threat(
        id="T1", threat="RCE", actor="anonymous", surface="api",
        asset="db", impact="critical", likelihood="likely",
    )
    assert t.actor == "remote_unauth"


def test_threat_actor_unknown_falls_back():
    t = Threat(
        id="T2", threat="x", actor="martian", surface="s",
        asset="a", impact="high", likelihood="rare",
    )
    assert t.actor == "remote_auth"


def test_threat_impact_existential_alias():
    t = Threat(
        id="T3", threat="x", actor="insider", surface="s",
        asset="a", impact="catastrophic", likelihood="possible",
    )
    assert t.impact == "existential"


def test_threat_likelihood_alias():
    t = Threat(
        id="T4", threat="x", actor="insider", surface="s",
        asset="a", impact="low", likelihood="very_unlikely",
    )
    assert t.likelihood == "very_rare"


# ── Sink.line / int coercion ────────────────────────────────────────────────────

def test_sink_line_default_and_string_coercion():
    assert Sink(file="f.c", function="strcpy").line == 0
    assert Sink(file="f.c", function="strcpy", line="57").line == 57


def test_sink_line_bad_value_falls_back_zero():
    assert Sink(file="f.c", function="strcpy", line="not-a-number").line == 0
    assert Sink(file="f.c", function="strcpy", line=None).line == 0


# ── Chunk.size / risk_rank coercion ─────────────────────────────────────────────

def test_chunk_defaults():
    c = Chunk(id="chunk-01")
    assert c.size is ChunkSize.MEDIUM
    assert c.risk_rank == 999
    assert c.files == []
    assert c.threat_id is None
    assert c.specialist is None


def test_chunk_size_alias_coercion():
    assert Chunk(id="c", size="tiny").size is ChunkSize.SMALL
    assert Chunk(id="c", size="xl").size is ChunkSize.LARGE
    assert Chunk(id="c", size="bogus").size is ChunkSize.MEDIUM


def test_chunk_risk_rank_string_coercion():
    assert Chunk(id="c", risk_rank="3").risk_rank == 3
    assert Chunk(id="c", risk_rank="garbage").risk_rank == 999


# ── round-trip model_dump ───────────────────────────────────────────────────────

def test_finding_round_trip_model_dump():
    f = _minimal_finding(
        cwe="CWE-122",
        preconditions=["attacker controls length"],
        duplicates=[DupLocation(
            file="src/other.c", line_start=10, vuln_class=VulnClass.HEAP_OVERFLOW,
        )],
    )
    data = f.model_dump()
    assert data["line_start"] == 42
    assert "line" not in data            # confirms field name, not legacy `line`
    assert data["cwe"] == "CWE-122"
    assert data["confidence"] == pytest.approx(0.9)

    rebuilt = Finding(**data)
    assert rebuilt == f
    assert rebuilt.line_start == f.line_start
    assert rebuilt.duplicates[0].file == "src/other.c"


def test_dup_location_defaults():
    d = DupLocation(file="a.c", line_start=5, vuln_class=VulnClass.RACE)
    assert d.line_end == 0
    assert d.title == ""
    assert d.source_ref is None


def test_chain_round_trip_with_severity_enum():
    c = Chain(
        title="UAF -> arb write",
        steps=[0, 1],
        severity=Severity.CRITICAL,
        narrative="step chain",
    )
    data = c.model_dump()
    assert data["severity"] == "critical"
    rebuilt = Chain(**data)
    assert rebuilt.severity is Severity.CRITICAL
    assert rebuilt.blocked_by_controls == []


# ── DroppedFinding.reason Literal enforcement ───────────────────────────────────

def test_dropped_finding_valid_reason():
    d = DroppedFinding(
        file="f.c", line=3, vuln_class=VulnClass.OTHER,
        title="t", chunk_id="c", reason="FALSE_POSITIVE",
    )
    assert d.reason == "FALSE_POSITIVE"
    assert d.canonical_idx is None


def test_dropped_finding_rejects_bad_reason():
    with pytest.raises(ValidationError):
        DroppedFinding(
            file="f.c", line=3, vuln_class=VulnClass.OTHER,
            title="t", chunk_id="c", reason="MAYBE",
        )


# ── ScanMetrics computed properties ─────────────────────────────────────────────

def test_scan_metrics_coverage_pct():
    m = ScanMetrics(total_files_in_scope=200, analyzed_files_unique=50)
    assert m.coverage_pct == pytest.approx(25.0)


def test_scan_metrics_coverage_pct_zero_scope():
    assert ScanMetrics().coverage_pct == 0.0


def test_scan_metrics_verification_precision_pct():
    m = ScanMetrics(raw_findings_count=10, true_positive_count=7)
    assert m.verification_precision_pct == pytest.approx(70.0)


def test_scan_metrics_precision_no_raw_findings():
    assert ScanMetrics(true_positive_count=5).verification_precision_pct == 0.0

from vvaharness.models import (
    _demote_md_headings, _md_cell, AppProfile, FinalReport, RankedFinding, ThreatModel)


def test_demote_md_headings_demotes_leading_atx():
    assert _demote_md_headings("## Analysis\nbody") == "**Analysis**\nbody"
    assert _demote_md_headings("# H1") == "**H1**"
    assert _demote_md_headings("###### H6") == "**H6**"


def test_demote_md_headings_preserves_inline_and_fenced():
    # inline '#' is not a heading
    assert _demote_md_headings("use C# or #1 or #define") == "use C# or #1 or #define"
    # '#' comment inside a fenced code block must survive
    src = "```python\n# a comment\nx = 1\n```"
    assert _demote_md_headings(src) == src
    # 4-space indent is a code block, not an ATX heading
    assert _demote_md_headings("    # indented") == "    # indented"


def test_demote_md_headings_empty_and_none():
    assert _demote_md_headings("") == ""
    assert _demote_md_headings(None) is None


def test_md_cell_escapes_pipe_and_newline():
    assert _md_cell("a|b") == "a\\|b"
    assert _md_cell("line1\nline2") == "line1 line2"
    assert _md_cell(None) == ""


def test_md_cell_escapes_backslash_before_pipe():
    # A supplied "\" must be doubled, else it consumes the escape added for "|" and the
    # raw delimiter survives into the rendered table.
    assert _md_cell(r"a\|b") == r"a\\\|b"


def test_to_markdown_demotes_injected_verifier_heading():
    f = _minimal_finding(
        verdict="TRUE_POSITIVE", verdict_confidence=8, verdict_reason="confirmed",
        verifier_reasoning="## Fake Section\nthe model tried to inject a heading",
    )
    rf = RankedFinding(finding=f, severity=Severity.HIGH, exploitability_notes="n")
    rep = FinalReport(repo_root="/x", findings=[rf], chains=[], summary="s")
    md = rep.to_markdown()
    assert "## Fake Section" not in md
    assert "**Fake Section**" in md
    # the report's own structural heading is untouched
    assert "#### Adversarial verification" in md


def test_to_markdown_neutralizes_injected_precondition_bullet():
    # A model-supplied list field carrying a newline + ATX heading must not
    # break out of its bullet into a structural heading in the rendered report.
    f = _minimal_finding(preconditions=["ok\n## Injected Heading"])
    rf = RankedFinding(finding=f, severity=Severity.HIGH, exploitability_notes="n")
    rep = FinalReport(repo_root="/x", findings=[rf], chains=[], summary="s")
    md = rep.to_markdown()
    # no rendered LINE may start with the injected heading (newline collapsed)
    assert not any(ln.lstrip().startswith("## Injected")
                   for ln in md.splitlines())
    assert "- ok ## Injected Heading" in md     # flattened onto one bullet
    # the undetermined-verification line is rendered (0 here, additive)
    assert "Verifier errors (excluded" in md


def test_to_markdown_neutralizes_injected_cmdb_app_profile():
    # application_id / name / source come from --application-id and the CMDB CSV
    # (operator/enterprise-supplied). A crafted value with a newline must not
    # terminate the "Application profile (CMDB)" list and inject a real heading
    # or link into the rendered threat-model section.
    f = _minimal_finding()
    rf = RankedFinding(finding=f, severity=Severity.HIGH, exploitability_notes="n")
    ap = AppProfile(
        application_id="APP1\n## Pwned ID",
        name="evil\n## Pwned Name\n[click](http://evil)",
        source="src\n## Pwned Source",
    )
    rep = FinalReport(repo_root="/x", findings=[rf], chains=[], summary="s",
                      threat_model=ThreatModel(), app_profile=ap)
    md = rep.to_markdown()
    # The structural heading is still rendered…
    assert "### Application profile (CMDB)" in md
    # …but none of the injected payloads become real lines of their own.
    for ln in md.splitlines():
        assert not ln.lstrip().startswith("## Pwned")
        assert ln.strip() != "[click](http://evil)"
    # Newlines were collapsed (values flattened inline, not dropped).
    assert "## Pwned Name" in md          # present, but inline within the bullet


# ── CWE backfill in to_markdown (cwe_for / VulnClass fallback) ──────────────────

def _report_with(finding):
    rf = RankedFinding(finding=finding, severity=Severity.HIGH,
                       exploitability_notes="n")
    return FinalReport(repo_root="/x", findings=[rf], chains=[], summary="s")


def test_to_markdown_backfills_cwe_from_vuln_class_when_token_absent():
    # cwe is None but vuln_class=use-after-free → deterministic CWE-416 line.
    f = _minimal_finding(vuln_class=VulnClass.UAF, cwe=None)
    md = _report_with(f).to_markdown()
    assert "**CWE:** CWE-416" in md
    assert "data/definitions/416.html" in md


def test_to_markdown_uses_explicit_cwe_token_over_fallback():
    # An explicit cwe token is preserved (passes through cwe_for unchanged).
    f = _minimal_finding(vuln_class=VulnClass.UAF, cwe="CWE-787")
    md = _report_with(f).to_markdown()
    assert "**CWE:** CWE-787" in md
    assert "CWE-416" not in md


def test_to_markdown_other_class_renders_no_cwe_line():
    # "other" maps to no CWE → no **CWE:** line (honest: unclassified).
    f = _minimal_finding(vuln_class=VulnClass.OTHER, cwe=None)
    md = _report_with(f).to_markdown()
    assert "**CWE:**" not in md
