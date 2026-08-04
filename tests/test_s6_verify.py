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

"""Unit tests for vvaharness.pipeline.stages.s6_verify.

Offline + deterministic: the agentic LLM call is monkeypatched, no real
`claude` subprocess is ever spawned, and the cooperative-abort global plus
errlog file path are reset in an autouse fixture so the full suite is order
independent.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.models import ContextPackage, Finding, VulnClass
from vvaharness.pipeline.stages import s6_verify
from vvaharness.backends import claude_cli as cli
from vvaharness.backends.claude_cli import GuardrailBlocked


# ─────────────────────────────────────────────────────────────────────────────
# Global-state isolation (the full suite runs every file together).
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate():
    # cli._ABORT is a process-global Event; a prior test (or run()'s abort
    # path) may leave it set, which would poison _verify_one with
    # "aborted by user". Clear before and after every test. (errlog._path is
    # redirected by the shared tests/conftest.py fixture.)
    cli.reset_abort()
    yield
    cli.reset_abort()


# ─────────────────────────────────────────────────────────────────────────────
# Builders
# ─────────────────────────────────────────────────────────────────────────────

def _finding(**kw) -> Finding:
    base = dict(
        chunk_id="chunk-01",
        file="src/app.py",
        line_start=10,
        line_end=12,
        vuln_class=VulnClass.INJECTION,
        title="SQL injection in handler",
        description="user input flows into a raw query",
        code_snippet="cur.execute('SELECT ' + user_in)",
        confidence=0.8,
    )
    base.update(kw)
    return Finding(**base)


def _ctx(**kw) -> ContextPackage:
    base = dict(repo_root="/tmp/repo", language="python")
    base.update(kw)
    return ContextPackage(**base)


def _cfg(**step6) -> SimpleNamespace:
    step6_defaults = dict(parallel=2, min_confidence=7,
                          allowed_tools=["Read", "Grep"],
                          max_budget_usd=1.0, max_turns=None)
    step6_defaults.update(step6)
    return SimpleNamespace(
        step6_verify=SimpleNamespace(**step6_defaults),
        models=SimpleNamespace(verify="model-verify-test"),
    )


_GOOD_CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


# ─────────────────────────────────────────────────────────────────────────────
# _CVSS_RE — accepts 3.0 and 3.1, rejects 2.0
# ─────────────────────────────────────────────────────────────────────────────

def test_cvss_re_accepts_31():
    m = s6_verify._CVSS_RE.search("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert m is not None
    assert m.group(0) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_cvss_re_accepts_30():
    m = s6_verify._CVSS_RE.search("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H")
    assert m is not None
    assert m.group(0).startswith("CVSS:3.0/")


def test_cvss_re_rejects_20():
    # A CVSS 2.0 style vector has no "3.[01]" prefix → must not match.
    assert s6_verify._CVSS_RE.search(
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    # Even a 3.x-shaped vector mislabelled as 2.0 must be rejected.
    assert s6_verify._CVSS_RE.search(
        "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


def test_cvss_re_rejects_malformed_metric():
    # X is not a valid AV value.
    assert s6_verify._CVSS_RE.search(
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


# ─────────────────────────────────────────────────────────────────────────────
# _parse_verdict — pure helper: verdict/conf/reason/cvss/reasoning extraction
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_verdict_true_positive_with_cvss():
    raw = (
        "I read the file and traced callers.\n"
        "The route is unauthenticated.\n"
        "VERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable from unauth route\n"
        f"CVSS: {_GOOD_CVSS}\n"
    )
    verdict, conf, reason, cvss, reasoning = s6_verify._parse_verdict(raw)
    assert verdict == "TRUE_POSITIVE"
    assert conf == 9
    assert reason == "reachable from unauth route"
    assert cvss == _GOOD_CVSS
    # reasoning is everything BEFORE the verdict line.
    assert "traced callers" in reasoning
    assert "VERDICT" not in reasoning


def test_parse_verdict_false_positive():
    raw = (
        "Analysis body.\n"
        "VERDICT: FALSE_POSITIVE (confidence: 8/10) — upstream allow-list neutralises input\n"
        f"CVSS: {_GOOD_CVSS}\n"
    )
    verdict, conf, reason, cvss, reasoning = s6_verify._parse_verdict(raw)
    assert verdict == "FALSE_POSITIVE"
    assert conf == 8
    assert reason == "upstream allow-list neutralises input"
    assert cvss == _GOOD_CVSS


def test_parse_verdict_unparseable_defaults_to_false_positive():
    raw = "The model rambled and never emitted a verdict line.\n"
    verdict, conf, reason, cvss, reasoning = s6_verify._parse_verdict(raw)
    assert verdict == "FALSE_POSITIVE"
    assert conf == 0
    assert reason == "verifier output unparseable"
    assert cvss is None


def test_parse_verdict_confidence_clamped_to_10():
    raw = "VERDICT: TRUE_POSITIVE (confidence: 99/10) — over the top\n" \
          f"CVSS: {_GOOD_CVSS}\n"
    verdict, conf, reason, cvss, reasoning = s6_verify._parse_verdict(raw)
    assert conf == 10


def test_parse_verdict_reads_last_verdict_line():
    # Multiple VERDICT lines: the scanner reads from the BOTTOM up, so the
    # final verdict wins.
    raw = (
        "VERDICT: FALSE_POSITIVE (confidence: 3/10) — early draft\n"
        "...more analysis...\n"
        "VERDICT: TRUE_POSITIVE (confidence: 10/10) — final answer\n"
        f"CVSS: {_GOOD_CVSS}\n"
    )
    verdict, conf, reason, cvss, reasoning = s6_verify._parse_verdict(raw)
    assert verdict == "TRUE_POSITIVE"
    assert conf == 10
    assert reason == "final answer"


def test_parse_verdict_prefers_cvss_after_verdict_line():
    # A decoy CVSS appears BEFORE the verdict; the real one is on the line
    # directly after VERDICT. The post-verdict vector must win.
    decoy = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L"
    raw = (
        f"Earlier I considered: {decoy}\n"
        "VERDICT: TRUE_POSITIVE (confidence: 8/10) — confirmed\n"
        f"CVSS: {_GOOD_CVSS}\n"
    )
    _, _, _, cvss, _ = s6_verify._parse_verdict(raw)
    assert cvss == _GOOD_CVSS
    assert cvss != decoy


def test_parse_verdict_falls_back_to_last_cvss_when_none_after_verdict():
    # No CVSS after the verdict line → fall back to the last CVSS anywhere
    # in the raw text.
    raw = (
        f"Body mentions {_GOOD_CVSS} up here.\n"
        "VERDICT: TRUE_POSITIVE (confidence: 7/10) — confirmed\n"
        "(no cvss on the next line)\n"
    )
    _, _, _, cvss, _ = s6_verify._parse_verdict(raw)
    assert cvss == _GOOD_CVSS


def test_parse_verdict_accepts_30_vector():
    v30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    raw = ("VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\n"
           f"CVSS: {v30}\n")
    _, _, _, cvss, _ = s6_verify._parse_verdict(raw)
    assert cvss == v30


# ─────────────────────────────────────────────────────────────────────────────
# _build_user_prompt — callgraph-first context with explicit fallback guidance
# ─────────────────────────────────────────────────────────────────────────────

def test_build_user_prompt_includes_sqlite_callgraph_context():
    f = _finding(
        file="src/app.py",
        line_start=10,
        line_end=12,
        source_ref="src/http.py:22",
        sink_ref="src/app.py:11",
    )
    ctx = _ctx(
        call_graph={
            "src/http.py::handle": ["src/app.py::danger"],
            "src/app.py::danger": ["src/db.py::exec"],
        },
        def_spans={
            "src/app.py::danger": [8, 20],
            "src/http.py::handle": [20, 35],
        },
        entry_points=[],
    )

    prompt = s6_verify._build_user_prompt(f, ctx)
    assert "CALL GRAPH CONTEXT (sqlite-hydrated; validate each edge with Grep/Read):" in prompt
    assert "candidate functions at/near finding line" in prompt
    assert "src/app.py::danger" in prompt
    assert "caller -> src/http.py::handle -> src/app.py::danger" in prompt
    assert "callee -> src/app.py::danger -> src/db.py::exec" in prompt


def test_build_user_prompt_includes_callgraph_fallback_when_candidates_missing():
    f = _finding(file="src/app.py", line_start=10, line_end=12)
    ctx = _ctx(call_graph={"src/a.py::x": ["src/b.py::y"]}, def_spans={})

    prompt = s6_verify._build_user_prompt(f, ctx)
    assert "candidate functions at finding location: (none)" in prompt
    assert "action: use Grep on file/class symbols to recover callers/callees from code" in prompt


# ─────────────────────────────────────────────────────────────────────────────
# run() — empty short-circuit
# ─────────────────────────────────────────────────────────────────────────────

def test_run_empty_returns_empty():
    verified, dropped = s6_verify.run([], _ctx(), _cfg())
    assert verified == []
    assert dropped == []


# ─────────────────────────────────────────────────────────────────────────────
# run() — happy path: TP above gate is verified; CVSS scored
# ─────────────────────────────────────────────────────────────────────────────

def test_run_true_positive_above_gate(monkeypatch):
    def fake_agentic(user, **kw):
        return ("traced it\n"
                "VERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable\n"
                f"CVSS: {_GOOD_CVSS}\n")
    monkeypatch.setattr(s6_verify, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg(min_confidence=7))
    assert len(verified) == 1
    assert dropped == []
    f = verified[0]
    assert f.verdict == "TRUE_POSITIVE"
    assert f.verdict_confidence == 9
    assert f.cvss_vector == _GOOD_CVSS
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → base score 9.8 → Critical
    assert f.cvss_score == 9.8
    assert f.cvss_rating == "Critical"
    assert "traced it" in f.verifier_reasoning


# ─────────────────────────────────────────────────────────────────────────────
# run() — TP below the confidence gate is dropped as UNCONFIRMED
# ─────────────────────────────────────────────────────────────────────────────

def test_run_true_positive_below_gate_is_unconfirmed(monkeypatch):
    def fake_agentic(user, **kw):
        return ("VERDICT: TRUE_POSITIVE (confidence: 4/10) — weak\n"
                f"CVSS: {_GOOD_CVSS}\n")
    monkeypatch.setattr(s6_verify, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg(min_confidence=7))
    assert verified == []
    assert len(dropped) == 1
    assert dropped[0].reason == "UNCONFIRMED"
    assert "below gate 7" in dropped[0].detail


# ─────────────────────────────────────────────────────────────────────────────
# run() — FALSE_POSITIVE is dropped with the verdict reason
# ─────────────────────────────────────────────────────────────────────────────

def test_run_false_positive_dropped(monkeypatch):
    def fake_agentic(user, **kw):
        return ("VERDICT: FALSE_POSITIVE (confidence: 9/10) — input is sanitised\n"
                f"CVSS: {_GOOD_CVSS}\n")
    monkeypatch.setattr(s6_verify, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg())
    assert verified == []
    assert len(dropped) == 1
    assert dropped[0].reason == "FALSE_POSITIVE"
    assert dropped[0].detail == "input is sanitised"


# ─────────────────────────────────────────────────────────────────────────────
# run() — an UNPARSEABLE verifier reply (no VERDICT line) is UNDETERMINED and
# must be recorded as VERIFY_ERROR, never laundered into the FALSE_POSITIVE
# tally (which would hide a possibly-real finding as "verified clean").
# ─────────────────────────────────────────────────────────────────────────────

def test_run_unparseable_reply_is_verify_error_not_false_positive(monkeypatch):
    def fake_agentic(user, **kw):
        return "I read the code but did not reach a conclusion.\n"
    monkeypatch.setattr(s6_verify, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg())
    assert verified == []
    assert len(dropped) == 1
    assert dropped[0].reason == "VERIFY_ERROR"
    assert dropped[0].reason != "FALSE_POSITIVE"
    assert "unparseable" in dropped[0].detail


# ─────────────────────────────────────────────────────────────────────────────
# run() — a raised Exception is captured as VERIFY_ERROR, not propagated
# ─────────────────────────────────────────────────────────────────────────────

def test_run_verify_error_captured(monkeypatch):
    def boom(user, **kw):
        raise ValueError("backend exploded")
    monkeypatch.setattr(s6_verify, "agentic", boom)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg())
    assert verified == []
    assert len(dropped) == 1
    assert dropped[0].reason == "VERIFY_ERROR"
    assert "backend exploded" in dropped[0].detail


# ─────────────────────────────────────────────────────────────────────────────
# run() — GUARDRAIL_BLOCKED counted separately in the summary
# (single block, below the abort gate → recorded as a dropped finding)
# ─────────────────────────────────────────────────────────────────────────────

def test_run_single_guardrail_block_recorded(monkeypatch):
    # One guardrail block among several successes: gate = max(3, parallel).
    findings = [_finding(line_start=10 * (i + 1)) for i in range(4)]

    def fake_agentic(user, **kw):
        # The first finding's prompt references its line; block exactly one.
        if "30-" in user or "src/app.py\nLine: 30" in user:
            raise GuardrailBlocked("Your request was not allowed")
        return ("VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\n"
                f"CVSS: {_GOOD_CVSS}\n")
    monkeypatch.setattr(s6_verify, "agentic", fake_agentic)

    verified, dropped = s6_verify.run(findings, _ctx(), _cfg(parallel=4))
    gb = [d for d in dropped if d.reason == "GUARDRAIL_BLOCKED"]
    assert len(gb) == 1
    # The other three findings succeeded.
    assert len(verified) == 3
    # cli should NOT have aborted because there were successes.
    assert cli.aborted() is False


# ─────────────────────────────────────────────────────────────────────────────
# run() — guardrail gate trips: enough blocks AND zero successes → abort
# ─────────────────────────────────────────────────────────────────────────────

def test_run_guardrail_gate_aborts_with_zero_successes(monkeypatch):
    # parallel=3 → guardrail_gate = max(3, 3) = 3. Every call blocks, so
    # after the 3rd cumulative block with zero successes run() must abort.
    findings = [_finding(line_start=10 * (i + 1)) for i in range(3)]

    def always_block(user, **kw):
        raise GuardrailBlocked("Your request was not allowed")
    monkeypatch.setattr(s6_verify, "agentic", always_block)

    with pytest.raises(RuntimeError) as ei:
        s6_verify.run(findings, _ctx(), _cfg(parallel=3))
    assert "cumulative guardrail" in str(ei.value)
    # abort() set the global stop flag.
    assert cli.aborted() is True


# ─────────────────────────────────────────────────────────────────────────────
# run() — summary label logic: GUARDRAIL_BLOCKED is NOT counted as an error
# ─────────────────────────────────────────────────────────────────────────────

def test_run_summary_separates_guardrail_from_errors(monkeypatch, capsys):
    # Mix: 1 TP, 1 FP, 1 UNCONFIRMED, 1 GUARDRAIL, 1 VERIFY_ERROR.
    # Distinguish by line_start encoded in the prompt.
    findings = [
        _finding(line_start=11),   # TP
        _finding(line_start=22),   # FP
        _finding(line_start=33),   # UNCONFIRMED (low conf TP)
        _finding(line_start=44),   # GUARDRAIL
        _finding(line_start=55),   # VERIFY_ERROR
    ]

    def router(user, **kw):
        if "Line: 11-" in user:
            return ("VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\n"
                    f"CVSS: {_GOOD_CVSS}\n")
        if "Line: 22-" in user:
            return ("VERDICT: FALSE_POSITIVE (confidence: 9/10) — safe\n"
                    f"CVSS: {_GOOD_CVSS}\n")
        if "Line: 33-" in user:
            return ("VERDICT: TRUE_POSITIVE (confidence: 2/10) — weak\n"
                    f"CVSS: {_GOOD_CVSS}\n")
        if "Line: 44-" in user:
            raise GuardrailBlocked("Your request was not allowed")
        if "Line: 55-" in user:
            raise RuntimeError("kaboom")
        raise AssertionError("unexpected prompt")
    monkeypatch.setattr(s6_verify, "agentic", router)

    verified, dropped = s6_verify.run(findings, _ctx(), _cfg(parallel=5, min_confidence=7))

    assert len(verified) == 1
    by_reason = {}
    for d in dropped:
        by_reason[d.reason] = by_reason.get(d.reason, 0) + 1
    assert by_reason.get("FALSE_POSITIVE") == 1
    assert by_reason.get("UNCONFIRMED") == 1
    assert by_reason.get("GUARDRAIL_BLOCKED") == 1
    assert by_reason.get("VERIFY_ERROR") == 1

    # The printed summary must report 1 GUARDRAIL_BLOCKED and exactly 1 error
    # (errs = total dropped - fp - unc - gb), proving the guardrail block is
    # NOT folded into the error count.
    err = capsys.readouterr().err
    assert "1 GUARDRAIL_BLOCKED" in err
    assert "1 errors" in err


# ─────────────────────────────────────────────────────────────────────────────
# run() — when cli is already aborted, _verify_one raises → VERIFY_ERROR
# ─────────────────────────────────────────────────────────────────────────────

def test_run_respects_prior_abort(monkeypatch):
    def fake_agentic(user, **kw):  # pragma: no cover - should not be reached
        raise AssertionError("agentic must not be called once aborted")
    monkeypatch.setattr(s6_verify, "agentic", fake_agentic)
    cli.abort()  # set the global stop flag before run()

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg())
    assert verified == []
    assert len(dropped) == 1
    assert dropped[0].reason == "VERIFY_ERROR"
    assert "aborted" in dropped[0].detail.lower()
