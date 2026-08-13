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

"""Unit tests for s5_prefilter AST/callgraph evidence backfill."""
from __future__ import annotations

from types import SimpleNamespace

from vvaharness.models import ContextPackage, EntryPoint, Finding, VulnClass
from vvaharness.pipeline.stages import s5_prefilter


def _cfg(*, require_evidence: bool = True,
         min_pre_confidence: float = 0.0,
         ast_backfill_evidence: bool = True,
         semantic: bool = False):
    return SimpleNamespace(
        step5_prefilter=SimpleNamespace(
            require_evidence=require_evidence,
            min_pre_confidence=min_pre_confidence,
            ast_backfill_evidence=ast_backfill_evidence,
        ),
        step6_verify=SimpleNamespace(),
        step7_dedup=SimpleNamespace(
            line_tolerance=3,
            pre_verify_threshold=999,
            semantic=semantic,
        ),
    )


def _finding(*, file: str = "svc.py", line: int = 42,
             vuln_class: VulnClass = VulnClass.INJECTION,
             source_ref=None, sink_ref=None) -> Finding:
    return Finding(
        chunk_id="taint-01",
        file=file,
        line_start=line,
        line_end=line,
        vuln_class=vuln_class,
        title="test finding",
        description="desc",
        code_snippet="snippet",
        confidence=0.9,
        source_ref=source_ref,
        sink_ref=sink_ref,
    )


def test_no_refs_dropped_even_when_backfill_can_reach_entry_anchor():
    # Precision-first: an entry anchor exists that COULD backfill this finding,
    # but require_evidence judges the finding's own (empty) refs first, so it is
    # dropped before backfill ever runs. Backfill decorates survivors only.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
        entry_points=[
            EntryPoint(file="svc.py", function="handle", kind="network", reachable_from_unauth=True)
        ],
        call_graph_files={"handle": ["svc.py:12"]},
    )
    f = _finding(file="svc.py", line=40, source_ref=None, sink_ref=None)

    keep, dropped = s5_prefilter.run([f], ctx, _cfg())

    assert keep == []
    assert len(dropped) == 1
    assert dropped[0].reason == "UNCONFIRMED"
    assert "missing source_ref/sink_ref" in dropped[0].detail


def test_no_refs_dropped_even_when_seed_taint_path_could_backfill():
    # A seed taint path could supply source/sink, but under require_evidence the
    # finding must arrive with its own evidence; backfill cannot manufacture it.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["api.py", "svc.py"],
        seed_taint_paths=[["api.py:9", "svc.py:40", "svc.py:44"]],
    )
    f = _finding(file="svc.py", line=44, source_ref=None, sink_ref=None)

    keep, dropped = s5_prefilter.run([f], ctx, _cfg())

    assert keep == []
    assert len(dropped) == 1
    assert dropped[0].reason == "UNCONFIRMED"


def test_finding_with_own_evidence_is_kept_and_backfill_decorates_it():
    # A finding that already carries the evidence the gate demands survives, and
    # backfill still decorates it on the keep-path (here filling the info-leak
    # source ref) without changing the kept/dropped outcome.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["config.py"],
    )
    f = _finding(file="config.py", line=7, vuln_class=VulnClass.INFO_LEAK,
                 source_ref="config.py:7", sink_ref="config.py:7")

    keep, dropped = s5_prefilter.run([f], ctx, _cfg())

    assert len(dropped) == 0
    assert len(keep) == 1
    assert keep[0].source_ref == "config.py:7"
    assert keep[0].sink_ref == "config.py:7"


def test_backfill_decorates_survivors_when_evidence_not_required():
    # With require_evidence off, a finding missing its sink ref survives the gate
    # and backfill fills the sink from the entry anchor on the keep-path.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
        entry_points=[
            EntryPoint(file="svc.py", function="handle", kind="network", reachable_from_unauth=True)
        ],
        call_graph_files={"handle": ["svc.py:12"]},
    )
    f = _finding(file="svc.py", line=40, source_ref=None, sink_ref=None)

    keep, dropped = s5_prefilter.run([f], ctx, _cfg(require_evidence=False))

    assert len(dropped) == 0
    assert len(keep) == 1
    assert keep[0].source_ref == "svc.py:12"
    assert keep[0].sink_ref == "svc.py:40"


def test_missing_evidence_still_drops_when_backfill_disabled():
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
    )
    f = _finding(file="svc.py", line=20, source_ref=None, sink_ref=None)

    keep, dropped = s5_prefilter.run(
        [f],
        ctx,
        _cfg(ast_backfill_evidence=False),
    )

    assert keep == []
    assert len(dropped) == 1
    assert dropped[0].reason == "UNCONFIRMED"
    assert "missing source_ref/sink_ref" in dropped[0].detail


def test_prefilter_does_not_collapse_different_cwes_in_same_class_overlap():
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
    )
    a = _finding(file="svc.py", line=40, vuln_class=VulnClass.LOGIC,
                 source_ref="svc.py:40", sink_ref="svc.py:45")
    b = _finding(file="svc.py", line=42, vuln_class=VulnClass.LOGIC,
                 source_ref="svc.py:42", sink_ref="svc.py:66")
    a.line_end = 45
    b.line_end = 66
    a.cwe = "CWE-863"
    b.cwe = "CWE-778"

    keep, dropped = s5_prefilter.run([a, b], ctx, _cfg(require_evidence=True))

    assert len(keep) == 2
    assert dropped == []


def test_prefilter_keeps_logic_overlap_when_one_cwe_missing():
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
    )
    a = _finding(file="svc.py", line=40, vuln_class=VulnClass.LOGIC,
                 source_ref="svc.py:40", sink_ref="svc.py:45")
    b = _finding(file="svc.py", line=42, vuln_class=VulnClass.LOGIC,
                 source_ref="svc.py:42", sink_ref="svc.py:66")
    a.line_end = 45
    b.line_end = 66
    a.cwe = "CWE-863"
    b.cwe = None

    keep, dropped = s5_prefilter.run([a, b], ctx, _cfg(require_evidence=True))

    assert len(keep) == 2
    assert dropped == []
