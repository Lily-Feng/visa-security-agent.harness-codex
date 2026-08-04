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

"""Unit tests for the deterministic dedup helpers in s7_dedup.

Covers overlapping/nested same-file range merging, the "additional call site"
attachment (disjoint-only, so an overlapping re-detection is not counted as a
new site), and de-duplication of the collapsed-location set. Pure functions.
"""
from vvaharness.pipeline.stages import s7_dedup
from vvaharness.models import ContextPackage, Finding, VulnClass


def _f(file: str, ls: int, le: int, vc: VulnClass = VulnClass.OTHER) -> Finding:
    return Finding(
        chunk_id="c", file=file, line_start=ls, line_end=le,
        vuln_class=vc, title="t", description="d", code_snippet="x",
        confidence=0.9,
    )


def test_collapse_trivial_merges_overlapping_ranges():
    findings = [_f("a.py", 10, 20), _f("a.py", 15, 25)]
    canon = s7_dedup._collapse_trivial(findings, line_tol=3)
    assert canon == {1: 0}


def test_collapse_trivial_keeps_disjoint_ranges_separate():
    findings = [_f("a.py", 10, 12), _f("a.py", 80, 82)]
    canon = s7_dedup._collapse_trivial(findings, line_tol=3)
    assert canon == {}


def test_collapse_trivial_keeps_overlapping_findings_with_different_cwe():
    a = _f("svc.py", 40, 45, VulnClass.LOGIC)
    b = _f("svc.py", 42, 66, VulnClass.LOGIC)
    a.cwe = "CWE-863"
    b.cwe = "CWE-778"
    canon = s7_dedup._collapse_trivial([a, b], line_tol=10)
    assert canon == {}


def test_collapse_trivial_still_merges_when_cwe_matches():
    a = _f("svc.py", 40, 45, VulnClass.LOGIC)
    b = _f("svc.py", 42, 66, VulnClass.LOGIC)
    a.cwe = "CWE-863"
    b.cwe = "CWE-863"
    canon = s7_dedup._collapse_trivial([a, b], line_tol=10)
    assert canon == {1: 0}


def test_collapse_trivial_keeps_logic_overlap_when_cwe_missing_on_one_side():
    a = _f("svc.py", 40, 45, VulnClass.LOGIC)
    b = _f("svc.py", 42, 66, VulnClass.LOGIC)
    a.cwe = "CWE-863"
    b.cwe = None
    canon = s7_dedup._collapse_trivial([a, b], line_tol=10)
    assert canon == {}


def test_attach_duplicates_skips_same_site_overlap():
    findings = [_f("a.py", 10, 20), _f("a.py", 15, 25)]
    s7_dedup._attach_duplicates(findings, {1: 0}, {1: "dup"})
    assert findings[0].duplicates == []


def test_attach_duplicates_records_disjoint_site():
    findings = [_f("a.py", 10, 12), _f("b.py", 50, 52)]
    s7_dedup._attach_duplicates(findings, {1: 0}, {1: "dup"})
    assert len(findings[0].duplicates) == 1
    assert findings[0].duplicates[0].file == "b.py"


def test_attach_duplicates_dedupes_identical_locations():
    findings = [_f("a.py", 10, 12), _f("b.py", 50, 52), _f("b.py", 50, 52)]
    s7_dedup._attach_duplicates(findings, {1: 0, 2: 0}, {1: "d", 2: "d"})
    assert len(findings[0].duplicates) == 1


def test_graph_context_for_finding_uses_def_span_candidates():
    f = _f("src/app.py", 10, 12)
    f.source_ref = "src/http.py:22"
    f.sink_ref = "src/app.py:11"
    ctx = ContextPackage(
        repo_root="/tmp/repo",
        language="python",
        call_graph={
            "src/http.py::handle": ["src/app.py::danger"],
            "src/app.py::danger": ["src/db.py::exec"],
        },
        def_spans={
            "src/app.py::danger": [8, 20],
            "src/http.py::handle": [20, 30],
        },
    )

    g = s7_dedup._graph_context_for_finding(f, ctx)
    assert g["available"] is True
    assert "src/app.py::danger" in g["qnodes"]
    around = g["around"]["src/app.py::danger"]
    assert "src/http.py::handle" in around["callers"]
    assert "src/db.py::exec" in around["callees"]


def test_graph_context_for_finding_handles_missing_graph():
    f = _f("src/app.py", 10, 12)
    ctx = ContextPackage(repo_root="/tmp/repo", language="python")
    g = s7_dedup._graph_context_for_finding(f, ctx)
    assert g == {"available": False}
