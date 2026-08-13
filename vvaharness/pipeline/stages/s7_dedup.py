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

"""
Step 7 — Deduplication.

Runs after s6 verify; collapses verified findings that describe the same
underlying vulnerability, then passes the canonical set to s8 chain.
Two passes:

  7a. Deterministic pre-filter (in-process): same file + same vuln_class +
      |line diff| ≤ N  → trivial duplicate.
  7b. Semantic dedup (single LLM call): for everything the pre-filter didn't
      resolve, decide whether two findings share one root cause and would be
      closed by a single remediation. Handles different category names,
      cause-vs-consequence pairs, shared vulnerable utilities, and a missing
      global control reported once per endpoint.
"""
from __future__ import annotations
import json
import logging
import re
import sys

log = logging.getLogger(__name__)

from vvaharness.models import ContextPackage, Finding, DroppedFinding, DupLocation, VulnClass
from vvaharness.backends.llm import prompt
from vvaharness.util import errlog as _errlog
from vvaharness.report.redact import redact
from vvaharness.pipeline.callgraph_consumer import graph_view, qnodes_at, neighborhood
from vvaharness.pipeline.stages.s1_preprocess import q_file


def _make_dup_location(f: Finding, reasoning: str) -> DupLocation:
    """Snapshot a finding into a DupLocation so its file:line, refs, and
    title survive the collapse and surface as a related location in the
    final report + SARIF."""
    return DupLocation(
        file=f.file,
        line_start=f.line_start,
        line_end=f.line_end,
        vuln_class=f.vuln_class,
        title=f.title,
        chunk_id=f.chunk_id,
        source_ref=f.source_ref,
        sink_ref=f.sink_ref,
        reasoning=reasoning,
    )


def _dedup_locations(locs: list) -> list:
    """Drop repeat (file, line_start, line_end) entries, keeping first order."""
    seen: set = set()
    out: list = []
    for d in locs:
        key = (d.file, d.line_start, d.line_end)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def _attach_duplicates(findings: list[Finding], canonical_of: dict[int, int],
                       reasoning: dict[int, str]) -> None:
    """For every collapsed finding, append a DupLocation onto its canonical.
    Resolves transitive chains (j→i→r) so dups always land on the root, and
    transfers any DupLocations already on `j` onto the root too — so a
    deterministic pass followed by a semantic pass doesn't lose dups attached
    in the earlier pass. Records a collapsed finding as an ADDITIONAL call site
    only when its range is disjoint from the canonical's (an overlapping
    re-detection of the same region is the same site, not a new one), and
    de-dupes the location set before it reaches the renderer."""
    def root(i: int) -> int:
        seen = set()
        while i in canonical_of and i not in seen:
            seen.add(i)
            i = canonical_of[i]
        return i
    roots: set[int] = set()
    for j, parent in canonical_of.items():
        r = root(parent)
        roots.add(r)
        dj, rf = findings[j], findings[r]
        same_site = (dj.file == rf.file
                     and dj.line_start <= rf.line_end
                     and rf.line_start <= dj.line_end)
        if not same_site:
            rf.duplicates.append(
                _make_dup_location(dj, reasoning.get(j, "duplicate"))
            )
        if dj.duplicates:
            rf.duplicates.extend(dj.duplicates)
            dj.duplicates = []
    for r in roots:
        findings[r].duplicates = _dedup_locations(findings[r].duplicates)


_LINE_RE = re.compile(
    r"index\s*=\s*(\d+)\s+is_duplicate\s*=\s*(true|false)\s+"
    r"canonical\s*=\s*(-?\d+)\s+reasoning\s*=\s*\"([^\"]*)\"",
    re.IGNORECASE,
)

SYSTEM = """You are collapsing overlapping SAST findings that several
independent reviewers raised against the same repository.

DECISION TEST: two findings are the SAME finding when one engineering fix
closes both. If each needs its own code change, they are separate — even if
the bug class and file are identical.

Collapse (is_duplicate=true) when any of these hold:
- Same defect, different label or line — e.g. "OS command exec" at L40 vs
  "shell injection" at L42.
- Both trace back to one shared helper / utility; the call sites differ but
  the fix lives in the helper.
- One global control is absent (auth filter, CSRF token, output encoder) and
  each affected route was filed as its own ticket.
- A cause/effect pair on one flow — "no input validation" filed alongside the
  resulting "SQLi" on the same sink.
- One insecure setting or default surfaces at several read points.
- Same file, lines within ~30 of each other, and the descriptions clearly
  describe one issue from two angles.

Keep separate (is_duplicate=false) when:
- The fixes land in different functions/files and neither fix covers the
  other.
- Same CWE class repeated independently (e.g. two unrelated string-built SQL
  queries) — each one needs its own patch.

Prefer graph-grounded decisions when graph evidence exists:
- Shared source_ref/sink_ref or shared function-hop neighborhoods usually
    indicates one root cause.
- Distinct source/sink refs and disjoint graph neighborhoods suggest
    independent bugs.
- If graph context is missing/sparse, fall back to file+line+description only.

OUTPUT — one line per input index, plain text, this exact grammar:
  index=N is_duplicate=true canonical=M reasoning="one sentence"
  index=N is_duplicate=false canonical=-1 reasoning="one sentence"

Rules: emit a line for EVERY input index, in ascending order. When N is a
duplicate of M, M must be smaller than N (lowest index is always canonical).
No markdown, no fences, no extra commentary."""


_TRIVIAL_REASON = "trivial: same file/class within line tolerance"
_STRICT_CWE_CLASS = {VulnClass.LOGIC}


def _collapse_trivial(findings: list[Finding], line_tol: int) -> dict[int, int]:
    """Deterministic dedup pass shared by prefilter() and run()'s 7a stage.

    Two findings are duplicates when they share file + vuln_class and their
    line_start values are within `line_tol`. Returns {dup_idx -> canonical_idx},
    where the canonical is always the lower index. No model call.
    """
    canonical_of: dict[int, int] = {}
    for j in range(len(findings)):
        if j in canonical_of:
            continue
        for i in range(j):
            if i in canonical_of:
                continue
            a, b = findings[i], findings[j]
            if a.file != b.file or a.vuln_class != b.vuln_class:
                continue
            # Guard LOGIC bucket: only collapse when CWE is
            # explicit and equal. Missing CWE at s5 time is common in real
            # runs; collapsing these pre-s6 can hide true positives.
            if a.vuln_class in _STRICT_CWE_CLASS:
                if not a.cwe or not b.cwe or a.cwe != b.cwe:
                    continue
            # For narrower classes, keep the previous behavior: explicit CWE
            # disagreement blocks a collapse; missing CWE can still collapse by
            # proximity/overlap.
            elif a.cwe and b.cwe and a.cwe != b.cwe:
                continue
            close = abs(a.line_start - b.line_start) <= line_tol
            # Overlapping / nested line ranges are the same region re-detected
            # at slightly different boundaries across runs — collapse them too,
            # not just line_start proximity.
            overlap = a.line_start <= b.line_end and b.line_start <= a.line_end
            if close or overlap:
                canonical_of[j] = i
                break
    return canonical_of


def prefilter(findings: list[Finding], line_tol: int
              ) -> tuple[list[Finding], list[DroppedFinding]]:
    """
    Deterministic dedup only: same file + same vuln_class + |line diff| ≤ tol.
    No model call. Safe to run before s6 verify to avoid verifying the same bug N×.
    """
    if len(findings) <= 1:
        return list(findings), []

    canonical_of = _collapse_trivial(findings, line_tol)

    _attach_duplicates(
        findings, canonical_of,
        {j: _TRIVIAL_REASON for j in canonical_of},
    )

    keep = [f for i, f in enumerate(findings) if i not in canonical_of]
    dropped = [
        DroppedFinding(
            file=f.file, line=f.line_start, vuln_class=f.vuln_class,
            title=f.title, chunk_id=f.chunk_id, reason="DUPLICATE",
            detail=_TRIVIAL_REASON,
        )
        for i, f in enumerate(findings) if i in canonical_of
    ]
    return keep, dropped


def run(verified: list[Finding], cfg, *, label: str = "s7-dedup"
    , ctx: ContextPackage | None = None
        ) -> tuple[list[Finding], list[DroppedFinding]]:
    """Return (canonical_findings, duplicate_dropped)."""
    if len(verified) <= 1:
        return list(verified), []

    line_tol = getattr(cfg.step7_dedup, "line_tolerance", 10)

    # ── 7a. Deterministic pre-filter ─────────────────────────────────────
    canonical_of = _collapse_trivial(verified, line_tol)   # idx -> canonical idx
    reasoning: dict[int, str] = {j: _TRIVIAL_REASON for j in canonical_of}

    unresolved = [i for i in range(len(verified)) if i not in canonical_of]
    print(f"  [{label}] pre-filter: {len(canonical_of)} trivial dups, "
          f"{len(unresolved)} unresolved", file=sys.stderr)

    # ── 7b. Semantic dedup (only if 2+ unresolved) ───────────────────────
    if len(unresolved) >= 2 and getattr(cfg.step7_dedup, "semantic", True):
        sem = _semantic_dedup(verified, unresolved, cfg, ctx=ctx)
        for local_idx, local_canon, why in sem:
            # Map "local" indices (positions in `unresolved`) back to global.
            g_idx = unresolved[local_idx]
            g_canon = unresolved[local_canon]
            if g_idx not in canonical_of and g_canon < g_idx:
                canonical_of[g_idx] = g_canon
                reasoning[g_idx] = why

    # ── Attach dups onto canonicals (carries description/refs onto the
    # ── canonical so the MD report + SARIF can surface every call site).
    _attach_duplicates(verified, canonical_of, reasoning)

    # ── Resolve transitive chains and build outputs ──────────────────────
    def root(i: int) -> int:
        while i in canonical_of:
            i = canonical_of[i]
        return i

    canonical: list[Finding] = []
    new_index_of: dict[int, int] = {}
    for i, f in enumerate(verified):
        if i not in canonical_of:
            new_index_of[i] = len(canonical)
            canonical.append(f)

    dropped: list[DroppedFinding] = []
    for i, f in enumerate(verified):
        if i in canonical_of:
            r = root(i)
            dropped.append(DroppedFinding(
                file=f.file, line=f.line_start, vuln_class=f.vuln_class,
                title=f.title, chunk_id=f.chunk_id,
                reason="DUPLICATE",
                detail=reasoning.get(i, "duplicate"),
                canonical_idx=new_index_of.get(r),
            ))

    print(f"  [{label}] done: {len(canonical)} canonical, "
          f"{len(dropped)} duplicates collapsed", file=sys.stderr)
    return canonical, dropped


def _semantic_dedup(verified: list[Finding], unresolved: list[int], cfg
                    , ctx: ContextPackage | None = None
                    ) -> list[tuple[int, int, str]]:
    """Return list of (local_idx, local_canonical_idx, reasoning) for dups."""
    payload = []
    for local, g in enumerate(unresolved):
        f = verified[g]
        payload.append({
            "index": local,
            "file": f.file,
            "line": f.line_start,
            "category": f.vuln_class.value,
            "title": f.title,
            "description": f.description[:500],
            "exploit_scenario": f.exploit_scenario[:300],
            "source_ref": f.source_ref,
            "sink_ref": f.sink_ref,
            "graph_context": _graph_context_for_finding(f, ctx),
        })

    user = ("FINDINGS TO DEDUPLICATE:\n"
            + json.dumps(payload, indent=2))

    try:
        raw = prompt(
            user,
            model=cfg.models.dedup,
            system_prompt=SYSTEM,
            max_tokens=getattr(cfg.step7_dedup, "max_tokens", 8000),
            tag="s7 dedup",
        )
    except Exception as e:
        print(f"    [s7-dedup] semantic dedup call failed (non-fatal): "
              f"{redact(str(e))}", file=sys.stderr)
        _errlog.log("s7-dedup", "semantic", e)
        return []

    return _parse_dedup_output(raw, len(unresolved))


def _parse_dedup_output(raw: str, n: int) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for m in _LINE_RE.finditer(raw):
        idx = int(m.group(1))
        is_dup = m.group(2).lower() == "true"
        canon = int(m.group(3))
        why = m.group(4).strip()
        if not is_dup:
            continue
        if 0 <= canon < idx < n:
            out.append((idx, canon, why))
    return out


def _graph_context_for_finding(f: Finding, ctx: ContextPackage | None,
                               max_qnodes: int = 4,
                               max_edges_per_node: int = 5) -> dict:
    """Compact graph signature used by semantic dedup for root-cause grouping."""
    if ctx is None:
        return {"available": False}

    graph = ctx.call_graph or {}
    if not graph:
        return {"available": False}

    # Shared, call-graph-first resolution + one per-run reverse index, so the
    # deduper describes graph context identically to s6/s8.
    view = graph_view(ctx)
    cands = qnodes_at(view, f.file or "",
                      int(f.line_start or 1), int(f.line_end or f.line_start or 1),
                      limit=max_qnodes)
    around = neighborhood(view, cands, max_edges=max_edges_per_node)

    return {
        "available": True,
        "source_ref": f.source_ref,
        "sink_ref": f.sink_ref,
        "qnodes": cands,
        "around": around,
    }
