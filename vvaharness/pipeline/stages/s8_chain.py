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
Step 8 — the chain-analysis LLM sees ALL findings together and:
  1. Identifies multi-step exploit chains.
  2. Re-ranks individual findings by true exploitability + design controls.
  3. Checks if any new finding combines with a known unpatched CVE.

Single CLI call.
"""
from __future__ import annotations
import sys

from vvaharness.models import (ContextPackage, Finding, DroppedFinding, FinalReport,
                    RankedFinding, Chain, Severity, ScanMetrics)
from vvaharness.backends.llm import prompt
from vvaharness.util.json_extract import extract_json
from vvaharness.util.prompts import SEVERITY_GUIDANCE
from vvaharness.util import errlog as _errlog
from vvaharness.report.redact import redact
from vvaharness.pipeline.callgraph_consumer import graph_view, qnodes_at
from vvaharness.pipeline.stages.s1_preprocess import q_file

SYSTEM = f"""You are an exploit development strategist reviewing verified findings
that have ALREADY PASSED adversarial verification by a security expert. Each finding
carries a TRUE_POSITIVE verdict, confidence level, and CVSS vector — use this as
authoritative ground truth. Your job is NOT to re-verify bugs or judge exploitability
directly — it's to assess what an attacker can actually DO with these bugs TOGETHER,
and to rank them by chaining opportunity.

For each finding, reassess only the CHAIN potential given:
- Is it pre-auth or post-auth? (check design controls)
- Can a prior finding (or external source) supply input to this sink?
- Does a prior finding's output become this finding's input?
- What primitive does it give? (read, write, control flow, leak, DoS only)

Then look for CHAINS — combinations more dangerous than any single bug:
- Info leak + ASLR bypass + memory corruption = full chain
- UAF + type confusion = arbitrary write
- Logic flaw bypassing auth + post-auth bug = pre-auth exploit
- New finding + known unpatched CVE = combined attack
- Reachability: Finding #A flows to Finding #B via call-graph if they share
  function neighborhoods or data flow (check the "reachability" block per finding).

If a design control genuinely blocks a chain, say so and downrank it.

Rank each finding primarily by its CVSS base score (verifier already validated it):
- CRITICAL (9.0-10.0): likely a standalone problem needing immediate patching
- HIGH (7.0-8.9): serious but may be blocked by pre-auth, sandboxing, or require a chain
- MEDIUM (4.0-6.9): chaining or multi-stage is common; look for it
- LOW (0.1-3.9): useful only in chain or as a stepping stone
- INFO: no standalone or chained exploit path visible

Respond with ONLY a JSON object:
{{
  "summary": "Executive summary, 2-4 sentences.",
  "ranked_findings": [
    {{
      "index": 0,
      "severity": "critical|high|medium|low|info",
      "exploitability_notes": "Why this severity, what controls apply."
    }}
  ],
  "chains": [
    {{
      "title": "UAF -> arb write -> RCE",
      "steps": [2, 0, 5],
      "severity": "high",
      "blocked_by_controls": ["seccomp-sandbox"],
      "narrative": "Step-by-step explanation."
    }}
  ]
}}
The 'index' and 'steps' values are 0-based indices into the findings list."""


def _reachability_for_finding(f: Finding, ctx: ContextPackage) -> str:
    """Compact reachability signature for chaining: shows source/sink refs and
    candidate call-graph neighborhoods to help the chain LLM spot data flow."""
    graph = ctx.call_graph or {}
    if not graph:
        parts = []
        if f.source_ref:
            marker = " (inferred from AST, unverified)" if "source_ref" in f.backfilled_refs else ""
            parts.append(f"source={f.source_ref}{marker}")
        if f.sink_ref:
            marker = " (inferred from AST, unverified)" if "sink_ref" in f.backfilled_refs else ""
            parts.append(f"sink={f.sink_ref}{marker}")
        return " ".join(parts) if parts else "(no graph context)"

    # Shared, call-graph-first resolution + per-run reverse index, so the
    # chain builder, verifier and deduper agree on reachability for the same
    # finding.
    view = graph_view(ctx)
    cands = qnodes_at(view, f.file or "",
                      int(f.line_start or 1), int(f.line_end or f.line_start or 1),
                      limit=6)

    parts = []
    if f.source_ref:
        marker = " (inferred from AST, unverified)" if "source_ref" in f.backfilled_refs else ""
        parts.append(f"source={f.source_ref}{marker}")
    if f.sink_ref:
        marker = " (inferred from AST, unverified)" if "sink_ref" in f.backfilled_refs else ""
        parts.append(f"sink={f.sink_ref}{marker}")

    if cands:
        qn = cands[0]
        callers = (view.rev.get(qn) or [])[:3]
        callees = (graph.get(qn) or [])[:3]
        reachable = []
        if callers:
            reachable.append(f"called-by: {', '.join(callers[:2])}")
        if callees:
            reachable.append(f"calls: {', '.join(callees[:2])}")
        if reachable:
            parts.append("neighbors=" + "; ".join(reachable))

    return " ".join(parts) if parts else "(no reachability data)"


def run(findings: list[Finding], ctx: ContextPackage, cfg, *,
        dropped: list[DroppedFinding] | None = None,
        raw_findings_count: int = 0,
        metrics: ScanMetrics | None = None) -> FinalReport:
    dropped = dropped or []
    if not findings:
        return FinalReport(
            repo_root=ctx.repo_root,
            findings=[],
            chains=[],
            dropped=dropped,
            raw_findings_count=raw_findings_count,
            metrics=metrics,
            summary="No findings survived adversarial verification."
        )

    user = _build_prompt(findings, ctx)

    # the LLM call itself can fail (provider/network/timeout). s7_dedup
    # already degrades on Exception; mirror that here so the FINAL pipeline
    # step never crashes the run — emit an unranked report instead.
    try:
        raw = prompt(
            user,
            model=cfg.models.chain,
            system_prompt=SYSTEM,
            max_tokens=getattr(cfg.step8, "max_tokens", None),
            timeout=getattr(cfg.step8, "timeout", 1800),
            tag="s8 chain",
        )
    except Exception as e:  # provider errors are heterogeneous
        print(f"  [s8] WARN: chain LLM call failed ({redact(str(e))}); "
              f"emitting unranked report.", file=sys.stderr)
        _errlog.log("s8", "chain", e)
        return _unranked_report(
            ctx, findings, dropped, raw_findings_count, metrics,
            summary=f"Chain analysis call failed ({e}). "
                    f"{len(findings)} verified findings reported unranked.",
        )

    # Recoverability: persist the FULL raw chain response next to the
    # errors log BEFORE parsing, so a parse/hydration failure is salvageable
    # offline without re-spending the s8 call. Best-effort — never let a disk
    # error here crash the final pipeline step.
    try:
        errp = _errlog.current_path()
        stem = (errp.name[:-len("_errors.jsonl")]
                if errp.name.endswith("_errors.jsonl") else errp.stem)
        raw_path = errp.parent / f"{stem}_s8_raw.txt"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(redact(raw or ""), encoding="utf-8")
    except OSError as e:
        print(f"  [s8] WARN: could not persist raw chain response "
              f"({redact(str(e))})", file=sys.stderr)

    try:
        data = extract_json(raw)
        if isinstance(data, list):
            # extract_json may return a top-level array. Recover it only when the
            # elements are actually chain- or ranked-finding-shaped; otherwise
            # (scalars, leaked transport events) raise so we degrade cleanly.
            data = _coerce_list_payload(data)
        if not isinstance(data, dict):
            raise ValueError(f"expected JSON object, got {type(data).__name__}")
    except ValueError as e:
        head = redact((raw or "")[:500]).replace("\n", "\\n")
        tail = redact((raw or "")[-200:]).replace("\n", "\\n")
        print(f"  [s8] WARN: chain response not parseable ({redact(str(e))}); "
              f"emitting unranked report.", file=sys.stderr)
        _errlog.log("s8", "chain", e, raw_head=head, raw_tail=tail)
        print(f"  [s8] raw[:500]  = {head!r}", file=sys.stderr)
        print(f"  [s8] raw[-200:] = {tail!r}", file=sys.stderr)
        return _unranked_report(
            ctx, findings, dropped, raw_findings_count, metrics,
            summary=f"Chain analysis failed to parse ({e}). "
                    f"{len(findings)} verified findings reported unranked.",
        )

    # extract_json() only guarantees a dict — its *values* are
    # still attacker/model-controlled and may be off-schema (string index,
    # int severity, null lists, …). Pydantic before-validators protect the
    # model fields, but this hand-rolled hydration accesses raw values
    # directly, so wrap the whole block and degrade to an unranked report
    # rather than crashing the final step.
    try:
        report = _hydrate_report(
            data, ctx, findings, dropped, raw_findings_count, metrics)
    except Exception as e:  # hydration touches model JSON
        print(f"  [s8] WARN: chain hydration failed ({redact(str(e))}); "
              f"emitting unranked report.", file=sys.stderr)
        _errlog.log("s8", "chain-hydrate", e)
        return _unranked_report(
            ctx, findings, dropped, raw_findings_count, metrics,
            summary=f"Chain analysis hydration failed ({e}). "
                    f"{len(findings)} verified findings reported unranked.",
        )

    print(f"  [s8] done: {len(report.findings)} ranked findings, "
          f"{len(report.chains)} chains", file=sys.stderr)
    return report


def _coerce_list_payload(items: list) -> dict:
    """Map a top-level JSON array onto the chain-object schema when its elements
    are recognisably chains or ranked findings; raise ValueError otherwise.

    A bare array is off-schema, but the model occasionally emits ``[{chain},…]``
    or ``[{ranked},…]`` directly. Element-shape gating is mandatory: blindly
    wrapping an arbitrary array as ``{"chains": …}`` would feed junk (e.g. a
    leaked transport-event array) into hydration and yield a silently-empty
    report — worse than the visible unranked degrade.
    """
    dicts = [x for x in items if isinstance(x, dict)]
    if dicts and all(("steps" in x or "title" in x) for x in dicts):
        return {"chains": dicts}
    if dicts and all("index" in x for x in dicts):
        return {"ranked_findings": dicts}
    raise ValueError("top-level array is not chain- or ranked-finding-shaped")


def _unranked_report(ctx, findings, dropped, raw_findings_count, metrics,
                     *, summary: str) -> FinalReport:
    """Degraded fallback used ONLY when the exploit-chain pass could not be
    COMPUTED (LLM call / parse / hydration failure). Findings keep their
    CVSS-anchored severity band (environmental first, then base CVSS); they drop
    to INFO only when a finding has no vector at all. What is lost is the
    chain-pass exploitability ranking — not the severity. This is NOT used for a
    healthy scan that simply produced no chains (that is normal and rendered as
    'No exploit chains were identified')."""
    ranked = [RankedFinding(finding=f,
                            severity=_final_severity(f, Severity.INFO),
                            exploitability_notes="(chain analysis unavailable — "
                                                 "severity from CVSS only)")
              for f in findings]
    # Order the fallback the same way the hydrated report would, so CRITICAL/
    # HIGH surface at the top instead of in arbitrary input order.
    order = _severity_sort_order(ranked)
    ranked = [ranked[k] for k in order]
    # orig finding index -> post-sort position, to keep "DUP of #N" correct.
    orig_to_sorted = {orig: new_i for new_i, orig in enumerate(order)}
    # Remap on FRESH copies so the caller's shared `dropped` is never mutated.
    dropped_out = [
        d.model_copy(update={"canonical_idx": orig_to_sorted[d.canonical_idx]})
        if (d.reason == "DUPLICATE" and d.canonical_idx in orig_to_sorted)
        else d
        for d in dropped
    ]
    return FinalReport(
        repo_root=ctx.repo_root,
        findings=ranked,
        chains=[],
        dropped=dropped_out,
        raw_findings_count=raw_findings_count,
        metrics=metrics,
        summary=summary,
        degraded=True,
        degraded_reason=summary,
    )


def _hydrate_report(data: dict, ctx, findings, dropped,
                    raw_findings_count, metrics) -> FinalReport:
    # ── hydrate ranked findings ──────────────────────────────────────────
    # track the ORIGINAL finding index alongside each ranked
    # entry instead of recovering it later via list.index(). Finding is a
    # Pydantic model with value-based __eq__, so list.index() returns the
    # FIRST value-equal element and silently mis-maps when the LLM repeats
    # an index or two findings compare equal. enumerate() indices are exact.
    ranked: list[RankedFinding] = []
    ranked_orig_idx: list[int] = []
    covered: set[int] = set()
    # guard against present-but-null lists (data.get returns the
    # explicit None, which is not iterable).
    for item in data.get("ranked_findings") or []:
        if not isinstance(item, dict):
            continue
        idx = item.get("index")
        # type-guard idx BEFORE the `< 0` comparison — a string index
        # ("0") or other non-int raises TypeError under py3 ordered compare.
        if isinstance(idx, bool) or not isinstance(idx, int):
            continue
        if idx < 0 or idx >= len(findings) or idx in covered:
            continue
        covered.add(idx)
        ranked.append(RankedFinding(
            finding=findings[idx],
            # Anchor the label to the CVSS framework (environmental band first,
            # then base); the LLM's qualitative severity is only a fallback when
            # the finding has no CVSS vector at all.
            severity=_final_severity(findings[idx],
                                     _coerce_sev(item.get("severity"))),
            exploitability_notes=item.get("exploitability_notes", ""),
        ))
        ranked_orig_idx.append(idx)

    for i, f in enumerate(findings):
        if i not in covered:
            ranked.append(RankedFinding(
                finding=f,
                severity=_final_severity(f, Severity.INFO),
                exploitability_notes="(not ranked by chaining pass)"
            ))
            ranked_orig_idx.append(i)

    # Sort (ranked, orig_idx) pairs together so the orig-index mapping
    # survives the reorder without any value-based identity lookup. Within a
    # severity band, OffensivePriority (reachability) breaks ties: P1 first.
    order = _severity_sort_order(ranked)
    ranked = [ranked[k] for k in order]
    ranked_orig_idx = [ranked_orig_idx[k] for k in order]

    orig_to_sorted = {orig: new_i
                      for new_i, orig in enumerate(ranked_orig_idx)}

    # ── hydrate chains ───────────────────────────────────────────────────
    chains: list[Chain] = []
    for item in data.get("chains") or []:
        if not isinstance(item, dict):
            continue
        raw_steps = item.get("steps") or []
        if not isinstance(raw_steps, list):
            raw_steps = []

        def _valid_step(s) -> bool:
            # An int (not bool) that maps to a finding in the verified set.
            return isinstance(s, int) and not isinstance(s, bool) and s in orig_to_sorted

        remapped = [orig_to_sorted[s] for s in raw_steps if _valid_step(s)]
        if len(remapped) < 2:
            continue
        narrative = item.get("narrative", "") or ""
        # Only integer indices pointing outside the verified set are meaningful
        # "dropped" references; non-int junk from the model is omitted entirely
        # and the list is capped, so a malformed/oversized steps[] can't balloon
        # the narrative with a raw repr.
        dropped_steps = [s for s in raw_steps
                         if isinstance(s, int) and not isinstance(s, bool)
                         and s not in orig_to_sorted]
        if dropped_steps:
            shown = dropped_steps[:20]
            extra = "" if len(dropped_steps) <= 20 else f" (+{len(dropped_steps) - 20} more)"
            narrative = (f"{narrative}\n\n_Note: this chain referenced finding "
                         f"indices {shown}{extra} that were not in the verified "
                         "set; they have been omitted from the path above._"
                         ).strip()
        blocked = item.get("blocked_by_controls") or []
        if not isinstance(blocked, list):
            blocked = []
        chains.append(Chain(
            title=item.get("title", "Unnamed chain") or "Unnamed chain",
            steps=remapped,
            severity=_coerce_sev(item.get("severity")),
            blocked_by_controls=blocked,
            narrative=narrative,
        ))

    # Remap duplicate canonical_idx so "DUP of #N" matches post-sort order.
    # Build FRESH copies rather than mutating the shared `dropped` list in place:
    # if a later step here raises (e.g. an off-schema summary), the caller's
    # exception fallback must still see the ORIGINAL canonical_idx values.
    dropped_out = [
        d.model_copy(update={"canonical_idx": orig_to_sorted[d.canonical_idx]})
        if (d.reason == "DUPLICATE" and d.canonical_idx in orig_to_sorted)
        else d
        for d in dropped
    ]

    return FinalReport(
        repo_root=ctx.repo_root,
        findings=ranked,
        chains=chains,
        dropped=dropped_out,
        raw_findings_count=raw_findings_count,
        metrics=metrics,
        # Coerce an off-schema (non-string) summary to "" — never its repr — so
        # a stray dict/list/number from the model can't raise ValidationError
        # here (which would land in the fallback with findings already reordered).
        summary=(data.get("summary") if isinstance(data.get("summary"), str) else ""),
    )


def _build_prompt(findings: list[Finding], ctx: ContextPackage) -> str:
    blocks = []
    for i, f in enumerate(findings):
        cvss = f.cvss_vector or "n/a"
        verified = (f"{f.verdict} {f.verdict_confidence}/10"
                    if f.verdict else "unverified")
        reachability = _reachability_for_finding(f, ctx)
        blocks.append(
            f"[{i}] {f.vuln_class.value} @ {f.file}:{f.line_start}-{f.line_end}\n"
            f"    Title: {f.title}\n"
            f"    CVSS: {cvss}  |  Verified: {verified}\n"
            f"    Confidence: {f.confidence:.2f} ({f.votes} runs agreed)\n"
            f"    {f.description}\n"
            f"    Reachability: {reachability}\n"
        )
    findings_block = "\n".join(blocks)

    controls_block = "\n".join(
        f"  - [{c.kind}] {c.name} -> protects: {', '.join(c.protects) or 'global'}"
        for c in ctx.design_controls
    ) or "  (none)"

    cve_block = "\n".join(
        f"  - {c.id} (CVSS {c.cvss}, {'patched' if c.patched else 'UNPATCHED'}): {c.summary}"
        for c in ctx.known_cves
    ) or "  (none)"

    tm_block = ""
    if ctx.app_profile:
        tm_block += ctx.app_profile.to_prompt_block() + "\n"
    if ctx.threat_model:
        tm_block += ctx.threat_model.to_prompt_block() + "\n"

    return f"""REPO: {ctx.repo_root}

{tm_block}DESIGN CONTROLS:
{controls_block}

KNOWN CVEs (check for combinations with new findings):
{cve_block}

FINDINGS (indices are 0-based):
{findings_block}

Analyze and respond with ONLY the JSON object."""


_CVSS_BAND_TO_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _sev_from_band(rating: str | None) -> Severity | None:
    """Map a CVSS qualitative band string ("Critical"/"High"/...) to a Severity,
    or None for a missing band ("None"/"Unknown"/None) so the caller can fall
    through to the next, less-contextual source."""
    return _CVSS_BAND_TO_SEV.get((rating or "").strip().lower())


def _final_severity(finding, llm_label: Severity) -> Severity:
    """Reconcile a finding's reported severity to the CVSS framework, most-
    contextual band first (CVSS 3.1):
      1. VulContextSeverity (environmental: CR/IR/AR + MAV + SAST temporal) —
         authoritative when an app/CMDB profile is present;
      2. else the base CVSS band;
      3. else the chaining LLM's qualitative label (only when no vector exists).
    OffensivePriority is a SEPARATE exploitability axis (see _offensive_rank)
    and is deliberately NOT folded into the severity band."""
    return (_sev_from_band(getattr(finding, "vsvs_rating", None))
            or _sev_from_band(getattr(finding, "cvss_rating", None))
            or llm_label)


def _offensive_rank(finding) -> int:
    """OffensivePriority as a secondary sort key (P1 first, unset last). Kept
    orthogonal to severity — it ranks reachability/exploitability, not impact."""
    op = (getattr(finding, "offensive_priority", None) or "").strip().upper()
    return int(op[1]) if len(op) == 2 and op[0] == "P" and op[1].isdigit() else 9


_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
              Severity.LOW: 3, Severity.INFO: 4}


def _severity_sort_order(ranked: list[RankedFinding]) -> list[int]:
    """Index permutation ordering `ranked` by severity band, then
    OffensivePriority (P1 first) as the tie-break. Shared by the hydrated report
    and the degraded fallback so CRITICAL/HIGH always surface at the top."""
    return sorted(range(len(ranked)),
                  key=lambda k: (_SEV_ORDER[ranked[k].severity],
                                 _offensive_rank(ranked[k].finding)))


def _coerce_sev(s) -> Severity:
    if not s:
        return Severity.INFO
    key = str(s).strip().lower()
    try:
        return Severity(key)
    except ValueError:
        return Severity.INFO
