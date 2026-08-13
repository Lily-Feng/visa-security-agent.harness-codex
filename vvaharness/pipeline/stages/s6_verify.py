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
Step 6 — Adversarial verification.

For every finding that survived the s4 vote, spawn a fresh agentic Claude
session inside the target repo with Read/Grep tools. The verifier's job is to
PROVE THE FINDING WRONG: re-read the source, trace callers, hunt for upstream
protections, and emit a TRUE_POSITIVE / FALSE_POSITIVE verdict + CVSS 3.1
vector.

Only TRUE_POSITIVE findings continue to s7. FALSE_POSITIVEs are recorded as
DroppedFinding entries for the audit trail.
"""
from __future__ import annotations
import fnmatch
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)

from vvaharness.models import ContextPackage, Finding, DroppedFinding
from vvaharness.backends.llm import agentic
from vvaharness.util.prompts import EXCLUSION_RULES
from vvaharness.report.cvss import score as cvss_score, rating as cvss_rating
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.backends import llm as cli
from vvaharness.backends.claude_cli import GuardrailBlocked
from vvaharness.pipeline.callgraph_consumer import graph_view, qnodes_at
from vvaharness.pipeline.stages.s1_preprocess import q_file


_CVSS_RE = re.compile(
    # Accept both CVSS:3.0 and CVSS:3.1 vectors — the downstream scorer
    # (report/cvss.py _VECTOR_RE) accepts CVSS:3.[01], so requiring exactly
    # 3.1 here silently dropped well-formed 3.0 vectors.
    r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
    r"C:[NLH]/I:[NLH]/A:[NLH]"
)
_VERDICT_RE = re.compile(
    r"VERDICT:\s*(TRUE_POSITIVE|FALSE_POSITIVE)\s*"
    r"\(confidence:\s*(\d{1,2})\s*/\s*10\)\s*[—\-–]?\s*(.*)",
    re.IGNORECASE,
)

SYSTEM = f"""You are the second-opinion reviewer in a SAST pipeline. A scanner
has produced the finding below; assume it is WRONG until you have personally
confirmed it in the source. Your only output that matters is a
TRUE_POSITIVE / FALSE_POSITIVE verdict plus a CVSS vector.

Tools available: Read, Glob, Grep. Use them — do not reason from the snippet
alone.

WORKFLOW
  A. Start from the CALL GRAPH CONTEXT section in the user prompt (it is
      SQLite-backed graph metadata from prior stages). Validate those edges
      in code with Grep/Read; do not assume they are perfect.
  B. Open the cited file at the cited line. Establish what the code really
      does (the scanner's description is a claim, not evidence).
  C. Walk the call chain outward: follow callers/callees from graph context,
      then verify each hop in source. Continue backward until you reach an
      external entry point or run out of callers. No external entry point →
      not exploitable.
  D. Try to kill the finding. Look specifically for: input validation or
     allow-lists earlier in the flow; framework-level encoding /
     parameterisation; type or length constraints; auth/authz gates in front
     of the route; feature flags or config that disable the path in prod;
     the code being test-only or simply never invoked.
  E. If you found a defence in (D), probe it: does it cover every route into
     the sink, or only the one you happened to read? Can edge-case input
     (encoding tricks, nulls, oversized values) slip past it?

If the call graph is sparse/ambiguous for this finding, say that clearly and
fall back to broader code-led verification (imports, router wiring, dispatch,
and upstream callers discovered via Grep). Missing graph edges are NOT enough
to refute a finding by themselves.

{EXCLUSION_RULES}

DECISION RULE
  TRUE_POSITIVE  — only when (B) reached an external/lower-privileged entry
                   point AND (C)/(D) found no defence that fully closes the
                   path AND the impact is real, not hypothetical.
  FALSE_POSITIVE — any one of: no external caller; an upstream control fully
                   neutralises the input; the scanner mis-read the code
                   (wrong sink, wrong class, wrong file).

Confidence 8–10 means you actively searched for the opposite verdict and
could not support it. Confidence ≤5 means you are guessing — say so.

═══════════════════════════════════════════════════════════════════════════
CVSS 3.1 BASE VECTOR — required on the line directly after VERDICT
═══════════════════════════════════════════════════════════════════════════
  AV  N network · A adjacent · L local · P physical
  AC  L trivial · H needs race/MITM/unusual state
  PR  N none · L any authenticated user · H admin/operator
  UI  N none · R victim must act
  S   U same component · C crosses a security boundary
  C/I/A  H full · L limited · N none

Score the vector against the claimed impact even when returning
FALSE_POSITIVE (it feeds severity calibration downstream).

Last two lines of your reply MUST match exactly:
VERDICT: TRUE_POSITIVE|FALSE_POSITIVE (confidence: N/10) — brief reason
CVSS: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_"""


def run(findings: list[Finding], ctx: ContextPackage, cfg
        ) -> tuple[list[Finding], list[DroppedFinding]]:
    """Verify every finding. Returns (verified, dropped)."""
    log.info("s6/verify: starting verification - findings=%d", len(findings))
    if not findings:
        log.info("s6/verify: no findings to verify")
        return [], []

    parallel = getattr(cfg.step6_verify, "parallel", 4)
    min_conf = getattr(cfg.step6_verify, "min_confidence", 7)
    print(f"  [s6-verify] verifying {len(findings)} findings "
          f"({parallel} parallel, gate≥{min_conf}/10)...", file=sys.stderr)

    verified: list[Finding] = []
    dropped: list[DroppedFinding] = []
    guardrail_hits = 0
    guardrail_gate = max(3, parallel)

    ex = ThreadPoolExecutor(max_workers=parallel)
    futs = {ex.submit(_verify_one, i, f, ctx, cfg): (i, f)
            for i, f in enumerate(findings)}
    try:
        for fut in as_completed(futs):
            i, f = futs[fut]
            try:
                f2 = fut.result()
            except GuardrailBlocked as e:
                guardrail_hits += 1
                print(f"    [s6-verify] #{i} GUARDRAIL-BLOCKED "
                      f"({guardrail_hits}/{guardrail_gate})", file=sys.stderr)
                _errlog.log("s6-verify", f"guardrail#{i}", e,
                            file=getattr(f, "file", None),
                            line=getattr(f, "line_start", None))
                dropped.append(_drop(f, "GUARDRAIL_BLOCKED", str(e)[:200]))
                if guardrail_hits >= guardrail_gate and not verified:
                    cli.abort()
                    ex.shutdown(wait=False, cancel_futures=True)
                    raise RuntimeError(
                        f"s6-verify: {guardrail_hits} cumulative guardrail "
                        "blocks with zero successes — aborting run.") from e
                continue
            except Exception as e:
                print(f"    [s6-verify] #{i} verify ERROR: {redact(str(e))}", file=sys.stderr)
                _errlog.log("s6-verify", f"#{i}", e,
                            file=getattr(f, "file", None),
                            line=getattr(f, "line_start", None),
                            vuln_class=str(getattr(f, "vuln_class", "")))
                dropped.append(_drop(f, "VERIFY_ERROR", str(e)[:200]))
                continue
            if f2.verdict == "TRUE_POSITIVE" and (f2.verdict_confidence or 0) >= min_conf:
                verified.append(f2)
            elif f2.verdict == "TRUE_POSITIVE":
                dropped.append(_drop(f2, "UNCONFIRMED",
                                     f"verifier confidence {f2.verdict_confidence}/10 "
                                     f"below gate {min_conf}"))
            elif (f2.verdict_reason == "verifier output unparseable"
                  and (f2.verdict_confidence or 0) == 0):
                # An unparseable verifier reply (no VERDICT line) is an
                # *undetermined* result, not a confirmed FALSE_POSITIVE.
                # Laundering it into the FP bucket understated true risk and
                # skewed the precision metric — record it as VERIFY_ERROR so a
                # flaky/truncated verification is visible, not silently "clean".
                dropped.append(_drop(f2, "VERIFY_ERROR", f2.verdict_reason))
            else:
                dropped.append(_drop(f2, "FALSE_POSITIVE", f2.verdict_reason))
    except KeyboardInterrupt:
        n = cli.abort()
        print(f"  [s6-verify] interrupted — killed {n} running verifier "
              f"process(es), cancelling {sum(1 for f in futs if not f.done())} "
              f"pending", file=sys.stderr)
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        ex.shutdown(wait=True)

    tp = len(verified)
    fp = sum(1 for d in dropped if d.reason == "FALSE_POSITIVE")
    unc = sum(1 for d in dropped if d.reason == "UNCONFIRMED")
    gb = sum(1 for d in dropped if d.reason == "GUARDRAIL_BLOCKED")
    errs = len(dropped) - fp - unc - gb
    print(f"  [s6-verify] done: {tp} TRUE_POSITIVE, {fp} FALSE_POSITIVE, "
          f"{unc} UNCONFIRMED, {gb} GUARDRAIL_BLOCKED, {errs} errors",
          file=sys.stderr)
    log.info("s6/verify: verification complete - tp=%d fp=%d unconfirmed=%d guardrail=%d errors=%d",
             tp, fp, unc, gb, errs)
    return verified, dropped


def _verify_one(idx: int, f: Finding, ctx: ContextPackage, cfg) -> Finding:
    if cli.aborted():
        raise RuntimeError("aborted by user (Ctrl-C)")
    user = _build_user_prompt(f, ctx)
    tools = getattr(cfg.step6_verify, "allowed_tools", None) or ["Read", "Glob", "Grep"]

    raw = agentic(
        user,
        model=cfg.models.verify,
        system_prompt=SYSTEM,
        allowed_tools=list(tools),
        cwd=ctx.repo_root,
        max_budget_usd=getattr(cfg.step6_verify, "max_budget_usd", 1.0),
        max_turns=getattr(cfg.step6_verify, "max_turns", None),
        tag=f"s6 verify#{idx}",
    )

    verdict, conf, reason, cvss, reasoning = _parse_verdict(raw)
    if reason == "verifier output unparseable":
        _errlog.log("s6-verify", f"unparseable#{idx}",
                    "no VERDICT line in verifier output",
                    file=f.file, line=f.line_start,
                    raw_len=len(raw or ""), raw=(raw or "")[:600])
        print(f"    [s6-verify] #{idx} UNPARSEABLE raw[:200]="
              f"{(raw or '')[:200]!r}", file=sys.stderr)
    s = cvss_score(cvss)
    print(f"    [s6-verify] #{idx} {f.file}:{f.line_start} → {verdict} "
          f"({conf}/10) cvss={s if s is not None else '-'}", file=sys.stderr)

    return f.model_copy(update={
        "verdict": verdict,
        "verdict_confidence": conf,
        "verdict_reason": reason,
        "cvss_vector": cvss,
        "cvss_score": s,
        "cvss_rating": cvss_rating(s) if s is not None else None,
        "verifier_reasoning": reasoning,
    })


def _controls_for(file: str, ctx: ContextPackage) -> list[str]:
    out = []
    for c in ctx.design_controls:
        hit = not c.protects or any(fnmatch.fnmatch(file, g) for g in c.protects)
        if hit:
            note = f" — {c.notes}" if c.notes else ""
            out.append(f"  - [{c.kind}] {c.name} protects this path{note}")
    return out


def _callers_of(file: str, ctx: ContextPackage, limit: int = 15) -> list[str]:
    out = []
    for caller, callees in ctx.call_graph.items():
        if any(q_file(cal) == file or q_file(cal).endswith("/" + file)
               for cal in callees):
            out.append(f"  - {caller}")
            if len(out) >= limit:
                break
    return out


def _candidate_qnodes_for_finding(f: Finding, ctx: ContextPackage,
                                  limit: int = 6) -> list[str]:
    """Best-effort qnodes for the finding location.

    Uses the shared, call-graph-first resolver: spans corroborate the precise
    function, the call graph's file membership is the fallback.
    """
    return qnodes_at(graph_view(ctx), f.file or "",
                     int(f.line_start or 1), int(f.line_end or f.line_start or 1),
                     limit=limit)


def _callgraph_context_for_finding(f: Finding, ctx: ContextPackage) -> str:
    graph = ctx.call_graph or {}
    if not graph:
        return "CALL GRAPH CONTEXT (sqlite-hydrated): (none available)"

    cands = _candidate_qnodes_for_finding(f, ctx)
    rev = graph_view(ctx).rev

    lines = [
        "CALL GRAPH CONTEXT (sqlite-hydrated; validate each edge with Grep/Read):",
        f"  - graph nodes: {len(graph)}",
        f"  - graph edges: {sum(len(v or ()) for v in graph.values())}",
    ]
    if f.source_ref:
        marker = " (inferred from AST, unverified)" if "source_ref" in f.backfilled_refs else ""
        lines.append(f"  - finding.source_ref: {f.source_ref}{marker}")
    if f.sink_ref:
        marker = " (inferred from AST, unverified)" if "sink_ref" in f.backfilled_refs else ""
        lines.append(f"  - finding.sink_ref: {f.sink_ref}{marker}")

    if not cands:
        lines.append("  - candidate functions at finding location: (none)")
        lines.append("  - action: use Grep on file/class symbols to recover callers/callees from code")
        return "\n".join(lines)

    lines.append("  - candidate functions at/near finding line:")
    for qn in cands:
        lines.append(f"    - {qn}")

    for qn in cands:
        callers = rev.get(qn, [])[:8]
        callees = (graph.get(qn) or [])[:8]
        lines.append(f"  - around {qn}:")
        if callers:
            for c in callers:
                lines.append(f"    - caller -> {c} -> {qn}")
        else:
            lines.append("    - caller -> (none in graph)")
        if callees:
            for c in callees:
                lines.append(f"    - callee -> {qn} -> {c}")
        else:
            lines.append("    - callee -> (none in graph)")

    return "\n".join(lines)


def _build_user_prompt(f: Finding, ctx: ContextPackage) -> str:
    pre = "\n".join(f"  - {p}" for p in f.preconditions) or "  (none listed)"

    eps = [f"  - {e.kind}: {e.function} @ {e.file}"
           f"{' [UNAUTH-REACHABLE]' if e.reachable_from_unauth else ''}"
           for e in ctx.entry_points]
    ep_block = ("KNOWN EXTERNAL ENTRY POINTS (from architecture scan):\n"
                + "\n".join(eps[:25])
                + ("\n  ...(+%d more)" % (len(eps) - 25) if len(eps) > 25 else "")
                ) if eps else ""

    callers = _callers_of(f.file, ctx)
    cg_block = ("KNOWN CALLERS OF THIS FILE (from call graph — verify with Grep):\n"
                + "\n".join(callers)) if callers else ""
    cg_focus = _callgraph_context_for_finding(f, ctx)

    controls = _controls_for(f.file, ctx)
    ctl_block = ("DESIGN CONTROLS IN EFFECT ON THIS PATH:\n"
                 + "\n".join(controls)
                 + "\nYou MUST demonstrate a bypass of these controls to return "
                   "TRUE_POSITIVE. If the control fully mitigates the finding, "
                   "return FALSE_POSITIVE.") if controls else ""

    notes_block = (f"ARCHITECTURE NOTES:\n{ctx.notes}") if ctx.notes else ""

    arch = "\n\n".join(b for b in (cg_focus, ep_block, cg_block, ctl_block, notes_block) if b)

    return f"""FINDING TO VERIFY:
File: {f.file}
Line: {f.line_start}-{f.line_end}
Category: {f.vuln_class.value}
Title: {f.title}

Description:
{f.description}

Exploit scenario:
{f.exploit_scenario or "(not provided)"}

Preconditions:
{pre}

Code snippet (as reported by scanner — verify against actual file):
{f.code_snippet}

═══════════════════════════════════════════════════════════════════════════
ARCHITECTURE CONTEXT (from prior repo analysis and sqlite callgraph — use as starting points,
but VERIFY against actual code; this may be incomplete or stale):
═══════════════════════════════════════════════════════════════════════════
{arch or "(none captured)"}

Investigate using Read/Grep. Start with CALL GRAPH CONTEXT, and if it is
ambiguous/incomplete for this finding, expand to broader code-led tracing.
Then end with the two required VERDICT and CVSS lines."""


def _parse_verdict(raw: str) -> tuple[str, int, str, str | None, str]:
    """Return (verdict, confidence, reason, cvss_vector|None, reasoning_body)."""
    lines = raw.strip().splitlines()

    verdict, conf, reason = "FALSE_POSITIVE", 0, "verifier output unparseable"
    verdict_line_idx = len(lines)
    for i in range(len(lines) - 1, -1, -1):
        m = _VERDICT_RE.search(lines[i])
        if m:
            verdict = m.group(1).upper()
            conf = max(0, min(10, int(m.group(2))))
            reason = m.group(3).strip() or "(no reason given)"
            verdict_line_idx = i
            break

    cvss = None
    tail = "\n".join(lines[verdict_line_idx:])
    m = _CVSS_RE.search(tail)
    if not m:
        matches = list(_CVSS_RE.finditer(raw))
        m = matches[-1] if matches else None
    if m:
        cvss = m.group(0)

    reasoning = "\n".join(lines[:verdict_line_idx]).strip()
    return verdict, conf, reason, cvss, reasoning


def _drop(f: Finding, reason: str, detail: str) -> DroppedFinding:
    return DroppedFinding(
        file=f.file,
        line=f.line_start,
        vuln_class=f.vuln_class,
        title=f.title,
        chunk_id=f.chunk_id,
        reason=reason,
        detail=detail,
    )
