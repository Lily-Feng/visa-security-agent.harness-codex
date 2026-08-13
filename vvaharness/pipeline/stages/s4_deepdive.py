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
Step 4 — Deep-dive each chunk N times, then majority-vote.

Temperature: when `models.deepdive.via` is `sdk` or `openai` AND the config
node sets `temperature`, the dispatcher passes that value through (see
backends/llm.py `resolve()`/`prompt()`), so each run samples differently and
the vote means something. The code supplies NO temperature default: if the
config omits `temperature`, none is sent and the provider's own default
applies. When `via == cli`, the CLI has no --temperature flag and the kwarg
is dropped — diversity is lower, expect tighter agreement.

Voting is effectively DISABLED by default. The shipped profile pins
`models.deepdive` to a model that rejects an explicit `temperature` (Opus
4.7+/Sonnet 4.5+/Haiku 4.5+; see backends/sdk._supports_temperature), so
`_effective_runs()` collapses runs/vote_threshold to 1/1 — N identical-temp
runs would just be N copies of one output (N× cost, 0 filtering). To enable
real majority voting, point `models.deepdive` at a temperature-capable model
(e.g. Opus 4.6 / Sonnet 4.6 / Haiku 4.5) AND set `temperature: 1.0` on that
node. The s5 prefilter + s6 verifier are the FP defence when voting is off.
"""
from __future__ import annotations
import logging
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

log = logging.getLogger(__name__)

from vvaharness.models import Chunk, ChunkSize, ContextPackage, Finding, VulnClass
from vvaharness.backends.llm import prompt, resolve
from vvaharness.report.redact import redact_counts, redact, _luhn
from vvaharness.util.json_extract import extract_json
from vvaharness.util import errlog as _errlog
from vvaharness.backends import claude_cli as cli
from vvaharness.backends.claude_cli import GuardrailBlocked
from vvaharness.backends.sdk import _supports_temperature
from vvaharness.util.prompts import (EXCLUSION_RULES, SELF_VERIFICATION,
                            SEVERITY_GUIDANCE, EXHAUSTIVENESS)
from vvaharness.lang.hints import hints_for, LANG_DISPLAY
from vvaharness.pipeline.stages.s1_preprocess import q_file, q_name
from vvaharness.rules import CweKB

_QUALITY_BAR = """\
QUALITY BAR:
- Trace data flow: WHERE untrusted input enters → HOW it reaches the dangerous
  operation. No confirmed data flow = no finding.
- Verify reachability from external input (not dead code, not test-only).
- Check for upstream protections (validation, sanitization, framework
  safeguards) BEFORE reporting.
- Write a concrete exploit: specific input, specific impact. If you can't,
  drop the finding.

For each file, trace the logic — don't just scan for patterns:
- What does the code assume about its inputs?
- What happens at boundary conditions?
- Are there check-then-act patterns where state could change between check
  and action?
- Do error paths leak state or skip validation?

CROSS-CUTTING (applies to docs/config/non-code files in your scope too):
- Insecure-transport directives committed to the repo (CWE-295): grep your
  scope for sslVerify=false, SSL_VERIFY_NONE, verify=False, verify_ssl: false,
  rejectUnauthorized: false, InsecureSkipVerify, NODE_TLS_REJECT_UNAUTHORIZED=0,
  curl -k / --insecure, TrustAllCerts, ALLOW_ALL_HOSTNAME_VERIFIER. A README
  or setup script that INSTRUCTS users to disable TLS verification is a
  reportable supply-chain finding even though it is not executable code.
- Output-side injection: data the program WRITES (CSV cells, HTML reports,
  log lines later parsed by another tool) is a sink. Hunt for unescaped
  emission, not just unescaped ingestion."""

_OUTPUT_SCHEMA = """\
Respond with ONLY a JSON object (no prose before or after):
{
  "findings": [
    {
      "file": "src/parser.c",
      "line_start": 142,
      "line_end": 158,
      "vuln_class": "heap-overflow|use-after-free|stack-overflow|format-string|integer-overflow|type-confusion|race-condition|injection|unsafe-deserialization|logic-flaw|info-leak|other",
      "cwe": "CWE-79  (single most-specific CWE id; omit if no clear mapping)",
      "title": "Under 12 words",
      "impact": "2-3 plain-language sentences: what an attacker gains, who is affected, why it matters",
      "description": "Detailed input-to-bug data flow explanation",
      "exploit_scenario": "Max 5 sentences: the specific input the attacker sends and the resulting impact",
      "preconditions": ["condition 1", "condition 2"],
      "recommendation": "Security property that must hold + specific location in THIS code and what to change",
      "code_snippet": "the vulnerable lines",
      "source_ref": "src/api/Controller.java:71   (where untrusted input enters; same as sink_ref for context-free bugs like hardcoded secrets)",
      "sink_ref": "src/parser.c:148   (where that input is used unsafely)",
      "confidence": 0.85
    }
  ]
}

An empty {"findings": []} is acceptable ONLY after you have traced every
entry point, every sink, and every cross-cutting pattern above and confirmed
each is mitigated or unreachable — never as a default. Assume at least one
exploitable defect is present in the slice."""


SYSTEM = "\n\n".join([
    "You are a security researcher performing deep code analysis. You receive "
    "source code for a focused slice of a repository plus a research lens "
    "(language/specialist hints) and a hypothesis from a strategist.",
    "Treat the slice as hostile: assume at least one exploitable defect is "
    "present and do not stop until every line and data flow has been examined.",
    _QUALITY_BAR,
    EXCLUSION_RULES,
    SELF_VERIFICATION,
    SEVERITY_GUIDANCE,
    EXHAUSTIVENESS,
    _OUTPUT_SCHEMA,
])


def build_research_lens(chunk: Chunk, code: str | None = None) -> str:
    """Per-chunk language/specialist guidance — lives in the USER prompt so the
    SYSTEM block stays byte-identical across all s4 calls and the sdk
    cache_control marker hits on every call after the first."""
    hints = hints_for(chunk.languages, chunk.specialist, code=code)
    if chunk.specialist:
        header = hints or f"You are a {chunk.specialist} specialist."
    else:
        lang_label = " / ".join(LANG_DISPLAY.get(l, l) for l in chunk.languages[:3]) \
                     or "this codebase"
        header = f"Research lens: {lang_label} security researcher."
        if hints:
            header += f"\n\n{hints}"
    return header


def build_system_prompt(chunk: Chunk) -> str:  # noqa: ARG001 — back-compat shim
    return SYSTEM

# Sliding window for LARGE chunks
WINDOW_LINES = 600
WINDOW_OVERLAP = 100
# Per-line character cap. A minified/single-line file would otherwise become one
# enormous "line" that bypasses WINDOW_LINES and blows the prompt/token budget.
# This caps per-line SIZE only; it does not re-window a single huge line.
MAX_LINE_CHARS = 8000

# Deprecated override: taint chunks now use models.deepdive like other chunk
# kinds. Keep reading step4.taint_model only to emit a one-time warning so
# legacy profiles fail soft instead of surprising users with hidden routing.
_TAINT_MODEL_WARNED = False
_DEF_SPANS_ABSENT_WARNED = False


def _effective_runs(cfg) -> tuple[int, int]:
    """
    Voting only filters noise when runs sample differently. The CLI backend
    has no temperature flag, and Opus 4.7+ / Sonnet 5+ / Haiku 5+ on SDK
    reject `temperature` outright — N identical-temp runs ≈ N copies of the
    same output → N× cost, 0 filtering. Degrade to 1/1 in those cases and
    warn once.
    """
    runs = cfg.step4.runs
    threshold = cfg.step4.vote_threshold
    if runs < 1:
        print(f"  [s4] WARN: invalid runs={runs}; forcing runs=1, "
              "vote_threshold=1.", file=sys.stderr)
        return 1, 1
    model_id, via, extras = resolve(cfg.models.deepdive)
    if via == "cli" and runs > 1:
        print(f"  [s4] WARN: models.deepdive.via={via!r} has no temperature control; "
              f"forcing runs=1, vote_threshold=1 (was {runs}/{threshold}). "
              f"Set via: sdk or via: openai to enable majority voting.",
              file=sys.stderr)
        return 1, 1
    if via == "sdk" and runs > 1 and not _supports_temperature(model_id):
        # The shipped default (claude-opus-4-8) lands here: voting is disabled
        # by design. This is NOT a silent scan-behaviour change — runs/vote
        # were already config-overridable and we warn loudly once per scan so
        # the operator can opt into a temperature-capable model if they want
        # real voting. See the module docstring for the rationale.
        print(f"  [s4] WARN: model {model_id!r} rejects `temperature` — "
              f"runs={runs} would produce identical samples, voting filters "
              f"nothing. Forcing runs=1, vote_threshold=1. Use Opus 4.6 / "
              f"Sonnet 4.6 / Haiku 4.5 with temperature: 1.0 if you want "
              f"voting on s4.", file=sys.stderr)
        return 1, 1
    # `temperature` omitted (not in extras) is NOT the same as temperature=0:
    # only warn about identical samples when the config EXPLICITLY pins temp 0.
    # When it is simply unset, the provider applies its own (non-zero) default
    # and runs do still diverge — esp. via:openai.
    if via != "cli" and runs > 1 and "temperature" in extras \
            and extras["temperature"] == 0:
        print(f"  [s4] WARN: runs={runs} but temperature=0 — runs will be identical. "
              f"Set temperature: 1.0 on models.deepdive.", file=sys.stderr)
    # vote_threshold must be reachable: a threshold > effective runs means NO
    # finding can ever accumulate enough votes and _deepdive_chunk silently
    # drops everything. Clamp down to runs and warn.
    if threshold > runs:
        print(f"  [s4] WARN: vote_threshold={threshold} exceeds runs={runs}; "
              f"no finding could survive the vote — clamping vote_threshold to "
              f"{runs}.", file=sys.stderr)
        threshold = runs
    if threshold < 1:
        threshold = 1
    return runs, threshold


def run(manifest_chunks: list[Chunk], ctx: ContextPackage, cfg
        ) -> tuple[list[Finding], dict[str, str]]:
    """Process every chunk.

    Returns ``(findings, outcomes)`` where ``outcomes`` maps each chunk id to
    ``"completed"`` / ``"error"`` / ``"guardrail"`` so the report can disclose
    coverage loss and distinguish a failed/timed-out chunk (which yields no
    findings) from a clean chunk that simply found nothing."""
    log.info("s4/deepdive: starting deep-dive analysis - chunks=%d", len(manifest_chunks))
    tracker = getattr(cfg, "_scan_progress", None)
    repo_root = Path(ctx.repo_root)
    chunks = sorted(manifest_chunks, key=lambda c: c.risk_rank)
    parallel = getattr(cfg.step4, "parallel", 1)
    runs_n, threshold = _effective_runs(cfg)

    def _label(chunk: Chunk) -> None:
        lens = chunk.specialist or "+".join(chunk.languages[:3]) or "generic"
        h = chunk.hypothesis
        print(f"  [s4] chunk {chunk.id} ({chunk.size.value}, rank {chunk.risk_rank}, "
              f"lens={lens}): {h[:120]}{'…' if len(h) > 120 else ''}",
              file=sys.stderr)

    guardrail_hits = 0
    guardrail_gate = max(3, parallel)
    successes = 0
    outcomes: dict[str, str] = {}   # chunk id -> "completed"|"error"|"guardrail"

    def _guardrail_fail_fast(e: GuardrailBlocked) -> None:
        raise RuntimeError(
            f"s4-deepdive: {guardrail_hits} guardrail blocks with zero "
            "successful chunks — aborting run. The CLI/OAuth path is "
            "intercepted; switch models.deepdive.via to 'sdk' .") from e

    if parallel <= 1:
        all_findings: list[Finding] = []
        for chunk in chunks:
            _label(chunk)
            if tracker is not None:
                tracker.scanning(chunk)
            try:
                findings = _deepdive_chunk(chunk, ctx, repo_root, cfg,
                                           runs_n, threshold)
            except GuardrailBlocked as e:
                guardrail_hits += 1
                print(f"  [s4] chunk {chunk.id} GUARDRAIL-BLOCKED "
                      f"({guardrail_hits}/{guardrail_gate})", file=sys.stderr)
                _errlog.log("s4", f"guardrail:{chunk.id}", e, scope="chunk",
                            files=len(chunk.files))
                outcomes[chunk.id] = "guardrail"
                if tracker is not None:
                    tracker.scanned(chunk, outcome="guardrail", n_findings=0)
                if guardrail_hits >= guardrail_gate and successes == 0:
                    _guardrail_fail_fast(e)
                continue
            except Exception as e:
                if cli.aborted():
                    raise
                # A chunk whose every run failed (timeout, socket drop, parse
                # error) raises here; record it as failed so the report can
                # disclose the coverage gap instead of silently dropping it.
                print(f"  [s4] chunk {chunk.id} ERROR: {redact(str(e))}", file=sys.stderr)
                _errlog.log("s4", chunk.id, e, scope="chunk",
                            files=len(chunk.files))
                outcomes[chunk.id] = "error"
                if tracker is not None:
                    tracker.scanned(chunk, outcome="error", n_findings=0)
                continue
            successes += 1
            outcomes[chunk.id] = "completed"
            all_findings.extend(findings)
            if tracker is not None:
                tracker.scanned(chunk, outcome="completed", n_findings=len(findings))
            print(f"  [s4] chunk {chunk.id}: {len(findings)} high-confidence findings",
                  file=sys.stderr)
        collapsed = _collapse_across_chunks(all_findings, cfg.step4.line_bucket)
        error_count = sum(1 for v in outcomes.values() if v == "error")
        guardrail_count = sum(1 for v in outcomes.values() if v == "guardrail")
        log.info("s4/deepdive: serial processing complete - chunks=%d findings=%d errors=%d guardrails=%d",
                 len(chunks), len(collapsed), error_count, guardrail_count)
        if tracker is not None:
            tracker.print_summary()
        return collapsed, outcomes

    print(f"  [s4] processing {len(chunks)} chunks ({parallel} parallel)...",
          file=sys.stderr)
    results: dict[str, list[Finding]] = {}
    ex = ThreadPoolExecutor(max_workers=parallel)
    futs = {}
    for chunk in chunks:
        _label(chunk)
        if tracker is not None:
            tracker.scanning(chunk)
        futs[ex.submit(_deepdive_chunk, chunk, ctx, repo_root, cfg,
                       runs_n, threshold)] = chunk
    try:
        for fut in as_completed(futs):
            chunk = futs[fut]
            try:
                findings = fut.result()
            except GuardrailBlocked as e:
                guardrail_hits += 1
                print(f"  [s4] chunk {chunk.id} GUARDRAIL-BLOCKED "
                      f"({guardrail_hits}/{guardrail_gate})", file=sys.stderr)
                _errlog.log("s4", f"guardrail:{chunk.id}", e, scope="chunk",
                            files=len(chunk.files))
                results[chunk.id] = []
                outcomes[chunk.id] = "guardrail"
                if tracker is not None:
                    tracker.scanned(chunk, outcome="guardrail", n_findings=0)
                if guardrail_hits >= guardrail_gate and successes == 0:
                    cli.abort()
                    ex.shutdown(wait=False, cancel_futures=True)
                    _guardrail_fail_fast(e)
                continue
            except Exception as e:
                print(f"  [s4] chunk {chunk.id} ERROR: {redact(str(e))}", file=sys.stderr)
                _errlog.log("s4", chunk.id, e, scope="chunk",
                            files=len(chunk.files))
                results[chunk.id] = []
                outcomes[chunk.id] = "error"
                if tracker is not None:
                    tracker.scanned(chunk, outcome="error", n_findings=0)
                continue
            successes += 1
            results[chunk.id] = findings
            outcomes[chunk.id] = "completed"
            if tracker is not None:
                tracker.scanned(chunk, outcome="completed", n_findings=len(findings))
            print(f"  [s4] chunk {chunk.id}: {len(findings)} high-confidence findings",
                  file=sys.stderr)
    except KeyboardInterrupt:
        n = cli.abort()
        print(f"  [s4] interrupted — killed {n} running subprocess(es), "
              f"cancelling {sum(1 for f in futs if not f.done())} pending chunks",
              file=sys.stderr)
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        ex.shutdown(wait=True)

    # Reassemble in risk-rank order so downstream ordering is stable.
    all_findings: list[Finding] = []
    for chunk in chunks:
        all_findings.extend(results.get(chunk.id, []))
    collapsed = _collapse_across_chunks(all_findings, cfg.step4.line_bucket)
    completed_count = sum(1 for v in outcomes.values() if v == "completed")
    error_count = sum(1 for v in outcomes.values() if v == "error")
    guardrail_count = sum(1 for v in outcomes.values() if v == "guardrail")
    log.info("s4/deepdive: parallel processing complete - chunks=%d (completed=%d errors=%d guardrails=%d) findings=%d",
             len(chunks), completed_count, error_count, guardrail_count, len(collapsed))
    if tracker is not None:
        tracker.print_summary()
    return collapsed, outcomes


def _deepdive_chunk(chunk: Chunk, ctx: ContextPackage, repo_root: Path, cfg,
                    runs_n: int, threshold: int) -> list[Finding]:
    code = _load_chunk_code(chunk, ctx, repo_root, cfg)
    code += _neighbor_context(chunk, ctx, repo_root, cfg)
    if chunk.specialist:
        # Specialist passes are a different LENS, not a consistency probe.
        # Run once; s6 adversarial verification is the FP filter.
        runs_n = max(1, int(getattr(cfg.step4, "specialist_runs", 1) or 1))
        threshold = 1
    elif chunk.path_funcs:
        # Taint chunks under taint.yaml: confirm/refute is single-shot — voting
        # adds no signal when the question is binary. Under default.yaml
        # taint_runs is unset → falls through to the global runs_n.
        tr = getattr(cfg.step4, "taint_runs", None)
        if tr:
            runs_n = max(1, int(tr))
            threshold = min(threshold, runs_n) or 1
    line_bucket = cfg.step4.line_bucket

    # ── N independent runs ───────────────────────────────────────────────
    runs: list[set[tuple]] = []
    by_key: dict[tuple, Finding] = {}
    runs_ok = 0

    for run_i in range(runs_n):
        if cli.aborted():
            raise RuntimeError("aborted by user (Ctrl-C)")
        try:
            findings = _single_run(chunk, ctx, code, cfg)
        except Exception as e:
            if cli.aborted():
                raise
            print(f"    [s4] {chunk.id} run {run_i+1}/{runs_n} failed: {e}",
                  file=sys.stderr)
            _errlog.log("s4", chunk.id, e, scope="run",
                        run=run_i + 1, runs_total=runs_n)
            runs.append(set())
            continue

        runs_ok += 1
        keys = set()
        for f in findings:
            k = f.canonical_key(line_bucket)
            keys.add(k)
            prev = by_key.get(k)
            if prev is None or f.confidence > prev.confidence:
                by_key[k] = f
        runs.append(keys)
        print(f"    [s4] {chunk.id} run {run_i+1}/{runs_n}: "
              f"{len(findings)} raw findings", file=sys.stderr)

    # A chunk where EVERY run failed produced no findings for a reason (timeout,
    # socket drop, parse error) — surface it as a failure so run() records the
    # coverage gap, rather than returning [] indistinguishable from a clean
    # chunk that simply found nothing. (One successful run, even with zero
    # findings, is a legitimate completed chunk.)
    if runs_n > 0 and runs_ok == 0:
        raise RuntimeError(
            f"all {runs_n} run(s) failed for chunk {chunk.id}")

    # ── Vote ─────────────────────────────────────────────────────────────
    votes = Counter(k for run_keys in runs for k in run_keys)
    survivors: list[Finding] = []
    for k, n in votes.items():
        if n >= threshold:
            f = by_key[k]
            f.votes = n
            survivors.append(f)

    return survivors


def _collapse_across_chunks(findings: list[Finding], line_bucket: int) -> list[Finding]:
    """
    Per-chunk voting can't see that risk-chunk-03 and spec-crypto-01 both
    flagged foo.py:142. Collapse on canonical_key globally, keeping the
    highest-confidence representative.
    """
    best: dict[tuple, Finding] = {}
    for f in findings:
        k = f.canonical_key(line_bucket)
        if k not in best or f.confidence > best[k].confidence:
            best[k] = f
    if len(best) < len(findings):
        print(f"  [s4] cross-chunk collapse: {len(findings)} → {len(best)}",
              file=sys.stderr)
    return list(best.values())


def _single_run(chunk: Chunk, ctx: ContextPackage, code: str, cfg) -> list[Finding]:
    # Taint chunks under taint.yaml: confirm/refute the seeded source→sink
    # instead of open-ended discovery, optionally on a cheaper model. Any
    # other chunk kind (and default.yaml's taint_prompt_mode=discover) keeps
    # the legacy prompt + model verbatim.
    global _TAINT_MODEL_WARNED
    model = cfg.models.deepdive
    if (chunk.path_funcs
            and str(getattr(cfg.step4, "taint_prompt_mode", "discover")
                    ).lower() == "confirm_refute"):
        user = _build_confirm_refute_prompt(chunk, ctx, code, cfg)
        if getattr(cfg.step4, "taint_model", None) is not None and not _TAINT_MODEL_WARNED:
            _TAINT_MODEL_WARNED = True
            print("  [s4] WARN: step4.taint_model is deprecated and ignored; "
                  "taint chunks now use models.deepdive.", file=sys.stderr)
    else:
        user = _build_prompt(chunk, ctx, code)

    try:
        raw = prompt(
            user,
            model=model,
            system_prompt=SYSTEM,
            max_tokens=getattr(cfg.step4, "max_tokens", None),
            timeout=getattr(cfg.step4, "timeout", 1800),
            output_format="json",
            tag=f"s4 {chunk.id}",
        )
    except GuardrailBlocked as e:
        print(f"    [s4] {chunk.id}: GUARDRAIL-BLOCKED — "
              f"{str(e)[:120]}", file=sys.stderr)
        raise

    data = extract_json(raw)
    raw_findings = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(raw_findings, list):
        raw_findings = []

    findings: list[Finding] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            print(f"    [s4] dropped non-object finding: {type(item).__name__}",
                  file=sys.stderr)
            _errlog.log("s4", chunk.id,
                        f"dropped non-object finding: {type(item).__name__}",
                        scope="item")
            continue
        item.setdefault("chunk_id", chunk.id)
        vc = item.get("vuln_class", "other")
        if vc not in {v.value for v in VulnClass}:
            item["vuln_class"] = "other"
        cwe_raw = str(item.get("cwe") or "").strip()
        m = re.search(r"\bCWE[-\s]?(\d{1,5})\b", cwe_raw, re.I)
        item["cwe"] = f"CWE-{m.group(1)}" if m else None
        try:
            findings.append(Finding.model_validate(item))
        except Exception as e:
            print(f"    [s4] dropped malformed finding: {e}", file=sys.stderr)
            _errlog.log("s4", chunk.id, e, scope="item",
                        file=str(item.get("file", "")))

    cap = getattr(cfg.step4, "max_findings_per_run", None)
    if cap and len(findings) > cap:
        findings.sort(key=lambda f: f.confidence, reverse=True)
        print(f"    [s4] {chunk.id}: capping {len(findings)} → {cap} by confidence",
              file=sys.stderr)
        findings = findings[:cap]
    return findings


def _trust_context_block(ctx: ContextPackage) -> str:
    """Compact exposure/trust-boundary summary so the researcher can apply
    OUT-OF-SCOPE rule A (NO REAL ATTACKER) itself instead of emitting FPs the
    verifier must drop."""
    ap = ctx.app_profile
    tm = ctx.threat_model
    if not ap and not tm:
        return ""
    lines = ["TRUST CONTEXT (use this to decide if input is attacker-controlled):"]
    if ap:
        lines.append(f"  - Externally facing: {'YES' if ap.externally_facing else 'NO — internal only'}")
        sens = [t for t, on in (("PCI", ap.pci_scoped), ("PAN", ap.processes_pan),
                                ("PII", ap.pii)) if on]
        if sens:
            lines.append(f"  - Data sensitivity: {', '.join(sens)}")
    if tm:
        if tm.system_context:
            ctx_short = tm.system_context.split("\n\n")[0][:400]
            lines.append(f"  - System: {ctx_short}")
        if tm.trust_boundaries:
            lines.append("  - UNTRUSTED entry points (only these cross a trust boundary):")
            for b in tm.trust_boundaries[:8]:
                lines.append(f"      • {b.entry_point}")
    lines.append("  - Operator argv/env on the operator's OWN host is TRUSTED. "
                 "But CI job parameters, scheduler args, shared config/CSV/"
                 "test-data files editable by other principals, and "
                 "framework-overridable variables ARE attack surface even on "
                 "an internal app — report those (typically LOW). See OUT-OF-"
                 "SCOPE rule A.")
    return "\n".join(lines) + "\n"


def _build_prompt(chunk: Chunk, ctx: ContextPackage, code: str) -> str:
    cve_block = ""
    if chunk.related_cves:
        relevant = [c for c in ctx.known_cves if c.id in chunk.related_cves]
        cve_block = "\nRELATED CVEs (hunt for variants/siblings):\n" + "\n".join(
            f"  - {c.id}: {c.summary}" for c in relevant
        ) + "\n"

    return f"""RESEARCH LENS:
{build_research_lens(chunk, code)}

CHUNK: {chunk.id}  SIZE: {chunk.size.value}
HYPOTHESIS: {chunk.hypothesis}
FOCUS ENTRY POINTS: {", ".join(chunk.focus_entry_points) or "(none)"}
{_trust_context_block(ctx)}{cve_block}
SOURCE CODE:
{code}

Analyze this code and respond with ONLY the JSON findings object."""


def _norm_rel_path(path: str) -> str:
    norm = (path or "").strip().replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def _parse_ref_file_line(ref: str) -> tuple[str, int | None]:
    raw = (ref or "").strip()
    if not raw:
        return "", None
    f, sep, _tail = raw.partition("::")
    if sep:
        return _norm_rel_path(f), None
    f, sep, ln = raw.rpartition(":")
    if sep and f and ln.isdigit():
        return _norm_rel_path(f), max(1, int(ln))
    return _norm_rel_path(raw), None


def _short_symbol(symbol: str, limit: int = 64) -> str:
    s = (symbol or "").strip()
    if not s:
        return "(unknown)"
    if len(s) <= limit:
        return s
    return s[:limit - 1] + "…"


def _compact_taint_evidence_block(chunk: Chunk, ctx: ContextPackage) -> str:
    """Render a bounded, single-path taint-evidence summary for s4 prompts.

    Returns an empty string when no structured evidence can be matched, keeping
    prompt bytes unchanged for non-evidence chunks.
    """
    evidence_paths = getattr(ctx, "seed_taint_evidence", None) or []
    if not evidence_paths:
        return ""

    src_file, _src_line = _parse_ref_file_line(chunk.source_ref)
    sink_file, sink_line = _parse_ref_file_line(chunk.sink_ref)
    chunk_path = set(chunk.path_funcs or [])

    best = None
    best_score = 0
    for ev in evidence_paths:
        edges = list(getattr(ev, "edges", None) or [])
        if not edges:
            continue
        ev_src_file, _ev_src_line = _parse_ref_file_line(getattr(ev, "source_ref", ""))
        ev_sink_file, ev_sink_line = _parse_ref_file_line(getattr(ev, "sink_ref", ""))
        score = 0
        if src_file and ev_src_file and src_file == ev_src_file:
            score += 3
        if sink_file and ev_sink_file and sink_file == ev_sink_file:
            score += 3
        if sink_line is not None and ev_sink_line is not None and sink_line == ev_sink_line:
            score += 2
        if chunk_path and getattr(ev, "path_funcs", None):
            overlap = len(chunk_path & set(ev.path_funcs or []))
            if overlap:
                score += min(3, overlap)
        if score > best_score:
            best = ev
            best_score = score

    if best is None:
        return ""

    edges = list(getattr(best, "edges", None) or [])
    key_kinds = (
        "assign",
        "arg_to_param",
        "return_to_local",
        "local_to_sink",
        "return_to_sink",
    )
    transfer_counts = Counter(
        getattr(edge, "transfer_kind", "") for edge in edges
        if getattr(edge, "transfer_kind", "") in key_kinds
    )
    if not transfer_counts:
        return ""

    source_edge = next((e for e in edges if getattr(e, "transfer_kind", "") == "source"), edges[0])
    sink_edge = next(
        (e for e in reversed(edges)
         if getattr(e, "transfer_kind", "") in {"local_to_sink", "return_to_sink"}),
        edges[-1],
    )

    transfer_summary = ", ".join(
        f"{k}:{transfer_counts[k]}" for k in key_kinds if transfer_counts.get(k)
    )
    sink_sym = _short_symbol(getattr(getattr(sink_edge, "dst", None), "symbol", ""))
    if sink_sym == "(unknown)":
        sink_sym = _short_symbol(getattr(getattr(sink_edge, "src", None), "symbol", ""))

    # Build optional extra lines for field/container/sanitize edges.
    # Priority: sanitized (highest signal) → field flow → container flow.
    extra_lines: list[str] = []
    sanitize_edges = [e for e in edges if getattr(e, "transfer_kind", "") == "sanitize"]
    if sanitize_edges:
        san_e = sanitize_edges[0]
        san_sym = q_name(san_e.function_qnode) or _short_symbol(
            getattr(getattr(san_e, "dst", None), "symbol", "")
        )
        extra_lines.append(f"  SANITIZED via              : {san_sym}")
    field_edges = [e for e in edges
                   if getattr(e, "transfer_kind", "") in {"field_write", "field_read"}]
    if field_edges:
        fw = sum(1 for e in field_edges if getattr(e, "transfer_kind", "") == "field_write")
        fr = sum(1 for e in field_edges if getattr(e, "transfer_kind", "") == "field_read")
        parts = ([f"field_write:{fw}"] if fw else []) + ([f"field_read:{fr}"] if fr else [])
        extra_lines.append(f"  FIELD FLOW                 : {', '.join(parts)}")
    container_edges = [e for e in edges
                       if getattr(e, "transfer_kind", "") in {"container_put", "container_get"}]
    if container_edges:
        cp = sum(1 for e in container_edges if getattr(e, "transfer_kind", "") == "container_put")
        cg = sum(1 for e in container_edges if getattr(e, "transfer_kind", "") == "container_get")
        parts = ([f"container_put:{cp}"] if cp else []) + ([f"container_get:{cg}"] if cg else [])
        extra_lines.append(f"  CONTAINER FLOW             : {', '.join(parts)}")
    # Condition edges — taint transfer gated by a (possibly tainted) condition.
    condition_edges = [e for e in edges if getattr(e, "transfer_kind", "") == "condition"]
    if condition_edges:
        cond_e = condition_edges[0]
        cond_text = getattr(cond_e, "condition_text", "") or "(unknown)"
        cond_conf = getattr(cond_e, "confidence", "high")
        extra_lines.append(f"  CONDITION GATE             : [{cond_text}] (confidence: {cond_conf})")
    # Reflection edges — speculative taint transfer via dynamic dispatch.
    reflect_edges = [e for e in edges if getattr(e, "transfer_kind", "") == "reflect"]
    if reflect_edges:
        ref_e = reflect_edges[0]
        call_type = getattr(ref_e, "call_type", "reflect")
        ref_conf = getattr(ref_e, "confidence", "medium")
        targets = list(getattr(ref_e, "reflected_targets", []) or [])
        if targets:
            first = _short_symbol(targets[0])
            if len(targets) >= 2:
                second = _short_symbol(targets[1])
                remaining = len(targets) - 2
                targets_str = (
                    f"{first}, {second}" + (f" +{remaining} more" if remaining > 0 else "")
                )
            else:
                targets_str = first
            extra_lines.append(
                f"  REFLECT EDGE               : [{call_type}] → {targets_str}"
                f" (confidence: {ref_conf}, speculative)"
            )
        else:
            extra_lines.append(
                f"  REFLECT EDGE               : [{call_type}]"
                f" (confidence: {ref_conf}, speculative)"
            )
    # Framework edges — taint via framework-level source injection.
    framework_edges = [e for e in edges if getattr(e, "transfer_kind", "") == "framework"]
    if framework_edges:
        fw_e = framework_edges[0]
        framework = getattr(fw_e, "framework", "framework")
        marker_name = getattr(fw_e, "marker_type", "marker")
        fw_conf = getattr(fw_e, "confidence", "high")
        extra_lines.append(
            f"  FRAMEWORK SOURCE           : [{framework}] {marker_name}"
            f" (confidence: {fw_conf})"
        )
    # Response dataflow — taint flows to response sink.
    # Common response sink patterns across frameworks (Spring, Django, ASP.NET, etc.).
    response_sink_patterns = {
        "JsonResponse", "ResponseEntity", "Ok", "Created", "BadRequest", "Conflict",
        "Response", "HttpResponse", "JsonResult", "ViewResult", "ContentResult",
        "DirectResult", "StatusCodeResult", "ObjectResult", "ApiResponse",
        "render", "json", "jsonify", "dumps", "to_json",
        "HttpServletResponse", "ServletResponse", "PrintWriter", "OutputStream",
    }
    to_sink = getattr(getattr(sink_edge, "dst", None), "symbol", "")
    sink_sym_for_response = _short_symbol(to_sink)
    if sink_sym_for_response in response_sink_patterns:
        response_type = "json"  # default
        if any(p in sink_sym_for_response.lower() for p in {"html", "render", "template"}):
            response_type = "html"
        elif any(p in sink_sym_for_response.lower() for p in {"json", "jsonify", "to_json"}):
            response_type = "json"
        elif any(p in sink_sym_for_response.lower() for p in {"xml"}):
            response_type = "xml"
        else:
            response_type = "text"
        extra_lines.append(
            f"  RESPONSE OUTPUT            : {sink_sym_for_response}"
            f" (type: {response_type})"
        )
    # Enforce max 9 total content lines (3 base + 6 extras):
    # Sanitize, field, container (up to 3); condition + reflect (up to 2); framework + response (up to 2).
    extra_lines = extra_lines[:6]

    extra_block = "".join(line + "\n" for line in extra_lines)

    # Annotation notes embedded in the prompt to guide model reasoning.
    # These are not counted against the line cap.
    annotation_lines: list[str] = []
    if condition_edges:
        cond_text = getattr(condition_edges[0], "condition_text", "") or "(unknown)"
        annotation_lines.append(
            f"  NOTE: Path is gated by condition: {cond_text}."
            " If condition is false, taint is neutralized."
        )
    if reflect_edges:
        targets = list(getattr(reflect_edges[0], "reflected_targets", []) or [])
        target_str = _short_symbol(targets[0]) if targets else "(unresolved)"
        annotation_lines.append(
            f"  NOTE: Path involves reflection to {target_str}."
            " This is a speculative path based on static analysis."
        )
    # Annotation notes for framework sources and response flows.
    if framework_edges:
        fw_framework = getattr(framework_edges[0], "framework", "framework")
        annotation_lines.append(
            f"  NOTE: Source is framework-injected ({fw_framework})."
            " Parameters are automatically tainted via framework binding."
        )
    if (getattr(getattr(sink_edge, "dst", None), "symbol", "") in response_sink_patterns or
        _short_symbol(getattr(getattr(sink_edge, "dst", None), "symbol", "")) in response_sink_patterns):
        annotation_lines.append(
            f"  NOTE: Output flows to response object. Risk: XSS if data not escaped,"
            f" or injection if response type is HTML/XML/JSON."
        )
    annotation_block = "".join(line + "\n" for line in annotation_lines)

    return (
        "\nSTRUCTURED TAINT EVIDENCE (compact)\n"
        f"  origin tainted symbol : {_short_symbol(getattr(source_edge.src, 'symbol', ''))}\n"
        f"  transfer edges kinds  : {transfer_summary}\n"
        f"  sink-consuming symbol : {sink_sym}\n"
        + extra_block
        + annotation_block
    )


def _build_confirm_refute_prompt(chunk: Chunk, ctx: ContextPackage,
                                 code: str, cfg=None) -> str:
    """Taint-first (taint.yaml) prompt for chunks with ``path_funcs``.

    The s0 static seed already named a concrete source, sink and (often) CWE.
    The model's job is verification, not discovery: trace the path hop-by-hop
    and either CONFIRM (emit one finding with the unsanitised hop as evidence)
    or REFUTE (emit zero findings, naming the sanitiser). Same JSON schema as
    the open-ended prompt so the existing parse path is unchanged."""
    src_file, _, src_fn = chunk.source_ref.rpartition("::")
    cwe = ", ".join(chunk.sink_cwe) if chunk.sink_cwe else "(infer from sink)"
    hops = " -> ".join(q_name(n) for n in chunk.path_funcs) or "(direct)"
    # Per-CWE sanitizer / non-sanitizer / FP-check guidance from rules/*.kb.yaml.
    # Empty string when the CWE is unknown → prompt is byte-identical to the
    # pre-KB shape, so default.yaml and unmapped sinks are unaffected.
    rules_cfg = getattr(cfg, "rules", None) if cfg is not None else None
    kb_overlays = getattr(rules_cfg, "kb_overlays", None)
    kb_block = CweKB.load(overlays=kb_overlays).prompt_block(
        chunk.sink_cwe, lang=(chunk.languages[0] if chunk.languages else None))
    evidence_block = _compact_taint_evidence_block(chunk, ctx)
    return f"""TASK: confirm or refute ONE candidate taint path. Do NOT hunt for
unrelated issues — that is covered by other chunks.

CANDIDATE PATH
  source : {src_fn or chunk.source_ref}()  [{src_file or chunk.source_ref}]
  sink   : {chunk.sink_ref}
  hops   : {hops}
    class  : {cwe}{evidence_block}
{kb_block}
The SOURCE CODE below contains ONLY the functions on this path (plus a few
context lines and out-of-chunk neighbor excerpts). Line numbers are real file
positions — cite them exactly.
{_trust_context_block(ctx)}
DECISION RULES
  • CONFIRMED  — attacker-controlled data from the source reaches the sink
    without an effective sanitiser/validator/allow-list on the path. Emit
    EXACTLY ONE finding. `source_ref` MUST cite the source line, `sink_ref`
    MUST cite the sink line, and `description` MUST name the first hop where
    sanitisation was missing.
  • Framework sources (with FRAMEWORK SOURCE marker): Source is framework-injected
    (Spring @RequestParam, Django request.GET, ASP.NET model binding, etc.).
    Parameters are automatically tainted and must be validated downstream
    before reaching a sink.
  • Response flows (with RESPONSE OUTPUT marker): Output flows to a response
    object (JSON, HTML, XML, plain text). Risk: XSS if data not escaped,
    or response-format injection if type not properly handled.
  • REFUTED    — a sanitiser/validator/type-coercion neutralises the input
    before it reaches the sink, OR the path is not actually connected in the
    code shown. Emit ZERO findings. In the JSON, set
    `findings: []` and add `refuted_reason: "<file:line> — <one-line why>"`.
    • If you cannot decide from the code shown, emit `findings: []` with
        `refuted_reason: "insufficient evidence in provided slice"`.
        Do NOT claim a sanitizer/control unless you can cite it in the shown code.

SOURCE CODE:
{code}

Respond with ONLY the JSON object (`findings` array, optional
`refuted_reason`)."""


# ─────────────────────────────────────────────────────────────────────────────
# Code loading (same as SDK version — CLI single-shot needs code in the prompt)
# ─────────────────────────────────────────────────────────────────────────────

# Mask them (keep BIN prefix + length so the researcher can still flag "test PAN in
# source" findings) before the code leaves the process.
_PAN_RX = re.compile(r"\b(?:\d[\s\-]?){13,19}\b")

# A card-context keyword sitting just before the digit run (e.g. `pan =`,
# `cardNumber:`, `acct_no`, `credit_card`). Matched in a short window preceding
# the match so a labelled-but-non-Luhn test PAN is still caught.
_CARD_CTX = re.compile(
    r"(?i)\b(pan|card(?:[\s_-]*(?:no|num|number))?"
    r"|cc(?:[\s_-]*(?:no|num|number))?|credit[\s_-]*card"
    r"|acct|account(?:[\s_-]*(?:no|num|number))?)\b")


def _mask_pan(m: re.Match) -> str:
    s = m.group(0)
    digits = re.sub(r"\D", "", s)
    if len(digits) < 13:
        return s
    # Card-likeness gate (option B): mask only when the run is Luhn-valid (every
    # issued PAN satisfies the Luhn check digit, regardless of IIN/prefix) OR a
    # card keyword sits immediately before it. This keeps real cards + labelled
    # test PANs masked before egress to the external LLM provider (CWE-201)
    # while no longer clobbering ordinary 13-19 digit literals — nanosecond
    # timestamps, Snowflake/DB ids, account/version numbers — that a length-only
    # gate mangled. Layer 2 (the shared IIN+Luhn-gated redactor in report.redact)
    # still runs after this and is unchanged. First 4 digits + length + layout
    # are preserved so a researcher can still flag "card/secret literal here".
    window = m.string[max(0, m.start() - 48): m.start()]
    if not (_luhn(digits) or _CARD_CTX.search(window)):
        return s
    kept = 0
    out = []
    for c in s:
        if c.isdigit():
            out.append(c if kept < 4 else "X")
            kept += 1
        else:
            out.append(c)
    return "".join(out)


def _redact_source(text: str, rel: str) -> str:
    """Mask sensitive data BEFORE source is packed into the prompt and sent to
    the model. A provider/gateway PII guard rejects requests containing live
    PII (e.g. SSNs), so this is both a privacy control and a hard requirement
    for the request to succeed.

    Two layers: (1) the partial PAN mask keeps the BIN prefix + length so the
    researcher can still flag "test card in source" findings, and catches any
    Luhn-valid card (any prefix) plus card-keyword-labelled non-Luhn test PANs;
    (2) the shared redactor masks SSNs, credentials, keys,
    JWTs and Luhn/IIN-valid cards the prefix mask doesn't cover. Both preserve
    line structure (no newlines added/removed) so finding line numbers stay
    accurate. redact_counts() is used (not redact()) because s4 runs chunks
    concurrently and must not race on the shared count side-channel."""
    # Count only runs actually masked: _mask_pan now returns non-card runs
    # unchanged, so subn's match count would over-report. nonlocal closure keeps
    # the tally local to this call (no cross-chunk race).
    n_pan = 0
    def _count_mask(m: re.Match) -> str:
        nonlocal n_pan
        repl = _mask_pan(m)
        if repl != m.group(0):
            n_pan += 1
        return repl
    masked = _PAN_RX.sub(_count_mask, text)
    masked, counts = redact_counts(masked)
    n_other = sum(counts.values())
    if n_pan or n_other:
        detail = (" [" + ", ".join(f"{k}:{v}" for k, v in sorted(counts.items())) + "]"
                  if counts else "")
        print(f"    [s4] redacted {n_pan} PAN-prefix + {n_other} sensitive "
              f"token(s) in {rel}{detail}", file=sys.stderr)
    return masked


def _load_chunk_code(chunk: Chunk, ctx: ContextPackage, repo_root: Path,
                     cfg) -> str:
    global _DEF_SPANS_ABSENT_WARNED
    slice_mode = _slice_mode(cfg)
    if slice_mode == "function" and not (ctx.def_spans or {}):
        if not _DEF_SPANS_ABSENT_WARNED:
            print("  [s4] WARN: def_spans absent — function-level slicing unavailable; "
                  "using whole-file fallback mode.",
                  file=sys.stderr)
            _DEF_SPANS_ABSENT_WARNED = True
    # Taint-first profile: ship only the function bodies on the BFS path, not
    # whole files. Gated on (a) the chunk actually having path metadata,
    # (b) tree-sitter having produced def_spans, and (c) the profile opting in
    # — so default.yaml is byte-identical.
    if chunk.path_funcs and slice_mode == "function":
        sliced = _load_taint_slice(chunk, ctx, repo_root)
        if sliced:
            return sliced
    # AST/callgraph-first slice for general risk/specialist chunks too.
    if slice_mode == "function":
        sliced = _load_graph_slice(chunk, ctx, repo_root, cfg)
        if sliced:
            return sliced
    if chunk.size != ChunkSize.LARGE:
        return _load_files_full(chunk.files, repo_root)
    return _load_sliding_window(chunk, repo_root, ctx=ctx)


def _slice_mode(cfg) -> str:
    """Resolve chunk slicing mode for S4.

    The shipped key is ``step3.taint_chunk_slice`` (declared in the defaults
    layer and set by ``profiles/taint.yaml``). An optional
    ``step4.taint_chunk_slice`` overrides it when explicitly present, but no
    shipped profile sets it, so ``step3`` is the effective key in practice.
    Defaults to ``file``.
    """
    s4 = getattr(cfg, "step4", None)
    mode = getattr(s4, "taint_chunk_slice", None)
    if mode is None:
        mode = getattr(getattr(cfg, "step3", None), "taint_chunk_slice", "file")
    return str(mode or "file").lower()


def _load_graph_slice(chunk: Chunk, ctx: ContextPackage,
                      repo_root: Path, cfg, pad: int = 6) -> str:
    """Render a graph/AST-prioritized code slice for non-taint chunks.

    Picks function spans in chunk files using call-graph and focus anchors.
    Any chunk file the graph cannot resolve a span for — or whose functions
    exceed the per-file cap — is shipped WHOLE (per-file fallback), never
    truncated to a fixed head, so coverage is preserved.
    """
    spans = ctx.def_spans or {}
    files_locs = ctx.call_graph_files or {}

    max_funcs_per_file = int(getattr(cfg.step4, "frontier_max_funcs_per_file", 24) or 24)
    chunk_files = set(chunk.files)
    focus = set(chunk.focus_entry_points or ())

    # Rank qnodes by threat relevance: explicit path hops and focus anchors first,
    # then caller/callee connectivity, then deterministic lexical tie-break.
    scores: dict[str, int] = defaultdict(int)
    for qn in dict.fromkeys(chunk.path_funcs or []):
        if q_file(qn) in chunk_files:
            scores[qn] += 100
    # Index qnodes by (file, name) once so entry-point and sink attribution are
    # direct lookups instead of a full scan of ``spans`` per anchor.
    qns_by_file_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    for qn in spans:
        qns_by_file_name[(q_file(qn), q_name(qn))].append(qn)
    for ep in ctx.entry_points:
        if ep.file in chunk_files and ep.function:
            for qn in qns_by_file_name.get((ep.file, ep.function), ()):
                scores[qn] += 50
    for sink in ctx.unsafe_sinks:
        if sink.file in chunk_files and sink.function:
            for qn in qns_by_file_name.get((sink.file, sink.function), ()):
                scores[qn] += 45
    for caller, callees in (ctx.call_graph or {}).items():
        if q_file(caller) in chunk_files:
            scores[caller] += 10
        for callee in callees or ():
            if q_file(callee) in chunk_files:
                scores[callee] += 8
            if q_file(caller) in chunk_files and q_file(callee) in chunk_files:
                scores[caller] += 3
                scores[callee] += 3
    for qn in spans:
        if q_file(qn) in chunk_files and q_name(qn) in focus:
            scores[qn] += 40

    ranked = sorted(
        (qn for qn in spans if q_file(qn) in chunk_files),
        key=lambda qn: (-scores.get(qn, 0), q_file(qn), q_name(qn)),
    )

    by_file: dict[str, list[tuple[int, int]]] = defaultdict(list)
    picked_per_file: dict[str, int] = defaultdict(int)
    clipped_files: set[str] = set()
    for qn in ranked:
        f = q_file(qn)
        if picked_per_file[f] >= max_funcs_per_file:
            # More resolved functions than the per-file cap: record the file so
            # the emit loop ships it WHOLE rather than dropping the functions
            # past the cap.
            clipped_files.add(f)
            continue
        sp = spans.get(qn)
        if not sp or len(sp) < 2:
            continue
        lo, hi = int(sp[0]), int(sp[1])
        if lo <= 0 or hi <= lo:
            continue
        by_file[f].append((max(1, lo - pad), hi + pad))
        picked_per_file[f] += 1

    # Focus anchors from call_graph_files: for specialist shards, this can
    # provide usable ranges even when no retained def_spans qnode hits a file.
    for fn in focus:
        for ref in files_locs.get(fn, ()):
            rf, sep, rl = ref.rpartition(":")
            if not sep or not rl.isdigit() or rf not in chunk_files:
                continue
            ln = int(rl)
            by_file[rf].append((max(1, ln - pad), ln + pad))

    # Include explicit sink line for module-scope sink calls.
    if chunk.sink_ref:
        sf, _, sl = chunk.sink_ref.rpartition(":")
        if sf and sl.isdigit() and sf in chunk_files:
            ln = int(sl)
            by_file[sf].append((max(1, ln - pad), ln + pad))

    # No span/anchor ranges resolved for this chunk: force caller fallback to
    # per-file loading instead of emitting tiny file-head snippets.
    if not by_file:
        return ""

    parts: list[str] = []
    n_lines = 0
    whole_file_fallbacks: list[str] = []
    for rel in chunk.files:
        p = repo_root / rel
        if not p.is_file():
            parts.append(f"=== {rel} ===\n[FILE NOT FOUND]\n")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            parts.append(f"=== {rel} ===\n[READ ERROR: {e}]\n")
            continue
        lines = [ln[:MAX_LINE_CHARS] for ln in _redact_source(text, rel).splitlines()]
        ranges = by_file.get(rel, [])
        merged = _merge_ranges(ranges, gap=pad) if ranges else []
        # A chunk file the call graph resolved no span for, or one whose
        # resolved functions were clipped at ``max_funcs_per_file``, is shipped
        # WHOLE so no code below a fixed head is dropped and the profile's
        # "falls back to file" guarantee holds.
        if not merged or rel in clipped_files:
            merged = [(1, len(lines))] if lines else []
            if lines:
                whole_file_fallbacks.append(rel)
        for lo, hi in merged:
            hi = min(hi, len(lines))
            if lo > hi:
                continue
            body = "\n".join(f"{i:5d}| {lines[i-1]}" for i in range(lo, hi + 1))
            parts.append(f"=== {rel} [lines {lo}-{hi}] ===\n{body}\n")
            n_lines += hi - lo + 1
    if not parts:
        return ""
    if whole_file_fallbacks:
        shown = ", ".join(whole_file_fallbacks[:5])
        more = (f" (+{len(whole_file_fallbacks) - 5} more)"
                if len(whole_file_fallbacks) > 5 else "")
        print(f"    [s4] {chunk.id}: shipped {len(whole_file_fallbacks)} "
              f"un-graphed/clipped file(s) whole to preserve coverage: "
              f"{shown}{more}", file=sys.stderr)
    print(f"    [s4] {chunk.id}: graph-slice {n_lines} lines "
          f"(files={len(chunk.files)}, spans={sum(len(v) for v in by_file.values())})",
          file=sys.stderr)
    return "\n".join(parts)


def _load_taint_slice(chunk: Chunk, ctx: ContextPackage,
                      repo_root: Path, pad: int = 8) -> str:
    """Render only the def-span of each qnode on ``chunk.path_funcs`` (plus
    ``pad`` context lines either side, plus the sink line itself). Per-file
    overlapping ranges are merged so a 5-hop path through one large class
    emits one contiguous block, not five overlapping ones.

    Returns ``""`` when no path qnode resolves to a span — caller falls back
    to whole-file loading so a missing tree-sitter install never drops code.
    """
    spans = ctx.def_spans or {}
    if not spans:
        return ""
    files_locs = ctx.call_graph_files or {}
    # qnode → (file, lo, hi); fall back to def-line ±pad when no AST span.
    by_file: dict[str, list[tuple[int, int]]] = defaultdict(list)
    whole_file: set[str] = set()
    n_ast = n_anchor = n_whole = 0
    for qn in dict.fromkeys(chunk.path_funcs):
        f = q_file(qn)
        if not f:
            continue
        sp = spans.get(qn)
        if sp:
            lo, hi = sp[0], sp[1]
            n_ast += 1
        else:
            # No AST span (regex-fallback file or unmapped lang) — anchor on
            # the def line from call_graph_files and pad generously.
            anchor = 0
            for ref in files_locs.get(q_name(qn), ()):
                rf, _, rl = ref.rpartition(":")
                if rf == f and rl.isdigit():
                    anchor = int(rl)
                    break
            if not anchor:
                # Neither an AST span nor a def-line anchor resolved for this
                # hop. Load THIS hop's file whole: the confirm/refute prompt
                # tells the model the slice contains the whole path, so a hop
                # must not be dropped from it.
                whole_file.add(f)
                n_whole += 1
                continue
            lo = hi = anchor
            n_anchor += 1
        by_file[f].append((max(1, lo - pad), hi + pad))
    # Always include the sink line even if its enclosing def wasn't on the
    # path (e.g. the sink is a bare call at module scope).
    if chunk.sink_ref:
        sf, _, sl = chunk.sink_ref.rpartition(":")
        if sf and sl.isdigit():
            ln = int(sl)
            by_file[sf].append((max(1, ln - pad), ln + pad))
    if not by_file and not whole_file:
        return ""

    parts: list[str] = []
    n_lines = 0
    for rel in chunk.files:       # preserve s3's file ordering (entry → sink)
        ranges = by_file.get(rel)
        if not ranges and rel not in whole_file:
            continue
        p = repo_root / rel
        if not p.is_file():
            parts.append(f"=== {rel} ===\n[FILE NOT FOUND]\n")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            parts.append(f"=== {rel} ===\n[READ ERROR: {e}]\n")
            continue
        lines = [ln[:MAX_LINE_CHARS]
                 for ln in _redact_source(text, rel).splitlines()]
        if rel in whole_file:
            emit_ranges = [(1, len(lines))] if lines else []
        else:
            emit_ranges = _merge_ranges(ranges, gap=pad)
        for lo, hi in emit_ranges:
            hi = min(hi, len(lines))
            if lo > hi:
                continue
            body = "\n".join(f"{i:5d}| {lines[i-1]}" for i in range(lo, hi + 1))
            parts.append(f"=== {rel} [lines {lo}-{hi}] ===\n{body}\n")
            n_lines += hi - lo + 1
    if not parts:
        return ""
    print(f"    [s4] {chunk.id}: function-slice {n_lines} lines "
          f"({n_ast} AST spans, {n_anchor} anchor-only, {n_whole} whole-file) "
          f"vs {sum(_count_lines(repo_root / f) for f in chunk.files)} "
          f"whole-file", file=sys.stderr)
    return "\n".join(parts)


def _merge_ranges(ranges: list[tuple[int, int]],
                  gap: int = 0) -> list[tuple[int, int]]:
    """Merge overlapping / near-adjacent (≤gap apart) line ranges."""
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + gap + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _count_lines(p: Path) -> int:
    try:
        return sum(1 for _ in p.open("r", encoding="utf-8", errors="replace"))
    except OSError:
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Neighbor context: callers/callees that live OUTSIDE this chunk. Gives the
# researcher enough upstream/downstream visibility to rule out FPs ("input is
# already validated in the caller") and confirm TPs ("callee passes it to
# Runtime.exec") without paying for the whole other chunk.
# ─────────────────────────────────────────────────────────────────────────────

def _neighbor_context(chunk: Chunk, ctx: ContextPackage, repo_root: Path,
                      cfg) -> str:
    n_lines = getattr(cfg.step4, "neighbor_context_lines", 12)
    max_neighbors = getattr(cfg.step4, "neighbor_context_max", 20)
    if n_lines <= 0:
        return ""

    chunk_files = set(chunk.files)
    fwd = ctx.call_graph or {}
    rev: dict[str, list[str]] = defaultdict(list)
    for caller, callees in fwd.items():
        for cal in callees:
            rev[cal].append(caller)

    # bare-name → [(file, line)] from s1's def-site scan, for excerpt anchors.
    def_line: dict[tuple[str, str], int] = {}
    for fn, locs in (ctx.call_graph_files or {}).items():
        for loc in locs:
            f, _, ln = loc.rpartition(":")
            def_line[(f or loc, fn)] = int(ln) if ln.isdigit() else 0

    # qnode → AST start line (preferred over heuristic fn text scans).
    qn_line: dict[str, int] = {}
    for qn, sp in (ctx.def_spans or {}).items():
        if isinstance(sp, (list, tuple)) and sp:
            try:
                qn_line[qn] = int(sp[0])
            except Exception:  # noqa: BLE001
                continue

    in_chunk_qns = {qn for qn in set(fwd) | set(rev)
                    if q_file(qn) in chunk_files}
    focus = set(chunk.focus_entry_points or ())
    in_chunk_qns.update(qn for qn in set(fwd) | set(rev)
                        if q_name(qn) in focus and q_file(qn) in chunk_files)

    want: list[tuple[str, str, str]] = []  # (relation, neighbor_qn, anchor_qn)
    for qn in in_chunk_qns:
        for caller in rev.get(qn, ()):
            if q_file(caller) not in chunk_files:
                want.append(("CALLS", caller, qn))
        for callee in fwd.get(qn, ()):
            if q_file(callee) not in chunk_files:
                want.append(("CALLED BY", callee, qn))

    seen: set[tuple[str, int]] = set()
    parts: list[str] = []
    for relation, neighbor_qn, anchor_qn in want:
        if len(parts) >= max_neighbors:
            break
        nfile = q_file(neighbor_qn)
        nname = q_name(neighbor_qn)
        if not nfile or nfile in chunk_files:
            continue
        nline = qn_line.get(neighbor_qn) or def_line.get((nfile, nname), 0)
        excerpt, lo = _excerpt(repo_root / nfile, nname, nline, n_lines)
        if excerpt is None or (nfile, lo) in seen:
            continue
        seen.add((nfile, lo))
        parts.append(
            f"-- {nfile}:{lo}  [{nname} {relation} {q_name(anchor_qn)}] --\n"
            f"{excerpt}\n"
        )
    if not parts:
        return ""
    print(f"    [s4] {chunk.id}: +{len(parts)} neighbor-context excerpts",
          file=sys.stderr)
    return ("\n=== NEIGHBOR CONTEXT (callers/callees OUTSIDE this chunk — "
            "read-only, do NOT report findings in these files) ===\n"
            + "\n".join(parts))


def _excerpt(p: Path, fn: str, hint_line: int, n: int) -> tuple[str | None, int]:
    try:
        lines = _redact_source(
            p.read_text(encoding="utf-8", errors="replace"), str(p)
        ).splitlines()
    except OSError:
        return None, 0
    anchor = hint_line - 1 if 0 < hint_line <= len(lines) else None
    if anchor is None:
        for i, ln in enumerate(lines):
            if fn and fn in ln and "(" in ln:
                anchor = i
                break
    if anchor is None:
        return None, 0
    lo, hi = max(0, anchor - 2), min(len(lines), anchor + n)
    body = "\n".join(f"{i+1:5d}| {lines[i]}" for i in range(lo, hi))
    return body, lo + 1


def _load_files_full(files: list[str], repo_root: Path) -> str:
    parts = []
    for rel in files:
        p = repo_root / rel
        if not p.is_file():
            parts.append(f"=== {rel} ===\n[FILE NOT FOUND]\n")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            parts.append(f"=== {rel} ===\n[READ ERROR: {e}]\n")
            continue
        text = _redact_source(text, rel)
        numbered = "\n".join(f"{i+1:5d}| {ln[:MAX_LINE_CHARS]}"
                             for i, ln in enumerate(text.splitlines()))
        parts.append(f"=== {rel} ===\n{numbered}\n")
    return "\n".join(parts)


def _load_sliding_window(chunk: Chunk, repo_root: Path,
                         ctx: ContextPackage | None = None) -> str:
    parts = []
    for rel in chunk.files:
        p = repo_root / rel
        if not p.is_file():
            print(f"    [s4] WARN: file not found: {rel}", file=sys.stderr)
            parts.append(f"=== {rel} ===\n[FILE NOT FOUND]\n")
            continue
        # Degrade per-file on an unreadable LARGE file (OSError: permission,
        # transient FS error, special file) instead of aborting the whole
        # chunk — mirrors _load_files_full's read-error guard.
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"    [s4] WARN: read error on {rel}: {e}", file=sys.stderr)
            parts.append(f"=== {rel} ===\n[READ ERROR: {e}]\n")
            continue
        lines = [ln[:MAX_LINE_CHARS] for ln in _redact_source(text, rel).splitlines()]
        anchors: list[int] = []
        if ctx is not None:
            anchors = _graph_anchor_lines_for_file(chunk, ctx, rel)
        windows = _windows_for_anchors(lines, anchors)
        if not windows:
            windows = _windows_for_entrypoints(lines, chunk.focus_entry_points)
        if not windows:
            # No entry-point anchors → tile the entire file so nothing is skipped.
            step = WINDOW_LINES - WINDOW_OVERLAP
            windows = [(lo, min(lo + WINDOW_LINES, len(lines)))
                       for lo in range(0, max(len(lines), 1), step)]
        for (lo, hi) in windows:
            slice_lines = lines[lo:hi]
            numbered = "\n".join(f"{i+lo+1:5d}| {ln}" for i, ln in enumerate(slice_lines))
            parts.append(f"=== {rel} [lines {lo+1}-{hi}] ===\n{numbered}\n")
    return "\n".join(parts)


def _windows_for_entrypoints(lines: list[str], entry_fns: list[str]) -> list[tuple[int, int]]:
    if not entry_fns:
        return []
    anchors: list[int] = []
    for i, ln in enumerate(lines):
        for fn in entry_fns:
            if fn in ln and "(" in ln:
                anchors.append(i)
                break
    if not anchors:
        return []
    half = WINDOW_LINES // 2
    raw = [(max(0, a - half), min(len(lines), a + half)) for a in sorted(set(anchors))]
    merged = [raw[0]]
    for lo, hi in raw[1:]:
        plo, phi = merged[-1]
        if lo <= phi + WINDOW_OVERLAP:
            merged[-1] = (plo, max(phi, hi))
        else:
            merged.append((lo, hi))
    return merged


def _windows_for_anchors(lines: list[str], anchors: list[int]) -> list[tuple[int, int]]:
    """Window builder from exact 1-based line anchors."""
    if not anchors:
        return []
    half = WINDOW_LINES // 2
    norm = sorted({a for a in anchors if 1 <= a <= len(lines)})
    if not norm:
        return []
    raw = [(max(0, a - 1 - half), min(len(lines), a - 1 + half)) for a in norm]
    merged = [raw[0]]
    for lo, hi in raw[1:]:
        plo, phi = merged[-1]
        if lo <= phi + WINDOW_OVERLAP:
            merged[-1] = (plo, max(phi, hi))
        else:
            merged.append((lo, hi))
    return merged


def _graph_anchor_lines_for_file(chunk: Chunk, ctx: ContextPackage,
                                 rel: str) -> list[int]:
    """Collect graph/AST anchor lines for one file.

    Priority sources: path qnodes, def_spans for focus entry points/sinks,
    call-graph def-site lines, and explicit sink_ref.
    """
    out: list[int] = []
    spans = ctx.def_spans or {}

    def _add(n: int) -> None:
        if n > 0 and n not in out:
            out.append(n)

    for qn in dict.fromkeys(chunk.path_funcs or []):
        if q_file(qn) != rel:
            continue
        sp = spans.get(qn)
        if sp and len(sp) >= 1:
            _add(int(sp[0]))

    focus = set(chunk.focus_entry_points or ())
    for qn, sp in spans.items():
        if q_file(qn) != rel or not sp:
            continue
        bare = q_name(qn)
        if bare in focus:
            _add(int(sp[0]))

    for ep in ctx.entry_points:
        if ep.file == rel:
            for qn, sp in spans.items():
                if q_file(qn) == rel and q_name(qn) == ep.function and sp:
                    _add(int(sp[0]))
                    break

    for sink in ctx.unsafe_sinks:
        if sink.file == rel:
            _add(int(getattr(sink, "line", 0) or 0))
            for qn, sp in spans.items():
                if q_file(qn) == rel and q_name(qn) == sink.function and sp:
                    _add(int(sp[0]))
                    break

    if chunk.sink_ref:
        sf, _, sl = chunk.sink_ref.rpartition(":")
        if sf == rel and sl.isdigit():
            _add(int(sl))

    # def-site hints for focus functions when AST span is unavailable.
    if focus:
        for fn in focus:
            for loc in (ctx.call_graph_files or {}).get(fn, ()):
                lf, _, ln = loc.rpartition(":")
                if lf == rel and ln.isdigit():
                    _add(int(ln))

    return out
