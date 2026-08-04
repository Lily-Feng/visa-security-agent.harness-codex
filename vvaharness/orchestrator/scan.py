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
from __future__ import annotations
"""orchestrator.scan — see package docstring."""
import copy
import os
import subprocess
import sys
import time
from pathlib import Path
from vvaharness import config as config_mod
from vvaharness.injectors.cve_feed import load_cves
from vvaharness.injectors.design_controls import load_controls
from vvaharness.models import (ContextPackage, TaskManifest, Finding,
                    FinalReport, ThreatModel)
from vvaharness.pipeline.stages import (
    s0_seed, s1_preprocess, s1_autoexclude, s2_threatmodel, s3_decompose,
    s4_deepdive, s5_prefilter, s6_verify, s7_dedup, s8_chain)
from vvaharness.util import metrics as _metrics
from vvaharness.backends.llm import resolve as resolve_model
from vvaharness.util.tokens import TOKENS
from vvaharness.util import errlog as _errlog
from vvaharness.util.status import stage
from vvaharness.util.scan_progress import ScanProgress
from vvaharness.report import enrich as vcs_enrich
from vvaharness.report.redact import redact
from vvaharness.orchestrator.config_paths import (_resolve_against, _iter_model_roles)
from vvaharness.orchestrator.checkpoints import (save_ckpt, load_ckpt,
    run_id_for)
from vvaharness.orchestrator import store as _store
from vvaharness.orchestrator.cmdb import _load_app_profile
from vvaharness.orchestrator.enrich_findings import _enrich_findings


def _head_sha(repo: Path) -> str | None:
    """Return the scanned repo's current git HEAD SHA (or None for a non-git
    target / git failure). Used to pin the report's git_sha and to refuse
    remediation when the working tree has moved since the scan."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=20)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:                                  # noqa: BLE001
        return None


def _hydrate_ctx_callgraph_from_store(run_id: str, ctx: ContextPackage,
                                      *steps: str) -> ContextPackage:
    """Use the stored SQLite callgraph for runtime prompt context.

    The step list is searched in order; first hit wins.
    """
    for step in steps:
        graph = _store.load_callgraph(run_id, step)
        if not graph:
            continue
        print(
            "  [graphdb] hydrated ctx.call_graph from sqlite: "
            f"step={step} nodes={graph['node_count']} edges={graph['edge_count']}",
            file=sys.stderr,
        )
        return ctx.model_copy(update={
            "call_graph": graph["call_graph"],
            "call_graph_files": graph["call_graph_files"],
            "def_spans": graph["def_spans"],
        })
    return ctx


def scan_repo(repo: Path, repo_name: str, application_id: str | None,
              args, cfg,
              path_prefix: str | None = None) -> tuple[Path | None, int]:
    """
    Run the profile-selected S0/S1-S11 workflow against one local checkout.

    Returns (markdown_report_path, verified_finding_count). Raises on failure —
    the batch driver catches and records it. Returns (None, 0) when
    --stop-after short-circuits before s8. Step 10 (remediation) runs when
    selected via --remediate or cfg.step_remediate.enabled; it walks the
    findings one-by-one with the Remediation Agent and writes per-finding
    artefacts under <repo>/security-remediation/. Step 11 (validation) runs
    when cfg.step_validate.enabled; it reads those artefacts
    and fills each DTO's validation block via the vvaharness.validation package.
    """
    run_id = run_id_for(repo)

    # ── per-repo output layout ───────────────────────────────────────────
    # SECURITY: checkpoint state MUST NOT live inside the scanned repo — a
    # hostile target could otherwise pre-plant state that --resume would
    # load. (Payloads are JSON, never pickle, so planted bytes cannot execute
    # code — but they could still poison the pipeline, so defense-in-depth
    # keeps them outside the clone.) State is the SQLite DB at
    # <state>/vvaharness.db; the legacy <state>/checkpoints/<run_id>/ dir is
    # used only for the --auto-step1 overlay file. Override the root with
    # $VVAHARNESS_STATE_DIR for CI / tests.
    _state = Path(os.environ.get("VVAHARNESS_STATE_DIR")
                  or (Path.home() / ".vvaharness" / "state"))
    ckpt_dir = _state / "checkpoints" / run_id
    # Checkpoint payloads now live in the SQLite state store; ckpt_dir is
    # passed through to save_ckpt/load_ckpt for call-site compatibility
    # (they ignore it). It is created on disk ONLY under --auto-step1, for
    # the per-target step1.yaml overlay — see the auto_step1 block below.
    _store.register_run(run_id, repo_root=str(repo.resolve()),
                        repo_name=repo_name, app_id=application_id)

    # Fresh scan (no --resume) == start over. run_id is path-derived, so a
    # rescan of this same repo reuses the prior run's checkpoint rows; without
    # an explicit reset, stale rows survive — steps a stopped run never reached,
    # and the dynamic remediate_<idx>/validate_<id> rows (whose keys may not
    # recur for a changed finding set) — and a later --resume would load them.
    # Purge them now so the only state a future --resume can see is this scan's.
    # Gated on `not args.resume`: --resume deliberately keeps prior state.
    if not args.resume:
        _cleared = _store.reset_run(run_id)
        if _cleared:
            print(f"  [ckpt] reset {run_id[:12]}… — cleared {_cleared} stale "
                  f"checkpoint row(s) from a prior scan", file=sys.stderr)

    out_dir = repo / "security-scan"

    # Belt-and-braces: refuse --resume if ckpt_dir somehow resolves inside the
    # target tree (symlink, hostile $VVAHARNESS_STATE_DIR, future refactor).
    if args.resume:
        try:
            ckpt_dir.resolve().relative_to(repo.resolve())
        except ValueError:
            pass  # good — ckpt_dir is OUTSIDE the repo
        else:
            print("✗ refusing --resume: checkpoint dir resolves inside the "
                  "scanned repository", file=sys.stderr)
            return None, 0

    t0 = time.time()
    start_ts = _metrics.now_iso()
    # Filesystem-safe timestamp (':' is illegal on Windows).
    ts_safe = start_ts.replace(":", "").replace("-", "")
    module_safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in repo_name)
    out_path = out_dir / f"{module_safe}_{ts_safe}_report.md"
    sarif_path = out_dir / f"{module_safe}_{ts_safe}_report.sarif"
    # Configure the per-scan error log BEFORE any stage (incl. the optional
    # auto-step1 block below) can call _errlog.log(), so its failures land in
    # <repo>/security-scan/..._errors.jsonl rather than the module-global
    # default (cwd/pipeline-errors.jsonl).
    _errlog.configure(out_dir / f"{module_safe}_{ts_safe}_errors.jsonl")

    # ── Optional: AI-derive a per-target step1 overlay ──────────────────
    # Runs once per cloned target, BEFORE s1, and layers its exclusions on
    # top of config.yaml's step1. cfg is deep-copied so batch entries don't
    # accumulate each other's overlays. Skipped when --step1-config supplied
    # an explicit overlay (handled at startup).
    if getattr(args, "auto_step1", False):
        ckpt_dir.mkdir(parents=True, exist_ok=True)
        auto_path = ckpt_dir / "step1.yaml"
        if not (args.resume and auto_path.is_file()):
            try:
                with TOKENS.phase("s1-autoexclude"):
                    s1_autoexclude.run(repo, cfg, out_path=auto_path)
            except Exception as e:
                print(f"  [auto-step1] WARN: failed ({e}); continuing with "
                      f"global step1 only.", file=sys.stderr)
                _errlog.log("s1.autoexclude", repo_name, e)
                auto_path = None
        else:
            print(f"  [auto-step1] reusing {auto_path}", file=sys.stderr)
        if auto_path and auto_path.is_file():
            cfg = config_mod.Config(copy.deepcopy(cfg._data))
            cfg, _ = config_mod.apply_step1_overlay(cfg, auto_path)
            s1 = cfg._data.get("step1", {})
            print(f"  [auto-step1] applied overlay  "
                  f"(exclude_dirs={len(s1.get('exclude_dirs') or [])} "
                  f"exts={len(s1.get('exclude_exts') or [])} "
                  f"globs={len(s1.get('exclude_globs') or [])})",
                  file=sys.stderr)

    # Optional file/chunk progress tracker (stages consume cfg._scan_progress).
    tracker = ScanProgress.from_cfg(cfg, repo_name=repo_name)
    cfg._data["_scan_progress"] = tracker

    def _sp_start(step_id: str, label: str) -> None:
        if tracker.enabled:
            tracker.stage_started(step_id, label=label)

    def _sp_done(step_id: str, *, outcome: str = "completed",
                 detail: str = "") -> None:
        if tracker.enabled:
            tracker.stage_done(step_id, outcome=outcome, detail=detail)

    print(f"Agentic SAST  repo={repo}  module={repo_name}  "
          f"app_id={application_id or '-'}  run_id={run_id}",
          file=sys.stderr)
    print("  models:", file=sys.stderr)
    for role, m in _iter_model_roles(cfg):
        mid, via, extras = resolve_model(m)
        ex = f" {extras}" if extras else ""
        print(f"    {role:<11} -> {mid:<28} [{via}]{ex}", file=sys.stderr)

    # ── inject external context once ─────────────────────────────────────
    cfg_dir = Path(args.config).resolve().parent
    cves = load_cves(_resolve_against(cfg_dir, cfg.inject.cve_file))
    controls = load_controls(_resolve_against(cfg_dir, cfg.inject.controls_file))
    app_profile, app_info = _load_app_profile(application_id)
    print(f"  injected: {len(cves)} CVEs, {len(controls)} controls, "
          f"app_profile={'yes' if app_profile else 'no'}", file=sys.stderr)

    def _m(role: str) -> str:
        mid, via, _ = resolve_model(getattr(cfg.models, role))
        return f"{mid} [{via}]"

    # ── Step 0 — Static seed (profile-controlled) ──────────────────────
    # Pure static, zero tokens. Runs the configured seed engine over the in-scope file set and
    # returns EntryPoint/Sink/taint-path lists that s1 merges into the
    # ContextPackage. default.yaml and taint.yaml enable it; sdk.yaml,
    # full.yaml, and partial configs that inherit the scalar default disable it.
    seed = load_ckpt(ckpt_dir, run_id, "s0") if args.resume else None
    if seed is None:
        s0_engine = getattr(getattr(cfg, "step0", None), "engine", "callgraph")
        _sp_start("s0", f"{s0_engine}")
        with stage(f"Step 0 — Static seed ({s0_engine})", n=0, total=11), \
                TOKENS.phase("s0-seed"):
            seed = s0_seed.run(str(repo), cfg, ckpt_dir=ckpt_dir)
        save_ckpt(ckpt_dir, run_id, "s0", seed)
        _sp_done("s0", detail=(f"entry_points={len(getattr(seed, 'entry_points', []) or [])} "
                               f"sinks={len(getattr(seed, 'unsafe_sinks', []) or [])}"))
    else:
        _sp_done("s0", outcome="cached")
    _store.save_callgraph(run_id, "s0", seed)
    if args.stop_after == "s0":
        return None, 0

    # ── Step 1 — Pre-process (runs first; s2 consumes its output) ───────
    ctx: ContextPackage | None = load_ckpt(ckpt_dir, run_id, "s1") if args.resume else None
    if ctx is None:
        _sp_start("s1", f"{_m('preprocess')}")
        with stage(f"Step 1 — Pre-process ({_m('preprocess')})", n=1, total=11), \
                TOKENS.phase("s1-preprocess"):
            ctx = s1_preprocess.run(str(repo), cfg, cves, controls, seed=seed)
        save_ckpt(ckpt_dir, run_id, "s1", ctx)
        _sp_done("s1", detail=f"files={len(getattr(ctx, 'all_files', []) or [])}")
    else:
        _sp_done("s1", outcome="cached")
    _store.save_callgraph(run_id, "s1", ctx)
    ctx = _hydrate_ctx_callgraph_from_store(run_id, ctx, "s1", "s0")
    ctx.app_profile = app_profile
    if args.stop_after == "s1":
        return None, 0

    # ── Step 2 — Threat model (optional; reasons over s1's mapped surface) ─
    s2_enabled = getattr(getattr(cfg, "step2", None), "enabled", True)
    tm: ThreatModel | None = (load_ckpt(ckpt_dir, run_id, "s2")
                              if args.resume else None)
    if tm is None and s2_enabled:
        try:
            _sp_start("s2", f"{_m('threatmodel')}")
            with stage(f"Step 2 — Threat model ({_m('threatmodel')})",
                       n=2, total=11), TOKENS.phase("s2-threatmodel"):
                tm = s2_threatmodel.run(str(repo), repo_name, cfg, cves,
                                        controls, ctx=ctx,
                                        app_profile=app_profile)
            save_ckpt(ckpt_dir, run_id, "s2", tm)
            _sp_done("s2", detail=(f"assets={len(tm.assets)} boundaries={len(tm.trust_boundaries)} "
                                   f"threats={len(tm.threats)}"))
        except Exception as e:
            print(f"  [s2] WARN: threat-model step failed ({e}); "
                  f"continuing without it.", file=sys.stderr)
            _errlog.log("s2", repo_name, e)
            _sp_done("s2", outcome="error",
                     detail=redact(f"{type(e).__name__}: {e}"))
            tm = None
    elif tm is not None:
        _sp_done("s2", outcome="cached")
    else:
        _sp_done("s2", outcome="skipped", detail="disabled in config")
    # Always re-attach (s2/CMDB may differ across resumed runs).
    ctx.threat_model = tm
    _store.save_callgraph(run_id, "s2", ctx)
    ctx = _hydrate_ctx_callgraph_from_store(run_id, ctx, "s2", "s1", "s0")
    if args.stop_after == "s2":
        return None, 0

    # ── Step 3 ───────────────────────────────────────────────────────────
    manifest: TaskManifest | None = load_ckpt(ckpt_dir, run_id, "s3") if args.resume else None
    if manifest is None:
        _sp_start("s3", f"{_m('decompose')}")
        with stage(f"Step 3 — Decompose ({_m('decompose')})", n=3, total=11), \
                TOKENS.phase("s3-decompose"):
            manifest = s3_decompose.run(ctx, cfg)
        save_ckpt(ckpt_dir, run_id, "s3", manifest)
        _sp_done("s3", detail=f"chunks={len(getattr(manifest, 'chunks', []) or [])}")
    else:
        _sp_done("s3", outcome="cached")
    _store.save_callgraph(run_id, "s3", ctx)
    if args.stop_after == "s3":
        return None, 0

    # ── Step 4 ───────────────────────────────────────────────────────────
    s4_ckpt = load_ckpt(ckpt_dir, run_id, "s4") if args.resume else None
    chunk_outcomes: dict[str, str] = {}
    if s4_ckpt is None:
        _sp_start("s4", f"{_m('deepdive')}")
        with stage(f"Step 4 — Deep-dive ({_m('deepdive')}; {cfg.step4.runs} runs, "
                   f"vote≥{cfg.step4.vote_threshold}, "
                   f"parallel={getattr(cfg.step4, 'parallel', 1)})",
                   n=4, total=11), TOKENS.phase("s4-deepdive"):
            findings, chunk_outcomes = s4_deepdive.run(manifest.sorted_chunks(), ctx, cfg)
        # Bundle the per-chunk outcomes with the findings so a --resume that
        # rebuilds metrics still sees the coverage tally.
        save_ckpt(ckpt_dir, run_id, "s4",
                  {"findings": findings, "outcomes": chunk_outcomes})
        _sp_done("s4", detail=f"findings={len(findings)}")
    elif isinstance(s4_ckpt, dict):
        findings = s4_ckpt.get("findings", [])
        chunk_outcomes = s4_ckpt.get("outcomes", {})
        _sp_done("s4", outcome="cached")
    else:  # legacy bare-list checkpoint (pre outcome-tracking)
        findings = s4_ckpt
        _sp_done("s4", outcome="cached")
    _store.save_callgraph(run_id, "s4", ctx)
    if args.stop_after == "s4":
        return None, 0

    raw_count = len(findings)

    # ── Steps 5+6+7 — Pre-filter + verify + dedup (checkpointed together) ──
    s7_ckpt = load_ckpt(ckpt_dir, run_id, "s7") if args.resume else None
    if s7_ckpt is None:
        _sp_start("s5", "prefilter")
        with stage("Step 5 — Pre-filter (deterministic + semantic pre-dedup)",
                   n=5, total=11), TOKENS.phase("s5-prefilter"):
            findings, pre_dropped = s5_prefilter.run(findings, ctx, cfg)
        _sp_done("s5", detail=f"kept={len(findings)} dropped={len(pre_dropped)}")
        if args.stop_after == "s5":
            return None, 0
        # Re-hydrate callgraph context from SQLite right before verification so
        # s6 always reasons over the latest persisted graph snapshot.
        ctx = _hydrate_ctx_callgraph_from_store(run_id, ctx,
                                                "s4", "s3", "s2", "s1", "s0")
        _sp_start("s6", f"{_m('verify')}")
        with stage(f"Step 6 — Verify ({_m('verify')})", n=6, total=11), \
                TOKENS.phase("s6-verify"):
            verified, dropped = s6_verify.run(findings, ctx, cfg)
        _sp_done("s6", detail=f"verified={len(verified)} dropped={len(dropped)}")
        if args.stop_after == "s6":
            return None, 0
        # Ensure s7 semantic dedup sees the latest sqlite-backed callgraph
        # context before making root-cause grouping decisions.
        ctx = _hydrate_ctx_callgraph_from_store(run_id, ctx,
                                                "s4", "s3", "s2", "s1", "s0")
        _sp_start("s7", f"{_m('dedup')}")
        with stage(f"Step 7 — Dedup ({_m('dedup')})", n=7, total=11), \
                TOKENS.phase("s7-dedup"):
            canonical, dup_dropped = s7_dedup.run(verified, cfg, ctx=ctx)
        _sp_done("s7", detail=f"canonical={len(canonical)} dup_dropped={len(dup_dropped)}")
        save_ckpt(ckpt_dir, run_id, "s7",
                  (pre_dropped, verified, dropped, canonical, dup_dropped))
    elif len(s7_ckpt) == 5:
        pre_dropped, verified, dropped, canonical, dup_dropped = s7_ckpt
        _sp_done("s5", outcome="cached")
        _sp_done("s6", outcome="cached")
        _sp_done("s7", outcome="cached")
    else:  # legacy 4-tuple checkpoint (pre_dropped not stored)
        verified, dropped, canonical, dup_dropped = s7_ckpt
        pre_dropped = []
        _sp_done("s5", outcome="cached")
        _sp_done("s6", outcome="cached")
        _sp_done("s7", outcome="cached")
    # Honour --stop-after s5 / s6 even on a --resume that loaded a combined
    # s5+6+7 checkpoint: the in-branch early-returns above are skipped when
    # s7_ckpt is present, so without this the flags would be silently ignored.
    if args.stop_after in ("s5", "s6"):
        return None, 0
    _enrich_findings(canonical, app_info, path_prefix=path_prefix)
    all_dropped = pre_dropped + dropped + dup_dropped
    _store.save_callgraph(run_id, "s7", ctx)
    if args.stop_after == "s7":
        return None, 0

    # ── Step 8 — Chain ───────────────────────────────────────────────────
    # Ensure chain analysis sees the latest sqlite-backed callgraph context
    # for reachability reasoning and exploit-chain assembly.
    ctx = _hydrate_ctx_callgraph_from_store(run_id, ctx,
                                            "s4", "s3", "s2", "s1", "s0")
    report: FinalReport | None = load_ckpt(ckpt_dir, run_id, "s8") if args.resume else None
    if report is None:
        end_ts = _metrics.now_iso()
        fp = sum(1 for d in dropped if d.reason == "FALSE_POSITIVE")
        metrics = _metrics.build(
            ctx, manifest,
            repo_name=repo_name, start_ts=start_ts, end_ts=end_ts,
            raw_findings=raw_count, true_pos=len(verified),
            false_pos=fp, duplicates=len(dup_dropped),
            chunk_outcomes=chunk_outcomes,
        )
        _sp_start("s8", f"{_m('chain')}")
        with stage(f"Step 8 — Chain ({_m('chain')})", n=8, total=11), \
                TOKENS.phase("s8-chain"):
            report = s8_chain.run(canonical, ctx, cfg,
                              dropped=all_dropped,
                              raw_findings_count=raw_count,
                              metrics=metrics)
        report.repo_name = repo_name
        report.threat_model = tm
        report.app_profile = app_profile
        if getattr(cfg.output, "emit_unreachable_appendix", False):
            report.unreachable_files = manifest.unreachable_files
        # B9: pin HEAD so step 10 (now or later via remediate --from-report)
        # can refuse on mismatch.
        report.git_sha = _head_sha(repo)
        save_ckpt(ckpt_dir, run_id, "s8", report)
        _sp_done("s8", detail=f"findings={len(report.findings)} chains={len(report.chains)}")
    else:
        _sp_done("s8", outcome="cached")
    _store.save_callgraph(run_id, "s8", ctx)

    # ── Output (always re-render — cheap, and s9 needs it on disk) ───────
    out_path.parent.mkdir(parents=True, exist_ok=True)
    md_text = redact(report.to_markdown())
    out_path.write_text(md_text, encoding="utf-8")
    n_redacted = sum(getattr(redact, "last_counts", {}).values())
    print(f"  [out] wrote {out_path}"
          + (f"  ({n_redacted} sensitive values masked)" if n_redacted else ""),
          file=sys.stderr)
    if args.stop_after == "s8":
        return out_path, len(report.findings)

    # ── Step 9 — SARIF (parse the already-enriched MD) ──────────────────
    s9_done = load_ckpt(ckpt_dir, run_id, "s9") if args.resume else None
    if s9_done is None or not sarif_path.exists():
        _sp_start("s9", "sarif")
        scan_health = {
            "executionSuccessful": not report.degraded,
            "degraded": report.degraded,
            "chunks_failed": report.metrics.chunks_failed if report.metrics else 0,
            "errors_by_stage": (report.metrics.errors_by_stage
                                if report.metrics else {}),
        }
        with stage(f"Step 9 — SARIF (app_id={application_id or '-'})",
                   n=9, total=11):
            vcs_enrich.md_to_sarif(str(out_path), application_id, app_info,
                                    str(sarif_path), scan_health=scan_health)
        print(f"  [out] wrote {sarif_path}", file=sys.stderr)
        save_ckpt(ckpt_dir, run_id, "s9", str(sarif_path))
        _sp_done("s9", detail=f"sarif={sarif_path.name}")
    else:
        _sp_done("s9", outcome="cached")
    _store.save_callgraph(run_id, "s9", ctx)
    if args.stop_after == "s9":
        return out_path, len(report.findings)

    # ── Step 10 — Remediate (profile/flag-controlled) ───────────────────
    # B3: runs INSIDE scan_repo() so the clone still exists. Selected by
    # --remediate or step_remediate.enabled. The Remediation Agent walks the
    # verified findings one-by-one and writes per-finding artefacts under
    # <repo>/security-remediation/<NN_slug>/ — exactly the same layout the
    # standalone `vvaharness remediate` command produces. 
    rem_cfg = getattr(cfg, "step_remediate", None)
    rem_on = bool(getattr(args, "remediate", False)
                  or getattr(rem_cfg, "enabled", False))

    if rem_on and report.findings:
        rem_err = _remediate_preflight(cfg, args, repo, report)
        if rem_err:
            print(f"  [s10] DISABLED — {rem_err}", file=sys.stderr)
            _errlog.log("s10.preflight", repo_name, RuntimeError(rem_err))
        else:
            with stage(f"Step 10 — Remediate ({_m('remediate')})",
                       n=10, total=11), TOKENS.phase("s10-remediate"):
                _run_remediation(report, repo, cfg, ckpt_dir, run_id,
                                 resume=args.resume,
                                 top=getattr(args, "top", None),
                                 report_md=out_path)

    if args.stop_after == "s10":
        return out_path, len(report.findings)

    # ── Step 11 — Validate (profile-controlled) ─────────────────────────
    val_cfg = getattr(cfg, "step_validate", None)
    val_on = bool(getattr(val_cfg, "enabled", False))
    if val_on:
        val_err = _validate_preflight(cfg)
        if val_err:
            print(f"  [s11] DISABLED — {val_err}", file=sys.stderr)
            _errlog.log("s11.preflight", repo_name, RuntimeError(val_err))
        else:
            with stage("Step 11 — Validate (s11)", n=11, total=11), \
                    TOKENS.phase("s11-validate"):
                _run_validation(repo, cfg, config_path=args.config, resume=args.resume,
                                report_md=out_path)
    if args.stop_after == "s11":
        return out_path, len(report.findings)

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.0f}s. {len(report.findings)} verified findings "
          f"({len(report.dropped)} dropped), {len(report.chains)} chains.",
          file=sys.stderr)
    m = report.metrics
    tok_p = m.prompt_tokens if m and m.prompt_tokens is not None else "unavailable"
    tok_c = m.completion_tokens if m and m.completion_tokens is not None else "unavailable"
    tok_t = m.total_tokens if m and m.total_tokens is not None else "unavailable"
    print(f"Tokens: prompt={tok_p}, completion={tok_c}, total={tok_t}",
          file=sys.stderr)
    print(f"Report: {out_path}", file=sys.stderr)

    # Print markdown to stdout for piping
    print(md_text)
    return out_path, len(report.findings)


def _ranked_to_ra_finding(rf, idx: int):
    """Adapt a pipeline ``RankedFinding`` into the Remediation Agent's
    lightweight ``Finding`` shape so the same prompt/artefact path the
    standalone ``vvaharness remediate`` command uses also drives the
    in-pipeline run. Kept local to the orchestrator so remediation does not
    depend on the (separately owned) validation bridge."""
    from vvaharness.remediation_agent.report_parser import Finding as RAFinding
    f = rf.finding
    loc = f"{f.file}:{f.line_start}"
    if f.line_end and f.line_end != f.line_start:
        loc = f"{f.file}:{f.line_start}-{f.line_end}"
    body_parts = [
        f"### {idx + 1}. [{rf.severity.value.upper()}] {f.title}",
        f"**Class:** {f.cwe or f.vuln_class.value}",
        f"**File:** `{loc}`",
        "",
        f.description or "",
    ]
    if f.source_ref:
        body_parts.append(f"**Source:** {f.source_ref}")
    if f.sink_ref:
        body_parts.append(f"**Sink:** {f.sink_ref}")
    if f.code_snippet:
        body_parts.append("\n```\n" + f.code_snippet + "\n```")
    return RAFinding(
        index=idx + 1,
        severity=rf.severity.value.upper(),
        title=f.title,
        file=loc,
        body="\n".join(body_parts),
    )


def _run_remediation(report: FinalReport, repo: Path, cfg, ckpt_dir, run_id,
                     *, resume: bool = False, top: int | None = None,
                     report_md: Path | None = None) -> None:
    """Walk the verified findings one-by-one with the Remediation Agent.

    Adapts the pipeline's ranked findings into the Remediation Agent's
    ``Finding`` shape, applies the profile-driven top-N cap, then delegates the
    per-finding loop to the SAME ``runner.process_findings`` the standalone
    ``vvaharness remediate`` command uses — so the in-pipeline and standalone
    paths share ONE loop implementation (checkpoint/resume, failure-isolation,
    policy gate, and report augmentation) instead of duplicating it (CWE-1041).

    Each finding's artefacts land under ``<repo>/security-remediation/<NN_slug>/``
    (a canonical ``remediate_report.json`` plus an ``evidence/`` subfolder) for
    the s11 validation step to read.

    The top-N cap is profile-driven (``step_remediate.top_n_findings``); when
    *top* is set (``--top N``) it overrides the profile for this run. Either way
    only the N highest-CVSS findings are remediated (limit & reorder, highest
    score first) via the SAME shared selection helper the standalone command
    uses; selection happens on the in-memory list only — the report on disk is
    untouched.

    Progress is checkpointed per finding (``remediate_<idx>``) using the same
    state store as the scan pipeline: the scan's existing ``ckpt_dir``/``run_id``
    are threaded through ``Layout`` so ``--resume`` skips completed findings and
    scan + remediation state live together."""
    from vvaharness.remediation_agent.report_parser import REMEDIATION_DIR_NAME
    from vvaharness.remediation_agent.select import resolve_top, select_top_logged
    from vvaharness.remediation_agent.runner import process_findings
    from vvaharness.remediation_agent.discovery import Layout
    from vvaharness.remediation_agent.options import RemediateOptions

    rem_dir = repo / REMEDIATION_DIR_NAME
    rem_dir.mkdir(parents=True, exist_ok=True)

    # Top-N cap: profile's step_remediate.top_n_findings is the source of truth;
    # --top N overrides it ad-hoc. Keep only the N highest-CVSS findings.
    # RankedFinding carries the numeric base score on its wrapped Finding; the
    # shared helper applies the SAME gate + log line as the standalone command
    # and reorders highest→lowest, then we adapt each to the Remediation Agent's
    # Finding shape (process_findings consumes a pre-selected list; selecting on
    # RankedFindings is orchestrator-specific).
    eff_top = resolve_top(top, cfg)
    selected = select_top_logged(
        report.findings, eff_top,
        score_of=lambda rf: rf.finding.cvss_score,
        log_prefix="[s10]")
    findings = [_ranked_to_ra_finding(rf, idx) for idx, rf in enumerate(selected)]

    # The Anthropic and DeepAgents harnesses expose confined Edit/Write tools;
    # via:openai remains read-only on the legacy dispatcher.
    _, _remediate_via, _ = resolve_model(cfg.models.remediate)
    if _remediate_via in ("cli", "sdk", "deepagents"):
        print(f"  [s10] ⚠ FIX MODE — about to EDIT source files in {repo}; "
              f"rerun with --stop-after s9 to scan without modifying the target", file=sys.stderr)
    else:
        print(f"  [s10] ⚠ {_remediate_via} backend cannot edit files (no Edit/Write tool); "
              f"fix mode errors per finding — use report-only or via:cli/sdk/deepagents",
              file=sys.stderr)
    print(f"  [s10] remediating {len(findings)} finding(s) via Remediation Agent; "
          f"artefacts → {rem_dir}", file=sys.stderr)

    # Delegate the per-finding loop to the shared runner, retiring the duplicate
    # loop. Thread the scan's existing ckpt_dir/run_id through Layout so resume
    # state is shared, and force fix mode (the in-pipeline path always auto-edits);
    # process_findings builds the policy context and runs the SAME deny-list +
    # playbook + diff post-gate, and binds *report_md* for augmentation so the
    # combined report cannot be redirected by a newest-wins glob (MV-06).
    layout = Layout(rem_dir=rem_dir, ckpt_dir=ckpt_dir, run_id=run_id)
    opts = RemediateOptions(resume=resume, mode="fix")
    process_findings(findings, layout=layout, cfg=cfg, repo_path=repo,
                     opts=opts, report=report_md)




def _run_validation(repo: Path, cfg, *, config_path: str, resume: bool = False,
                    report_md: Path | None = None) -> None:
    """Invoke the s11 validation package against any validatable remediate_report.json files.

    ``config_path`` is the scan's resolved ``--config`` (``args.config``): the validator
    re-reads it so the s11 model/backend/budget match the profile the scan ran with,
    rather than silently falling back to the packaged default.

    Resumes (skips already-checkpointed findings) iff the scan was launched with
    ``--resume`` — lockstep with s10 remediation."""
    from vvaharness.pipeline.stages.s11_validate import run as s11_run
    rc = s11_run(repo, cfg=cfg, config_path=config_path, resume=resume, report_md=report_md)
    if rc != 0:
        print(f"  [s11] WARN: validation exited with code {rc}", file=sys.stderr)


def _remediate_preflight(cfg, args, repo: Path, report) -> str | None:
    """Hard checks before remediation may run. Returns an error string
    (which DISABLES remediation for this repo, scan continues) or
    None to proceed.

    Checks are scoped to what the Remediation Agent needs: a configured
    ``models.remediate`` role, a usable credential for that role's backend, and a
    stable working tree (so the report's line numbers still match the code on
    disk)."""
    rem = getattr(cfg.models, "remediate", None)
    if rem is None:
        return "models.remediate must be set"

    # The startup probe only WARNs on a post-scan credential gap so detection can
    # still run; this is where that gap becomes the decision to skip s10.
    # Imported locally: vvaharness.util.environment reaches back into the validation
    # CLI, which imports this package.
    from vvaharness.util.environment import _backend_credential_ok
    model_id, via, _ = resolve_model(rem)
    ready, detail = _backend_credential_ok(via, model_id, getattr(rem, "provider", None))
    if not ready:
        return f"models.remediate via:{via} — {detail}"

    # B9: refuse if the working tree has moved since the report was
    # built (line numbers would be stale → patch lands on wrong code).
    cur = _head_sha(repo)
    if (report.git_sha and cur and report.git_sha != cur
            and not getattr(args, "force", False)):
        return (f"HEAD moved since scan ({report.git_sha[:8]} → "
                f"{cur[:8]}); pass --force to override")
    return None


def _validate_preflight(cfg: object) -> str | None:
    """Hard checks before in-scan s11 validation may run.

    Returns an error string (which DISABLES validation for this repo, scan continues)
    or None to proceed. Symmetrical with ``_remediate_preflight``: a configured
    ``models.validate.orchestrator`` role, a backend s11 can actually run on, and a
    usable credential for it. Mirrors ``util.environment._validate_checks`` so
    ``vvaharness doctor`` and a real scan agree on what makes s11 runnable - the
    startup probe only WARNs on a post-scan credential gap, so this is where that
    gap turns into skipping the stage instead of failing the scan.
    """
    # Local import: see the note in _remediate_preflight.
    from vvaharness.util.environment import _backend_credential_ok
    from vvaharness.validation.cli._model import (
        _normalize_validate_backend,
        _validate_model_spec,
    )

    val = _validate_model_spec(cfg)
    if val is None:
        return "models.validate.orchestrator must be set"

    model_id, via, _ = resolve_model(val)
    # Same routing the validate CLI applies, so this gate checks the credential for the
    # backend s11 will actually use rather than the one the profile spelled.
    via, provider = _normalize_validate_backend(via, getattr(val, "provider", None))

    ready, detail = _backend_credential_ok(via, model_id, provider)
    return None if ready else f"models.validate.orchestrator via:{via} — {detail}"
