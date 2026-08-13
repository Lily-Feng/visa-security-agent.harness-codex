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
"""orchestrator.entry — see package docstring."""
import argparse
import os
import sys
import traceback
from pathlib import Path
from vvaharness import config as config_mod
from vvaharness.util import errlog as _errlog
from vvaharness.report.redact import redact
from vvaharness.orchestrator.config_paths import _default_config
from vvaharness.orchestrator.cmdb import (_cmdb_path, _set_cmdb_path)
from vvaharness.orchestrator.preflight import (configure_backends,
    check_backends)
from vvaharness.orchestrator.scan import scan_repo
from vvaharness.orchestrator.batch import run_batch

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass


def _top_arg(raw: str):
    """argparse ``type`` for ``--top``: accept a positive integer cap or the
    ``all`` / ``*`` wildcard (remediate every finding). Reuses the SAME coercion
    the standalone ``remediate`` command uses so both entry points agree on
    spellings and error text. Raises ``argparse.ArgumentTypeError`` on a bad
    value so argparse prints a clean usage error."""
    from vvaharness.remediation_agent.select import _coerce_top_value
    try:
        return _coerce_top_value(raw, source="--top")
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


def _resolve_auto_step1(flag: bool, cfg,
                        disable: bool = False) -> tuple[bool, str | None]:
    """Resolve whether AI auto-exclude (the s1_autoexclude / --auto-step1
    overlay) runs for this scan.

    Precedence (highest first):
      1. ``--no-auto-step1`` (``disable=True``) — hard OFF, wins over the flag
         AND any config default, irrespective of which profile is in use.
      2. ``--auto-step1`` (``flag=True``) — ON.
      3. ``step1.auto_exclude`` in config — ON when truthy.
      4. otherwise OFF.

    Steps 2–3 mirror the OR-precedence ``--remediate`` uses with
    ``step_remediate.enabled``. The config value is read from the already
    trust-gated ``cfg`` (an in-target config is refused before load), so this
    adds no new path for attacker-influenced input to enable a stage.

    Pure helper — callers still apply ``--step1-config`` precedence (which wins
    over an enabled auto-derivation) and emit the operator-facing messages.
    Returns ``(enabled, source-label)`` where source-label names what decided
    it (``None`` when off via default).
    """
    if disable:
        return False, "--no-auto-step1"
    if flag:
        return True, "--auto-step1"
    step1 = getattr(cfg, "step1", None)
    if bool(getattr(step1, "auto_exclude", False)):
        return True, "step1.auto_exclude"
    return False, None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo", help="path to a single local target codebase")
    src.add_argument("--repo-file",
                     help="batch input: either a .txt with one "
                          "'application_id,repository_name,path' per line, "
                          "or a .csv with header columns AppID,RepoName[,Path] "
                          "(Path derived from batch.git_base_url when absent); "
                          "each entry is cloned/scanned in sequence with a "
                          "fresh context")
    ap.add_argument("--config", default=str(_default_config()))
    ap.add_argument("--repo-name",
                    help="module / repositoryName tag for report filenames and "
                         "SARIF run.properties (single-repo mode only; "
                         "default: dir name)")
    ap.add_argument("--application-id",
                    help="application/asset ID — drives CMDB AppProfile lookup, "
                         "VulContextSeverity scoring, and SARIF run.properties.applicationId")
    ap.add_argument("--workspace", default="./batch-workspace",
                    help="directory to clone remote repos into (batch mode)")
    ap.add_argument("--keep-clones", action="store_true",
                    help="do not delete cloned repos after scanning (batch mode)")
    ap.add_argument("--group-by-app", action="store_true",
                    help="batch mode: clone every repo sharing an AppID under "
                         "{workspace}/{app_id}/ and run ONE scan over that "
                         "directory (one report per application instead of "
                         "one per repo)")
    ap.add_argument("--resume", action="store_true",
                    help="reuse existing checkpoints for completed steps")
    ap.add_argument("--stop-after",
                    choices=["clone", "s0", "s1", "s2", "s3", "s4", "s5", "s6",
                             "s7", "s8", "s9", "s10", "s11"],
                    help="stop after the named step (for debugging); "
                         "'clone' stops right after acquiring repos in batch "
                         "mode and implies --keep-clones")
    ap.add_argument("--remediate", action="store_true",
                    help="run step 10 in fix mode: the Remediation Agent can "
                         "apply a fix to selected verified findings and writes "
                         "per-finding artefacts under "
                         "<repo>/security-remediation/ (also enabled via "
                         "step_remediate.enabled in config)")
    ap.add_argument("--top", type=_top_arg, default=None, metavar="N|all",
                    help="when step 10 is enabled: override "
                         "step_remediate.top_n_findings "
                         "for this run — remediate only the N highest-CVSS "
                         "findings (limit & reorder, highest score first), or "
                         "pass 'all' / '*' to remediate every finding. The "
                         "profile's top_n_findings is the default cap.")
    ap.add_argument("--force", action="store_true",
                    help="override safety refusals (currently: the s10 "
                         "git-SHA staleness check)")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="skip the startup credential/backend readiness probe "
                         "(does NOT bypass model/API authentication)")
    ap.add_argument("--step1-config",
                    help="explicit step1 overlay YAML (exclude_dirs/exts/"
                         "globs, max_file_kb, config_dedup). Lists APPEND to "
                         "config.yaml's step1. Mutually exclusive with "
                         "--auto-step1 (this wins). No implicit default.")
    auto_grp = ap.add_mutually_exclusive_group()
    auto_grp.add_argument("--auto-step1", action="store_true",
                    help="after clone, AI-survey each target to derive its "
                         "step1 overlay; writes <state>/checkpoints/<run_id>/"
                         "step1.yaml and applies it before s1. Ignored when "
                         "--step1-config is given. Also enabled via "
                         "step1.auto_exclude in config (on by default in the "
                         "shipped default profile); this flag forces it on.")
    auto_grp.add_argument("--no-auto-step1", action="store_true",
                    help="hard-disable AI auto-exclude for this run, "
                         "irrespective of step1.auto_exclude in the "
                         "default/sdk/full profile. Wins over --auto-step1 and "
                         "any config default. (To also disable it persistently, "
                         "set step1.auto_exclude: false in your profile.)")
    args = ap.parse_args(argv)

    # Trust gate: a config sourced from INSIDE the scan target is attacker-
    # influenced (the canonical "cd into the checkout, then scan" CI pattern).
    # Refuse it and fall back to the packaged default unless the operator
    # explicitly opts in. Only IN-TARGET paths are refused, so the documented
    # copy-then-edit workflow (an operator-owned ./config.yaml) is unaffected.
    if args.repo and not os.environ.get("VVAHARNESS_ALLOW_CWD_CONFIG"):
        from vvaharness.orchestrator.config_paths import (_packaged_default,
                                                          _path_within)
        if _path_within(args.config, args.repo):
            print(f"  WARN: ignoring config inside the scan target "
                  f"({args.config}) — attacker-influenced; using the packaged "
                  f"default. Set VVAHARNESS_ALLOW_CWD_CONFIG=1 to override.",
                  file=sys.stderr)
            args.config = str(_packaged_default())

    cfg = config_mod.load(args.config)
    cfg_path = Path(args.config)
    cfg_dir = cfg_path.resolve().parent
    cfg_display = "config.yaml" if cfg_path.resolve() == (Path.cwd() / "config.yaml").resolve() else str(cfg_path)
    print(f"  config: {cfg_display}", file=sys.stderr)
    # The config.local.yaml overlay (and the keys it overrides) is logged by
    # config.load() itself now, uniformly across every command — no separate
    # provenance print needed here.
    _set_cmdb_path(cfg, cfg_dir)

    # AI auto-exclude is enabled by the --auto-step1 flag OR by
    # step1.auto_exclude in the (already trust-gated) config, and hard-disabled
    # by --no-auto-step1 (which wins over both). --step1-config still wins over
    # an enabled auto-derivation, handled below.
    args.auto_step1, auto_step1_src = _resolve_auto_step1(
        args.auto_step1, cfg, disable=args.no_auto_step1)
    if args.no_auto_step1:
        print("  step1 overlay: --no-auto-step1 (AI auto-exclude disabled, "
              "overriding any config default)", file=sys.stderr)

    if args.step1_config:
        if config_mod.is_network_path(args.step1_config):
            print(f"ERROR: --step1-config must be a local path; refusing "
                  f"network/UNC path {args.step1_config}", file=sys.stderr)
            return 2
        s1_path = Path(args.step1_config)
        cfg, s1_applied = config_mod.apply_step1_overlay(cfg, s1_path)
        if not s1_applied:
            print(f"ERROR: --step1-config {s1_path} not found", file=sys.stderr)
            return 2
        s1 = cfg._data.get("step1", {})
        print(f"  step1 overlay: {s1_path}  "
              f"(exclude_dirs={len(s1.get('exclude_dirs') or [])} "
              f"exts={len(s1.get('exclude_exts') or [])} "
              f"globs={len(s1.get('exclude_globs') or [])})", file=sys.stderr)
        if args.auto_step1:
            print(f"  step1 overlay: --step1-config given; ignoring "
                  f"{auto_step1_src}", file=sys.stderr)
            args.auto_step1 = False
    elif args.auto_step1:
        print(f"  step1 overlay: {auto_step1_src} (per-target "
              f"checkpoints/step1.yaml will be derived)", file=sys.stderr)

    # ── CMDB is OPTIONAL — without it, VulContextSeverity environmental scoring is skipped
    #    (CVSS base scores + OffensivePriority are still computed). Warn, continue.
    _cmdb = _cmdb_path()
    if not _cmdb or not os.path.isfile(_cmdb):
        _where = _cmdb or "inject.cmdb_file unset"
        print(f"  WARN: no CMDB file ({_where}) — VulContextSeverity environmental scoring "
              f"skipped (CVSS + OffensivePriority still computed).", file=sys.stderr)

    configure_backends(cfg, cfg_dir)

    # ── Verify whichever backend(s) the config uses ────────────────────
    if not args.skip_preflight and args.stop_after != "clone":
        try:
            if not check_backends(cfg):
                return 1
        except KeyboardInterrupt:
            print("\n  ✗ scan aborted by user (Ctrl-C).", file=sys.stderr)
            return 130

    if args.repo_file:
        list_file = Path(args.repo_file)
        if not list_file.is_file():
            print(f"ERROR: {list_file} is not a file", file=sys.stderr)
            return 2
        return run_batch(list_file, args, cfg)

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"ERROR: {repo} is not a directory", file=sys.stderr)
        return 2
    repo_name = args.repo_name or repo.name
    try:
        scan_repo(repo, repo_name, args.application_id, args, cfg)
    except KeyboardInterrupt:
        print("\n  ✗ scan aborted by user (Ctrl-C).", file=sys.stderr)
        return 130
    except Exception as e:
        # Clean one-line failure for the operator; the full traceback is
        # recorded to the structured error log and shown inline only when
        # VVAHARNESS_DEBUG is set. A raw traceback on stdout/stderr is exactly
        # what tempts an agent to "fix" the source — so we keep it concise and
        # actionable by default.
        print(f"  ✗ scan failed: {type(e).__name__}: {redact(str(e))}", file=sys.stderr)
        # Record the fatal failure to the structured error log too, so the
        # single-repo path is consistent with both batch paths (which log via
        # _errlog.log("batch", ...)). scan_repo() has already called
        # _errlog.configure() pointing at this repo's security-scan/ dir.
        _errlog.log("scan", repo_name, e, application_id=args.application_id)
        if os.environ.get("VVAHARNESS_DEBUG"):
            traceback.print_exc(file=sys.stderr)
        else:
            print("  (set VVAHARNESS_DEBUG=1 for the full traceback; details "
                  "in the *_errors.jsonl under security-scan/)", file=sys.stderr)
        return 1
    return 0
