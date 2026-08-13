# Copyright 2026 Visa, Inc.
# Modifications Copyright 2026 Lily Feng.
# Modified by Lily Feng in 2026 for native Codex support.
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

"""vvaharness CLI entry point — `scan`, `doctor`, `estimate`.

`scan` (the default) delegates to the pipeline orchestrator and writes a
run-level manifest. `doctor` reports credential/backend readiness. `estimate`
prints a rough scope/cost preview without spending any API budget.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

from vvaharness.validation.constants.artifacts import VALIDATE_COMMANDS


def _doctor(rest: list[str]) -> int:
    """Read-only diagnostic. Renders the SAME static readiness checks as
    `setup` (one shared engine in util.environment) and then runs the live
    backend connectivity probe — the part setup can't do without spending
    tokens. Returns non-zero on any blocking issue or probe failure."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import configure_backends, probe_backends
    from vvaharness.util import environment as env
    cfg_path = _config_path_from(rest)
    if not Path(cfg_path).exists():
        print(f"doctor: config not found: {cfg_path}", file=sys.stderr)
        return 2
    cfg = config_mod.load(cfg_path)
    # Apply sdk/openai base_url, ca_cert, api_key from the SAME config the scan
    # will use (honours --config) so the live probe hits the real endpoints.
    configure_backends(cfg, Path(cfg_path).resolve().parent)

    checks = env.run_checks(cfg_path)
    for c in checks:
        print(f"  {_ICON.get(c.status, '?')} {c.name:<30} {c.detail}")
    n_ok, n_warn, n_blocking = env.summarize(checks)
    print("  " + "─" * 60)
    print(f"  {n_ok} ok · {n_warn} warning(s) · {n_blocking} blocking issue(s)")

    if n_blocking:
        print("  [probe] skipped — fix the blocking item(s) above first")
        return 1
    return 0 if probe_backends(cfg) else 1


def _estimate(rest: list[str]) -> int:
    repo = None
    for i, a in enumerate(rest):
        # Accept both the split form (`--repo PATH`) and the joined form
        # (`--repo=PATH`) so `estimate` matches what `scan`'s argparse accepts.
        if a == "--repo" and i + 1 < len(rest):
            repo = rest[i + 1]
        elif a.startswith("--repo="):
            repo = a.split("=", 1)[1]
    if not repo:
        print("usage: vvaharness estimate --repo <path>", file=sys.stderr)
        return 2
    root = Path(repo)
    if not root.exists():
        print(f"no such path: {repo}", file=sys.stderr)
        return 1
    text_ext = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs",
                ".c", ".cpp", ".h", ".kt", ".scala", ".rs", ".sql", ".yaml",
                ".yml", ".json", ".tf", ".sh"}
    files = bytes_ = 0
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in text_ext:
            try:
                bytes_ += p.stat().st_size
                files += 1
            except OSError:
                pass
    approx_tokens = bytes_ // 4
    print(f"scope estimate for {repo}")
    print(f"  code files       : {files:,}")
    print(f"  bytes            : {bytes_:,}")
    print(f"  ~input tokens    : {approx_tokens:,} (rough, bytes/4)")
    print("  note: the pipeline reads each file across several stages; expect")
    print("  total token usage to be a multiple of the above. Cost depends on")
    print("  the model in config.yaml. Use --stop-after s3 for an exact scope.")
    return 0


def _gc(rest: list[str]) -> int:
    """Delete old run records from the SQLite state DB (``$VVAHARNESS_STATE_DIR/vvaharness.db``):
    ``runs`` rows (and their checkpoints via ON DELETE CASCADE) older than --max-age-days or
    outside the --keep-runs most recent. Reports/SARIF/manifest under ``<repo>/security-scan/``
    are never touched."""
    import argparse
    from vvaharness.orchestrator.checkpoints import prune_checkpoints, run_id_for
    ap = argparse.ArgumentParser(prog="vvaharness gc")
    ap.add_argument("--keep-runs", type=int, default=100,
                    help="retain the N most-recent run_ids (default: 100)")
    ap.add_argument("--max-age-days", type=int, default=5,
                    help="delete runs older than D days (default: 5)")
    ap.add_argument("--run", metavar="PATH",
                    help="fully evict the run for this repo PATH (its run_id is "
                         "derived from the path) instead of age/count pruning")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be deleted; touch nothing")
    a = ap.parse_args(rest)

    # Targeted eviction: purge exactly the run for a given repo path. Useful
    # before a clean rescan, or to drop a run without waiting for age/count GC.
    if a.run:
        from vvaharness.orchestrator import store
        rid = run_id_for(a.run)
        if a.dry_run:
            print(f"  [dry-run] gc: would evict run {rid} for {a.run}")
            return 0
        ok = store.delete_run(rid)
        print(f"  gc: {'evicted' if ok else 'no run found for'} {a.run} "
              f"(run_id {rid})")
        return 0

    r = prune_checkpoints(keep_runs=a.keep_runs,
                          max_age_days=a.max_age_days,
                          dry_run=a.dry_run)
    tag = "[dry-run] " if a.dry_run else ""
    print(f"  gc: {r['root']}")
    print(f"  {tag}kept {r['kept']} run(s), "
          f"{'would delete' if a.dry_run else 'deleted'} {len(r['deleted'])}")
    for rid in r["deleted"]:
        print(f"    - {rid}")
    return 0


def _validate(rest: list[str]) -> int:
    """Run the s11 agentic validation agent. Lazy import: requires the `validation` extra
    (Claude Agent SDK). The subcommand owns its own --config / model resolution.
    Invocable as `vvaharness validate …` or `vvaharness s11 …`."""
    from vvaharness.validation.cli import main as validate_main
    return validate_main(rest)


def _remediate(rest: list[str]) -> int:
    """Drive remediation from a prior scan's output. Reads the findings from
    ``<repo>/security-scan/`` and walks them with the same per-stage CLI look
    used by `scan`, running the configured ``models.remediate`` role per finding.
    Honours ``--config`` (same resolution as scan/doctor). Delegates to remediation_agent."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import configure_backends
    from vvaharness.remediation_agent import remediate
    repo = _repo_from(rest)
    if not repo:
        print("usage: vvaharness remediate --repo <path>", file=sys.stderr)
        return 2
    cfg_path = _config_path_from(rest)
    if not Path(cfg_path).exists():
        print(f"remediate: config not found: {cfg_path}", file=sys.stderr)
        return 2
    cfg = config_mod.load(cfg_path)
    # Apply sdk/openai/cli TLS + key settings so the remediate role's backend
    # is configured exactly as a scan would configure it.
    configure_backends(cfg, Path(cfg_path).resolve().parent)
    return remediate(repo, rest, cfg)


def _config_path_from(rest: list[str]) -> str:
    """Resolve the effective config path the way the orchestrator's argparse
    does — the value after ``--config`` (or ``--config=…``), else the packaged
    default. Used so the run manifest and ``doctor`` reflect the config actually
    in force rather than always the default profile."""
    from vvaharness.orchestrator import _default_config
    found: str | None = None
    for i, a in enumerate(rest):
        # Last occurrence wins, matching argparse's behaviour on a repeated flag.
        if a == "--config" and i + 1 < len(rest):
            found = rest[i + 1]
        elif a.startswith("--config="):
            found = a.split("=", 1)[1]
    return found if found is not None else str(_default_config())



def _check_python() -> str | None:
    """Return an error string if the interpreter is older than the minimum the
    package declares in its metadata (``Requires-Python``), else ``None``. The
    floor is read from metadata — never hardcoded — so it always tracks
    pyproject. Skips silently when metadata is unavailable (e.g. running from a
    bare source tree)."""
    try:
        from importlib.metadata import metadata
        req = (
            metadata("codex-vulnerability-agentic-harness").get("Requires-Python")
            or ""
        )
    except Exception:
        return None
    import re
    m = re.search(r">=\s*(\d+)\.(\d+)", req)
    if not m:
        return None
    floor = (int(m.group(1)), int(m.group(2)))
    if sys.version_info[:2] < floor:
        cur = ".".join(str(v) for v in sys.version_info[:3])
        return (f"vvaharness requires Python >= {floor[0]}.{floor[1]}; this "
                f"interpreter is {cur}. Please use a newer Python.")
    return None


def _repo_from(rest: list[str]) -> str | None:
    """Extract the ``--repo`` target (split or ``=`` form) from raw args, else
    None — used to refuse a ``.env`` that lives inside the scan target."""
    for i, a in enumerate(rest):
        if a == "--repo" and i + 1 < len(rest):
            return rest[i + 1]
        if a.startswith("--repo="):
            return a.split("=", 1)[1]
    return None


def _load_dotenv(repo: str | None = None) -> None:
    """Best-effort: load a ``.env`` found from the current directory upward into
    the environment WITHOUT overriding already-exported variables, so values in
    ``.env`` are picked up without a manual ``source``. No-ops if python-dotenv
    is unavailable or no ``.env`` is found.

    Refuses a ``.env`` that resolves INSIDE the scan target (an attacker-
    influenced checkout) unless ``VVAHARNESS_ALLOW_CWD_CONFIG`` is set, and
    prints a provenance line naming the file actually loaded."""
    try:
        from dotenv import load_dotenv, find_dotenv
    except Exception:
        return
    path = find_dotenv(usecwd=True)
    if not path:
        return
    if repo and not os.environ.get("VVAHARNESS_ALLOW_CWD_CONFIG"):
        from vvaharness.orchestrator.config_paths import _path_within
        if _path_within(path, repo):
            print(f"  WARN: ignoring .env inside the scan target ({path}) — "
                  f"attacker-influenced; set VVAHARNESS_ALLOW_CWD_CONFIG=1 to "
                  f"override.", file=sys.stderr)
            return
    load_dotenv(path, override=False)
    print(f"  [env] loaded {path}", file=sys.stderr)


_ICON = {"ok": "✓", "warn": "⚠", "fail": "✗"}


def _install_agents() -> int:
    """Drop the operating instructions into the files each installed AI agent
    reads, so 'open it in Claude/Copilot/Gemini' just works. Existing files are
    left untouched (we never clobber a user's own CLAUDE.md). Claude also gets a
    discoverable skill under ~/.claude/skills/."""
    import shutil
    from vvaharness import agentdoc
    cwd, home = Path.cwd(), Path.home()

    def put(path: Path, content: str) -> None:
        if path.exists():
            print(f"    • exists, left as-is: {path}")
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"    ✓ wrote {path}")

    # Cross-tool standard + Copilot (no CLI to detect, so always provide it).
    put(cwd / "AGENTS.md", agentdoc.AGENT_DOC)
    put(cwd / ".github" / "copilot-instructions.md", agentdoc.AGENT_DOC)
    if shutil.which("claude"):
        put(cwd / "CLAUDE.md", agentdoc.AGENT_DOC)
        put(home / ".claude" / "skills" / "vvaharness" / "SKILL.md",
            agentdoc.CLAUDE_SKILL)
    if shutil.which("gemini"):
        put(cwd / "GEMINI.md", agentdoc.gemini_doc())
    return 0


def _setup(rest: list[str]) -> int:
    """Guided readiness wizard: check Python/git, detect installed AI agents and
    their keys, verify deps, flag the Anthropic gateway gap, and validate the
    active config profile. Offers to scaffold a .env. Read-only unless
    --write-env is passed. Returns non-zero when a *required* item is missing."""
    from vvaharness import __version__
    from vvaharness.util import environment as env
    from vvaharness.util.environment import FAIL

    cfg_path = _config_path_from(rest)
    write_env = "--write-env" in rest

    print(f"\n  ⟐  vvaharness {__version__} — setup\n")
    _prompt_for_remediation_inputs()
    checks = env.run_checks(cfg_path)
    for c in checks:
        print(f"  {_ICON.get(c.status, '?')} {c.name:<30} {c.detail}")

    n_ok, n_warn, n_blocking = env.summarize(checks)
    print("  " + "─" * 60)
    print(f"  {n_ok} ok · {n_warn} warning(s) · {n_blocking} blocking issue(s)")

    # Recommend the profile that matches the creds actually present, so the
    # user isn't stuck on the sdk default when only a Claude Code gateway token
    # is available.
    prof, why = env.recommend_profile()
    if prof:
        print(f"\n  → Recommended profile: {prof}  ({why})")
        if prof != "default":
            print(f"      vvaharness scan --repo <path> "
                  f"--config vvaharness/config/profiles/{prof}.yaml")

    # Targeted remediation for the most common trap (gateway token, no base_url),
    # using a gateway auto-discovered from the env or the shell rc files.
    gw = next((c for c in checks if c.name == "via:sdk endpoint"
               and c.status == FAIL), None)
    gw_url, gw_src = env.detect_gateway()
    ca = env.detect_ca_cert()
    if gw:
        print("\n  → Fix the Anthropic endpoint:")
        if gw_url:
            print(f"      export ANTHROPIC_BASE_URL={gw_url.split('?', 1)[0]}"
                  f"   # found in {gw_src}")
        else:
            print("      export ANTHROPIC_BASE_URL=https://<your-gateway>/")
        if ca:
            print(f"      export NODE_EXTRA_CA_CERTS={ca}")
        print("      export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1   "
              "# if the gateway rejects beta flags (400)")

    # .env scaffold — pre-fill the discovered gateway/CA so the next run works.
    env_file = Path(".env")
    if not env_file.exists():
        example = Path(".env.example")
        if write_env:
            base = example.read_text(encoding="utf-8") if example.exists() else ""
            extra = ""
            if gw_url:
                extra += f"\n# auto-detected from {gw_src}\nANTHROPIC_BASE_URL={gw_url}\n"
            if ca:
                extra += f"NODE_EXTRA_CA_CERTS={ca}\n"
            if gw_url or ca:
                extra += "# uncomment if the gateway rejects beta flags (400):\n" \
                         "# CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1\n"
            env_file.write_text(base + extra, encoding="utf-8")
            print("\n  ✓ wrote .env"
                  + (" (incl. detected gateway)" if gw_url else "")
                  + " — fill in any remaining keys, then "
                  "`set -a && source .env && set +a`")

    # Taint profile convenience: make rulepack generation discoverable when the
    # generated source/sink files are absent.
    rules_dir = Path(__file__).resolve().parent / "rules"
    src_gen = rules_dir / "sources.generated.yaml"
    sink_gen = rules_dir / "sinks.generated.yaml"
    if not src_gen.is_file() and not sink_gen.is_file():
        print("\n  → Optional (taint profile): generated callgraph rulepacks not found")
        print(f"      missing: {src_gen.name}, {sink_gen.name}")
        print("      build them from local corpus clones:")
        print("      python -m vvaharness.rules.build_kb \\")
        print("        --semgrep /path/to/semgrep-rules \\")
        print("        --codeql /path/to/codeql \\")
        print(f"        --sources-out {src_gen} \\")
        print(f"        --sinks-out {sink_gen}")
        print("      No corpus clones yet? See docs/SETUP_GUIDE.md section")
        print("      'Generated source/sink rule files (taint profile)'.")

    # Install agent operating instructions for whatever AI agent is present so
    # it runs the tool correctly. Opt-in (--install-agents); otherwise suggest.
    if "--install-agents" in rest:
        print("\n  Installing AI-agent instructions:")
        _install_agents()
    else:
        print("\n  AI agent driving this? Run `vvaharness setup --install-agents` "
              "to drop the right instructions for your agent (Codex/Claude/"
              "Copilot/Gemini) so it runs the tool correctly.")
        print("  (Operating manual: AGENTS.md · capabilities: docs/SKILLS.md)")
    if n_blocking:
        print(f"\n  Not ready: fix the {n_blocking} blocking item(s) above, "
              f"then `vvaharness scan`.\n")
        return 1
    print("\n  Ready ✓  →  vvaharness scan --repo /path/to/target")
    try:
        from vvaharness import config as config_mod
        active_cfg = config_mod.load(cfg_path)
        remediation_on = bool(getattr(
            getattr(active_cfg, "step_remediate", None), "enabled", False))
    except Exception:
        remediation_on = True
    if remediation_on:
        print("  ⚠ the active profile runs remediation in fix mode, so `scan` EDITS "
              "source files in the target repo.")
        print("    For detection only (no code changes): vvaharness scan --repo … --stop-after s9\n")
    else:
        print("  ✓ the active profile has remediation disabled (detection only; no source edits).\n")
    return 0


def _prompt_for_remediation_inputs() -> None:
    """Persist an inputs directory when wheel defaults cannot be resolved."""
    from vvaharness.remediation_agent import rule_paths

    missing = rule_paths.missing_rules(rule_paths.__file__)
    if not missing or not sys.stdin.isatty():
        return
    print("  ! remediation defaults are missing: " + ", ".join(missing))
    while True:
        try:
            answer = input(
                "  Path to the VVAH inputs directory (blank to skip): "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not answer:
            return
        directory, absent = rule_paths.validate_inputs_dir(answer)
        if absent:
            print(f"  ! {directory} is missing: {', '.join(absent)}")
            continue
        target = rule_paths.save_inputs_dir(directory)
        print(f"  ✓ saved remediation inputs directory in {target}")
        return


def _print_help() -> None:
    from vvaharness import __version__
    print(f"""vvaharness {__version__} — agentic SAST pipeline

Usage: vvaharness <command> [options]

Commands:
  setup      Guided readiness check: AI agents, keys, deps, gateway, config
  doctor     Check credentials + live backend connectivity (read-only)
  estimate   Print a rough scope/cost preview for a repo (no API spend)
  gc         Delete old checkpoint runs (--keep-runs / --max-age-days / --dry-run)
  scan       Scan a repo (or --repo-file batch) for vulnerabilities
             (⚠ default profile EDITS source files in fix mode — `--stop-after s9` = detection only)
  remediate  Walk findings from a prior scan and remediate them (Remediation Agent)
             (--interactive/-i to pick issues from a menu; --mode fix|report-only;
              --top N overrides step_remediate.top_n_findings to remediate only
              the N highest-CVSS findings (--top all / --top * remediates every one);
              --verbose/-v to print the prompt + raw LLM response per finding)
  validate   Run the s11 agentic validation agent on applied remediations
  s11        Alias for `validate` — the s11 agentic validation stage

Run 'vvaharness scan --help' for the full list of scan options.
Run 'vvaharness validate --help' (or 'vvaharness s11 --help') for validation options.
Config:
  vvaharness uses ./config.yaml when present; otherwise it uses the packaged default.
  Customise: cp vvaharness/config/profiles/sdk.yaml config.yaml   (all-SDK profile; see also full.yaml)
Quick start:
  vvaharness setup
  vvaharness estimate --repo /path/to/target
  vvaharness scan --repo /path/to/target --application-id 12345   # ⚠ edits source by default (S10 fix mode)
  vvaharness scan --repo /path/to/target --stop-after s9          # detection only — no code changes
""")



def main(argv: list[str] | None = None) -> int:
    try:
        err = _check_python()
        if err:
            print(f"ERROR: {err}", file=sys.stderr)
            return 2

        args = list(sys.argv[1:] if argv is None else argv)
        _load_dotenv(_repo_from(args))
        # Bare invocation or a top-level help request shows the command list and
        # exits — it does NOT silently default to `scan` (which would then dump an
        # argparse usage error and, worse, write a junk run_manifest.json).
        if not args or args[0] in ("-h", "--help", "help"):
            _print_help()
            return 0
        cmd = args[0]
        if cmd in ("setup", "init"):
            return _setup(args[1:])
        if cmd == "doctor":
            return _doctor(args[1:])
        if cmd == "estimate":
            return _estimate(args[1:])
        if cmd == "gc":
            return _gc(args[1:])
        if cmd == "remediate":
            return _remediate(args[1:])
        if cmd in VALIDATE_COMMANDS:
            return _validate(args[1:])
        if cmd == "scan":
            args = args[1:]

        from vvaharness import orchestrator, manifest
        cfg_path = _config_path_from(args)
        # orchestrator.main() takes its argv explicitly, so no global sys.argv
        # mutation is needed — a concurrent in-process main() (tests / embedding)
        # can no longer consume another invocation's arguments.
        with manifest.capture(cfg_path, args) as m:
            rc = orchestrator.main(args)
            m["exit_code"] = rc
        return rc
    except KeyboardInterrupt:
        print("\n  ✗ command aborted by user (Ctrl-C).", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
