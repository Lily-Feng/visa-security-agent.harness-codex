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

"""Config loader. Reads config.yaml, expands ${ENV:-default} placeholders."""
from __future__ import annotations
import os
import re
import sys
from pathlib import Path, PureWindowsPath
import yaml

_ENV_PAT = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")

# Overlay paths already announced this process — load() is called several times
# per run (manifest capture, orchestrator, doctor, …); dedupe so the
# config.local.yaml provenance line is emitted once per unique overlay, not once
# per load() call.
_logged_overlays: set[str] = set()


def _expand_env(m):
    # POSIX ${VAR:-default}: use the default when VAR is unset OR set-but-empty.
    name, default = m.group(1), m.group(2)
    val = os.environ.get(name)
    if val:
        return val
    return default if default is not None else ""


def _expand(val):
    if isinstance(val, str):
        return _ENV_PAT.sub(_expand_env, val)
    if isinstance(val, dict):
        return {k: _expand(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_expand(v) for v in val]
    return val


class Config:
    """Thin attribute wrapper over the YAML dict. cfg.models.deepdive etc."""
    def __init__(self, data: dict):
        self._data = data

    def __getattr__(self, name):
        # Guard against recursion during copy.deepcopy: _data and dunder probes
        # (__deepcopy__, __setstate__, __getstate__, ...) must NOT re-enter via
        # self._data, which is absent while the object is being reconstructed.
        if (name.startswith("__") and name.endswith("__")) or name == "_data":
            raise AttributeError(name)
        data = self.__dict__.get("_data")
        try:
            v = data[name]
        except (KeyError, TypeError) as e:
            raise AttributeError(name) from e
        return Config(v) if isinstance(v, dict) else v

    def __getitem__(self, k):
        return self._data[k]

    def __repr__(self):
        return f"Config({self._data!r})"


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


# ── Built-in scalar defaults for every tunable the pipeline reads directly ───
# Merged UNDER any loaded config so a partial/hand-written config can never
# crash a stage with KeyError/AttributeError (e.g. a CLI-only config missing
# step4 knobs). User values always win; these only fill gaps. Structural keys
# (lists/dicts like exclude_dirs, specialists, config_dedup, allowed_tools) are
# intentionally omitted — the stages already default those internally and a
# defaults-layer entry would interfere with their append/merge semantics.
_STEP_DEFAULTS: dict = {
    "step0": {
        # Profile-controlled static seed. The scalar fallback is disabled;
        # default.yaml and taint.yaml explicitly enable it. Rules mode requires
        # source/sink YAML; without applicable rules it returns an empty seed.
        "enabled": False,
        "callgraph_detection": "rules",
        "sources_yaml": None, "sinks_yaml": None,
        # Optional static-seed language filter (s0_seed._filter_step0_languages).
        "languages": None,
    },
    "step1": {
        "max_budget_usd": 25.0, "max_turns": 40, "max_file_kb": 1024,
        "mode": "full", "call_graph": "regex",
        "call_graph_validate": True, "call_graph_supplement": True,
        "call_graph_rounds": 4, "call_graph_max_targets": 3,
        # Opt-in LLM auto-exclusion pass (s1_autoexclude): when enabled, an
        # extra model call proposes scan exclusions from a repo survey.
        # auto_exclude_max_tokens caps that survey prompt.
        "auto_exclude": False, "auto_exclude_max_tokens": 8000,
        # Back-compat symlink toggle: off-root symlink targets are dropped
        # regardless; when set, s1 warns rather than silently honouring it.
        "follow_symlinks": False,
    },
    "step2": {
        "enabled": True, "max_tokens": 64000, "max_threats": 50,
        "baseline": "auto", "max_doc_chars": 20000, "max_manifest_chars": 4000,
        "max_modules": 100, "max_entry_points": 400, "max_config_reps": 80,
        "max_api_artefacts": 100,
        "max_graph_files": 220, "max_graph_sinks": 80, "max_graph_edges": 100,
        "max_notes_chars": 2500, "max_function_sites": 80,
        # Prompt-truncation caps, distinct from the frontier-view caps above
        # (max_modules / max_entry_points).
        "max_prompt_modules": 100, "max_prompt_entry_points": 400,
    },
    "step3": {
        "max_tokens": 64000, "timeout": 3600, "taint_chunks": True,
        "taint_max_hops": 10, "taint_max_chunks": 60, "taint_files_per_hop": 5,
        "pack_by": "loc", "chunk_token_budget": 180000,
        "chunk_overhead_tokens": 80000, "risk_chunk_loc": 10000,
        "catchall_enabled": True, "catchall_mode": "all", "catchall_chunk_loc": 4000,
        "catchall_max_files": 100, "max_files_per_chunk": 80,
        "specialist_chunk_loc": 10000, "taint_chunk_slice": "file",
        "max_prompt_files": 180, "max_prompt_entry_points": 60,
        "max_prompt_sinks": 80, "max_prompt_modules": 24,
        "max_prompt_call_edges": 80, "max_prompt_notes_chars": 2500,
        "catchall_reachable_min_ratio": 0.0, "catchall_reachable_min_files": 0,
    },
    "step4": {
        # Single-pass scalar default. sdk.yaml and full.yaml opt into majority
        # voting by setting runs>1 and pointing models.deepdive at
        # a temperature-capable sdk/openai model, else _effective_runs() (see
        # s4_deepdive) forces 1/1.
        "parallel": 5, "timeout": 1800, "runs": 1, "vote_threshold": 1,
        "specialist_runs": 1, "line_bucket": 10, "max_findings_per_run": 10,
        "max_tokens": 64000, "neighbor_context_lines": 25,
        "neighbor_context_max": 50,
        # taint-first overrides — all no-ops under default.yaml so the legacy
        # path is byte-identical: discover prompt, no per-kind run override,
        # no per-kind model override.
        "taint_prompt_mode": "discover", "taint_runs": None, "taint_model": None,
        # Optional override of step3.taint_chunk_slice. Left None so the
        # effective mode is read from step3; set to "file"/"function" here to
        # override the chunk slicing mode for the deep-dive stage only.
        "taint_chunk_slice": None,
        "frontier_max_funcs_per_file": 24, "frontier_fallback_head_lines": 80,
    },
    "step5_prefilter": {"min_pre_confidence": 0.6, "require_evidence": True,
                        "ast_backfill_evidence": True},
    "step6_verify": {
        "parallel": 5, "min_confidence": 7, "max_budget_usd": 10.0,
        "max_turns": 30,
    },
    "step7_dedup": {"line_tolerance": 3, "semantic": True, "max_tokens": 64000},
    "step8": {"max_tokens": 64000, "timeout": 3600},
    "step_remediate": {"max_budget_usd": 10.0, "max_turns": 40,
                       "top_n_findings": 20},
    "step_validate": {"enabled": False, "effort": "high", "max_turns": 50, "max_budget_usd": 15.0, "max_findings": 20},
    "output": {"emit_unreachable_appendix": False},
    # CWE knowledge-base overlays. kb_overlays is an operator-supplied path (or
    # list of paths) to extra rules/*.kb.yaml corpora spliced onto the built-in
    # KB by CweKB.load(overlays=...) for the s4 confirm/refute prompt. None ⇒
    # built-in KB only.
    "rules": {"kb_overlays": None},
}


def load(path: str | Path = "config.yaml") -> Config:
    p = Path(path)
    # safe_load returns None for an empty/all-comments/whitespace file; treat
    # that as an empty mapping rather than crashing on later attribute access.
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"config {p} must be a YAML mapping, got {type(raw).__name__}")
    # Fill any missing scalar step-knobs from the built-in defaults so partial
    # configs never crash a stage. User-supplied values take precedence.
    raw = _deep_merge(_STEP_DEFAULTS, raw)
    # config.local.yaml (git-ignored, never bundled) deep-merges OVER the chosen
    # config. It can override security-relevant keys (model routing, sdk/openai
    # base_url, TLS ca_cert, tool permissions), so the merge is made VISIBLE
    # rather than silent: log the overlay file and the top-level keys it
    # overrides, on every command (not just scan). Set VVAHARNESS_NO_LOCAL_CONFIG
    # (to any value) to skip the overlay entirely — for a reproducible run that
    # honours only the operator-selected config. The overlay resolves next to
    # the --config path (operator-controlled), never the scanned target.
    local = p.with_name("config.local.yaml")
    if local.exists():
        key = str(local.resolve())
        if os.environ.get("VVAHARNESS_NO_LOCAL_CONFIG"):
            if key not in _logged_overlays:
                _logged_overlays.add(key)
                print(f"  config overlay: {local} present but SKIPPED "
                      f"(VVAHARNESS_NO_LOCAL_CONFIG set)", file=sys.stderr)
        else:
            over = yaml.safe_load(local.read_text(encoding="utf-8")) or {}
            if not isinstance(over, dict):
                raise ValueError(f"config {local} must be a YAML mapping, got {type(over).__name__}")
            if key not in _logged_overlays:
                _logged_overlays.add(key)
                overrides = ", ".join(sorted(map(str, over))) or "(empty)"
                print(f"  config overlay: {local} applied "
                      f"(overrides: {overrides})", file=sys.stderr)
            raw = _deep_merge(raw, over)
    cfg = Config(_expand(raw))
    # Record the directory the config was loaded from so input-style paths
    # (e.g. inject.cve_file, step_remediate.policy_file) can be resolved
    # against it — exactly how scan.py resolves cfg.inject.* against cfg_dir.
    cfg._data["_config_dir"] = str(p.resolve().parent)
    return cfg


def _replace_merge(base: dict, over: dict) -> dict:
    """Deep-merge where dicts recurse and everything else (incl. lists)
    REPLACES. Used for nested step1 sub-blocks like config_dedup so the
    latest overlay's list values win outright instead of accumulating."""
    out = dict(base)
    for k, v in over.items():
        cur = out.get(k)
        if isinstance(v, dict) and isinstance(cur, dict):
            out[k] = _replace_merge(cur, v)
        else:
            out[k] = v
    return out


def _append_merge(base: dict, over: dict) -> dict:
    """step1 overlay merge: top-level lists (exclude_dirs/exts/globs) APPEND
    so per-app files add to the global baseline; nested dicts switch to
    replace-merge so e.g. config_dedup.exts is taken from the latest overlay
    rather than concatenated."""
    out = dict(base)
    for k, v in over.items():
        cur = out.get(k)
        if isinstance(v, dict) and isinstance(cur, dict):
            out[k] = _replace_merge(cur, v)
        elif isinstance(v, list) and isinstance(cur, list):
            out[k] = list(cur) + [x for x in v if x not in cur]
        else:
            out[k] = v
    return out


def is_network_path(path: str | Path) -> bool:
    """True if *path* is a UNC / network location (``\\\\host\\share`` or
    ``//host/share``). Reading such a path on Windows triggers SMB
    authentication, which transmits the caller's NTLMv2 hash to the (possibly
    attacker-controlled) host. Callers must refuse these before any filesystem
    access. Evaluated with PureWindowsPath so the result is identical on every
    OS, not just where the run happens to land."""
    s = str(path).strip()
    if s.startswith("\\\\") or s.startswith("//"):
        return True
    # UNC drives render as '\\host\share'; local drives render as 'C:'.
    return PureWindowsPath(s).drive.startswith("\\\\")


def apply_step1_overlay(cfg: Config, path: str | Path) -> tuple[Config, bool]:
    """Layer a per-scan step1 file on top of cfg.step1. Accepts either a
    bare-key file (exclude_dirs:, exclude_exts:, …) or one wrapped in a
    top-level `step1:` block. Lists append; scalars replace. Returns
    (cfg, applied)."""
    p = Path(path)
    # Refuse network/UNC paths before the first filesystem touch (is_file
    # below) — on Windows that touch would leak the user's NTLM hash via SMB.
    if is_network_path(p):
        raise ValueError(
            f"step1 overlay must be a local path; refusing network/UNC path {p!r} "
            f"(reading it could leak credentials over SMB)")
    if not p.is_file():
        return cfg, False
    over = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(over, dict):
        raise ValueError(f"step1 overlay {p} must be a YAML mapping")
    over = _expand(over)
    if set(over) == {"step1"} and isinstance(over["step1"], dict):
        over = over["step1"]
    base1 = cfg._data.get("step1") or {}
    cfg._data["step1"] = _append_merge(base1, over)
    return cfg, True
