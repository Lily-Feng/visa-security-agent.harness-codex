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
Step 1 — Claude CLI explores the repo agentically and emits a ContextPackage.

The CLI already has Read, Glob, Grep, Bash tools built in — no custom tools
needed. We give it a system prompt, point it at the repo, and ask it to
produce a JSON ContextPackage.
"""
from __future__ import annotations
import ast
import configparser
import fnmatch
import hashlib
import json
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path

log = logging.getLogger(__name__)

from vvaharness.models import ContextPackage, CVE, Control
from vvaharness.backends.llm import agentic
from vvaharness.util.json_extract import extract_json
from vvaharness.lang.hints import EXT_TO_LANG

# Deterministic repo walk — guarantees s3/s4 see every source file regardless
# of what the agentic exploration chose to look at.
_DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".idea", ".vscode", "target", "vendor", ".terraform",
    ".next", ".nuxt", "coverage", ".pytest_cache", ".mypy_cache",
    # test code — not part of the production attack surface
    # ("spec"/"specs" intentionally NOT here — collides with UI component
    #  folders; *.spec.* test FILES are caught by _DEFAULT_EXCLUDE_GLOBS)
    "test", "tests", "__tests__", "__test__", "e2e", "testdata",
    "fixtures", "__fixtures__", "mocks", "__mocks__", "stubs",
    # IaC / CI / container dirs (helm, docker, k8s, kubernetes, deploy,
    # deployment, .github, .gitlab, ci, ansible, terraform) are KEPT in
    # scope — the `iac` specialist in s3_decompose sweeps them for cloud /
    # supply-chain misconfigurations. Only `.terraform/` (provider state,
    # listed above) stays excluded. 
    # pipeline writes these INTO the target repo — never scan our own output
    "checkpoints", "security-scan",
}
_DEFAULT_EXCLUDE_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip", ".gz",
    ".tar", ".7z", ".jar", ".war", ".class", ".exe", ".dll", ".so", ".dylib",
    ".bin", ".o", ".a", ".obj", ".pyc", ".pyo", ".pkl", ".lock", ".min.js", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav",
}
# Glob patterns matched against the repo-relative posix path. Catches test
# files that live alongside production code and infra files at repo root.
_DEFAULT_EXCLUDE_GLOBS = (
    "**/test_*.py", "**/*_test.py", "**/conftest.py",
    "**/*_test.go", "**/*.test.js", "**/*.test.ts", "**/*.test.jsx", "**/*.test.tsx",
    "**/*.spec.js", "**/*.spec.ts", "**/*.spec.jsx", "**/*.spec.tsx",
    "**/*Test.java", "**/*Tests.java", "**/*IT.java",
    "**/*Test.cs", "**/*Tests.cs", "**/*Test.kt",
    # Dockerfile / Jenkinsfile / Makefile / *.tf / *.tfvars and Helm chart
    # YAML are KEPT in scope — the `iac` specialist hunts them. The repo
    # metadata block below stays excluded.
    # repo / tooling metadata — never attack surface
    "**/.gitignore", "**/.gitattributes", "**/.gitmodules", "**/.gitkeep",
    "**/.editorconfig", "**/.dockerignore", "**/.npmignore", "**/.eslintignore",
    "**/.prettierignore", "**/.mailmap", "**/CODEOWNERS", "**/.DS_Store",
    "**/LICENSE", "**/LICENSE.*", "**/NOTICE",
)

_GAP_FILL_ESCALATE_REPO_KINDS = frozenset({"web-api", "web-app", "service"})
_GAP_FILL_SERVICE_HINTS = frozenset({
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "chart.yaml", "values.yaml", "procfile", "wsgi.py", "asgi.py",
})
_GAP_FILL_WEBAPP_SUFFIXES = (
    ".html", ".htm", ".jinja", ".jinja2", ".jsx", ".tsx", ".vue", ".svelte",
)


def _exclusion_sets(cfg) -> tuple[set[str], set[str], list[str]]:
    """Resolve (dirs, exts, globs) once — built-in defaults + config.yaml step1.* appends.
    Single source of truth shared by the deterministic walk, the agent prompt
    skip-list, and the post-agent JSON filter."""
    excl_dirs = {d.lower() for d in
                 _DEFAULT_EXCLUDE_DIRS | set(getattr(cfg.step1, "exclude_dirs", None) or [])}
    excl_exts = _DEFAULT_EXCLUDE_EXTS | set(getattr(cfg.step1, "exclude_exts", None) or [])
    excl_globs = list(_DEFAULT_EXCLUDE_GLOBS) + list(
        getattr(cfg.step1, "exclude_globs", None) or [])
    return excl_dirs, excl_exts, excl_globs


def _seed_repo_kinds(seed, all_files: list[str]) -> set[str]:
    """Cheap repo-kind guess for deciding whether S1 should stay in gap_fill.

    This is intentionally path/seed based only: the decision must be available
    before any agentic exploration and should not require another code pass.
    """
    kinds: set[str] = set()
    if any((getattr(ep, "kind", "") or "").lower() == "network"
           or bool(getattr(ep, "reachable_from_unauth", False))
            for ep in getattr(seed, "entry_points", ()) or ()): 
        kinds.add("web-api")

    low_files = [f.lower() for f in all_files]
    base_names = {Path(f).name.lower() for f in all_files}
    if any(name in _GAP_FILL_SERVICE_HINTS for name in base_names):
        kinds.add("service")
    if any(f.endswith(_GAP_FILL_WEBAPP_SUFFIXES) for f in low_files):
        kinds.add("web-app")
    return kinds or {"library"}


def _should_escalate_gap_fill(seed, all_files: list[str]) -> tuple[bool, str]:
    """Decide whether sparse S0 seed coverage should re-enable S1 discovery.

    Starter policy:
      - source files > 500
      - repo kind includes web-api/web-app/service
      - entry points >= 10
      - sinks < 5
    """
    source_files = sum(1 for f in all_files if Path(f).suffix.lower() in EXT_TO_LANG)
    if source_files <= 500:
        return False, f"source_files={source_files} <= 500"

    kinds = _seed_repo_kinds(seed, all_files)
    active_kinds = sorted(kinds & _GAP_FILL_ESCALATE_REPO_KINDS)
    if not active_kinds:
        return False, f"repo_kind={sorted(kinds)}"

    entry_points = len(getattr(seed, "entry_points", ()) or ())
    if entry_points < 10:
        return False, f"entry_points={entry_points} < 10"

    sinks = len(getattr(seed, "unsafe_sinks", ()) or ())
    if sinks >= 5:
        return False, f"sinks={sinks} >= 5"

    return True, (
        f"source_files={source_files}, repo_kind={active_kinds}, "
        f"entry_points={entry_points}, sinks={sinks}"
    )


def glob_hit(rel: str, globs) -> str | None:
    """Return the first glob that excludes the repo-relative posix path `rel`,
    else None. Unlike a bare ``fnmatch``, a ``**/x`` pattern ALSO matches a
    repo-ROOT ``x``: ``fnmatch``'s ``**`` requires a slash, so root-level files
    (LICENSE, .gitignore, test_*.py) would otherwise escape the exclusion the
    patterns clearly intend. Shared by the deterministic walk and the survey so
    the two never diverge."""
    name = rel.rsplit("/", 1)[-1]
    for g in globs:
        if fnmatch.fnmatchcase(rel, g):
            return g
        if g.startswith("**/") and fnmatch.fnmatchcase(name, g[3:]):
            return g
    return None


def _norm_rel(repo_root: str, p: str) -> str:
    """Normalize an agent-emitted path to the same repo-relative posix form
    that _walk_repo produces, so set-membership checks work.

    Handles: backslashes, leading './', absolute paths (agent often emits the
    resolved cwd), and Windows case-insensitive drive/dir names. repo_root may
    itself be relative (batch mode passes e.g. 'scans-.../17745'), so we try
    both its literal and resolved forms as strip prefixes."""
    if not p:
        return p
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    rel_root = str(Path(repo_root)).replace("\\", "/").rstrip("/") + "/"
    abs_root = str(Path(repo_root).resolve()).replace("\\", "/").rstrip("/") + "/"
    pl = p.lower()
    for r in (abs_root, rel_root):
        if pl.startswith(r.lower()):
            return p[len(r):]
    return p


def _resolve_scope_path(path: str, repo_root: str, keep: set[str],
                        top_dirs: list[str]) -> tuple[str | None, bool]:
    """Resolve an agent-emitted path to its in-scope inventory form.

    Returns ``(resolved, ambiguous)``:
      * exact inventory hit                          -> (rel, False)
      * unprefixed path under EXACTLY ONE top dir    -> (that path, False)
      * unprefixed path under 2+ top dirs            -> (None, True)   # ambiguous
      * no match                                     -> (None, False)

    The agent sometimes omits the leading directory (in --group-by-app mode the
    repo prefix; in single-repo mode a top-level dir). The fallback re-prefixes
    with each top-level dir. When 2+ top dirs match the same relative path,
    returning the alphabetically-first one would misattribute sinks / entry
    points / module files to the wrong directory (or wrong repo). So that case
    is NOT guessed — it returns ambiguous=True and the caller drops it (fail
    safe: no wrong attribution) and logs the loss. Exact and single-match cases
    are byte-identical to the previous first-match behaviour."""
    rel = _norm_rel(repo_root, path)
    if rel in keep:
        return rel, False
    matches = [f"{td}/{rel}" for td in top_dirs if f"{td}/{rel}" in keep]
    if len(matches) == 1:
        return matches[0], False
    return None, len(matches) > 1


def _walk_repo(repo_root: str, cfg) -> tuple[list[str], dict]:
    root = Path(repo_root)
    root_resolved = root.resolve()
    excl_dirs, excl_exts, excl_globs = _exclusion_sets(cfg)
    max_kb = getattr(cfg.step1, "max_file_kb", 1024)
    # Default-secure AND not config-disableable: in-tree symlinks (common in
    # monorepos) are still scanned, but links whose target resolves OUTSIDE the
    # repo are dropped UNCONDITIONALLY (see the loop below). This blocks an
    # untrusted repo's off-root link plus a shared/CI config writer from
    # exfiltrating host files (SSH keys, /etc/passwd) into the inventory and
    # LLM prompts. `follow_symlinks` is still accepted for back-compat; if it
    # is set, warn that off-root targets remain blocked rather than silently
    # ignore the operator's intent.
    follow_symlinks = bool(getattr(cfg.step1, "follow_symlinks", False))
    if follow_symlinks:
        print("  [s1] NOTE: step1.follow_symlinks is set, but symlinks whose "
              "target resolves outside the repo are still dropped (host-file "
              "disclosure guard); only in-tree symlinks are followed.",
              file=sys.stderr)

    out: list[str] = []
    skipped_dirs: dict[str, int] = {}
    skipped_exts: dict[str, int] = {}
    skipped_globs: dict[str, int] = {}
    skipped_size: list[tuple[str, int]] = []
    skipped_symlinks: dict[str, int] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        # rglob + is_file() follow symbolic links, so a committed symlink whose
        # target resolves outside the repo would otherwise pull arbitrary host
        # file content (e.g. ~/.ssh/id_rsa, /etc/passwd) into the inventory and
        # LLM prompts. This containment check is UNCONDITIONAL — it is not gated
        # on follow_symlinks — so neither a shared/CI config flag nor an
        # attacker-supplied --step1-config overlay can re-open off-host reads.
        if p.is_symlink():
            try:
                tgt = p.resolve(strict=False)
                escapes = not tgt.is_relative_to(root_resolved)
            except OSError:
                escapes = True
            if escapes:
                skipped_symlinks[rel] = skipped_symlinks.get(rel, 0) + 1
                continue
        rel_parts = rel.split("/")
        hit_dir = next((part for part in rel_parts[:-1]
                        if part.lower() in excl_dirs), None)
        if hit_dir:
            prefix = "/".join(rel_parts[:rel_parts.index(hit_dir) + 1])
            skipped_dirs[prefix] = skipped_dirs.get(prefix, 0) + 1
            continue
        name = p.name.lower()
        hit_ext = next((e for e in excl_exts
                        if p.suffix.lower() == e or name.endswith(e)), None)
        if hit_ext:
            skipped_exts[hit_ext] = skipped_exts.get(hit_ext, 0) + 1
            continue
        hit_glob = glob_hit(rel, excl_globs)
        if hit_glob:
            skipped_globs[hit_glob] = skipped_globs.get(hit_glob, 0) + 1
            continue
        try:
            sz = p.stat().st_size
            if sz > max_kb * 1024:
                skipped_size.append((rel, sz))
                continue
        except OSError:
            continue
        out.append(rel)

    excluded = {
        "dirs": skipped_dirs,
        "exts": skipped_exts,
        "globs": skipped_globs,
        "oversize": len(skipped_size),
        "oversize_files": sorted(skipped_size, key=lambda kv: -kv[1]),
        "symlinks": skipped_symlinks,
    }
    return sorted(out), excluded


# ─── Config-file structural dedup ────────────────────────────────────────────
# Collapses near-duplicate per-environment config files (e.g. 5,000 copies of
# service/<svc>/<env>/config.yml) to one representative per shape-cluster, so
# downstream steps don't burn tokens on identical-structure variants. A file
# is only ever dropped if (a) ≥ min_cluster_size siblings share its exact key
# structure AND (b) it passes a secret / insecure-value regex safety net.
# Anything unparseable, unique, or suspicious is kept.

_DEDUP_DEFAULTS = {
    "enabled": True,
    "exts": (".yml", ".yaml", ".json", ".toml", ".ini",
             ".properties", ".conf", ".cfg", ".env"),
    "min_cluster_size": 3,
    "keep_per_top_dir": True,
    "promote_on_secret_hit": True,
    "promote_on_insecure_value": True,
    "max_file_kb": 512,
}

# Layer-2 safety net — literal credential material that must never be
# silently dropped. Negative lookahead skips templated / encrypted refs
# ({{var}}, ${VAR}, CRYPT:…, ENC(…), <%= … %>, vault:…) and nested-key
# false positives (`auth-token:\n  timeout:` — value-looks-like-a-key).
_SECRET_RX = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"auth[_-]?token|private[_-]?key|client[_-]?secret|credential)s?"
    r"[ \t]*[:=][ \t]*['\"]?"
    r"(?!CRYPT:|ENC\(|\{\{|\$\{|<%=|<%|vault:|secret:|file:|/)"
    r"(?![\w.-]+[ \t]*:)"
    r"[^\s'\",}{]{8,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bxox[baprs]-[0-9A-Za-z-]{10,}\b"
    r"|\bgh[pousr]_[0-9A-Za-z]{36,}\b"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

# Insecure *values* (not secrets) whose presence makes a config variant worth
# scanning even if its shape matches a safe sibling.
_INSECURE_RX = re.compile(
    r"(?i)\b(?:verify|verif(?:y|ication)[_-]?ssl|ssl[_-]?verify|"
    r"validate[_-]?cert\w*|tls[_-]?verify|check[_-]?hostname|"
    r"reject[_-]?unauthori[sz]ed)\b\s*[:=]\s*['\"]?(?:false|0|no|none|off)\b"
    r"|\binsecure\w*\s*[:=]\s*['\"]?(?:true|1|yes)\b"
    r"|\bInsecureSkipVerify\s*[:=]\s*true\b"
    r"|\b(?:auth|authentication|authn|security)\s*[:=]\s*['\"]?(?:none|disabled|off|false)\b"
    r"|\bdebug\s*[:=]\s*['\"]?(?:true|1|yes)\b"
    r"|\ballow[_-]?anonymous\s*[:=]\s*['\"]?(?:true|1|yes)\b"
)


def _flatten_keys(obj, prefix: str = "") -> list[str]:
    if isinstance(obj, dict):
        out: list[str] = []
        for k in obj:
            out.extend(_flatten_keys(obj[k], f"{prefix}.{k}" if prefix else str(k)))
        return out or [prefix]
    if isinstance(obj, list):
        out = []
        for it in obj:
            out.extend(_flatten_keys(it, f"{prefix}[]"))
        return out or [prefix]
    return [prefix]


_KV_LINE_RX = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[:=]")
_YAML_KEY_RX = re.compile(r"^( *)(?:- +)?([\w.\-]+)\s*:")


def _shape_hash(text: str, ext: str) -> str | None:
    """Hash of the sorted key-path set (values stripped). None ⇒ keep file.
    YAML uses a fast line-based indent+key scan instead of full safe_load."""
    keys: list[str] = []
    try:
        if ext in (".yml", ".yaml"):
            stack: list[tuple[int, str]] = []
            for ln in text.splitlines():
                if not ln or ln.lstrip().startswith("#"):
                    continue
                m = _YAML_KEY_RX.match(ln)
                if not m:
                    continue
                indent, name = len(m.group(1)), m.group(2)
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                stack.append((indent, name))
                keys.append(".".join(n for _, n in stack))
        elif ext == ".json":
            keys = _flatten_keys(json.loads(text))
        elif ext in (".ini", ".cfg", ".conf"):
            cp = configparser.ConfigParser(strict=False, allow_no_value=True)
            cp.read_string(text)
            for sec in cp.sections():
                for opt in cp.options(sec):
                    keys.append(f"{sec}.{opt}")
        else:
            for ln in text.splitlines():
                m = _KV_LINE_RX.match(ln)
                if m:
                    keys.append(m.group(1))
    except Exception:
        return None
    if not keys:
        return None
    return hashlib.sha1("\n".join(sorted(set(keys))).encode()).hexdigest()


def _suspicious_set(text: str, want_secret: bool, want_insecure: bool) -> set[str]:
    """Normalized set of suspicious-pattern hits — used to diff a candidate
    against its cluster representative so we only promote *new* signals."""
    out: set[str] = set()
    if want_secret:
        for m in _SECRET_RX.finditer(text):
            out.add("secret:" + re.sub(r"\s+", " ", m.group(0))[:80])
    if want_insecure:
        for m in _INSECURE_RX.finditer(text):
            out.add("insecure:" + re.sub(r"\s+", " ", m.group(0))[:80])
    return out


def _rep_score(rel: str, size: int) -> tuple:
    """Pick the most production-relevant variant as the cluster representative."""
    low = rel.lower()
    env = (0 if "/prod" in low else
           1 if any(e in low for e in ("/cert", "/stag", "/stg")) else
           2 if any(e in low for e in ("/perf", "/qa")) else
           3)
    return (env, -size, rel)


def _dedup_configs(files: list[str], repo_root: Path, cfg) -> tuple[list[str], dict]:
    dd = dict(_DEDUP_DEFAULTS)
    user = getattr(getattr(cfg, "step1", None), "config_dedup", None)
    if user is not None:
        raw = (user if isinstance(user, dict)
               else getattr(user, "_data", None) or vars(user))
        dd.update({k: v for k, v in raw.items() if v is not None})
    if not dd["enabled"]:
        return files, {"enabled": False}

    exts = {e.lower() for e in dd["exts"]}
    min_cluster = int(dd["min_cluster_size"])
    max_bytes = int(dd["max_file_kb"]) * 1024

    candidates: list[str] = []
    passthrough: list[str] = []
    for rel in files:
        if Path(rel).suffix.lower() in exts:
            candidates.append(rel)
        else:
            passthrough.append(rel)

    if len(candidates) < min_cluster:
        return files, {"enabled": True, "candidates": len(candidates),
                       "clusters": 0, "dropped": 0, "promoted": 0}

    want_sec = dd["promote_on_secret_hit"]
    want_ins = dd["promote_on_insecure_value"]

    # Pass 1 — shape-hash only. We deliberately DISCARD each body after hashing
    # rather than retaining it: holding every parseable candidate's text in one
    # dict made peak RAM scale with candidate count (only per-file size was ever
    # capped, never count or aggregate bytes), an availability pressure on the
    # worker for a hostile repo with many sub-cap config files. Parallel because
    # Windows file I/O (and AV on-access scanning) dominates; ~6-8x here.
    def _hash(rel: str):
        p = repo_root / rel
        try:
            sz = p.stat().st_size
            if sz > max_bytes:
                return rel, sz, None
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return rel, 0, None
        return rel, sz, _shape_hash(text, p.suffix.lower())

    clusters: dict[str, list[tuple[str, int]]] = defaultdict(list)
    unclustered: list[str] = []
    from concurrent.futures import ThreadPoolExecutor
    workers = int(dd.get("io_workers", 16))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for rel, sz, h in ex.map(_hash, candidates):
            if h is None:
                unclustered.append(rel)
            else:
                clusters[h].append((rel, sz))

    keep: list[str] = list(passthrough) + unclustered
    promoted: list[tuple[str, str]] = []
    dropped: list[str] = []
    cluster_report: list[dict] = []

    # Only large clusters reach the suspicious-set diff, so only THEIR members
    # need a body. Re-read just that bounded subset (a strict subset of
    # candidates — singletons / small clusters are never re-read) and retain
    # only the small normalized suspicious-SET per file, never the body. Peak
    # body residency is now the thread pool's transient buffers
    # (~workers x max_file_kb), independent of candidate count.
    need_sus = [rel for members in clusters.values()
                if len(members) >= min_cluster for rel, _ in members]

    def _susload(rel: str):
        p = repo_root / rel
        try:
            if p.stat().st_size > max_bytes:
                return rel, None
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return rel, None
        return rel, _suspicious_set(text, want_sec, want_ins)

    sus_by_rel: dict[str, set[str]] = {}
    if need_sus:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for rel, sus in ex.map(_susload, need_sus):
                if sus is not None:
                    sus_by_rel[rel] = sus

    # Pass 2 — only large clusters need the (expensive) suspicious-set diff.
    for h, members in clusters.items():
        if len(members) < min_cluster:
            keep.extend(r for r, _ in members)
            continue
        members.sort(key=lambda m: _rep_score(m[0], m[1]))
        reps: dict[str, str] = {}
        if dd["keep_per_top_dir"]:
            for rel, _ in members:
                reps.setdefault(rel.split("/", 1)[0], rel)
        else:
            reps["*"] = members[0][0]
        rep_set = set(reps.values())
        rep_sus: set[str] = set()
        for r in rep_set:
            rep_sus |= sus_by_rel.get(r, set())
        keep.extend(rep_set)

        c_dropped: list[str] = []
        for rel, _ in members:
            if rel in rep_set:
                continue
            if rel not in sus_by_rel:
                # Body unreadable on re-read (TOCTOU: changed / removed since
                # Pass 1). Can't prove it's a pure duplicate -> keep it.
                keep.append(rel)
                continue
            sus = sus_by_rel[rel]
            extra = sus - rep_sus
            if extra:
                keep.append(rel)
                promoted.append((rel, sorted(extra)[0]))
                rep_sus |= sus
            else:
                c_dropped.append(rel)
        dropped.extend(c_dropped)
        cluster_report.append({
            "shape": h[:12],
            "size": len(members),
            "reps": sorted(rep_set),
            "dropped": len(c_dropped),
            "sample": members[0][0],
        })

    cluster_report.sort(key=lambda c: -c["size"])
    report = {
        "enabled": True,
        "candidates": len(candidates),
        "unparseable_kept": len(unclustered),
        "clusters": len([c for c in cluster_report if c["size"] >= min_cluster]),
        "kept_reps": sum(len(c["reps"]) for c in cluster_report),
        "promoted": len(promoted),
        "promoted_files": promoted[:50],
        "dropped": len(dropped),
        "dropped_files": dropped,
        "top_clusters": cluster_report[:10],
    }

    if dropped:
        top = ", ".join(f"{c['sample']} x{c['size']}"
                        for c in cluster_report[:3])
        print(f"  [s1] config-dedup: {len(candidates)} config files -> "
              f"{report['clusters']} shape-clusters; "
              f"kept {report['kept_reps']} reps + {len(promoted)} promoted, "
              f"dropped {len(dropped)} near-duplicates", file=sys.stderr)
        print(f"  [s1]   largest: {top}", file=sys.stderr)
        if promoted:
            print(f"  [s1]   promoted (suspicious value not in rep): "
                  f"{', '.join(p for p, _ in promoted[:5])}"
                  + (f" ... +{len(promoted)-5} more" if len(promoted) > 5 else ""),
                  file=sys.stderr)
    return sorted(keep), report

# ─── Deterministic call-graph supplement ─────────────────────────────────────
# The agent's call_graph is LLM-guessed: sparse, unvalidated, bare function
# names. Taint chunks / neighbor context / connected-component grouping in
# s3/s4 all depend on it. This pass (a) drops hallucinated names, (b) fills
# missing edges by regex-scanning source for calls to known functions, and
# (c) records def-site file:line for every function it sees so downstream
# steps can locate intermediate hops.
#
# P5: nodes are FILE-QUALIFIED (`rel/path/File.java::method`) so polymorphic
# names like save()/process() don't collapse the whole repo into one BFS
# component or shadow real entry→sink paths in s3.

QSEP = "::"
MODULE_SCOPE = "<module>"


def q_join(file: str, name: str) -> str:
    return f"{file}{QSEP}{name}"


def q_split(qname: str) -> tuple[str, str]:
    if QSEP in qname:
        f, _, n = qname.rpartition(QSEP)
        return f, n
    return "", qname


def q_file(qname: str) -> str:
    return q_split(qname)[0]


def q_name(qname: str) -> str:
    return q_split(qname)[1]


# ── import-aware callee resolution helpers ──────────────────────────────────

# Regex-based import parsers keyed by file extension.  Each pattern yields
# (alias, fq_module) pairs where alias is the local name a caller uses.
_IMPORT_RXS: dict[str, list[re.Pattern]] = {
    ".py": [
        # from x.y import z [as alias]
        re.compile(r"^from\s+([\w.]+)\s+import\s+(\w+)(?:\s+as\s+(\w+))?"),
        # import x.y.z [as alias]
        re.compile(r"^import\s+([\w.]+)(?:\s+as\s+(\w+))?"),
    ],
    ".java": [
        re.compile(r"^import\s+(?:static\s+)?([\w.]+)\.([\w*]+)\s*;"),
    ],
    ".js": [
        re.compile(r"""^(?:const|let|var)\s+\{?(\w+)\}?\s*=\s*require\s*\(['"]([^'"]+)['"]\)"""),
        re.compile(r"""^import\s+(?:\{?\s*(\w+)\s*\}?)\s+from\s+['"]([^'"]+)['"]"""),
    ],
    ".ts": [
        re.compile(r"""^import\s+(?:\{?\s*(\w+)\s*\}?)\s+from\s+['"]([^'"]+)['"]"""),
    ],
    ".go": [
        re.compile(r"""^\s+(\w+)?\s*["]([\w./]+)["]\s*$"""),
    ],
    ".cs": [
        re.compile(r"^using\s+([\w.]+)\s*;"),
        re.compile(r"^using\s+(\w+)\s*=\s*([\w.]+)\s*;"),
    ],
}
_IMPORT_RXS[".jsx"] = _IMPORT_RXS[".js"]
_IMPORT_RXS[".tsx"] = _IMPORT_RXS[".ts"]
_IMPORT_RXS[".cjs"] = _IMPORT_RXS[".js"]
_IMPORT_RXS[".mjs"] = _IMPORT_RXS[".js"]


def _resolve_py_import_module(caller_file: str, module: str, level: int) -> str:
    """Resolve a Python ImportFrom module to an absolute dotted module path.

    Example:
      caller_file="pkg/sub/handler.py", module="services", level=1
      -> "pkg.sub.services"
    """
    rel = caller_file.replace("\\", "/").strip("/")
    dirs = [p for p in rel.split("/")[:-1] if p]
    # In Python AST, level=1 means "current package" (no upward hop),
    # level=2 means "one parent", etc.
    up = max(0, level - 1)
    if up:
        base = dirs[:-up] if up <= len(dirs) else []
    else:
        base = dirs
    mod_parts = [p for p in module.split(".") if p]
    parts = base + mod_parts
    return ".".join(parts)


def _scan_imports(lines: list[str], ext: str, caller_file: str = "") -> dict[str, str]:
    """Return {local_name: fq_module} for the given file's import statements.

    Only simple, statically-detectable imports are captured; star imports and
    dynamic imports fall back to the proximity scorer in _resolve_callee_files.
    """
    # Python uses AST parsing so multiline imports, aliases, and relative
    # imports are handled structurally rather than by line regexes.
    if ext == ".py":
        src = "\n".join(lines)
        result: dict[str, str] = {}
        try:
            tree = ast.parse(src)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod = (alias.name or "").strip()
                        if not mod:
                            continue
                        local = alias.asname or mod.split(".")[0]
                        result[local] = mod
                elif isinstance(node, ast.ImportFrom):
                    level = int(getattr(node, "level", 0) or 0)
                    mod = (node.module or "").strip()
                    resolved_mod = _resolve_py_import_module(caller_file, mod, level)
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        local = alias.asname or alias.name
                        # Map imported symbol -> module path (not module.symbol)
                        # so the resolver can match files like pkg/sub/services.py.
                        if resolved_mod:
                            result[local] = resolved_mod
                        elif mod:
                            result[local] = mod
            if result:
                return result
    patterns = _IMPORT_RXS.get(ext)
    if not patterns:
        return {}
    result: dict[str, str] = {}
    for ln in lines:
        stripped = ln.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        if ext == ".py":
            m = patterns[0].match(stripped)
            if m:
                mod, _sym, alias = m.group(1), m.group(2), m.group(3)
                local = alias if alias else _sym
                result[local] = mod
                continue
            m = patterns[1].match(stripped)
            if m:
                mod, alias = m.group(1), m.group(2)
                local = alias if alias else mod.split(".")[0]
                result[local] = mod
            continue
        if ext == ".java":
            m = patterns[0].match(stripped)
            if m:
                pkg, sym = m.group(1), m.group(2)
                if sym != "*":
                    result[sym] = f"{pkg}.{sym}"
            continue
        if ext in (".js", ".jsx", ".cjs", ".mjs", ".ts", ".tsx"):
            for p in patterns:
                m = p.match(stripped)
                if m:
                    sym, mod = m.group(1), m.group(2)
                    if sym:
                        result[sym] = mod
                    break
            continue
        if ext == ".go":
            m = patterns[0].match(stripped)
            if m:
                alias, mod = m.group(1), m.group(2)
                local = alias if alias else mod.rsplit("/", 1)[-1]
                result[local] = mod
            continue
        if ext == ".cs":
            m = patterns[1].match(stripped)
            if m:
                result[m.group(1)] = m.group(2)
                continue
            m = patterns[0].match(stripped)
            if m:
                ns = m.group(1)
                result[ns.rsplit(".", 1)[-1]] = ns
    return result


def _file_matches_import(file_path: str, fq_module: str, ext: str) -> bool:
    """Return True if file_path is the likely definition site for fq_module.

    Converts 'com.foo.Bar' → 'com/foo/Bar' and checks whether file_path ends
    with that path (with or without the extension).
    """
    as_path = fq_module.replace(".", "/").replace("//", "/")
    norm = file_path.replace("\\", "/")
    stem = norm[: -len(ext)] if norm.endswith(ext) else norm
    if stem.endswith(as_path) or norm.endswith(as_path + ext):
        return True
    if ext == ".py" and norm.endswith(as_path + "/__init__.py"):
        return True
    return False


def _resolve_callee_files(name: str, caller_file: str,
                          def_files: dict[str, set[str]],
                          max_targets: int,
                          caller_imports: dict[str, str] | None = None) -> list[str]:
    """Pick ≤max_targets def-site files for bare `name` when called from
    `caller_file`.

    Resolution order:
    1. Same file (unambiguous).
    2. Import-aware exact match — if the caller imports ``name`` from a known
       module and a def-site file path matches that module, return it directly.
    3. Longest-common-dir-prefix proximity (original heuristic), capped at
       ``max_targets``.
    """
    cands = def_files.get(name)
    if not cands:
        return []
    if caller_file in cands:
        return [caller_file]
    if len(cands) == 1:
        return list(cands)
    # Import-aware exact match — short-circuit proximity ranking when the
    # caller's imports tell us exactly which module ``name`` came from.
    if caller_imports and name in caller_imports:
        fq = caller_imports[name]
        caller_ext = "." + caller_file.rsplit(".", 1)[-1] if "." in caller_file else ""
        # Try module path first (from x.y import name -> x.y.py), then a
        # symbol-as-module fallback (from x import name -> x/name.py).
        probes = [fq, f"{fq}.{name}"] if fq else [name]
        matches = [
            f for f in cands
            if any(_file_matches_import(f, probe, caller_ext) for probe in probes)
        ]
        if matches:
            return matches[:max_targets]
    cp = caller_file.split("/")
    def _score(f: str) -> int:
        n = 0
        for a, b in zip(cp, f.split("/")):
            if a == b:
                n += 1
            else:
                break
        return n
    return sorted(cands, key=_score, reverse=True)[:max_targets]


_DEF_RXS: tuple[re.Pattern, ...] = (
    re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\*?\s+(\w+)\s*\("),
    re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*[(<]"),
    re.compile(r"^\s*fn\s+(\w+)"),
    re.compile(r"^\s*sub\s+(\w+)"),
    re.compile(
        r"^\s*(?:@\w+\s*)?"
        r"(?:(?:public|private|protected|internal|static|final|override|"
        r"virtual|abstract|async|synchronized|native|inline|extern)\s+)+"
        r"[\w<>\[\],.?*&\s]+?\b(\w+)\s*\("
    ),
    re.compile(r"^\s*(?:[\w*&:]+\s+){1,2}(\w+)\s*\([^;()]*\)\s*\{"),
    re.compile(r"^\s{2,}(?:async\s+|static\s+|get\s+|set\s+)?(\w+)\s*\([^;()]*\)\s*\{"),
)
_NOT_A_DEF = frozenset({
    "if", "for", "while", "switch", "catch", "return", "throw", "new", "else",
    "do", "try", "with", "using", "lock", "super", "this", "typeof", "delete",
    "sizeof", "instanceof", "synchronized", "yield", "await", "assert", "print",
})
_CALL_TOKEN_RX = re.compile(r"\b([A-Za-z_]\w{2,})\s*\(")


def _scan_defs(lines: list[str]) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for i, ln in enumerate(lines, 1):
        for rx in _DEF_RXS:
            m = rx.match(ln)
            if m and m.group(1) not in _NOT_A_DEF:
                out.append((i, m.group(1)))
                break
    return out


def _seed_covered_languages(data: dict) -> set[str]:
    """Languages that S0's callgraph artifacts actually name a file in.

    S0's engine only has plugins for a handful of languages, so its graph can
    only ever describe files in those languages. Deriving the covered set from
    the artifacts themselves (rather than hard-coding the plugin list) means a
    plugin language that happened to contribute no nodes is treated as residual
    and re-scanned, which only improves coverage.
    """
    langs: set[str] = set()

    def _add(rel: str) -> None:
        lang = EXT_TO_LANG.get(Path(rel).suffix.lower())
        if lang:
            langs.add(lang)

    for qn in (data.get("def_spans") or {}):
        _add(q_file(qn))
    for qn, vs in (data.get("call_graph") or {}).items():
        _add(q_file(qn))
        for v in vs or ():
            _add(q_file(v))
    for locs in (data.get("call_graph_files") or {}).values():
        for loc in locs or ():
            f = loc.rpartition(":")[0]
            if f:
                _add(f)
    return langs


def _merge_graph_artifacts(data: dict, seed_cg: dict, seed_cgf: dict,
                           seed_spans: dict) -> None:
    """Merge S0's snapshotted artifacts back over a residual-language rebuild.

    ``ts_graph.build`` overwrites ``data``'s three graph dicts, so S0's
    (plugin-language) graph is snapshotted before the residual build and folded
    back in here. Keys are qnodes ``file::name`` for the edge/span maps (no
    cross-language collisions) and bare names for ``call_graph_files`` (which
    CAN collide across languages, so those lists are unioned). S0's def_spans
    win on the rare qnode collision — its AST spans are authoritative.
    """
    cg = data.get("call_graph") or {}
    for k, vs in seed_cg.items():
        cg[k] = sorted(set(cg.get(k, ())) | set(vs or ()))
    data["call_graph"] = cg

    cgf = data.get("call_graph_files") or {}
    for k, vs in seed_cgf.items():
        cgf[k] = sorted(set(cgf.get(k, ())) | set(vs or ()))
    data["call_graph_files"] = cgf

    spans = data.get("def_spans") or {}
    spans.update(seed_spans)   # seed (plugin AST) wins on collision
    data["def_spans"] = spans


def _supplement_call_graph(data: dict, all_files: list[str],
                           repo_root: Path, cfg) -> None:
    s1 = getattr(cfg, "step1", None)
    do_supp = getattr(s1, "call_graph_supplement", True) if s1 else True
    do_validate = getattr(s1, "call_graph_validate", True) if s1 else True
    rounds = int(getattr(s1, "call_graph_rounds", 3)) if s1 else 3
    max_targets = int(getattr(s1, "call_graph_max_targets", 3)) if s1 else 3
    if not do_supp and not do_validate:
        return

    raw_cg: dict[str, set[str]] = defaultdict(set)
    for k, vs in (data.get("call_graph") or {}).items():
        if k:
            raw_cg[q_name(k)].update(q_name(v) for v in (vs or []) if v)

    seeds: set[str] = set()
    for ep in data.get("entry_points") or []:
        if ep.get("function"):
            seeds.add(ep["function"])
    for s in data.get("unsafe_sinks") or []:
        if s.get("function"):
            seeds.add(s["function"])
    seeds.update(raw_cg.keys())
    for vs in raw_cg.values():
        seeds.update(vs)
    seeds = {s for s in seeds if s and s not in _NOT_A_DEF and len(s) >= 3}

    src_files: list[tuple[str, list[str], list[tuple[int, str]]]] = []
    seen_call_tokens: set[str] = set()
    fn_locs: dict[str, set[str]] = defaultdict(set)
    def_files: dict[str, set[str]] = defaultdict(set)
    imports_by_file: dict[str, dict[str, str]] = {}
    for rel in all_files:
        if Path(rel).suffix.lower() not in EXT_TO_LANG:
            continue
        p = repo_root / rel
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        defs = _scan_defs(lines)
        for lineno, name in defs:
            fn_locs[name].add(f"{rel}:{lineno}")
            def_files[name].add(rel)
        for m in _CALL_TOKEN_RX.finditer(text):
            seen_call_tokens.add(m.group(1))
        imports_by_file[rel] = _scan_imports(lines, Path(rel).suffix.lower(), rel)
        src_files.append((rel, lines, defs))

    seen_any = seen_call_tokens | set(fn_locs)

    # ── Qualify + validate the agent-emitted graph ───────────────────────
    cg: dict[str, set[str]] = defaultdict(set)
    n_agent_edges = sum(len(v) for v in raw_cg.values())
    n_dropped = 0
    for caller, callees in raw_cg.items():
        if do_validate and seen_any and caller not in seen_any:
            n_dropped += len(callees)
            continue
        caller_sites = sorted(def_files.get(caller, ()))[:max_targets] or [""]
        for callee in callees:
            if do_validate and seen_any and callee not in seen_any:
                n_dropped += 1
                continue
            for cf in caller_sites:
                ci = imports_by_file.get(cf) if cf else None
                tgts = (_resolve_callee_files(callee, cf, def_files, max_targets, ci)
                        if cf else sorted(def_files.get(callee, ()))[:max_targets])
                if not tgts:
                    if do_validate:
                        n_dropped += 1
                    else:
                        cg[q_join(cf, caller) if cf else caller].add(callee)
                    continue
                for tf in tgts:
                    cg[q_join(cf, caller) if cf else caller].add(q_join(tf, callee))

    # ── Supplement: regex-scan source, emit qualified edges ──────────────
    n_added = 0
    if do_supp and seeds:
        targets = (seeds & seen_any) if seen_any else set(seeds)
        known: set[str] = set(targets)
        for _ in range(max(1, rounds)):
            if not targets:
                break
            esc = sorted((re.escape(t) for t in targets), key=len, reverse=True)[:600]
            rx = re.compile(r"(?<!\w)(" + "|".join(esc) + r")\s*\(")
            new_targets: set[str] = set()
            for rel, lines, defs in src_files:
                _is_py = Path(rel).suffix.lower() == ".py"
                # Scope tracking — Python uses indent-level stack; brace-based
                # languages count { / } depth.  Both reset cur to None when the
                # enclosing function scope ends so module-level code between two
                # functions is attributed to MODULE_SCOPE rather than the
                # previous function.
                scope_stack: list[tuple[str, int]] = []  # Python: [(name, def_indent)]
                brace_depth = 0      # net open-braces inside current function
                brace_entered = False  # have we seen the opening '{' for this fn?
                cur = None
                di = 0
                for lineno, ln in enumerate(lines, 1):
                    stripped = ln.lstrip()
                    # ── scope exit (check before advancing to next def) ──────
                    if cur is not None:
                        if _is_py:
                            if stripped and stripped[0] != "#":
                                curr_indent = len(ln) - len(stripped)
                                while scope_stack and curr_indent <= scope_stack[-1][1]:
                                    scope_stack.pop()
                                cur = scope_stack[-1][0] if scope_stack else None
                        else:
                            for ch in ln:
                                if ch == "{":
                                    brace_depth += 1
                                    brace_entered = True
                                elif ch == "}":
                                    brace_depth = max(0, brace_depth - 1)
                            if brace_entered and brace_depth == 0:
                                cur = None
                                brace_entered = False
                    # ── scope advance ────────────────────────────────────────
                    while di < len(defs) and defs[di][0] <= lineno:
                        name = defs[di][1]
                        if _is_py:
                            def_ln = lines[defs[di][0] - 1]
                            def_indent = len(def_ln) - len(def_ln.lstrip())
                            scope_stack.append((name, def_indent))
                        else:
                            brace_depth = 0
                            brace_entered = False
                        cur = name
                        di += 1
                    # ── emit edges ───────────────────────────────────────────
                    for m in rx.finditer(ln):
                        callee = m.group(1)
                        enclosing = cur if cur is not None else MODULE_SCOPE
                        if enclosing == callee:
                            continue
                        qcur = q_join(rel, enclosing)
                        _ci = imports_by_file.get(rel)
                        for tf in _resolve_callee_files(callee, rel, def_files,
                                                        max_targets, _ci):
                            qcal = q_join(tf, callee)
                            if qcal not in cg[qcur]:
                                cg[qcur].add(qcal)
                                n_added += 1
                        if cur is not None and cur not in known:
                            new_targets.add(cur)
            known |= new_targets
            targets = new_targets

    data["call_graph"] = {k: sorted(v) for k, v in cg.items() if v}
    relevant: set[str] = set()
    for k, vs in data["call_graph"].items():
        relevant.add(q_name(k))
        relevant.update(q_name(v) for v in vs)
    data["call_graph_files"] = {k: sorted(v) for k, v in fn_locs.items()
                                if k in relevant}

    n_edges_after = sum(len(v) for v in data["call_graph"].values())
    print(f"  [s1] call-graph: agent={n_agent_edges} edges "
          f"→ validate -{n_dropped} hallucinated "
          f"→ supplement +{n_added} regex "
          f"= {n_edges_after} qualified edges over "
          f"{len(data['call_graph'])} nodes, "
          f"{len(data['call_graph_files'])} located fns "
          f"({len(src_files)} source files scanned)", file=sys.stderr)


SYSTEM = """You are a security-focused codebase mapper. Explore this repository
using your built-in tools (Read, Glob, Grep) to build a structural
understanding.

1. Start with Glob to see the file layout and identify the primary language.
2. Grep for unsafe sinks (strcat, strcpy, sprintf, memcpy, system, exec, eval,
   pickle.loads, yaml.load, deserialize, etc — adapt to the language).
3. Grep for entry points (main, HTTP handlers, RPC handlers, socket listeners,
   CLI parsers, deserializers).
4. Read key files to understand purpose (one-line summary per module).
5. Build a rough call graph for paths from entry points to unsafe sinks.

Be efficient — broad searches first, then targeted reads.

IMPORTANT: Your FINAL output must be ONLY a JSON object with this exact schema
(no prose before or after):
{
  "language": "primary language",
  "modules": [{"name":"str", "files":["path"], "loc":1234, "purpose":"one-line"}],
  "entry_points": [{"file":"str", "function":"str", "kind":"network|ipc|file|cli|deserialization|other", "reachable_from_unauth":true}],
  "unsafe_sinks": [{"file":"str", "line":123, "function":"str", "snippet":"the line"}],
  "call_graph": {"caller_func": ["callee_func"]},
  "notes": "free-form observations"
}

Do NOT include raw source code in the output. Include file paths, line numbers,
function names, and short snippets (max 120 chars each) only."""


def run(repo_root: str, cfg, known_cves: list[CVE], controls: list[Control],
        seed=None) -> ContextPackage:
    """``seed`` is the optional s0_seed.SeedPackage. When present its
    entry_points/unsafe_sinks are merged into the ContextPackage AFTER the
    agentic phase (so the deterministic exclusion filter still applies).
    In ``gap_fill`` mode S1 skips agentic exploration only when the S0 seed is
    strong enough; sparse seed coverage on a large app repo escalates back to
    agentic discovery."""
    cve_block = "\n".join(f"  - {c.id}: {c.summary}" for c in known_cves) or "  (none)"

    # Option B: tell the agent up front which dirs/patterns to skip so it
    # doesn't burn the max_budget_usd reading test/build/vendor code. This is
    # advisory only — Option A below enforces it deterministically.
    excl_dirs, _excl_exts, _excl_globs = _exclusion_sets(cfg)
    skip_dirs = ", ".join(sorted(excl_dirs))

    user_prompt = f"""Map this repository for security analysis.

Known CVEs already filed (do NOT re-flag these as new findings):
{cve_block}

OUT OF SCOPE — do NOT Glob into, Grep through, or Read files under any
directory named one of these (tests / build artifacts / vendor / infra; they
are not production attack surface and waste your tool budget):
  {skip_dirs}

Also skip individual test files matching:
  *_test.*  *.test.*  *.spec.*  *Test.java  *Tests.java  *IT.java  conftest.py

Do not report unsafe_sinks, entry_points or modules from those paths.

Explore the codebase thoroughly, then output the JSON ContextPackage."""

    # Parse allowed_tools from config (it's a list in YAML)
    allowed_tools = cfg.step1.allowed_tools
    if isinstance(allowed_tools, list):
        tools = allowed_tools
    else:
        tools = ["Read", "Glob", "Grep", "Bash"]

    # Inject repo_root, ground-truth file list, CVEs, controls (not generated by the model)
    # Reuse s0's walk when it ran (taint profile) rather than walking the repo a
    # second time; both the file list and the exclusion report travel on the
    # seed. Fall back to our own walk when s0 was disabled or produced no walk
    # (e.g. a checkpoint from before the walk was threaded, on --resume).
    if seed is not None and getattr(seed, "all_files", None):
        all_files, excluded = list(seed.all_files), dict(seed.excluded)
    else:
        all_files, excluded = _walk_repo(repo_root, cfg)
    all_files, dedup_report = _dedup_configs(all_files, Path(repo_root), cfg)
    excluded["config_dedup"] = dedup_report
    tracker = getattr(cfg, "_scan_progress", None)
    if tracker is not None:
        tracker.discovered(all_files)

    mode = getattr(cfg.step1, "mode", "full")
    effective_mode = mode
    if mode == "gap_fill" and seed:
        escalate, reason = _should_escalate_gap_fill(seed, all_files)
        if escalate:
            effective_mode = "full"
            print(f"  [s1] mode=gap_fill — escalating to agentic discovery "
                  f"({reason})", file=sys.stderr)
            log.info("s1/preprocess: gap_fill escalated to full mode - reason=%s", reason)
        else:
            print(f"  [s1] mode=gap_fill — using s0 seed "
                  f"({len(seed.entry_points)} EPs / {len(seed.unsafe_sinks)} sinks); "
                  f"skipping agentic exploration ({reason})", file=sys.stderr)
            log.info("s1/preprocess: using gap_fill mode with s0 seed - "
                     "entry_points=%d sinks=%d reason=%s",
                     len(seed.entry_points), len(seed.unsafe_sinks), reason)

    if effective_mode == "gap_fill" and seed:
        raw = "{}"
    else:
        raw = agentic(
            user_prompt,
            model=cfg.models.preprocess,
            system_prompt=SYSTEM,
            allowed_tools=tools,
            cwd=repo_root,
            max_budget_usd=cfg.step1.max_budget_usd,
            max_turns=getattr(cfg.step1, "max_turns", None),
        )

    # The agentic output may have tool-use chatter before the final JSON.
    # Extract the last JSON block.
    #
    # degrade — don't abort the whole scan — when the mapper emits empty
    # or non-JSON output, mirroring s4/s8's fallback behaviour. The downstream
    # ground-truth walk (_walk_repo) and the deterministic call-graph supplement
    # below repopulate file inventory + edges, so an empty agent map still yields
    # a usable ContextPackage (we just lose the LLM's sink/entry-point guesses).
    try:
        data = extract_json(raw)
        if not isinstance(data, dict):
            raise ValueError(f"expected JSON object, got {type(data).__name__}")
    except Exception as e:  # noqa: BLE001 — model output is heterogeneous
        head = (raw or "")[:500].replace("\n", "\\n")
        print(f"  [s1] WARN: mapper response not parseable ({e}); proceeding "
              f"with deterministic inventory only. raw[:500]={head!r}",
              file=sys.stderr)
        data = {}

    # The model occasionally wraps the payload in a single container key
    # (e.g. {"context_package": {...}} or {"ContextPackage": {...}}) because
    # the prompt says "output the JSON ContextPackage". Unwrap it.
    if (isinstance(data, dict) and "language" not in data
            and len(data) == 1):
        inner = next(iter(data.values()))
        if isinstance(inner, dict) and ("language" in inner
                                         or "modules" in inner
                                         or "entry_points" in inner):
            print(f"  [s1] unwrapping model output from "
                  f"{next(iter(data))!r} container", file=sys.stderr)
            data = inner

    # Option A: deterministically strip any agent-emitted path that isn't in
    # the exclusion-filtered ground-truth inventory. The agent ignores the
    # prompt skip-list ~10% of the time; this guarantees test/mock/vendor
    # paths never reach s3 chunking regardless. Paths are normalized so
    # './foo', 'foo', '<abs>/foo' and 'foo\\bar' all match the inventory form.
    keep = set(all_files)
    # In --group-by-app mode repo_root is the app dir and each repo is a
    # top-level subdir. The agent sometimes reports paths relative to the
    # repo it explored (omitting that prefix), so fall back to trying each
    # top-level dir as a prefix before discarding.
    top_dirs = sorted(d.name for d in Path(repo_root).iterdir()
                      if d.is_dir() and d.name not in ("checkpoints",
                                                       "security-scan"))

    ambiguous: list[str] = []   # unprefixed paths matching 2+ top dirs — dropped, not guessed

    def _resolve_in_scope(path: str) -> str | None:
        hit, amb = _resolve_scope_path(path, repo_root, keep, top_dirs)
        if amb:
            ambiguous.append(path)        # raw agent string — useful in the log
        return hit

    n_sinks_raw = len(data.get("unsafe_sinks") or [])
    n_eps_raw = len(data.get("entry_points") or [])

    data["unsafe_sinks"] = [
        dict(s, file=hit)
        for s in (data.get("unsafe_sinks") or [])
        if (hit := _resolve_in_scope(s.get("file", "")))
    ]
    data["entry_points"] = [
        dict(e, file=hit)
        for e in (data.get("entry_points") or [])
        if (hit := _resolve_in_scope(e.get("file", "")))
    ]
    for m in (data.get("modules") or []):
        m["files"] = [hit for f in (m.get("files") or [])
                      if (hit := _resolve_in_scope(f))]

    n_sinks_drop = n_sinks_raw - len(data["unsafe_sinks"])
    n_eps_drop = n_eps_raw - len(data["entry_points"])
    if n_sinks_drop or n_eps_drop:
        print(f"  [s1] filtered agent output: -{n_sinks_drop} sinks, "
              f"-{n_eps_drop} entry points (excluded/test/nonexistent paths)",
              file=sys.stderr)

    # ── merge s0 static seed ────────────────────────────────────────────
    # Seed paths are already repo-relative posix and pre-filtered to s0's
    # in-scope set, but re-check against `keep` here so config-dedup drops
    # propagate. Seed entries are appended AFTER agent output so the dedup
    # in s3/s7 collapses overlap; order doesn't affect ranking.
    if seed:
        seed_sinks = [dict(s.model_dump(), file=hit)
                      for s in seed.unsafe_sinks
                      if (hit := _resolve_in_scope(s.file))]
        seed_eps = [dict(e.model_dump(), file=hit)
                    for e in seed.entry_points
                    if (hit := _resolve_in_scope(e.file))]
        data["unsafe_sinks"].extend(seed_sinks)
        data["entry_points"].extend(seed_eps)
        log.info("s1/preprocess: merged s0 seed - sinks=%d entry_points=%d "
                 "engine=%s", len(seed_sinks), len(seed_eps), 
                 getattr(seed, "engine", "unknown"))
        # Semgrep codeFlow paths → ContextPackage.seed_taint_paths. Hops are
        # "file:line"; re-resolve each file against the ground-truth inventory
        # (drops out-of-scope hops but keeps the path so long as ≥2 hops
        # survive) so s3._reachable_files can trust every file it names.
        seed_paths: list[list[str]] = []
        for path in getattr(seed, "taint_paths", None) or []:
            resolved = []
            for hop in path:
                f, sep, ln = hop.rpartition(":")
                hit = _resolve_in_scope(f or hop)
                if hit:
                    resolved.append(f"{hit}:{ln}" if sep else hit)
            if len(resolved) >= 2:
                seed_paths.append(resolved)
        data["seed_taint_paths"] = seed_paths
        log.debug("s1/preprocess: seed taint paths processed - paths=%d", len(seed_paths))

        # Structured taint evidence from S0 (Phase-1) mirrors seed_taint_paths
        # filtering: keep only evidence whose source+sink refs both resolve in
        # scope, then best-effort prune path funcs / edges to in-scope files.
        seed_evidence = []
        for evidence in getattr(seed, "taint_evidence", None) or []:
            src_file, src_sep, src_tail = evidence.source_ref.partition("::")
            if not src_sep:
                src_file, src_sep, src_tail = evidence.source_ref.rpartition(":")
            src_hit = _resolve_in_scope(src_file or evidence.source_ref)
            if not src_hit:
                continue
            source_ref = f"{src_hit}{src_sep}{src_tail}" if src_sep else src_hit

            sink_file, sink_sep, sink_tail = evidence.sink_ref.rpartition(":")
            sink_hit = _resolve_in_scope(sink_file or evidence.sink_ref)
            if not sink_hit:
                continue
            sink_ref = f"{sink_hit}:{sink_tail}" if sink_sep else sink_hit

            path_funcs = []
            for qn in evidence.path_funcs:
                q_file, sep, q_tail = qn.partition("::")
                q_hit = _resolve_in_scope(q_file)
                if q_hit:
                    path_funcs.append(f"{q_hit}{sep}{q_tail}" if sep else q_hit)

            edges = []
            for edge in evidence.edges:
                edge_hit = _resolve_in_scope(edge.file)
                if not edge_hit:
                    continue

                fn_file, fn_sep, fn_tail = edge.function_qnode.partition("::")
                fn_hit = _resolve_in_scope(fn_file)
                if fn_hit:
                    function_qnode = (f"{fn_hit}{fn_sep}{fn_tail}"
                                      if fn_sep else fn_hit)
                else:
                    function_qnode = edge.function_qnode

                src_q_file, src_q_sep, src_q_tail = edge.src.qnode.partition("::")
                src_q_hit = _resolve_in_scope(src_q_file)
                src_qnode = (f"{src_q_hit}{src_q_sep}{src_q_tail}"
                             if src_q_hit else edge.src.qnode)

                dst_q_file, dst_q_sep, dst_q_tail = edge.dst.qnode.partition("::")
                dst_q_hit = _resolve_in_scope(dst_q_file)
                dst_qnode = (f"{dst_q_hit}{dst_q_sep}{dst_q_tail}"
                             if dst_q_hit else edge.dst.qnode)

                edge_data = edge.model_dump()
                edge_data["file"] = edge_hit
                edge_data["function_qnode"] = function_qnode
                edge_data["src"]["qnode"] = src_qnode
                edge_data["dst"]["qnode"] = dst_qnode
                edges.append(edge_data)

            seed_evidence.append({
                "source_ref": source_ref,
                "sink_ref": sink_ref,
                "path_funcs": path_funcs,
                "edges": edges,
                "sink_cwe": list(evidence.sink_cwe or []),
            })
        data["seed_taint_evidence"] = seed_evidence

        # Extract framework entry points from seed.
        # Framework markers are detected during scanning and emitted as framework-kind
        # entry points. Extract and resolve them against in-scope inventory like
        # regular entry points.
        framework_eps = []
        framework_unresolvable: set[str] = set()
        for ep in getattr(seed, "entry_points", []) or []:
            if getattr(ep, "kind", "").lower() == "framework":
                hit = _resolve_in_scope(ep.file)
                if hit:
                    framework_eps.append(dict(ep.model_dump(), file=hit))
                else:
                    framework_unresolvable.add(f"{ep.file}::{ep.function}")
        if framework_eps:
            data["entry_points"].extend(framework_eps)
        if framework_unresolvable:
            sample = ", ".join(sorted(framework_unresolvable)[:3])
            n_str = f" (+{len(framework_unresolvable)-3} more)" if len(framework_unresolvable) > 3 else ""
            print(f"  [s1] WARN: {len(framework_unresolvable)} framework entry points "
                  f"could not be resolved to in-scope inventory: {sample}{n_str}",
                  file=sys.stderr)

        # Reuse AST call-graph artifacts from S0 when available. This avoids
        # reparsing the same repository in S1 for callgraph-enabled profiles.
        if getattr(seed, "call_graph", None):
            data["call_graph"] = {
                k: sorted(v)
                for k, v in (seed.call_graph or {}).items()
                if v
            }
        if getattr(seed, "call_graph_files", None):
            data["call_graph_files"] = {
                k: sorted(v)
                for k, v in (seed.call_graph_files or {}).items()
                if v
            }
        if getattr(seed, "def_spans", None):
            data["def_spans"] = {
                k: [int(v[0]), int(v[1])]
                for k, v in (seed.def_spans or {}).items()
                if isinstance(v, list) and len(v) >= 2
            }

        if seed_sinks or seed_eps or seed_paths or seed_evidence or framework_eps:
            print(f"  [s1] merged s0 seed: +{len(seed_eps)} entry points, "
                  f"+{len(seed_sinks)} sinks, {len(seed_paths)} codeFlow "
                  f"paths, +{len(framework_eps)} framework EPs ({seed.engine})", 
                  file=sys.stderr)

    if ambiguous:
        uniq = sorted(set(ambiguous))
        sample = ", ".join(uniq[:5]) + ("…" if len(uniq) > 5 else "")
        print(f"  [s1] WARN: dropped {len(ambiguous)} unprefixed path(s) "
              f"matching 2+ top-level directories (ambiguous — not guessed): "
              f"{sample}", file=sys.stderr)

    data["repo_root"] = repo_root
    # `language` is a required field with no default; on the degraded path
    # (empty agent output) the model never supplied one. Derive a deterministic
    # fallback from the most common source extension so model_validate succeeds.
    if not data.get("language"):
        ext_counts: dict[str, int] = {}
        for f in all_files:
            lang = EXT_TO_LANG.get(Path(f).suffix.lower())
            if lang:
                ext_counts[lang] = ext_counts.get(lang, 0) + 1
        data["language"] = (max(ext_counts, key=ext_counts.get)
                            if ext_counts else "unknown")
    data["all_files"] = all_files
    data["excluded"] = excluded
    data["known_cves"] = [c.model_dump() for c in known_cves]
    data["design_controls"] = [c.model_dump() for c in controls]

    # Call-graph backend dispatch. ``tree_sitter`` (default) gives exact
    # def end-lines / byte-ranges → precise enclosing-caller resolution and
    # populates def_spans for Phase-4 function slicing. Falls back to the
    # regex supplement when tree-sitter-language-pack is unavailable.
    cg_mode = str(getattr(cfg.step1, "call_graph", "tree_sitter")).lower()
    has_seed_cg = bool(data.get("call_graph"))
    has_seed_cg_files = bool(data.get("call_graph_files"))
    has_seed_spans = bool(data.get("def_spans"))

    if has_seed_cg and has_seed_cg_files and has_seed_spans:
        print("  [s1] reusing S0 callgraph artifacts as the primary graph",
              file=sys.stderr)
    elif has_seed_cg or has_seed_cg_files or has_seed_spans:
        print("  [s1] partial S0 callgraph artifacts detected; completing in S1",
              file=sys.stderr)

    if cg_mode == "tree_sitter":
        all_three = has_seed_cg and has_seed_cg_files and has_seed_spans
        if all_three:
            # S0's graph is authoritative but only covers the few languages its
            # engine has plugins for. Reusing it wholesale would mark every file
            # in the other ~36 languages structurally unreachable. Gate reuse on
            # LANGUAGE COVERAGE rather than artifact non-emptiness: keep S0 as
            # the primary graph, but back the residual-language file set with a
            # tree-sitter rebuild and merge per language so no language is
            # silently dropped from reachability.
            covered = _seed_covered_languages(data)
            residual = [
                f for f in all_files
                if EXT_TO_LANG.get(Path(f).suffix.lower())
                and EXT_TO_LANG[Path(f).suffix.lower()] not in covered
            ]
            if residual:
                seed_cg = dict(data.get("call_graph") or {})
                seed_cgf = dict(data.get("call_graph_files") or {})
                seed_spans = dict(data.get("def_spans") or {})
                from vvaharness.lang import ts_graph
                if ts_graph.build(data, residual, Path(repo_root), cfg):
                    _merge_graph_artifacts(data, seed_cg, seed_cgf, seed_spans)
                    print(f"  [s1] backed S0 graph with tree-sitter over "
                          f"{len(residual)} residual-language file(s) "
                          f"(langs S0 missed); merged per language",
                          file=sys.stderr)
                # build() returns False only when the backend is unavailable,
                # in which case it leaves ``data`` (S0's artifacts) untouched —
                # no restore needed.
            else:
                print("  [s1] S0 graph already covers every inventory language;"
                      " reuse is complete", file=sys.stderr)
        else:
            from vvaharness.lang import ts_graph
            if not ts_graph.build(data, all_files, Path(repo_root), cfg):
                _supplement_call_graph(data, all_files, Path(repo_root), cfg)
    else:
        if not (has_seed_cg and has_seed_cg_files and has_seed_spans):
            _supplement_call_graph(data, all_files, Path(repo_root), cfg)

    # Off-schema enum/int values (e.g. kind="rpc", line=null) are coerced by
    # field_validator(mode="before") hooks in models.py — see _coerce_enum /
    # _coerce_int. model_validate() therefore never raises on a stray value.
    pkg = ContextPackage.model_validate(data)
    n_ex_dirs = sum(excluded["dirs"].values())
    n_ex_exts = sum(excluded["exts"].values())
    n_ex_globs = sum(excluded["globs"].values())
    n_ex_size = excluded["oversize"]
    n_ex_dedup = (excluded.get("config_dedup") or {}).get("dropped", 0) or 0
    n_in_scope = len(pkg.all_files)
    n_total = n_in_scope + n_ex_dirs + n_ex_exts + n_ex_globs + n_ex_size + n_ex_dedup
    print(f"  [s1] file inventory: {n_total} on disk -> {n_in_scope} in scope "
          f"(excluded: {n_ex_dirs} dir, {n_ex_exts} ext, {n_ex_globs} glob, "
          f"{n_ex_size} oversize, {n_ex_dedup} config-dedup)", file=sys.stderr)
    print(f"  [s1] done: {len(pkg.modules)} modules, "
          f"{len(pkg.entry_points)} entry points, "
          f"{len(pkg.unsafe_sinks)} sinks, {n_in_scope} files in scope",
          file=sys.stderr)
    return pkg
