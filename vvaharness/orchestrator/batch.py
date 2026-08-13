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
from __future__ import annotations
"""orchestrator.batch — see package docstring."""
import csv
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path
from vvaharness.backends import llm as cli
from vvaharness.util.tokens import TOKENS
from vvaharness.util import errlog as _errlog
from vvaharness.orchestrator.cleanup import (_rmtree_rw, _preserve_set,
    _purge_clone)
from vvaharness.orchestrator.cmdb import _load_app_profile
from vvaharness.orchestrator.scan import scan_repo



def _module_name_from(ref: str) -> str:
    tail = ref.rstrip("/").split("/")[-1]
    if tail.lower().endswith(".git"):
        tail = tail[:-4]
    return tail or "repo"


def _is_remote(ref: str) -> bool:
    return ref.startswith(("http://", "https://", "git@", "ssh://")) or ref.endswith(".git")


# Strip `scheme://user:token@host` userinfo down to `scheme://***@host` so an
# inline credential carried in a repo URL never reaches stderr, the error
# string, or the on-disk batch summary. Token-in-URL is HTTP Basic auth, so the
# whole userinfo segment (everything between "://" and the first "@") is masked.
_URL_USERINFO_RX = re.compile(r"(\w[\w+.\-]*://)[^/@\s]+@")


def _scrub_url_secrets(s: str) -> str:
    if not s:
        return s
    return _URL_USERINFO_RX.sub(r"\1***@", s)


def _md_cell(text) -> str:
    """Neutralise Markdown-breaking chars in an untrusted value before it is
    interpolated into the batch summary (table cells AND headings/list items).

    Operator-supplied app_id / repo_name (and exception text) flow into the
    summary; a raw ``|`` forges/shifts cells, a newline forges rows or
    terminates a table/heading to append attacker-chosen Markdown. A backslash is
    escaped before ``|`` so a supplied backslash cannot consume the escape added
    for the delimiter. Mirrors the audited escaper in
    vvaharness/remediation_agent/report_augment/mdsafe.py."""
    if text is None:
        return ""
    return (str(text).replace("\r", " ").replace("\n", " ")
            .replace("\\", "\\\\").replace("|", "\\|").strip())


def _stash_url_for(repo_name: str, base: str) -> str:
    """RepoName is the full repo slug — '{base}/{repo_name}.git'."""
    return f"{base.rstrip('/')}/{repo_name}.git"


# ── Stage-binding markers ────────────────────────────────────────────────────
# A staged repo at workspace/<app>/<slug> is bound to the repo it was created
# from via a marker kept OUTSIDE the (shared, possibly stale- or attacker-
# writable) workspace — in the operator-private state dir. On reuse we require a
# marker whose ref-hash matches the requested repo; otherwise the dir is
# re-staged. This stops silent reuse of a stale/wrong-repo checkout and a
# slug-collision dir, and defeats a *pre-seeded* workspace dir: a writer who
# controls only the workspace cannot forge a marker in the state dir they don't
# control. It is NOT a guarantee against an attacker who also controls the state
# dir / host — for that, use a fresh per-run --workspace only you can write.
def _state_root() -> Path:
    return Path(os.environ.get("VVAHARNESS_STATE_DIR")
                or (Path.home() / ".vvaharness" / "state"))


def _ref_id(ref: str) -> str:
    """Stable, token-free id for a repo ref — the original csv URL / local path
    (NOT the token-bearing clone URL)."""
    return hashlib.sha256(str(ref).encode("utf-8")).hexdigest()[:32]


def _stage_marker_path(dest: Path) -> Path:
    key = hashlib.sha256(str(Path(dest).resolve()).encode("utf-8")).hexdigest()[:32]
    return _state_root() / "stage-markers" / f"{key}.json"


def _write_stage_marker(dest: Path, ref: str, kind: str) -> None:
    """Record that `dest` was staged from `ref`. Best-effort: a marker-write
    failure must not abort staging (the marker is a reuse-safety aid, not
    load-bearing for the scan itself) — it just means the next run re-stages."""
    mp = _stage_marker_path(dest)
    try:
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(json.dumps({"v": 1, "kind": kind, "ref_id": _ref_id(ref)}),
                      encoding="utf-8")
    except OSError as e:
        print(f"  [batch] WARN: could not write stage marker for {dest}: {e}",
              file=sys.stderr)


def _stage_dir_bound(dest: Path, ref: str) -> bool:
    """True iff `dest` carries a state-dir marker proving it was staged from
    `ref` by a prior run. Missing / mismatched / corrupt marker → not bound →
    the caller must re-stage."""
    try:
        data = json.loads(_stage_marker_path(dest).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("ref_id") == _ref_id(ref)


def _assign_slugs(repos: list[dict]) -> list[str]:
    """Map each repo in an app group to a UNIQUE staging slug. Two repo names
    with the same tail (e.g. ``org-a/service`` and ``org-b/service`` both →
    ``service``) would otherwise collide at ``app_dir/<slug>``: the second
    silently reuses the first's dir and is never scanned. The first keeps the
    clean tail; each later collider is disambiguated with a short, stable hash
    of its full repo_name so every repo gets its own directory."""
    slugs: list[str] = []
    used: set[str] = set()
    for r in repos:
        base = _module_name_from(r["repo_name"])
        slug = base
        salt = r["repo_name"]
        while slug in used:                  # collision (or pathological re-hit)
            slug = f"{base}-{hashlib.sha1(salt.encode('utf-8')).hexdigest()[:8]}"
            salt = slug + r["repo_name"]
        used.add(slug)
        slugs.append(slug)
    return slugs


# A batch manifest is a tiny control file — a few hundred bytes per repo row.
# These caps bound the decode/parse so an oversized or pathological manifest
# fails fast with a clear error instead of OOM-killing the batch runner (the
# parsers must NOT pull an unbounded file fully into memory). The manifest is
# operator/scheduler-supplied in this single-tenant CLI, so this guards an
# accidental/runaway file — availability self-DoS — not a hostile party. The
# caps are deliberately generous: ~orders of magnitude above any real batch.
_MANIFEST_MAX_BYTES = 64 * 1024 * 1024      # 64 MiB on disk
_MANIFEST_MAX_ROWS = 200_000                # data rows / physical lines


def _check_manifest_size(list_file: Path) -> None:
    """Reject a manifest larger than the byte cap BEFORE it is decoded into
    memory. Raises ValueError (caught by run_batch -> exit 2)."""
    try:
        size = list_file.stat().st_size
    except OSError as e:
        raise ValueError(f"{list_file}: cannot stat manifest: {e}")
    if size > _MANIFEST_MAX_BYTES:
        raise ValueError(
            f"{list_file}: manifest is {size} bytes, over the "
            f"{_MANIFEST_MAX_BYTES // (1024 * 1024)} MiB cap — split the batch "
            f"into smaller manifests")


def _parse_repo_csv(list_file: Path, git_base_url: str | None) -> list[dict]:
    """
    Parse a .csv batch sheet. Accepted column layouts (header row required,
    case-insensitive):

        AppID , RepoName               → path derived from batch.git_base_url
        AppID , RepoName , Path        → path is git URL or local dir (as .txt)

    Header aliases: AppID/application_id, RepoName/repository_name, Path/url.
    """
    _check_manifest_size(list_file)
    # Stream the reader rather than list(csv.reader(fh)): a manifest must never
    # be fully materialized into memory before validation. The file stays open
    # for the parse loop; rows are consumed lazily under a hard row cap.
    with open(list_file, newline="", encoding="utf-8-sig") as fh:
        rows = csv.reader(fh)
        try:
            header = next(rows)
        except StopIteration:
            raise ValueError(f"{list_file}: empty file")

        hdr = {str(h).strip().lower(): i for i, h in enumerate(header) if h}
        def col(*names):
            for n in names:
                if n in hdr:
                    return hdr[n]
            return None
        i_app = col("appid", "application_id", "app_id", "applicationid")
        i_repo = col("reponame", "repository_name", "repo_name", "repo")
        i_path = col("path", "url", "repo_url", "ref")
        if i_app is None or i_repo is None:
            raise ValueError(
                f"{list_file}: header must contain AppID and RepoName columns "
                f"(found: {list(hdr.keys())})")
        if i_path is None and not git_base_url:
            raise ValueError(
                f"{list_file}: no Path column and batch.git_base_url is not set — "
                f"cannot derive clone URLs")

        entries: list[dict] = []
        errors: list[str] = []
        seen: set[str] = set()
        for lineno, row in enumerate(rows, 2):
            if lineno - 1 > _MANIFEST_MAX_ROWS:
                raise ValueError(
                    f"{list_file}: over {_MANIFEST_MAX_ROWS} data rows — "
                    f"split the batch into smaller manifests")
            def at(i):
                if i is None or i >= len(row):
                    return ""
                return str(row[i]).strip()
            app_id, repo_name, ref = at(i_app), at(i_repo), at(i_path)
            if not app_id and not repo_name:
                continue
            if not app_id or not repo_name:
                errors.append(f"row {lineno}: AppID and RepoName are both required")
                continue
            if not ref:
                # A blank Path cell can only be resolved when git_base_url is set;
                # otherwise this is a validation error caught up-front (per
                # docs/repos-csv.md), NOT an opaque AttributeError mid-derive.
                if not git_base_url:
                    errors.append(
                        f"row {lineno}: Path is blank and batch.git_base_url is "
                        f"not set — cannot derive a clone URL")
                    continue
                ref = _stash_url_for(repo_name, git_base_url)
            if ref.lstrip().startswith("-"):
                # A leading "-" would be consumed by `git clone` as an option
                # (e.g. --upload-pack=…) rather than a URL operand. Reject up front.
                errors.append(f"row {lineno}: path '{ref}' may not start with '-'")
                continue
            if not _is_remote(ref) and not Path(ref).is_dir():
                errors.append(f"row {lineno}: path '{ref}' is neither a git URL "
                              f"nor an existing local directory")
                continue
            if ref in seen:
                errors.append(f"row {lineno}: duplicate path '{ref}'")
                continue
            seen.add(ref)
            entries.append({"application_id": app_id,
                            "repo_name": repo_name,
                            "ref": ref})

    if errors:
        raise ValueError(f"{list_file}: {len(errors)} validation error(s):\n  - "
                         + "\n  - ".join(errors))
    if not entries:
        raise ValueError(f"{list_file}: no repo entries found")
    return entries


def _parse_repo_file(list_file: Path) -> list[dict]:
    """
    Parse the batch input file. Each non-blank, non-comment line must be:

        application_id,repository_name,path

    where `path` is either a git URL (http/https/ssh/git@…/.git) or a local
    directory. Validates structure up-front so a bad line fails the batch
    before any scan starts.
    """
    _check_manifest_size(list_file)
    entries: list[dict] = []
    errors: list[str] = []
    seen: set[str] = set()

    # Stream lines rather than read_text().splitlines(): a manifest must never
    # be fully materialized into memory. Lines are consumed lazily under a hard
    # row cap.
    with open(list_file, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            if lineno > _MANIFEST_MAX_ROWS:
                raise ValueError(
                    f"{list_file}: over {_MANIFEST_MAX_ROWS} lines — "
                    f"split the batch into smaller manifests")
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 3:
                errors.append(f"line {lineno}: expected 3 comma-separated fields "
                              f"(application_id,repository_name,path) — got {len(parts)}")
                continue

            app_id, repo_name, ref = parts
            if not app_id:
                errors.append(f"line {lineno}: application_id is empty")
            if not repo_name:
                errors.append(f"line {lineno}: repository_name is empty")
            if not ref:
                errors.append(f"line {lineno}: path is empty")
            if not (app_id and repo_name and ref):
                continue

            if ref.lstrip().startswith("-"):
                # A leading "-" would be consumed by `git clone` as an option
                # (e.g. --upload-pack=…) rather than a URL operand. Reject up front.
                errors.append(f"line {lineno}: path '{ref}' may not start with '-'")
                continue
            if not _is_remote(ref) and not Path(ref).is_dir():
                errors.append(f"line {lineno}: path '{ref}' is neither a git URL "
                              f"nor an existing local directory")
                continue

            if ref in seen:
                errors.append(f"line {lineno}: duplicate path '{ref}'")
                continue
            seen.add(ref)

            entries.append({"application_id": app_id,
                            "repo_name": repo_name,
                            "ref": ref})

    if errors:
        msg = f"{list_file}: {len(errors)} validation error(s):\n  - " \
              + "\n  - ".join(errors)
        raise ValueError(msg)
    if not entries:
        raise ValueError(f"{list_file}: no repo entries found")
    return entries


def _with_token(url: str, token: str | None) -> str:
    if not token or not url.startswith(("http://", "https://")) or "@" in url.split("//", 1)[1]:
        return url
    scheme, rest = url.split("://", 1)
    return f"{scheme}://x-access-token:{token}@{rest}"


def _acquire_repo(ref: str, workspace: Path, git_token: str | None,
                  dest_name: str | None = None) -> Path:
    """Return a local directory for `ref`, cloning into `workspace` if remote."""
    if not _is_remote(ref):
        p = Path(ref)
        if not p.is_dir():
            raise RuntimeError(f"local path does not exist: {ref}")
        return p

    workspace.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "._-" else "_"
                   for c in (dest_name or _module_name_from(ref)))
    # "." and ".." survive the per-char allowlist (dot is permitted) and would
    # escape the workspace, after which _purge_clone deletes the PARENT. Refuse.
    if safe in (".", "..") or not safe.strip("."):
        raise RuntimeError(
            f"refusing unsafe clone dest name {safe!r} derived from "
            f"{(dest_name or ref)!r}: '.'/'..' would escape the workspace")
    dest = workspace / safe
    if dest.exists():
        has_content = any(p for p in dest.iterdir() if p.name != ".git")
        # Reuse ONLY a dir that is both non-empty AND bound (by a state-dir
        # marker) to THIS ref — never a stale/foreign/pre-seeded dir.
        if has_content and _stage_dir_bound(dest, ref):
            print(f"  [batch] reusing verified checkout {dest}", file=sys.stderr)
            return dest
        reason = ("empty" if not has_content else
                  "unverified (no matching stage marker — stale, foreign, or "
                  "pre-seeded)")
        print(f"  [batch] {reason} dir at {dest} — removing and re-cloning",
              file=sys.stderr)
        _rmtree_rw(dest)
        if dest.exists():
            print(f"  [batch] could not remove {dest}; reusing as-is",
                  file=sys.stderr)
            return dest
    clone_url = _with_token(ref, git_token)
    print(f"  [batch] git clone {_scrub_url_secrets(ref)} -> {dest}",
          file=sys.stderr)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    # Bound the clone so a network stall / unresponsive remote / connection
    # held open by the server cannot hang the whole batch indefinitely.
    # GIT_TERMINAL_PROMPT=0 only suppresses interactive auth, not stalls.
    try:
        r = subprocess.run(["git", "-c", "core.longpaths=true",
                            "clone", "--depth", "1", "--", clone_url, str(dest)],
                           capture_output=True, text=True, env=env,
                           timeout=600)
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"git clone timed out after 600s: {ref} (network stall or "
            f"unresponsive remote)")
    if r.returncode != 0:
        err = (r.stderr.strip() or r.stdout.strip())
        if git_token:
            err = err.replace(git_token, "***")
        # Mask any inline userinfo credential the remote echoed back before the
        # RuntimeError reaches stderr / errlog / the batch summary.
        err = _scrub_url_secrets(err)
        raise RuntimeError(f"git clone failed: {err}")
    _write_stage_marker(dest, ref, "remote")
    return dest


def run_batch(list_file: Path, args, cfg) -> int:
    batch_cfg = getattr(cfg, "batch", None)
    git_token = getattr(batch_cfg, "git_token", None) or None
    git_base = getattr(batch_cfg, "git_base_url", None) or None
    try:
        if list_file.suffix.lower() == ".csv":
            entries = _parse_repo_csv(list_file, git_base)
        else:
            entries = _parse_repo_file(list_file)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    # ── Drop test-automation / non-production repos by name pattern ─────
    # so they are never cloned or scanned. Patterns are case-insensitive
    # fnmatch globs against RepoName (e.g. "*automation*", "*-karate*").
    skip_pats = [p.lower() for p in
                 (getattr(batch_cfg, "skip_repo_patterns", None) or [])]
    if skip_pats:
        kept: list[dict] = []
        for e in entries:
            name = e["repo_name"]
            hit = next((p for p in skip_pats
                        if fnmatch.fnmatch(name.lower(), p)), None)
            if hit:
                print(f"  [batch] skipping '{name}' (app {e['application_id']}) "
                      f"— matches batch.skip_repo_patterns: {hit}",
                      file=sys.stderr)
            else:
                kept.append(e)
        if len(kept) != len(entries):
            print(f"  [batch] {len(entries)} rows → {len(kept)} after "
                  f"skip_repo_patterns ({len(entries) - len(kept)} dropped)",
                  file=sys.stderr)
        entries = kept
        if not entries:
            print(f"ERROR: all rows in {list_file} were excluded by "
                  f"batch.skip_repo_patterns", file=sys.stderr)
            return 2

    workspace = Path(args.workspace)

    if getattr(args, "group_by_app", False):
        return _run_batch_grouped(entries, workspace, git_token, args, cfg,
                                  list_file)

    results: list[dict] = []
    batch_t0 = time.time()

    for i, entry in enumerate(entries, 1):
        ref = entry["ref"]
        repo_name = entry["repo_name"]
        app_id = entry["application_id"]
        print(f"\n{'='*72}\n[batch {i}/{len(entries)}] {repo_name}  "
              f"app_id={app_id}  ({_scrub_url_secrets(ref)})\n{'='*72}",
              file=sys.stderr)
        TOKENS.reset()  # fresh accounting per repo
        cli.reset_abort()  # don't let a prior repo's guardrail abort poison this one
        t0 = time.time()
        cloned: Path | None = None
        try:
            local = _acquire_repo(ref, workspace, git_token,
                                  dest_name=repo_name)
            if _is_remote(ref):
                cloned = local
            if args.stop_after == "clone":
                results.append({
                    "ref": ref, "module": repo_name, "app_id": app_id,
                    "status": "OK", "findings": 0, "report": str(local),
                    "elapsed": time.time() - t0, "error": "",
                })
                continue
            report_path, n_findings = scan_repo(local, repo_name, app_id,
                                                args, cfg,
                                                path_prefix=repo_name)
            results.append({
                "ref": ref, "module": repo_name, "app_id": app_id,
                "status": "OK", "findings": n_findings,
                "report": str(report_path) if report_path else "",
                "elapsed": time.time() - t0, "error": "",
            })
        except KeyboardInterrupt:
            results.append({"ref": ref, "module": repo_name, "app_id": app_id,
                            "status": "ABORTED", "findings": 0, "report": "",
                            "elapsed": time.time() - t0,
                            "error": "interrupted by user"})
            raise
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            _errlog.log("batch", repo_name, e, app_id=app_id, ref=ref)
            results.append({"ref": ref, "module": repo_name, "app_id": app_id,
                            "status": "FAILED", "findings": 0, "report": "",
                            "elapsed": time.time() - t0, "error": str(e)[:500]})
        finally:
            if cloned and not args.keep_clones and args.stop_after != "clone":
                _purge_clone(cloned, _preserve_set(cfg))

    summary_path = workspace / "batch_summary.md"
    workspace.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(_render_batch_summary(results, list_file,
                                                  time.time() - batch_t0),
                            encoding="utf-8")
    print(f"\n[batch] summary written to {summary_path}", file=sys.stderr)

    failed = [r for r in results if r["status"] != "OK"]
    if failed:
        print(f"\n[batch] {len(failed)}/{len(results)} repos FAILED:", file=sys.stderr)
        for r in failed:
            print(f"  - {r['module']} ({_scrub_url_secrets(r['ref'])}): "
                  f"{_scrub_url_secrets(r['error'])}", file=sys.stderr)
        return 1
    print(f"\n[batch] all {len(results)} repos OK", file=sys.stderr)
    return 0


def _stage_repo(ref: str, app_dir: Path, slug: str, git_token: str | None) -> None:
    """Place repo `ref` at app_dir/slug — clone if remote, copytree if local."""
    if _is_remote(ref):
        _acquire_repo(ref, app_dir, git_token, dest_name=slug)
        return
    src = Path(ref)
    if not src.is_dir():
        raise RuntimeError(f"local path does not exist: {ref}")
    dest = app_dir / slug
    if dest.exists():
        # Reuse ONLY a copy bound (by a state-dir marker) to THIS ref — never a
        # stale/foreign/pre-seeded dir that happens to sit at the same path.
        if _stage_dir_bound(dest, ref):
            print(f"  [batch] reusing verified local copy {dest}", file=sys.stderr)
            return
        print(f"  [batch] unverified local copy at {dest} (stale, foreign, or "
              f"pre-seeded) — replacing", file=sys.stderr)
        _rmtree_rw(dest)
        if dest.exists():
            print(f"  [batch] could not remove {dest}; reusing as-is",
                  file=sys.stderr)
            return
    app_dir.mkdir(parents=True, exist_ok=True)
    print(f"  [batch] copytree {src} -> {dest}", file=sys.stderr)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".git"))
    _write_stage_marker(dest, ref, "local")


def _app_module_name(app_id: str, repos: list[dict]) -> str:
    profile, _ = _load_app_profile(app_id)
    if profile and profile.name:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in profile.name)
        return safe or f"app_{app_id}"
    if len(repos) == 1:
        return _module_name_from(repos[0]["repo_name"])
    return f"app_{app_id}"


def _run_batch_grouped(entries: list[dict], workspace: Path,
                       git_token: str | None, args, cfg,
                       list_file: Path) -> int:
    from collections import defaultdict
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        groups[e["application_id"]].append(e)

    results: list[dict] = []
    batch_t0 = time.time()

    for n, (app_id, repos) in enumerate(sorted(groups.items()), 1):
        # app_id is operator/CMDB-supplied; sanitise before using as a path
        # component so "../x" / "." cannot escape the workspace root.
        safe_app = "".join(c if c.isalnum() or c in "._-" else "_"
                           for c in str(app_id)).strip(".") or "app"
        app_dir = workspace / safe_app
        slugs = _assign_slugs(repos)   # unique per repo — no silent slug collision
        print(f"\n{'='*72}\n[batch {n}/{len(groups)}] app_id={app_id}  "
              f"({len(repos)} repos → {app_dir})\n  repos: {', '.join(slugs)}\n"
              f"{'='*72}", file=sys.stderr)
        TOKENS.reset()
        cli.reset_abort()  # don't let a prior app's guardrail abort poison this one
        t0 = time.time()
        try:
            staged: list[str] = []
            for r, slug in zip(repos, slugs):
                try:
                    _stage_repo(r["ref"], app_dir, slug, git_token)
                    staged.append(slug)
                except Exception as ce:
                    print(f"  [batch] WARN skipping repo '{slug}': {ce}",
                          file=sys.stderr)
                    _errlog.log("batch.clone", slug, ce, app_id=app_id)
            if not staged:
                raise RuntimeError(
                    f"all {len(repos)} repo(s) failed to stage for app {app_id}")
            if len(staged) < len(repos):
                print(f"  [batch] staged {len(staged)}/{len(repos)} repos for "
                      f"app {app_id}; continuing scan", file=sys.stderr)
            module = _app_module_name(app_id, repos)
            if args.stop_after == "clone":
                results.append({
                    "ref": f"{len(repos)} repos", "module": module,
                    "app_id": app_id, "status": "OK", "findings": 0,
                    "report": str(app_dir), "elapsed": time.time() - t0,
                    "error": "",
                })
                continue
            report_path, n_findings = scan_repo(app_dir, module, app_id, args, cfg)
            results.append({
                "ref": f"{len(repos)} repos", "module": module, "app_id": app_id,
                "status": "OK", "findings": n_findings,
                "report": str(report_path) if report_path else "",
                "elapsed": time.time() - t0, "error": "",
            })
        except KeyboardInterrupt:
            results.append({"ref": f"{len(repos)} repos", "module": str(app_id),
                            "app_id": app_id, "status": "ABORTED", "findings": 0,
                            "report": "", "elapsed": time.time() - t0,
                            "error": "interrupted by user"})
            raise
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            _errlog.log("batch", f"app_{app_id}", e, app_id=app_id)
            results.append({"ref": f"{len(repos)} repos", "module": str(app_id),
                            "app_id": app_id, "status": "FAILED", "findings": 0,
                            "report": "", "elapsed": time.time() - t0,
                            "error": str(e)[:500]})
        finally:
            if not args.keep_clones and args.stop_after != "clone":
                _purge_clone(app_dir, _preserve_set(cfg))

    summary_path = workspace / "batch_summary.md"
    workspace.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(_render_batch_summary(results, list_file,
                                                  time.time() - batch_t0),
                            encoding="utf-8")
    print(f"\n[batch] summary written to {summary_path}", file=sys.stderr)

    failed = [r for r in results if r["status"] != "OK"]
    if failed:
        print(f"\n[batch] {len(failed)}/{len(results)} apps FAILED:", file=sys.stderr)
        for r in failed:
            print(f"  - app_id={r['app_id']}: {_scrub_url_secrets(r['error'])}",
                  file=sys.stderr)
        return 1
    print(f"\n[batch] all {len(results)} apps OK", file=sys.stderr)
    return 0


def _render_batch_summary(results: list[dict], list_file: Path, elapsed: float) -> str:
    ok = sum(1 for r in results if r["status"] == "OK")
    out = [
        "# Agentic SAST batch summary",
        "",
        f"- Input list: `{list_file}`",
        f"- Repos: {len(results)} ({ok} OK, {len(results) - ok} failed)",
        f"- Total elapsed: {elapsed:.0f}s",
        "",
        "| # | App ID | Repo | Status | Findings | Elapsed (s) | Report | Source |",
        "|--:|---|---|---|--:|--:|---|---|",
    ]
    for i, r in enumerate(results, 1):
        # Every operator-supplied / influenced field is credential-scrubbed (where
        # it may carry an inline URL token) then Markdown-neutralised via _md_cell
        # so a crafted app_id / repo_name / ref / error can't forge cells, shift a
        # FAILED status to OK, or terminate the table and append fake Markdown.
        rep = f"`{_md_cell(r['report'])}`" if r["report"] else ""
        src = _md_cell(_scrub_url_secrets(r["ref"]))
        out.append(f"| {i} | {_md_cell(r['app_id'])} | {_md_cell(r['module'])} | "
                   f"{_md_cell(r['status'])} | {r['findings']} | {r['elapsed']:.0f} | "
                   f"{rep} | {src} |")
    failed = [r for r in results if r["status"] != "OK"]
    if failed:
        out.extend(["", "## Failures", ""])
        for r in failed:
            out.extend([f"### {_md_cell(r['module'])} (app {_md_cell(r['app_id'])})",
                        f"- Source: `{_md_cell(_scrub_url_secrets(r['ref']))}`",
                        f"- Error: {_md_cell(_scrub_url_secrets(r['error']))}", ""])
    return "\n".join(out) + "\n"
