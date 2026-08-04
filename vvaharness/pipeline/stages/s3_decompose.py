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
Step 3 — the strategist LLM receives the ContextPackage (no raw code) and produces a
risk-ranked TaskManifest. Single CLI call; repeating this wastes tokens.
"""
from __future__ import annotations
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path, PurePosixPath

log = logging.getLogger(__name__)

from vvaharness.models import ContextPackage, TaskManifest, Chunk, ChunkSize
from vvaharness.backends.llm import prompt
from vvaharness.util.json_extract import extract_json
from vvaharness.lang.hints import detect_languages, EXT_TO_LANG, is_iac_file
from vvaharness.pipeline.callgraph_consumer import (seed_reachable_files,
                                                    seed_paths_by_file,
                                                    graph_view, qnodes_at)
from vvaharness.pipeline.stages.s1_preprocess import q_join, q_file, q_name

SYSTEM = """You are a vulnerability research strategist. You receive a structured
map of a codebase — NOT the source code itself — and produce a prioritized
hunting plan.

Your job:
1. Rank attack surfaces by risk. Unauth-reachable entry points + unsafe sinks
   in the same data flow path = highest priority.
2. Hunt for VARIANTS of known CVEs. If CVE-X is a heap overflow in parser.c,
   look for sibling parsers with the same pattern.
3. Account for design controls. A bug behind strong auth ranks lower than the
   same bug pre-auth.
4. Tie every chunk to a THREAT. The THREAT MODEL section lists ranked threats
   T1..Tn. Each chunk MUST cite the threat_id it tests. Every threat should be
   covered by at least one chunk; if a threat has no plausible code surface,
   omit it — do NOT invent a chunk.
5. Chunk the work. Each chunk = a coherent set of files to deep-dive together.
   Use the CALL GRAPH section: when caller -> callee crosses files, put BOTH
   files in the same chunk so the entry-point and its sink are reviewed
   together. Tag size: small (<2k loc), medium (<8k), large (more).
6. For LARGE chunks, name the entry-point functions to anchor a sliding window.

Respond with ONLY a JSON object, no prose:
{
  "rationale": "one paragraph explaining your ranking",
  "chunks": [
    {
      "id": "chunk-01",
      "size": "small|medium|large",
      "risk_rank": 1,
      "files": ["src/parser.c", "src/parser.h"],
      "focus_entry_points": ["parse_request"],
      "hypothesis": "Specific reasoning about what to hunt and why",
      "threat_id": "T3",
      "related_cves": ["CVE-2024-1234"]
    }
  ]
}"""

_TOKEN_RX = re.compile(r"[a-z0-9]+")


def run(ctx: ContextPackage, cfg) -> TaskManifest:
    log.info("s3/decompose: starting task decomposition - files=%d entry_points=%d sinks=%d modules=%d",
             len(ctx.all_files), len(ctx.entry_points), len(ctx.unsafe_sinks), len(ctx.modules))
    prompt_ctx = ctx.ast_context_view(
        max_files=int(getattr(cfg.step3, "max_prompt_files", 180) or 180),
        max_entry_points=int(getattr(cfg.step3, "max_prompt_entry_points", 60) or 60),
        max_sinks=int(getattr(cfg.step3, "max_prompt_sinks", 80) or 80),
        max_modules=int(getattr(cfg.step3, "max_prompt_modules", 24) or 24),
        max_edges=int(getattr(cfg.step3, "max_prompt_call_edges", 80) or 80),
        max_notes_chars=int(getattr(cfg.step3, "max_prompt_notes_chars", 2500) or 2500),
    )
    user_prompt = prompt_ctx.to_decompose_prompt_block()
    print(
        "  [s3] ast frontier: "
        f"files {len(ctx.all_files)}->{len(prompt_ctx.all_files)}, "
        f"entry points {len(ctx.entry_points)}->{len(prompt_ctx.entry_points)}, "
        f"sinks {len(ctx.unsafe_sinks)}->{len(prompt_ctx.unsafe_sinks)}, "
        f"modules {len(ctx.modules)}->{len(prompt_ctx.modules)}, "
        f"call edges {sum(len(v) for v in ctx.call_graph.values())}"
        f"->{sum(len(v) for v in prompt_ctx.call_graph.values())}",
        file=sys.stderr,
    )
    log.debug("s3/decompose: prompt frontier - files=%d->%d eps=%d->%d sinks=%d->%d modules=%d->%d edges=%d->%d",
              len(ctx.all_files), len(prompt_ctx.all_files),
              len(ctx.entry_points), len(prompt_ctx.entry_points),
              len(ctx.unsafe_sinks), len(prompt_ctx.unsafe_sinks),
              len(ctx.modules), len(prompt_ctx.modules),
              sum(len(v) for v in ctx.call_graph.values()),
              sum(len(v) for v in prompt_ctx.call_graph.values()))

    try:
        raw = prompt(
            user_prompt,
            model=cfg.models.decompose,
            system_prompt=SYSTEM,
            max_tokens=getattr(cfg.step3, "max_tokens", None),
            timeout=getattr(cfg.step3, "timeout", 1800),
            tag="s3 decompose",
        )
    except Exception as e:  # provider timeout/network/auth
        print(f"  [s3] WARN: strategist call failed ({e}); proceeding "
              "with deterministic coverage only (no LLM ranking).",
              file=sys.stderr)
        raw = "{}"

    # degrade — don't abort the whole scan — on malformed/empty/wrong-shape
    # strategist output, mirroring how s4/s8 fall back instead of crashing.
    # extract_json raises ValueError on empty/non-JSON; TaskManifest requires
    # chunks + rationale (no defaults) so a valid-but-wrong-shape response raises
    # ValidationError. Either way we recover with an empty manifest: the taint /
    # catch-all / specialist passes below still sweep every ground-truth file,
    # so coverage is preserved (only the LLM's risk RANKING is lost).
    try:
        data = extract_json(raw)
        manifest = TaskManifest.model_validate(data)
    except Exception as e:  # provider/model output is heterogeneous
        head = (raw or "")[:500].replace("\n", "\\n")
        print(f"  [s3] WARN: strategist response not usable ({e}); "
              f"proceeding with deterministic coverage only (no LLM ranking). "
              f"raw[:500]={head!r}", file=sys.stderr)
        manifest = TaskManifest(chunks=[], rationale=(
            f"s3 strategist output unusable ({e}); risk ranking unavailable. "
            f"All files covered via deterministic taint/catch-all/specialist "
            f"passes."))

    # ── Coverage guarantee ───────────────────────────────────────────────
    # Normalize model-emitted paths against the ground-truth list, drop
    # hallucinated paths, then sweep any uncovered files into catch-all chunks.
    _normalize_chunk_files(manifest, ctx)
    cb = _char_budget(cfg)
    if cb is not None:
        print(f"    [s3] pack_by=tokens  budget="
              f"{getattr(cfg.step3, 'chunk_token_budget', 180000)}tok "
              f"− overhead={getattr(cfg.step3, 'chunk_overhead_tokens', 80000)}tok "
              f"→ {cb} chars/chunk  (legacy *_chunk_loc caps ignored)",
              file=sys.stderr)
    else:
        print("    [s3] pack_by=loc  (legacy *_chunk_loc caps active)",
              file=sys.stderr)
    n_taint = _add_taint_chunks(manifest, ctx, cfg)
    _split_oversize_risk_chunks(manifest, ctx, cfg)
    n_catchall = _add_catchall_chunks(manifest, ctx, cfg)

    # ── Language tagging ─────────────────────────────────────────────────
    repo_root = Path(ctx.repo_root)
    for c in manifest.chunks:
        c.languages = detect_languages(c.files, repo_root=repo_root)

    # ── Specialist passes (repo-wide; lenses defined in _lang_hints.SPECIALIST_HINTS) ──
    n_spec = _add_specialist_chunks(manifest, ctx, cfg)
    n_fallback = _add_threat_surface_fallback_chunks(manifest, ctx, cfg)

    _report_threat_coverage(manifest, ctx)
    _report_chunk_loc(manifest, ctx, cfg)

    tracker = getattr(cfg, "_scan_progress", None)
    if tracker is not None:
        for chunk in manifest.chunks:
            tracker.queued(chunk)

    print(
        f"  [s3] done: {len(manifest.chunks)} chunks "
        f"({n_taint} taint, {n_catchall} catch-all, {n_spec} specialist, "
        f"{n_fallback} threat-fallback), "
        f"top risk = {manifest.sorted_chunks()[0].id if manifest.chunks else 'none'}",
        file=sys.stderr,
    )
    log.info(
        "s3/decompose: decomposition complete - chunks=%d (taint=%d catchall=%d specialist=%d threat_fallback=%d)",
        len(manifest.chunks), n_taint, n_catchall, n_spec, n_fallback,
    )
    return manifest


# ─────────────────────────────────────────────────────────────────────────────
# Coverage helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_chunk_files(manifest: TaskManifest, ctx: ContextPackage) -> None:
    """Map model-emitted paths onto ctx.all_files; drop anything that doesn't exist."""
    truth = set(ctx.all_files)
    by_name: dict[str, list[str]] = defaultdict(list)
    for f in ctx.all_files:
        by_name[PurePosixPath(f).name].append(f)

    for chunk in manifest.chunks:
        fixed: list[str] = []
        for f in chunk.files:
            cand = f.replace("\\", "/")
            while cand.startswith("./"):
                cand = cand[2:]
            if cand in truth:
                fixed.append(cand)
                continue
            # try basename match (model sometimes drops directories)
            matches = by_name.get(PurePosixPath(cand).name, [])
            if len(matches) == 1:
                fixed.append(matches[0])
            else:
                print(f"    [s3] dropped non-existent file from {chunk.id}: {f}",
                      file=sys.stderr)
        chunk.files = list(dict.fromkeys(fixed))  # dedupe, keep order


_SECURITY_CONFIG_NAMES = {
    "web.xml", "struts.xml", "struts-config.xml", "applicationcontext.xml",
    "spring-security.xml", "beans.xml", "faces-config.xml", "shiro.ini",
    "security.xml", "ejb-jar.xml", "jboss-web.xml", "weblogic.xml",
    "androidmanifest.xml", "info.plist",
    "application.properties", "application.yml", "application.yaml",
    "appsettings.json", "web.config", "app.config",
}
_SECURITY_CONFIG_EXTS = {".xml", ".properties"}


def _is_source(f: str) -> bool:
    p = PurePosixPath(f)
    ext = p.suffix.lower()
    if ext in EXT_TO_LANG:
        return True
    name = p.name.lower()
    if name in _SECURITY_CONFIG_NAMES:
        return True
    # Descriptor XML / .properties under canonical Java config roots — not data XML.
    if ext in _SECURITY_CONFIG_EXTS:
        parts = f.lower().split("/")
        return any(seg in parts for seg in ("web-inf", "meta-inf", "resources", "conf", "config"))
    # IaC / CI / container configs — Dockerfile, *.tf, .github/workflows/*.yml,
    # helm/k8s manifests etc. The iac specialist sweeps these.
    if is_iac_file(f):
        return True
    return False


def _file_call_graph(ctx: ContextPackage) -> dict[str, set[str]]:
    """Project the qualified call_graph onto an undirected FILE graph.
    Every node is `file::name` (P5), so the file is read straight off the
    key — no more component-walk over unlocated bare names."""
    adj: dict[str, set[str]] = defaultdict(set)
    for caller, callees in (ctx.call_graph or {}).items():
        cf = q_file(caller)
        if not cf:
            continue
        for cal in callees:
            tf = q_file(cal)
            if tf and tf != cf:
                adj[cf].add(tf)
                adj[tf].add(cf)
    return adj


def _cohesive_groups(files: list[str], ctx: ContextPackage) -> list[tuple[str, list[str]]]:
    """
    Partition `files` into semantically related groups so a researcher sees
    callers and callees together. Preference order:
      1. ctx.modules (s1's agentic grouping — already relation-aware)
      2. call-graph connected components (controller+service+DAO stay together
         even when they live under /web/, /svc/, /dao/)
      3. depth-2 directory (last resort for files with no graph edges)
    Every input file lands in exactly one group.
    """
    pending = set(files)
    groups: list[tuple[str, list[str]]] = []

    for m in ctx.modules:
        hit = [f for f in m.files if f in pending]
        if hit:
            groups.append((m.name, hit))
            pending.difference_update(hit)

    adj = _file_call_graph(ctx)
    visited: set[str] = set()
    for f in sorted(pending):
        if f in visited or f not in adj:
            continue
        comp, stack = [], [f]
        while stack:
            n = stack.pop()
            if n in visited or n not in pending:
                continue
            visited.add(n)
            comp.append(n)
            stack.extend(adj.get(n, ()))
        if comp:
            groups.append((f"cg:{PurePosixPath(comp[0]).stem}", sorted(comp)))
    pending.difference_update(visited)

    by_dir: dict[str, list[str]] = defaultdict(list)
    for f in sorted(pending):
        parts = f.split("/")
        key = "/".join(parts[:2]) if len(parts) > 1 else "."
        by_dir[key].append(f)
    for key in sorted(by_dir):
        groups.append((key, by_dir[key]))

    return groups


def _report_threat_coverage(manifest: TaskManifest, ctx: ContextPackage) -> None:
    tm = ctx.threat_model
    if not tm or not tm.threats:
        return
    valid = {t.id for t in tm.threats}
    covered: set[str] = set()
    for c in manifest.chunks:
        if c.threat_id and c.threat_id not in valid:
            print(f"    [s3] {c.id}: unknown threat_id {c.threat_id!r} → dropped",
                  file=sys.stderr)
            c.threat_id = None
        if c.threat_id:
            covered.add(c.threat_id)
    missing = sorted(valid - covered)
    print(f"    [s3] threat coverage: {len(covered)}/{len(valid)} threats have ≥1 chunk"
          + (f"; UNCOVERED: {', '.join(missing)}" if missing else ""),
          file=sys.stderr)


_THREAT_IAC_RX = re.compile(
    r"\b(supply\s*chain|dependency|dependencies|package|sbom|build|release|"
    r"ci/?cd|pipeline|workflow|actions?|github\s*actions|jenkins|docker|"
    r"kubernetes|k8s|terraform|helm|image)\b",
    re.IGNORECASE,
)
_THREAT_LLM_RX = re.compile(
    r"\b(llm|prompt|jailbreak|rag|tool\s*call|agent|assistant|model\s*output|"
    r"prompt\s*inject|indirect\s*inject)\b",
    re.IGNORECASE,
)
_THREAT_AUTHZ_RX = re.compile(
    r"\b(authz|authorization|access\s*control|idor|rbac|acl|privilege|session|"
    r"csrf|oauth|jwt|tenant\s*isolation)\b",
    re.IGNORECASE,
)
_THREAT_CRYPTO_RX = re.compile(
    r"\b(crypto|cipher|encryption|decrypt|signature|hmac|hash|md5|sha|tls|ssl|"
    r"x509|certificate|secret\s*key|key\s*management)\b",
    re.IGNORECASE,
)
_THREAT_DESER_RX = re.compile(
    r"\b(deserial|pickle|marshal|yaml\.load|objectinputstream|readobject|"
    r"binaryformatter|xstream|snakeyaml|hessian|kryo)\b",
    re.IGNORECASE,
)
_THREAT_BATCH_RX = re.compile(
    r"\b(batch|etl|file\s*ingest|bulk\s*import|job\s*scheduler|mainframe|"
    r"jcl|cobol|record\s*format)\b",
    re.IGNORECASE,
)
_THREAT_CONFIG_RX = re.compile(
    r"\b(config|configuration|policy|feature\s*flag|runtime\s*toggle|"
    r"environment\s*variable|env\b|deployment\s*setting)\b",
    re.IGNORECASE,
)
_IAC_PATH_RX = re.compile(
    r"(\.github/workflows/|dockerfile|jenkinsfile|\.gitlab-ci|azure-pipelines|"
    r"\.tf$|helm/|k8s/|kubernetes/|chart\.ya?ml$|values\.ya?ml$|"
    r"pom\.xml$|package\.json$|requirements(\.txt)?$|pyproject\.toml$|"
    r"poetry\.lock$|setup\.py$)",
    re.IGNORECASE,
)
_LLM_PATH_RX = re.compile(
    r"(llm|prompt|agent|assistant|openai|anthropic|rag|chat|completion|tool)",
    re.IGNORECASE,
)
_AUTHZ_PATH_RX = re.compile(
    r"(auth|oauth|jwt|rbac|acl|permission|policy|session|tenant)",
    re.IGNORECASE,
)
_CONFIG_EXTS = {".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".properties", ".xml", ".env"}


def _tok(s: str) -> set[str]:
    return set(_TOKEN_RX.findall((s or "").lower()))


def _is_config_file(rel: str) -> bool:
    p = PurePosixPath(rel)
    if p.name.lower().startswith(".env"):
        return True
    if p.suffix.lower() in _CONFIG_EXTS:
        return True
    name = p.name.lower()
    return ("config" in name or "policy" in name or "settings" in name)


def _threat_text(t) -> str:
    return " ".join(filter(None, [t.threat, t.surface, t.asset, t.controls, t.actor]))


def _matches_threat_surface(ep, t) -> bool:
    surface_tokens = _tok(t.surface)
    if not surface_tokens:
        return False
    fn = (ep.function or "").lower()
    if fn and t.surface.lower() == fn:
        return True
    return bool(surface_tokens & _tok(ep.function or ""))


def _candidate_files_for_threat(t, ctx: ContextPackage,
                                specialist_files: dict[str, list[str]],
                                max_files: int) -> list[str]:
    txt = _threat_text(t)
    files = [f for f in ctx.all_files if _is_source(f) or _is_config_file(f)]
    chosen: list[str] = []

    def _add(seq):
        for f in seq:
            if f in ctx.all_files and f not in chosen:
                chosen.append(f)
                if len(chosen) >= max_files:
                    return

    if t.actor == "supply_chain" or _THREAT_IAC_RX.search(txt):
        _add(specialist_files.get("iac", []))
        _add([f for f in files if is_iac_file(f) or _IAC_PATH_RX.search(f)])
    if _THREAT_LLM_RX.search(txt):
        _add([f for f in files if _LLM_PATH_RX.search(f)])
    if t.actor in {"remote_unauth", "remote_auth"} or _THREAT_AUTHZ_RX.search(txt):
        _add(specialist_files.get("access-control", []))
        _add([f for f in files if _AUTHZ_PATH_RX.search(f)])
    if _THREAT_CRYPTO_RX.search(txt):
        _add(specialist_files.get("crypto", []))
    if _THREAT_DESER_RX.search(txt):
        _add(specialist_files.get("deserialization", []))
    if _THREAT_BATCH_RX.search(txt):
        _add(specialist_files.get("batch-etl", []))
    if _THREAT_CONFIG_RX.search(txt):
        _add([f for f in files if _is_config_file(f)])

    ep_hits = [ep.file for ep in ctx.entry_points if _matches_threat_surface(ep, t)]
    _add(ep_hits)

    if chosen:
        return chosen[:max_files]
    return []


def _add_threat_surface_fallback_chunks(manifest: TaskManifest,
                                        ctx: ContextPackage,
                                        cfg) -> int:
    """Deterministically map uncovered threats to concrete code surface chunks.

    This closes known blind spots where specialist/catch-all chunks provide
    review coverage but do not increment threat coverage because they carry no
    ``threat_id``.
    """
    step3 = getattr(cfg, "step3", None)
    if not bool(getattr(step3, "threat_surface_fallbacks", True)):
        return 0
    tm = ctx.threat_model
    if not tm or not tm.threats:
        return 0

    valid = [t for t in tm.threats if t.id]
    covered = {c.threat_id for c in manifest.chunks if c.threat_id}
    missing = [t for t in valid if t.id not in covered]
    if not missing:
        return 0

    max_files = int(getattr(step3, "threat_fallback_max_files", 12) or 12)
    base_rank = max((c.risk_rank for c in manifest.chunks), default=0)
    repo_root = Path(ctx.repo_root)

    specialist_files: dict[str, list[str]] = defaultdict(list)
    for c in manifest.chunks:
        if c.specialist:
            specialist_files[c.specialist].extend(c.files)
    for k, v in specialist_files.items():
        specialist_files[k] = list(dict.fromkeys(v))

    added = 0
    for t in missing:
        files = _candidate_files_for_threat(t, ctx, specialist_files, max_files)
        if not files:
            continue
        loc = sum(_count_loc(repo_root / f) for f in files)
        cid = f"threat-{t.id.lower()}-fallback"
        used = {c.id for c in manifest.chunks}
        if cid in used:
            n = 2
            while f"{cid}-{n}" in used:
                n += 1
            cid = f"{cid}-{n}"
        focus = [ep.function for ep in ctx.entry_points if _matches_threat_surface(ep, t)][:8]
        manifest.chunks.append(Chunk(
            id=cid,
            size=_size_for(loc),
            risk_rank=base_rank + added + 1,
            files=files,
            focus_entry_points=focus,
            hypothesis=(
                f"Deterministic threat-surface fallback for {t.id}: "
                f"{t.threat}. Review likely files derived from actor/surface "
                "signals and repository specialist coverage."
            ),
            related_cves=[],
            threat_id=t.id,
        ))
        added += 1

    if added:
        print(f"    [s3] threat-surface fallback: added {added} chunk(s) "
              f"for previously uncovered threats",
              file=sys.stderr)
    return added


def _pick_hop_files(candidates, anchors: list[str], cap: int) -> list[str]:
    """Return ≤`cap` candidate files, ranked by longest common directory
    prefix with any anchor (entry/sink file). Java package == dir path, so
    same-package definitions sort first. cap<=0 ⇒ no cap."""
    cands = list(dict.fromkeys(candidates))
    if cap <= 0 or len(cands) <= cap:
        return cands
    aps = [a.split("/") for a in anchors if a]

    def _aff(f: str) -> int:
        fp = f.split("/")
        best = 0
        for ap in aps:
            n = 0
            for x, y in zip(fp, ap):
                if x != y:
                    break
                n += 1
            best = max(best, n)
        return best

    cands.sort(key=lambda f: (-_aff(f), f))
    return cands[:cap]


def _qnode_for_file_line(ctx: ContextPackage, file_rel: str,
                         line: int) -> str | None:
    """Best-effort qnode lookup for a concrete file:line anchor.

    Uses the shared, call-graph-first resolver
    (:func:`callgraph_consumer.qnodes_at`); ``nearest_if_empty`` gives a
    single-anchor result when neither a span nor the call graph resolves the
    file.
    """
    if line <= 0:
        return None
    hits = qnodes_at(graph_view(ctx), file_rel, line, line,
                     limit=1, nearest_if_empty=True)
    return hits[0] if hits else None


def _sink_qnodes_for_sink(s, ctx: ContextPackage,
                          match_qnodes) -> list[str]:
    """Resolve sink candidates to qnodes using function then line anchors."""
    out: list[str] = []
    if s.function:
        out.extend(match_qnodes(s.file, s.function))
    if not out and getattr(s, "line", 0):
        qn = _qnode_for_file_line(ctx, s.file, int(s.line))
        if qn:
            out.append(qn)
    return list(dict.fromkeys(out))


def _seed_paths_for_entry(ctx: ContextPackage, ep,
                          sink_by_qn: dict[str, list],
                          all_file_set: set[str]) -> list[tuple[str, list[str], str | None, str | None, list[str]]]:
    """Materialize seed taint paths touching an entry file into taint hits.

    Returns tuples of:
      (sink_qn, qnode_path, source_ref, sink_ref, sink_cwe)
    """
    out: list[tuple[str, list[str], str | None, str | None, list[str]]] = []

    def _ref_file(ref: str) -> str:
        if not ref:
            return ""
        if "::" in ref:
            return ref.split("::", 1)[0]
        return ref.split(":", 1)[0]

    def _ref_line(ref: str) -> int:
        if not ref or "::" in ref:
            return 0
        _, _, tail = ref.rpartition(":")
        return int(tail) if tail.isdigit() else 0

    # Prefer structured taint evidence when available; fall back to legacy
    # seed_taint_paths when there is no matching evidence for this entry.
    if ctx.seed_taint_evidence:
        seen_ev: set[tuple[str, str, tuple[str, ...]]] = set()
        for evidence in ctx.seed_taint_evidence:
            # Skip flows that were sanitized before the sink — they
            # are not exploitable and should not become taint chunks.
            if evidence.sanitized:
                continue
            source_ref = evidence.source_ref or ""
            sink_ref = evidence.sink_ref or ""
            source_file = _ref_file(source_ref).replace("\\", "/")
            sink_file = _ref_file(sink_ref).replace("\\", "/")
            if source_file != ep.file:
                continue

            qpath = list(dict.fromkeys(evidence.path_funcs or []))
            hop_files = [q_file(fn) for fn in qpath if q_file(fn)]
            hop_files = [f for f in dict.fromkeys(hop_files) if f in all_file_set]
            if not hop_files:
                hop_files = [f for f in (source_file, sink_file) if f in all_file_set]
            if len(hop_files) < 2:
                continue

            sink_qn = ""
            sink_line = _ref_line(sink_ref)
            if sink_file in all_file_set and sink_line > 0:
                sink_qn = _qnode_for_file_line(ctx, sink_file, sink_line) or ""
            if not sink_qn and qpath:
                sink_qn = qpath[-1]

            sink_cwe = sorted(dict.fromkeys(evidence.sink_cwe or []))
            if not sink_cwe and sink_qn in sink_by_qn:
                sink_cwe = sorted({c for s in sink_by_qn[sink_qn]
                                   for c in getattr(s, "cwe", None) or ()})

            ev_key = (source_ref, sink_ref, tuple(qpath))
            if ev_key in seen_ev:
                continue
            seen_ev.add(ev_key)
            out.append((sink_qn, qpath, source_ref, sink_ref, sink_cwe))

        if out:
            return out

    by_file = seed_paths_by_file(ctx.seed_taint_paths)
    for path in by_file.get(ep.file, ()): 
        if len(path) < 2:
            continue
        qpath: list[str] = []
        hop_files: list[str] = []
        for hop in path:
            hf, _, hline = hop.rpartition(":")
            file_rel = hf if hline else hop
            file_rel = file_rel.replace("\\", "/")
            if file_rel not in all_file_set:
                continue
            hop_files.append(file_rel)
            if hline.isdigit():
                qn = _qnode_for_file_line(ctx, file_rel, int(hline))
                if qn:
                    qpath.append(qn)
        if len(hop_files) < 2:
            continue
        sink_ref = path[-1]
        sf, _, sl = sink_ref.rpartition(":")
        sink_qn = ""
        sink_cwe: list[str] = []
        if sf and sl.isdigit():
            sink_qn = _qnode_for_file_line(ctx, sf, int(sl)) or ""
            if sink_qn in sink_by_qn:
                sink_cwe = sorted({c for s in sink_by_qn[sink_qn]
                                   for c in getattr(s, "cwe", None) or ()})
        source_ref = path[0]
        out.append((sink_qn, qpath, source_ref, sink_ref, sink_cwe))
    return out


def _add_taint_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> int:
    """
    Walk ctx.call_graph from each entry point to each unsafe sink and emit one
    chunk per reachable (entry, sink) pair containing every file we can resolve
    along the path. Guarantees the s4 researcher sees source AND sink together,
    which is the precondition for a confirmed data-flow finding.
    """
    if not getattr(cfg.step3, "taint_chunks", True):
        return 0
    if not ctx.entry_points or not ctx.unsafe_sinks:
        print("    [s3] taint: skipped (no entry points or sinks from s1)",
              file=sys.stderr)
        return 0

    graph = ctx.call_graph or {}
    graph_nodes: set[str] = set(graph)
    for vs in graph.values():
        graph_nodes.update(vs)
    by_bare: dict[str, list[str]] = defaultdict(list)
    for k in graph_nodes:
        by_bare[q_name(k)].append(k)

    def _match_qnodes(file: str, name: str) -> list[str]:
        cands = by_bare.get(name, [])
        hit = [k for k in cands if q_file(k) == file]
        if hit:
            return hit
        # Path-suffix match, but anchored on a "/" boundary so a partial
        # filename component can't match: "auth.py" must NOT match
        # "src/oauth.py". A == B, or one ends with "/" + the other.
        def _path_suffix(a: str, b: str) -> bool:
            return a == b or a.endswith("/" + b) or b.endswith("/" + a)
        hit = [k for k in cands if _path_suffix(q_file(k), file)]
        return hit or [q_join(file, name)]

    sink_qnodes: set[str] = set()
    sink_by_qn: dict[str, list] = defaultdict(list)
    for s in ctx.unsafe_sinks:
        if not s.function and not getattr(s, "line", 0):
            continue
        for qn in _sink_qnodes_for_sink(s, ctx, _match_qnodes):
            sink_qnodes.add(qn)
            sink_by_qn[qn].append(s)

    repo_root = Path(ctx.repo_root)
    max_hops = getattr(cfg.step3, "taint_max_hops", 8)
    max_chunks = getattr(cfg.step3, "taint_max_chunks", 40)
    per_hop = int(getattr(cfg.step3, "taint_files_per_hop", 5) or 0)

    # Taint chunks are the highest-signal work — rank them ABOVE the LLM's
    # risk chunks so s4 processes them first.
    for c in manifest.chunks:
        c.risk_rank += max_chunks

    threats = ctx.threat_model.threats if ctx.threat_model else []

    # Per-threat surface tokens are loop-invariant across entry points, so
    # tokenize each threat surface once here rather than on every _threat_for
    # call.
    _threat_tokens = [(t, _tok(t.surface)) for t in threats if t.surface]

    def _threat_for(ep) -> str | None:
        # Associate a taint chunk with a threat by matching the threat's
        # surface (an entry-point/function NAME) to the entry function on a
        # whole-token / exact basis. Looser substring matching (incl. matching
        # against the file PATH) over-tagged this coverage metric, so it is
        # avoided. Exact (case-insensitive) wins; otherwise the first threat
        # sharing a whole token with the function name.
        fn_lower = (ep.function or "").lower()
        fn_tokens = _tok(fn_lower)
        best: str | None = None
        for t, surf_tokens in _threat_tokens:
            if t.surface.lower() == fn_lower:
                return t.id
            if best is None and fn_tokens and (surf_tokens & fn_tokens):
                best = t.id
        return best

    seen_paths: set[tuple] = set()
    reached_fns: set[str] = set()
    entry_files = {e.file for e in ctx.entry_points}
    added = 0
    entries = sorted(ctx.entry_points,
                     key=lambda e: (not e.reachable_from_unauth, e.kind))

    all_file_set = set(ctx.all_files)
    for ep in entries:
        if added >= max_chunks:
            break
        hits: list[tuple[str, list[str]]] = []

        # Prefer concrete S0-proven taint paths when available.
        for sink_qn, qpath, src_ref, snk_ref, cwes in _seed_paths_for_entry(
                ctx, ep, sink_by_qn, all_file_set):
            if added >= max_chunks:
                break
            hop_files = [q_file(fn) for fn in qpath if q_file(fn)]
            if not hop_files:
                # Keep at least source/sink files from seed hops.
                sf, _, _ = (src_ref or "").rpartition(":")
                tf, _, _ = (snk_ref or "").rpartition(":")
                hop_files = [x for x in (sf, tf) if x]
            files = _pick_hop_files(hop_files, [ep.file],
                                    per_hop * max(1, len(qpath) or 2))
            files.append(ep.file)
            if snk_ref:
                tf, _, _ = snk_ref.rpartition(":")
                if tf:
                    files.append(tf)
            files = [f for f in dict.fromkeys(files) if f in all_file_set]
            if not files:
                continue
            sig = (ep.function, sink_qn or snk_ref or "seed", tuple(sorted(files)))
            if sig in seen_paths:
                continue
            seen_paths.add(sig)
            added += 1
            manifest.chunks.append(Chunk(
                id=f"taint-{added:02d}",
                size=_size_for(sum(_count_loc(repo_root / f) for f in files)),
                risk_rank=added,
                files=files,
                focus_entry_points=[ep.function],
                hypothesis=(
                    f"Seed path evidence: {ep.kind} input at {ep.function}() "
                    f"[{ep.file}] reaches sink [{snk_ref or sink_qn or 'unknown'}]. "
                    "Validate each hop for missing sanitization and real exploitability."
                ),
                related_cves=[],
                threat_id=_threat_for(ep),
                path_funcs=qpath,
                source_ref=src_ref or q_join(ep.file, ep.function),
                sink_ref=snk_ref or (q_file(sink_qn) if sink_qn else ""),
                sink_cwe=cwes,
            ))

        for start in _match_qnodes(ep.file, ep.function):
            hits.extend(_bfs_to_sinks(start, graph, sink_qnodes, max_hops))
        reached_fns.update(qn for qn, _ in hits)
        # Direct sink in the entry file with no graph edge → still a chunk.
        if not hits:
            hits = [(q_join(s.file, s.function),
                     [q_join(ep.file, ep.function), q_join(s.file, s.function)])
                    for s in ctx.unsafe_sinks if s.file == ep.file]
        for sink_qn, path in hits:
            if added >= max_chunks:
                break
            sinks_here = sink_by_qn.get(sink_qn, ())
            sink_files = [s.file for s in sinks_here] or [q_file(sink_qn)]
            anchors = [ep.file, *sink_files]
            hop_files = [q_file(fn) for fn in path if q_file(fn)]
            files = _pick_hop_files(hop_files, anchors,
                                    per_hop * max(1, len(path)))
            files.append(ep.file)
            files.extend(sink_files)
            files = [f for f in dict.fromkeys(files) if f in all_file_set]
            if not files:
                continue
            sig = (ep.function, sink_qn, tuple(sorted(files)))
            if sig in seen_paths:
                continue
            seen_paths.add(sig)
            added += 1
            sink_refs = ", ".join(f"{s.file}:{s.line}"
                                  for s in sinks_here[:3]) or q_file(sink_qn)
            unauth = "UNAUTH " if ep.reachable_from_unauth else ""
            sink_first = sinks_here[0] if sinks_here else None
            manifest.chunks.append(Chunk(
                id=f"taint-{added:02d}",
                size=_size_for(sum(_count_loc(repo_root / f) for f in files)),
                risk_rank=added,
                files=files,
                focus_entry_points=[ep.function],
                hypothesis=(
                    f"Taint path: {unauth}{ep.kind} input at "
                    f"{ep.function}() [{ep.file}] flows via "
                    f"{' -> '.join(q_name(n) for n in path)} to sink "
                    f"{q_name(sink_qn)}() [{sink_refs}]. Verify every hop for "
                    f"sanitization/validation; if none, this is exploitable."
                ),
                related_cves=[],
                threat_id=_threat_for(ep),
                # structured taint metadata → s4 function-slice + confirm/refute
                path_funcs=list(path),
                source_ref=q_join(ep.file, ep.function),
                sink_ref=(f"{sink_first.file}:{sink_first.line}"
                          if sink_first else q_file(sink_qn)),
                # Union of CWE tags from every seed-sink at this qnode. Drives
                # CweKB.prompt_block() in s4 — empty when the sink was
                # agent-discovered (KB block then omits itself → legacy prompt).
                sink_cwe=sorted({c for s in sinks_here
                                 for c in getattr(s, "cwe", None) or ()}),
            ))

    reached_sink_objs = {id(s) for qn in reached_fns
                         for s in sink_by_qn.get(qn, ())}
    orphans = [s for s in ctx.unsafe_sinks
               if id(s) not in reached_sink_objs and s.file not in entry_files]
    n_sinks = len(ctx.unsafe_sinks)
    pct = (100 * (n_sinks - len(orphans)) / n_sinks) if n_sinks else 0
    sample = ", ".join(f"{s.file}:{s.line}" for s in orphans[:6])
    if len(orphans) > 6:
        sample += f", …(+{len(orphans) - 6})"
    print(f"    [s3] taint reachability: {n_sinks - len(orphans)}/{n_sinks} "
          f"sinks ({pct:.0f}%) on ≥1 entry→sink path"
          + (f"; ORPHANED: {sample}" if orphans else ""), file=sys.stderr)

    if added:
        print(f"    [s3] taint: {added} entry→sink path chunks "
              f"({len(ctx.entry_points)} entries × {len(ctx.unsafe_sinks)} sinks, "
              f"graph={len(graph)} nodes)", file=sys.stderr)
    else:
        # Nothing reachable — undo the rank shift so ordering is unchanged.
        for c in manifest.chunks:
            c.risk_rank -= max_chunks
        print("    [s3] taint: 0 reachable entry→sink paths in call graph",
              file=sys.stderr)
    return added


def _bfs_to_sinks(start: str, graph: dict[str, list[str]],
                  sinks: set[str], max_hops: int) -> list[tuple[str, list[str]]]:
    """Return [(sink_fn, path_funcs)] for every sink reachable from `start`
    via a path that does NOT pass through a known sanitizer.

    Paths that cross a sanitizer are silently dropped: they still generate
    reachability noise but carry no proven taint, so skipping them reduces
    false-positive chunk generation.  S4 (LLM confirm/refute) handles the
    residual uncertain cases.
    """
    if not start:
        return []
    # Minimal set of sanitizer bare-names — mirrors _SANITIZER_NAMES from the
    # callgraph engine without importing across package boundaries.
    _SANITIZER_BARE: frozenset[str] = frozenset({
        "escape", "quote", "sanitize", "clean", "encode", "validate",
        "strip_tags", "html_escape", "xml_escape", "quote_plus", "urlencode",
        "bleach_clean", "prepared_statement", "parameterized",
        "to_int", "int", "float", "bool",
    })
    out: list[tuple[str, list[str]]] = []
    visited = {start}
    # frontier entries: (node, path, sanitized_on_path)
    frontier: list[tuple[str, list[str], bool]] = [(start, [start], False)]
    while frontier:
        nxt = []
        for node, path, is_sanitized in frontier:
            for callee in graph.get(node, ()):
                if callee in visited:
                    continue
                visited.add(callee)
                callee_bare = callee.rpartition("::")[2].lower()
                hit = is_sanitized or callee_bare in _SANITIZER_BARE
                p = path + [callee]
                if callee in sinks:
                    if not hit:
                        out.append((callee, p))
                if len(p) <= max_hops:
                    nxt.append((callee, p, hit))
        frontier = nxt
    return out


def _size_for(loc: int) -> ChunkSize:
    if loc < 2000:
        return ChunkSize.SMALL
    if loc < 8000:
        return ChunkSize.MEDIUM
    return ChunkSize.LARGE


def _char_budget(cfg) -> int | None:
    """Shard-boundary char cap when step3.pack_by == 'tokens', else None.
    chars ≈ tokens × 4; budget = (context window − fixed overhead) × 4."""
    if str(getattr(cfg.step3, "pack_by", "loc")).lower() != "tokens":
        return None
    budget = int(getattr(cfg.step3, "chunk_token_budget", 180_000))
    overhead = int(getattr(cfg.step3, "chunk_overhead_tokens", 80_000))
    return max(10_000, (budget - overhead) * 4)


def _split_oversize_risk_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> None:
    """Re-pack any LLM-emitted chunk whose total LOC exceeds step3.risk_chunk_loc
    into chunk-NN-a, chunk-NN-b, … so s4 never sends a prompt past the model's
    context window. Preserves risk_rank, hypothesis, CVEs and entry points."""
    max_loc = getattr(cfg.step3, "risk_chunk_loc", 8000)
    max_files = getattr(cfg.step3, "max_files_per_chunk", 25)
    char_cap = _char_budget(cfg)
    if not max_loc and char_cap is None:
        return
    repo_root = Path(ctx.repo_root)

    out: list[Chunk] = []
    for c in manifest.chunks:
        loc = sum(_count_loc(repo_root / f) for f in c.files)
        if char_cap is not None:
            chars = sum(_count_chars(repo_root / f) for f in c.files)
            fits = chars <= char_cap and len(c.files) <= max_files
            cap_txt = f"{char_cap} chars (~{char_cap//4} tok)"
            got_txt = f"{chars} chars"
        else:
            fits = loc <= max_loc and len(c.files) <= max_files
            cap_txt = f"{max_loc} LOC"
            got_txt = f"{loc} LOC"
        if fits:
            c.size = _size_for(loc)
            out.append(c)
            continue
        groups = _cohesive_groups(c.files, ctx)
        buckets = _pack(groups, repo_root, max_loc, max_files,
                        max_chars=char_cap)
        print(f"    [s3] {c.id}: {got_txt} / {len(c.files)} files > cap "
              f"({cap_txt} / {max_files} files) → split into {len(buckets)}",
              file=sys.stderr)
        for i, (_, files, bloc) in enumerate(buckets):
            suffix = chr(ord("a") + i) if i < 26 else str(i + 1)
            out.append(c.model_copy(update={
                "id": f"{c.id}-{suffix}",
                "files": files,
                "size": _size_for(bloc),
            }))
    manifest.chunks = out


def _pack(groups: list[tuple[str, list[str]]], repo_root: Path,
          max_loc: int, max_files: int, *,
          max_chars: int | None = None) -> list[tuple[str, list[str], int]]:
    """Split each group into (label, files, loc) buckets.

    Shard boundary is decided by `max_chars` (bytes ≈ tokens×4) when given,
    otherwise by `max_loc` — so step3.pack_by switches the metric without
    touching callers. The returned `loc` is always real line count so
    `_size_for()` and the LOC distribution report stay correct in both modes.
    Groups that shard into N>1 buckets get a `[shard k/N]` label suffix."""
    use_chars = max_chars is not None
    out: list[tuple[str, list[str], int]] = []
    for label, files in groups:
        shards: list[tuple[list[str], int]] = []
        b_files: list[str] = []
        b_loc = b_chars = 0
        for f in files:
            loc = _count_loc(repo_root / f)
            chars = _count_chars(repo_root / f) if use_chars else 0
            over = ((b_chars + chars > max_chars) if use_chars
                    else (b_loc + loc > max_loc))
            if b_files and (over or len(b_files) >= max_files):
                shards.append((b_files, b_loc))
                b_files, b_loc, b_chars = [], 0, 0
            b_files.append(f)
            b_loc += loc
            b_chars += chars
        if b_files:
            shards.append((b_files, b_loc))
        n = len(shards)
        for k, (bf, bl) in enumerate(shards, 1):
            lbl = label if n == 1 else f"{label} [shard {k}/{n}]"
            out.append((lbl, bf, bl))
    return out


# Files that can't realistically carry an exploitable vuln. Dropped from
# catch-all coverage so 90+ chunks of docs/locks/snapshots don't get scanned.
# Credential-prone configs (.env, .npmrc, .yarnrc, *.key/pem/p12…) are KEPT.
_CATCHALL_SKIP_EXTS = {
    ".md", ".mdx", ".txt", ".rst", ".adoc",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
    ".css", ".scss", ".sass", ".less",
    ".lock", ".log", ".map", ".min.js", ".min.css",
    ".snap", ".d.ts",
    ".csv", ".tsv", ".xls", ".xlsx",
    ".po", ".pot", ".mo",
}
_CATCHALL_SKIP_NAMES = {
    "license", "changelog", "changes", "authors", "contributors", "notice",
    "readme", "codeowners", ".gitignore", ".gitattributes", ".editorconfig",
    ".prettierrc", ".prettierignore", ".eslintignore", ".dockerignore",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "go.sum", "cargo.lock", "composer.lock",
}
_CATCHALL_SKIP_DIR_PARTS = {
    "__snapshots__", "__fixtures__", "fixtures", "__mocks__", "mocks",
    "docs", "doc", "examples", "example", "samples",
}


def _catchall_eligible(rel: str) -> bool:
    p = Path(rel)
    name = p.name.lower()
    if name in _CATCHALL_SKIP_NAMES:
        return False
    # Match either the single final suffix (".js") or any trailing
    # multi-suffix tail (".min.js") against the skip set. A bare
    # ``suffixes in SET`` check missed multi-dotted names like
    # ``foo.bundle.min.js`` whose full joined suffixes (".bundle.min.js")
    # is not itself a skip key — so test every trailing dotted tail.
    name = p.name.lower()
    if p.suffix.lower() in _CATCHALL_SKIP_EXTS:
        return False
    if any(name.endswith(ext) for ext in _CATCHALL_SKIP_EXTS):
        return False
    if any(part.lower() in _CATCHALL_SKIP_DIR_PARTS for part in p.parts[:-1]):
        return False
    return True


def _lang_of_file(f: str) -> str | None:
    """Language for a repo-relative path via extension, or None if unknown."""
    return EXT_TO_LANG.get(PurePosixPath(f).suffix.lower())


def _reachable_files(ctx: ContextPackage) -> set[str]:
    """
    File-level reachability set for ``step3.catchall_mode: reachable_only``.

    A file is *reachable* iff it lies on the forward closure from any
    ``EntryPoint.file`` OR the backward closure to any ``Sink.file`` over a
    file-level projection of ``ctx.call_graph`` (whose nodes are already
    file-qualified ``path::name``). This is intentionally coarser than the
    function-level taint walk — for catch-all gating we only need to decide
    *which files* might sit on an attacker-controlled data path, not which
    functions. Full BFS (no hop cap): the file graph has ≤ len(all_files)
    nodes, so it's cheap.

    Conservative biases (all widen the set, never shrink it):
      • every EntryPoint.file and Sink.file is always reachable, even if the
        call graph never mentions it;
      • polymorphic defs: any file listed in ``ctx.call_graph_files[name]``
        for a reachable function name is pulled in too, so an interface call
        keeps every implementation file in scope.
    """
    fwd: dict[str, set[str]] = defaultdict(set)
    rev: dict[str, set[str]] = defaultdict(set)
    for caller, callees in (ctx.call_graph or {}).items():
        cf = q_file(caller)
        for callee in callees or ():
            tf = q_file(callee)
            if cf and tf and cf != tf:
                fwd[cf].add(tf)
                rev[tf].add(cf)

    # Polymorphic widening: bare-name → all def-site files. If file F calls
    # bare name N, treat F → every file that defines N.
    name_to_files: dict[str, set[str]] = defaultdict(set)
    for name, sites in (ctx.call_graph_files or {}).items():
        bare = q_name(name)
        for ref in sites or ():
            f = ref.split(":", 1)[0]
            if f:
                name_to_files[bare].add(f)
    for caller, callees in (ctx.call_graph or {}).items():
        cf = q_file(caller)
        if not cf:
            continue
        for callee in callees or ():
            for tf in name_to_files.get(q_name(callee), ()):
                if tf != cf:
                    fwd[cf].add(tf)
                    rev[tf].add(cf)

    def _bfs(seeds: set[str], graph: dict[str, set[str]]) -> set[str]:
        seen = set(seeds)
        frontier = list(seeds)
        while frontier:
            nxt: list[str] = []
            for n in frontier:
                for m in graph.get(n, ()):
                    if m not in seen:
                        seen.add(m)
                        nxt.append(m)
            frontier = nxt
        return seen

    ep_files = {e.file for e in ctx.entry_points if e.file}
    sk_files = {s.file for s in ctx.unsafe_sinks if s.file}
    # s0 codeFlow evidence: any file semgrep placed on a source→sink path is
    # reachable by construction, regardless of whether the call-graph (which
    # is blind to reflection/DI/dynamic dispatch) has an edge for it. This is
    # widen-only — it can never shrink the set.
    seed_files = seed_reachable_files(ctx.seed_taint_paths)

    # Fail-safe for language coverage: the call graph is built only for the
    # languages the s0 engine has plugins for (6 of ~42). Files in a language
    # that contributed *zero* graph nodes are structurally absent from the
    # closures above and would be labelled unreachable purely for lack of a
    # parser — an unknown, not a proven-unreachable, state. Treat such files as
    # reachable so reachable_only never drops a whole language. This is
    # widen-only; a language that DID contribute nodes is still pruned normally.
    graph_node_files: set[str] = set(ep_files) | set(sk_files) | set(seed_files)
    for caller, callees in (ctx.call_graph or {}).items():
        if (cf := q_file(caller)):
            graph_node_files.add(cf)
        for callee in callees or ():
            if (tf := q_file(callee)):
                graph_node_files.add(tf)
    for sites in (ctx.call_graph_files or {}).values():
        for ref in sites or ():
            if (f := ref.split(":", 1)[0]):
                graph_node_files.add(f)
    covered_langs = {lang for f in graph_node_files
                     if (lang := _lang_of_file(f))}
    unknown_lang_files = {
        f for f in ctx.all_files
        if (lang := _lang_of_file(f)) is not None and lang not in covered_langs
    }

    return (_bfs(ep_files, fwd) | _bfs(sk_files, rev)
            | ep_files | sk_files | seed_files | unknown_lang_files)


def _reachable_only_too_sparse(reachable_count: int, total_count: int, cfg) -> tuple[bool, str]:
    """Return True when reachable-only coverage is too sparse to trust.

    Taint profiles use reachable-only to save tokens, but an under-built graph
    should fail open rather than exclude most catch-all review. Both thresholds
    default to disabled for backwards compatibility; taint profiles opt in.
    """
    if total_count <= 0:
        return False, ""
    step3 = getattr(cfg, "step3", None)
    min_ratio = float(getattr(step3, "catchall_reachable_min_ratio", 0.0) or 0.0)
    min_files = int(getattr(step3, "catchall_reachable_min_files", 0) or 0)
    ratio = reachable_count / total_count
    reasons: list[str] = []
    if min_ratio > 0 and ratio < min_ratio:
        reasons.append(f"reachable ratio {ratio:.0%} < {min_ratio:.0%}")
    if min_files > 0 and reachable_count < min_files:
        reasons.append(f"reachable files {reachable_count} < {min_files}")
    return bool(reasons), "; ".join(reasons)


def _add_catchall_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> int:
    """Create low-rank chunks for every file not already assigned to a chunk."""
    covered: set[str] = set()
    for c in manifest.chunks:
        covered.update(c.files)
    uncovered = [f for f in ctx.all_files if f not in covered]
    if not getattr(cfg.step3, "catchall_enabled", True):
        print(f"    [s3] coverage: {len(uncovered)} uncovered files — "
              f"catch-all DISABLED (step3.catchall_enabled: false)",
              file=sys.stderr)
        return 0
    eligible = [f for f in uncovered if _catchall_eligible(f)]

    # ── reachable-only gate (taint.yaml) ────────────────────────────────
    # Drop any catch-all candidate that is NOT forward-reachable from an
    # entry point NOR backward-reachable from a sink on the file-level call
    # graph. Dropped files are recorded on the manifest for the report
    # appendix — coverage is auditable, not silently truncated. Falls back
    # to legacy `all` when there are no entry points/sinks (gating would
    # otherwise drop the whole repo).
    mode = str(getattr(cfg.step3, "catchall_mode", "all")).lower()
    if mode == "reachable_only" and eligible:
        if not (ctx.entry_points or ctx.unsafe_sinks):
            print("    [s3] catchall_mode=reachable_only but s0/s1 produced "
                  "0 entry points and 0 sinks — falling back to mode=all",
                  file=sys.stderr)
        else:
            reach = _reachable_files(ctx) & set(ctx.all_files)
            before = len(eligible)
            dropped = sorted(f for f in eligible if f not in reach)
            kept = [f for f in eligible if f in reach]
            too_sparse, sparse_reason = _reachable_only_too_sparse(
                len(kept), before, cfg)
            if too_sparse:
                manifest.unreachable_files = []
                print(f"    [s3] catchall_mode=reachable_only: "
                      f"{before} eligible → {len(kept)} reachable; "
                      f"falling back to mode=all ({sparse_reason})",
                      file=sys.stderr)
            else:
                eligible = kept
                manifest.unreachable_files = dropped
                pct = (100 * len(dropped) / before) if before else 0
                sample = ", ".join(dropped[:5])
                if len(dropped) > 5:
                    sample += f", …(+{len(dropped) - 5})"
                print(f"    [s3] catchall_mode=reachable_only: "
                      f"{before} eligible → {len(eligible)} reachable "
                      f"({len(dropped)} dropped, {pct:.0f}% — listed in report "
                      f"appendix){'; e.g. ' + sample if dropped else ''}",
                      file=sys.stderr)

    if not eligible:
        if uncovered:
            print(f"    [s3] coverage: {len(uncovered)} uncovered files "
                  f"(all non-source → 0 catch-all chunks)", file=sys.stderr)
        return 0

    repo_root = Path(ctx.repo_root)
    max_loc = getattr(cfg.step3, "catchall_chunk_loc", 20000)
    max_files = getattr(cfg.step3, "catchall_max_files",
                        getattr(cfg.step3, "max_files_per_chunk", 100))
    base_rank = max((c.risk_rank for c in manifest.chunks), default=0)

    groups = _cohesive_groups(eligible, ctx)
    buckets = _pack(groups, repo_root, max_loc, max_files,
                    max_chars=_char_budget(cfg))

    for idx, (label, files, loc) in enumerate(buckets, 1):
        manifest.chunks.append(_mk_catchall(idx, label, files, loc, base_rank + idx))

    print(f"    [s3] coverage: {len(uncovered)} uncovered "
          f"→ {len(eligible)} eligible → {len(buckets)} catch-all chunks",
          file=sys.stderr)
    return len(buckets)


def _add_specialist_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> int:
    """
    Append repo-wide specialist passes (crypto, logic-bug). These see ALL source
    files regardless of risk-ranking — they hunt for cross-cutting bug classes
    that per-chunk language researchers miss.

    Sharding is module-aware (via _cohesive_groups) and restricted to actual
    source files so specialists don't waste budget on YAML/shell/markdown.
    """
    enabled = getattr(cfg.step3, "specialists", None)
    if enabled is None:
        enabled = ["crypto", "logic-bug"]
    source = [f for f in ctx.all_files if _is_source(f)]
    enabled = _gate_specialists(enabled, ctx, source)
    if not enabled:
        print("    [s3] specialists: all gated off (no matching surface)", file=sys.stderr)
        return 0
    if not source:
        print("    [s3] specialists: 0 source files after filtering", file=sys.stderr)
        return 0

    repo_root = Path(ctx.repo_root)
    max_loc = getattr(cfg.step3, "specialist_chunk_loc", 6000)
    max_files = getattr(cfg.step3, "max_files_per_chunk", 25)
    char_cap = _char_budget(cfg)
    base_rank = max((c.risk_rank for c in manifest.chunks), default=0)

    # Default bucketing covers all source. Specialists that need a narrower
    # scope (currently just `iac`) override below.
    default_buckets = _pack(_cohesive_groups(source, ctx),
                            repo_root, max_loc, max_files,
                            max_chars=char_cap)

    n_added = 0
    for spec in enabled:
        if spec == "iac":
            iac_source = [f for f in source if is_iac_file(f)]
            if not iac_source:
                print("    [s3] specialist 'iac' has 0 IaC files in source — skipped",
                      file=sys.stderr)
                continue
            spec_buckets = _pack(_cohesive_groups(iac_source, ctx),
                                 repo_root, max_loc, max_files,
                                 max_chars=char_cap)
            print(f"    [s3] specialist 'iac': scoped to {len(iac_source)} "
                  f"IaC file(s) → {len(spec_buckets)} shard(s)",
                  file=sys.stderr)
        else:
            spec_buckets = default_buckets
        for shard, (label, files, loc) in enumerate(spec_buckets, 1):
            focus = _specialist_focus_entry_points(files, ctx)
            manifest.chunks.append(_mk_specialist(
                spec, shard, label, files, loc, base_rank + n_added + 1,
                detect_languages(files, repo_root=repo_root), focus))
            n_added += 1

    print(f"    [s3] specialists: {', '.join(enabled)} -> {n_added} chunks "
          f"({len(source)}/{len(ctx.all_files)} source files)",
          file=sys.stderr)
    return n_added


_CRYPTO_RX = re.compile(
    r"\b(AES|RSA|HMAC|SHA-?(1|2|256|384|512)|MD5|PBKDF2|bcrypt|scrypt|argon2"
    r"|Cipher|KeyPair|SecretKey|X509|PKCS|TLS|SSLContext|jwt|jose|nacl|sodium"
    r"|hashlib|hmac\.|cryptography\.|javax\.crypto|BouncyCastle|OpenSSL"
    r"|Crypt::|Digest::|Mcrypt|RandomNumberGenerator|SecureRandom)\b",
    re.IGNORECASE,
)

_DESER_RX = re.compile(
    r"\b(ObjectInputStream|readObject|XMLDecoder|XStream|SnakeYAML|yaml\.load"
    r"|pickle\.|marshal\.load|unserialize|BinaryFormatter|Kryo|Hessian"
    r"|JdkSerializationRedisSerializer|Marshal\.load)\b",
)

_BATCH_ETL_RX = re.compile(
    r"\b(struct\.(?:un)?pack|codecs\.(?:encode|decode)\([^)]*ebcdic"
    r"|cp037|cp1047|COMP-3|packed[_-]?decimal|RECFM|LRECL"
    r"|glob\.glob|os\.listdir|shutil\.(?:move|copy)|csv\.(?:writer|reader)"
    r"|EXEC\s+PGM=|//\w+\s+DD\b|DISP=\()\b",
    re.IGNORECASE,
)


def _has_batch_surface(ctx: ContextPackage, repo_root: Path,
                       source: list[str]) -> bool:
    if any(ep.kind in {"file", "cli"} for ep in ctx.entry_points):
        return True
    langs = set(detect_languages(ctx.all_files, repo_root=repo_root))
    if langs & {"cobol", "jcl"}:
        return True
    return _scan_any(repo_root, source, _BATCH_ETL_RX)


def _scan_any(repo_root: Path, files: list[str], rx: re.Pattern) -> bool:
    for rel in files:
        p = repo_root / rel
        try:
            if rx.search(p.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


def _has_authz_surface(ctx: ContextPackage) -> bool:
    if ctx.app_profile and ctx.app_profile.externally_facing:
        return True
    if any(ep.kind in {"network", "ipc"} or ep.reachable_from_unauth
           for ep in ctx.entry_points):
        return True
    if any(c.kind == "auth" for c in ctx.design_controls):
        return True
    if ctx.threat_model:
        for t in ctx.threat_model.threats:
            if t.actor in {"remote_unauth", "remote_auth"}:
                return True
    return False


def _gate_specialists(enabled: list[str], ctx: ContextPackage,
                      source: list[str]) -> list[str]:
    """Drop specialist passes whose target surface doesn't exist in this repo,
    so s4/s5 don't burn budget verifying guaranteed-FP findings."""
    repo_root = Path(ctx.repo_root)
    gates = {
        "access-control":  lambda: _has_authz_surface(ctx),
        "crypto":          lambda: _scan_any(repo_root, source, _CRYPTO_RX),
        "deserialization": lambda: _scan_any(repo_root, source, _DESER_RX),
        "batch-etl":       lambda: _has_batch_surface(ctx, repo_root, source),
        "iac":             lambda: any(is_iac_file(f) for f in ctx.all_files),
    }
    kept: list[str] = []
    for spec in enabled:
        gate = gates.get(spec)
        if gate is None or gate():
            kept.append(spec)
        else:
            print(f"    [s3] specialist '{spec}' gated OFF — no matching surface in repo",
                  file=sys.stderr)
    return kept


def _mk_specialist(spec: str, shard: int, label: str, files: list[str], loc: int,
                   rank: int, langs: list[str],
                   focus: list[str]) -> Chunk:
    return Chunk(
        id=f"spec-{spec}-{shard:02d}",
        size=_size_for(loc),
        risk_rank=rank,
        files=files,
        focus_entry_points=focus,
        hypothesis=f"{spec} specialist sweep over module '{label}'.",
        related_cves=[],
        languages=langs,
        specialist=spec,
    )


def _specialist_focus_entry_points(files: list[str], ctx: ContextPackage,
                                   cap: int = 24) -> list[str]:
    """Best-effort method anchors for specialist shards.

    Uses call_graph_files def-sites to pick function names that are actually
    present in the shard's file set; S4 uses these names to prioritize spans.
    """
    if not files:
        return []
    file_set = set(files)
    out: list[str] = []
    for fn, locs in (ctx.call_graph_files or {}).items():
        if any((ref.rpartition(":")[0] in file_set) for ref in (locs or ())):
            out.append(fn)
            if len(out) >= cap:
                break
    return out


def _mk_catchall(idx: int, dir_name: str, files: list[str], loc: int, rank: int) -> Chunk:
    return Chunk(
        id=f"catchall-{idx:02d}",
        size=_size_for(loc),
        risk_rank=rank,
        files=files,
        focus_entry_points=[],
        hypothesis=f"Coverage sweep of '{dir_name}' — files not assigned to any "
                   f"risk-ranked chunk. Hunt for any vulnerability class.",
        related_cves=[],
    )


def _report_chunk_loc(manifest: TaskManifest, ctx: ContextPackage, cfg) -> None:
    repo_root = Path(ctx.repo_root)
    locs = sorted(sum(_count_loc(repo_root / f) for f in c.files)
                  for c in manifest.chunks)
    if not locs:
        return
    n = len(locs)
    cap = getattr(cfg.step3, "risk_chunk_loc", 8000) or 0
    over = sum(1 for x in locs if cap and x > cap)
    fmt = lambda x: f"{x/1000:.1f}k" if x >= 1000 else str(x)
    print(f"    [s3] chunk LOC: n={n} min={fmt(locs[0])} "
          f"p50={fmt(locs[n // 2])} p90={fmt(locs[min(n - 1, int(n * 0.9))])} "
          f"max={fmt(locs[-1])}"
          + (f"  ({over} over risk_chunk_loc={cap})" if cap else ""),
          file=sys.stderr)


_CHARS_CACHE: dict[str, int] = {}


def _count_chars(p: Path) -> int:
    """File size in bytes (≈ chars for source). stat() only — no read, so
    pack_by:tokens adds ~zero I/O over LOC mode even on 20k-file trees."""
    k = str(p)
    v = _CHARS_CACHE.get(k)
    if v is not None:
        return v
    try:
        v = p.stat().st_size
    except OSError:
        v = 0
    _CHARS_CACHE[k] = v
    return v


def _count_loc(p: Path) -> int:
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0
