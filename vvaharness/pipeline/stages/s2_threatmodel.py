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
Step 2 — Application threat model.

Runs AFTER s1 and consumes its ContextPackage, so the threat model reasons
over the *actual mapped attack surface* (modules, entry points, config
representatives, API contracts) rather than a blind alphabetical file
sample. Builds an application-level threat model (assets, trust boundaries,
STRIDE-tagged threats) so every downstream step has context for *what this
system is and who attacks it*, not just *what the code looks like*.

Backend: SDK (no tools). Evidence is assembled deterministically from ctx +
on-disk docs/manifests and packed into one prompt.

Output ThreatModel is attached to ContextPackage and rendered into:
  - s3 user prompt  (ctx.to_prompt_block) → drives chunk hypothesis ranking
  - s6 verify       (ARCHITECTURE CONTEXT) → actor/control reality-check
  - s8 chain        → severity ranking + chain narrative
"""
from __future__ import annotations
import fnmatch
import logging
import re
import sys
from collections import Counter
from pathlib import Path

log = logging.getLogger(__name__)

from vvaharness.models import ThreatModel, CVE, Control, AppProfile, ContextPackage
from vvaharness.backends.llm import prompt

from vvaharness.util.json_extract import extract_json
from vvaharness.lang.hints import EXT_TO_LANG, LANG_DISPLAY


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic evidence gathering (no LLM)
# ─────────────────────────────────────────────────────────────────────────────

_DOC_CANDIDATES = (
    "README.md", "README.rst", "README.txt", "README",
    "SECURITY.md", "THREAT_MODEL.md", "ARCHITECTURE.md",
    "CHANGELOG.md", "CHANGELOG",
)

# Design/analysis docs that aren't named README/ARCHITECTURE but describe
# data flows the threat model needs (e.g. COBOL→Python migration write-ups).
# Matched case-insensitively against the basename of any .md/.rst in the tree.
_DOC_NAME_RX = re.compile(
    r"(analysis|architecture|design|migration|specification|spec|"
    r"threat|security|dataflow|data[_-]?flow|interface)",
    re.IGNORECASE,
)
_DOC_EXTRA_MAX = 8

_MANIFEST_CANDIDATES = (
    "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
    "setup.py", "pyproject.toml", "requirements.txt",
    "go.mod", "Cargo.toml", "Gemfile", "composer.json",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".csproj",
)

_API_SURFACE_GLOBS = (
    "*openapi*.y*ml", "*openapi*.json",
    "*swagger*.y*ml", "*swagger*.json",
    "*.proto", "*.graphql", "*.graphqls",
    "*.avsc", "*.wsdl", "*.thrift",
    "*META-INF/*", "*AndroidManifest.xml",
)

_CONFIG_EXTS = {".yml", ".yaml", ".json", ".toml", ".ini",
                ".properties", ".conf", ".cfg", ".env"}

# Entry-point kind → STRIDE categories an attacker at that boundary can
# typically pursue. Used as a hint, not a constraint.
_STRIDE_BY_KIND = {
    "network":         "S T R I D E",
    "ipc":             "T I E",
    "file":            "T I D",
    "cli":             "T E",
    "deserialization": "T E",
    "other":           "T I",
}

_LANG_BY_EXT = {ext: LANG_DISPLAY.get(key, key) for ext, key in EXT_TO_LANG.items()}


# ─────────────────────────────────────────────────────────────────────────────
# Repo-kind classifier → minimum-baseline checklist (step2.baseline)
# ─────────────────────────────────────────────────────────────────────────────

_WEB_FW_RX = re.compile(
    r"\b(spring|express|fastify|koa|hapi|nest|next|nuxt|django|flask|fastapi|"
    r"tornado|rails|sinatra|laravel|symfony|gin-gonic|echo|fiber|actix|axum|"
    r"asp\.net|ktor|micronaut|quarkus|vertx|play-framework)\b", re.IGNORECASE)

_NATIVE_LANGS = {"c", "cpp", "c++", "c-cpp", "c/c++", "rust", "objective-c", "objc"}

_BASELINES: dict[str, tuple[str, ...]] = {
    "web-api": (
        "OWASP A01 Broken Access Control (IDOR, path traversal, forced browsing, privilege escalation)",
        "OWASP A02 Cryptographic Failures (weak/missing crypto, plaintext secrets/transport)",
        "OWASP A03 Injection (SQL/NoSQL/OS/LDAP/template/header)",
        "OWASP A04 Insecure Design (missing rate-limit, trust-boundary assumptions)",
        "OWASP A05 Security Misconfiguration (default creds, debug on, permissive CORS)",
        "OWASP A07 Identification & Authentication Failures (weak session, missing MFA, JWT flaws)",
        "OWASP A08 Software & Data Integrity Failures (unsafe deserialization, unsigned updates)",
        "OWASP A10 Server-Side Request Forgery",
        "XSS (reflected / stored / DOM)",
        "CSRF / state-changing GET",
    ),
    "mobile": (
        "OWASP M1 Improper Credential Usage (hardcoded keys, token leakage)",
        "OWASP M3 Insecure Authentication/Authorization",
        "OWASP M5 Insecure Communication (no cert pinning, cleartext traffic)",
        "OWASP M8 Security Misconfiguration (exported components, debuggable build)",
        "OWASP M9 Insecure Data Storage (world-readable prefs, unencrypted DB)",
    ),
    "native": (
        "CWE-119/787 Buffer overflow (stack/heap write OOB)",
        "CWE-416 Use-after-free / double-free",
        "CWE-190 Integer overflow leading to undersized allocation",
        "CWE-134 Format-string",
        "CWE-362 TOCTOU / race condition",
        "CWE-78 OS command injection via system()/exec()",
    ),
    "iac": (
        "Over-permissive IAM / RBAC (wildcard actions, cluster-admin bindings)",
        "Public network exposure (0.0.0.0/0 ingress, hostNetwork, public S3/bucket)",
        "Secrets committed in plaintext / env",
        "Privileged or root containers, missing securityContext",
        "Disabled TLS / unencrypted storage classes",
    ),
    "library": (
        "Injection via untrusted caller input (SQL/OS/path)",
        "Unsafe deserialization (pickle/yaml.load/XMLDecoder/ObjectInputStream)",
        "Path traversal in file-handling APIs",
        "ReDoS / algorithmic-complexity DoS",
    ),
}


def _repo_kind(ev: dict, ctx: ContextPackage | None) -> set[str]:
    kinds: set[str] = set()
    all_files = [f.lower() for f in (ctx.all_files if ctx else [])]
    manifest_text = "\n".join(body for _, body in ev["manifests"])

    if (any(k == "network" for k, *_ in ev["entry_points"])
            or ev["api_artefacts"]
            or _WEB_FW_RX.search(manifest_text)):
        kinds.add("web-api")

    if (any(f.endswith(("androidmanifest.xml", "info.plist", "podfile"))
            for f in all_files)
            or re.search(r"\bcom\.android\b", manifest_text)):
        kinds.add("mobile")

    if any(f.endswith((".tf", ".hcl", "chart.yaml", "values.yaml",
                       "kustomization.yaml", "kustomization.yml"))
           for f in all_files):
        kinds.add("iac")

    langs = {(ev["primary_language"] or "").lower(),
             *(l.lower() for l, _ in ev["languages"])}
    if langs & _NATIVE_LANGS:
        kinds.add("native")

    return kinds or {"library"}


def _baseline_block(ev: dict, ctx: ContextPackage | None, mode: str) -> tuple[set[str], str]:
    if mode == "none":
        return set(), ""
    kinds = {"web-api"} if mode == "owasp" else _repo_kind(ev, ctx)
    seen: set[str] = set()
    items: list[str] = []
    for k in sorted(kinds):
        for it in _BASELINES.get(k, ()):
            if it not in seen:
                seen.add(it)
                items.append(it)
    if not items:
        return kinds, ""
    body = "\n".join(f"  - {it}" for it in items)
    return kinds, (
        f"\nMINIMUM BASELINE for repo kind {{{', '.join(sorted(kinds))}}} — rank "
        f"each against THIS codebase; emit a threat ONLY if a matching surface "
        f"exists in the evidence above, otherwise omit silently:\n{body}\n")


def _read_capped(p: Path, cap_chars: int) -> str:
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    if len(txt) > cap_chars:
        txt = txt[:cap_chars] + f"\n…(truncated, {len(txt)} chars total)"
    return txt


def _gather_evidence(repo_root: str, cfg,
                     ctx: ContextPackage | None) -> dict:
    """Assemble threat-model evidence. When `ctx` is supplied (normal path)
    the high-signal blocks come from s1's mapped surface; docs/manifests are
    still read from disk."""
    root = Path(repo_root)
    s2 = getattr(cfg, "step2", None)
    doc_cap = getattr(s2, "max_doc_chars", 20000)
    manifest_cap = getattr(s2, "max_manifest_chars", 4000)

    def _cap_int(key: str, default: int) -> int:
        return int(getattr(s2, key, default) or default)

    max_graph_files = _cap_int("max_graph_files", 220)
    max_entry_points = _cap_int("max_entry_points", 80)
    max_graph_sinks = _cap_int("max_graph_sinks", 80)
    max_modules = _cap_int("max_modules", 40)
    max_graph_edges = _cap_int("max_graph_edges", 100)
    max_notes_chars = _cap_int("max_notes_chars", 2500)
    max_function_sites = _cap_int("max_function_sites", 80)
    max_config_reps = _cap_int("max_config_reps", 60)
    max_api_artefacts = _cap_int("max_api_artefacts", 80)
    # Prompt caps use their OWN keys, distinct from the frontier caps
    # (max_modules / max_entry_points) read above.
    max_modules_prompt = _cap_int("max_prompt_modules", 100)
    max_entry_points_prompt = _cap_int("max_prompt_entry_points", 400)

    frontier = None
    if ctx:
        frontier = ctx.ast_context_view(
            max_files=max_graph_files,
            max_entry_points=max_entry_points,
            max_sinks=max_graph_sinks,
            max_modules=max_modules,
            max_edges=max_graph_edges,
            max_notes_chars=max_notes_chars,
        )
    active_ctx = frontier or ctx
    all_files = list(active_ctx.all_files) if active_ctx else []

    lang_counts: Counter[str] = Counter()
    for rel in all_files:
        lang = _LANG_BY_EXT.get(Path(rel).suffix.lower())
        if lang:
            lang_counts[lang] += 1

    docs: list[tuple[str, str]] = []
    budget = doc_cap
    for name in _DOC_CANDIDATES:
        p = root / name
        if p.is_file() and budget > 0:
            body = _read_capped(p, min(budget, doc_cap // 2))
            if body:
                docs.append((name, body))
                budget -= len(body)

    seen = {n for n, _ in docs}
    extras = sorted(
        rel for rel in all_files
        if Path(rel).suffix.lower() in (".md", ".rst")
        and rel not in seen
        and _DOC_NAME_RX.search(Path(rel).stem)
    )[:_DOC_EXTRA_MAX]
    if extras:
        per_cap = max(1000, budget // max(len(extras), 1)) if budget > 0 else 0
        for rel in extras:
            if budget <= 0:
                break
            body = _read_capped(root / rel, min(budget, per_cap))
            if body:
                docs.append((rel, body))
                budget -= len(body)

    manifests: list[tuple[str, str]] = []
    for name in _MANIFEST_CANDIDATES:
        if name.startswith("."):
            hits = list(root.rglob(f"*{name}"))[:3]
        else:
            hits = [root / name] if (root / name).is_file() else []
        for p in hits:
            if p.is_file():
                manifests.append(
                    (str(p.relative_to(root)).replace("\\", "/"),
                     _read_capped(p, manifest_cap))
                )

    # Top-level component names (one line each — far cheaper than full tree).
    top_dirs = sorted({rel.split("/", 1)[0] for rel in all_files if "/" in rel})

    # s1-mapped modules (asset candidates) and entry points (trust boundaries).
    modules = [(m.name, m.purpose, m.loc) for m in (active_ctx.modules if active_ctx else [])]
    eps = [(e.kind, e.reachable_from_unauth, e.file, e.function)
           for e in (active_ctx.entry_points if active_ctx else [])]
    eps.sort(key=lambda t: (t[0] != "network", not t[1], t[0], t[2]))

    function_sites: list[tuple[str, list[str], str]] = []
    if active_ctx:
        for fn, sites in list(active_ctx.call_graph_files.items())[:max_function_sites]:
            span = active_ctx.def_spans.get(fn)
            span_txt = f" lines {span[0]}-{span[1]}" if span and len(span) == 2 else ""
            function_sites.append((fn, sites[:2], span_txt))

    call_edges: list[tuple[str, str]] = []
    if active_ctx:
        for caller, callees in active_ctx.call_graph.items():
            for callee in list(dict.fromkeys(callees or [])):
                call_edges.append((caller, callee))

    # Representative config files (post-dedup) — one per top-level dir is
    # enough to surface every external integration / data store.
    cfg_reps: list[str] = []
    seen: set[str] = set()
    for rel in all_files:
        name = Path(rel).name.lower()
        if (Path(rel).suffix.lower() in _CONFIG_EXTS
                or name in _CONFIG_EXTS):
            top = rel.split("/", 1)[0]
            if top not in seen:
                seen.add(top)
                cfg_reps.append(rel)
    cfg_reps = cfg_reps[:max_config_reps]

    # API-contract artefacts (proto/openapi/graphql/…) — explicit boundaries.
    api_artefacts: list[str] = []
    for rel in all_files:
        for g in _API_SURFACE_GLOBS:
            if fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(rel.lower(), g):
                api_artefacts.append(rel)
                break
    api_artefacts = api_artefacts[:max_api_artefacts]

    return {
        "file_count": len(all_files),
        "original_file_count": len(ctx.all_files) if ctx else len(all_files),
        "primary_language": ctx.language if ctx else "",
        "languages": lang_counts.most_common(),
        "top_dirs": top_dirs,
        "modules": modules[:max_modules_prompt],
        "modules_truncated": len(modules) > max_modules_prompt,
        "entry_points": eps[:max_entry_points_prompt],
        "entry_points_truncated": len(eps) > max_entry_points_prompt,
        "function_sites": function_sites,
        "call_edges": call_edges,
        "config_reps": cfg_reps,
        "api_artefacts": api_artefacts,
        "docs": docs,
        "manifests": manifests,
        "s1_notes": getattr(ctx, "notes", "") if ctx else "",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Prompt
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM = """\
You are an application-security threat modeler. You receive a STRUCTURAL
snapshot of a codebase — docs, manifests, the component list, the
agentically-mapped MODULES (purpose-tagged) and ENTRY POINTS (kind +
auth-reachability), representative CONFIG files, and API-contract artefacts —
NOT the source code bodies. From this you produce a threat model: what the
system IS, what it PROTECTS, where untrusted input ENTERS, and what an
attacker would TRY.

A threat survives a patch. "Heap overflow in parser.c:412" is a vulnerability;
"RCE via untrusted media parsing" is a threat. You produce threats.

Work through these stages:

1. SYSTEM CONTEXT — from docs/manifests/tree: what is this application, what
   does it do, who runs it, where (service / CLI / library / batch job)?

2. ASSETS — what does it protect or produce? Data (PII, payment data, secrets,
   credentials), process integrity, service availability, downstream consumers.
   Assign sensitivity: low|medium|high|critical.

3. TRUST BOUNDARIES — every place untrusted input enters or privilege changes.
   Derive from manifests, framework hints in the tree, and docs. Include
   supply-chain and infra/IAM surfaces. Name the crossing
   ("unauth network → application logic", "tenant A → shared DB").

4. THREATS — for EACH trust boundary, walk STRIDE (Spoofing, Tampering,
   Repudiation, Info-disclosure, DoS, Elevation) and emit the plausible ones.
   Use prior CVEs as EVIDENCE that raises likelihood; design controls LOWER it.
   Score impact (low|medium|high|critical|existential) and likelihood
   (very_rare|rare|possible|likely|almost_certain). Sort by (impact,likelihood)
   descending and assign ids T1, T2, …

5. OPEN QUESTIONS — things the snapshot can't tell you (deployment exposure,
   upstream WAF, who supplies inputs, risk appetite).

Respond with ONLY a JSON object — no prose, no markdown fences:
{
  "system_context": "1-3 paragraphs",
  "assets": [{"name":"str","description":"str","sensitivity":"low|medium|high|critical"}],
  "trust_boundaries": [{"entry_point":"str","crossing":"str","reachable_assets":["asset name"]}],
  "threats": [{"id":"T1","threat":"one sentence, names the outcome",
               "actor":"remote_unauth|remote_auth|adjacent_network|local_user|local_admin|supply_chain|insider",
               "surface":"entry_point name from trust_boundaries",
               "asset":"asset name",
               "impact":"low|medium|high|critical|existential",
               "likelihood":"very_rare|rare|possible|likely|almost_certain",
               "controls":"current mitigations or 'none'",
               "evidence":"CVE ids / commit hashes or ''"}],
  "open_questions": ["str"]
}

Coverage rule: every trust_boundary MUST appear as the surface of ≥1 threat."""


def _build_user_prompt(repo_root: str, repo_name: str, ev: dict,
                       cves: list[CVE], controls: list[Control],
                       app_profile: AppProfile | None = None,
                       baseline_block: str = "") -> str:
    lang_block = "\n".join(f"  - {lang}: {n} files" for lang, n in ev["languages"]) \
                 or "  (none detected)"
    comp_block = "\n".join(f"  - {d}/" for d in ev["top_dirs"]) \
                 or "  (flat repo)"

    mod_block = "\n".join(
        f"  - {name}  ({loc} LOC) — {purpose}"
        for name, purpose, loc in ev["modules"]
    ) or "  (s1 emitted no modules)"
    if ev["modules_truncated"]:
        mod_block += "\n  …(truncated)"

    ep_block = "\n".join(
        f"  - [{kind:<14}] {'UNAUTH' if unauth else 'auth  '}  "
        f"STRIDE:{_STRIDE_BY_KIND.get(kind, 'T I')}  "
        f"{file}::{func}"
        for kind, unauth, file, func in ev["entry_points"]
    ) or "  (s1 emitted no entry points)"
    if ev["entry_points_truncated"]:
        ep_block += "\n  …(truncated)"

    site_block = "\n".join(
        f"  - {fn} @ {', '.join(sites)}{span_txt}"
        for fn, sites, span_txt in ev["function_sites"]
    ) or "  (none)"

    edge_block = "\n".join(
        f"  - {caller} -> {callee}" for caller, callee in ev["call_edges"]
    ) or "  (none)"

    cfg_block = "\n".join(f"  - {p}" for p in ev["config_reps"]) \
                or "  (none)"
    api_block = "\n".join(f"  - {p}" for p in ev["api_artefacts"]) \
                or "  (none)"

    docs_block = "\n\n".join(
        f"=== {name} ===\n{body}" for name, body in ev["docs"]
    ) or "(no README / SECURITY / ARCHITECTURE docs found)"
    manifest_block = "\n\n".join(
        f"=== {name} ===\n{body}" for name, body in ev["manifests"]
    ) or "(no build/dependency manifests found)"
    cve_block = "\n".join(
        f"  - {c.id} (CVSS {c.cvss}, {'patched' if c.patched else 'UNPATCHED'}): {c.summary}"
        for c in cves
    ) or "  (none on file)"
    ctl_block = "\n".join(
        f"  - [{c.kind}] {c.name} → protects: {', '.join(c.protects) or 'global'}"
        + (f" — {c.notes}" if c.notes else "")
        for c in controls
    ) or "  (none on file)"

    cmdb_block = ""
    if app_profile:
        cmdb_block = (app_profile.to_prompt_block()
                      + "\n  → Use externally_facing to set default actor "
                        "(remote_unauth only if YES; otherwise adjacent_network/"
                        "remote_auth). Use PCI/PAN/PII flags to set asset "
                        "sensitivity = critical.\n\n")

    notes_block = ""
    if ev["s1_notes"]:
        notes_block = f"\nMAPPER OBSERVATIONS (s1 free-form):\n{ev['s1_notes']}\n"

    return f"""TARGET: {repo_name}  ({repo_root})
PRIMARY LANGUAGE: {ev['primary_language'] or 'unknown'}
FILES IN AST FRONTIER: {ev['file_count']} (from {ev['original_file_count']} total in-scope files)

{cmdb_block}LANGUAGE BREAKDOWN:
{lang_block}

COMPONENTS (top-level directories):
{comp_block}

MODULES (s1-mapped — treat as asset candidates):
{mod_block}

ENTRY POINTS (s1-mapped — these ARE the trust boundaries; STRIDE hint per kind):
{ep_block}

AST FUNCTION SITES (method-level anchors chosen from entry-point/sink/callgraph frontier):
{site_block}

AST CALL EDGES (bounded frontier, one edge per line):
{edge_block}

REPRESENTATIVE CONFIGURATION (one per component, post-dedup — reveals data
stores, message buses, key/secret managers, TLS posture, external endpoints):
{cfg_block}

API CONTRACT ARTEFACTS (OpenAPI/Swagger/Protobuf/GraphQL/WSDL/META-INF — the
explicit external interface):
{api_block}
{notes_block}
DOCUMENTATION:
{docs_block}

BUILD / DEPENDENCY MANIFESTS:
{manifest_block}

KNOWN PRIOR CVEs (use as evidence; raises likelihood):
{cve_block}

DESIGN CONTROLS (lower likelihood where they apply):
{ctl_block}
{baseline_block}
Produce the threat model JSON now. Anchor each trust_boundary.entry_point to
one of the ENTRY POINTS above where possible; use the STRIDE hint to seed
threats per boundary."""


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run(repo_root: str, repo_name: str, cfg,
        known_cves: list[CVE], controls: list[Control],
        ctx: ContextPackage | None = None,
        app_profile: AppProfile | None = None) -> ThreatModel:
    s2 = getattr(cfg, "step2", None)
    tracker = getattr(cfg, "_scan_progress", None)
    log.info("s2/threatmodel: starting threat modeling for %s", repo_name)
    if ctx is not None:
        print(
            "  [s2] ctx: "
            f"type={type(ctx).__module__}.{type(ctx).__name__}, "
            f"has_ast_context_view={hasattr(ctx, 'ast_context_view')}, "
            f"all_files={len(getattr(ctx, 'all_files', []) or [])}",
            file=sys.stderr,
        )
        log.debug("s2/threatmodel: context has_ast_view=%s files=%d",
                  hasattr(ctx, 'ast_context_view'), len(getattr(ctx, 'all_files', []) or []))
    ev = _gather_evidence(repo_root, cfg, ctx)
    if tracker is not None:
        tracker.stage_note(
            "s2",
            (f"evidence files={ev['file_count']} modules={len(ev['modules'])} "
             f"eps={len(ev['entry_points'])} api={len(ev['api_artefacts'])}"),
        )
    print(f"  [s2] evidence: {ev['file_count']} files, "
          f"{len(ev['modules'])} modules, {len(ev['entry_points'])} entry points, "
          f"{len(ev['config_reps'])} config reps, "
          f"{len(ev['api_artefacts'])} api artefacts, "
          f"{len(ev['docs'])} docs, {len(ev['manifests'])} manifests",
          file=sys.stderr)
    print(f"  [s2] frontier: {ev['file_count']} / {ev['original_file_count']} files "
          f"(AST-focused evidence view)", file=sys.stderr)

    baseline_mode = getattr(s2, "baseline", "auto")
    kinds, baseline = _baseline_block(ev, ctx, baseline_mode)
    print(f"  [s2] baseline={baseline_mode} repo_kind={sorted(kinds) or '-'}",
          file=sys.stderr)

    user = _build_user_prompt(repo_root, repo_name, ev, known_cves, controls,
                              app_profile=app_profile,
                              baseline_block=baseline)
    if tracker is not None:
        tracker.stage_note("s2", "threat-model LLM request started")

    raw = prompt(
        user,
        model=cfg.models.threatmodel,
        system_prompt=SYSTEM,
        max_tokens=getattr(s2, "max_tokens", 16000),
        tag="s2 threatmodel",
    )
    if tracker is not None:
        tracker.stage_note("s2", "threat-model LLM response received")

    data = extract_json(raw)
    tm = ThreatModel.model_validate(data)

    max_threats = getattr(s2, "max_threats", 20)
    if len(tm.threats) > max_threats:
        tm = tm.model_copy(update={"threats": tm.threats[:max_threats]})

    print(f"  [s2] done: {len(tm.assets)} assets, "
          f"{len(tm.trust_boundaries)} trust boundaries, "
          f"{len(tm.threats)} threats", file=sys.stderr)
    log.info("s2/threatmodel: threat model complete - assets=%d boundaries=%d threats=%d",
             len(tm.assets), len(tm.trust_boundaries), len(tm.threats))
    return tm
