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

"""LLM-backed source/sink spec derivation for callgraph mode.

This module converts tree-sitter-observed call fingerprints into MatchSpec
records so s0 can run without sources/sinks YAML files when
`step0.callgraph_detection: llm` is selected.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from typing import Any

from vvaharness.backends.llm import prompt as llm_prompt
from vvaharness.pipeline.stages.callgraph_engine._rules import MatchSpec
from vvaharness.pipeline.stages.callgraph_engine._scan import FileIndex
from vvaharness.rules.families import (
    OWASP_2025_BY_SEMANTIC as _FAMILIES_OWASP,
    norm_cwe as _families_norm_cwe,
)
from vvaharness.util.json_extract import extract_json

_SYSTEM = (
    "You classify API call fingerprints for taint seeding. "
    "Return JSON only with key 'results': a list of objects with fields "
    "id, role, confidence, cwe, kind. "
    "role must be one of source, sink, none. "
    "confidence must be a number between 0 and 1. "
    "cwe should be like CWE-89. "
    "kind for source should be one of network, ipc, file, cli, "
    "deserialization, other. "
    "kind for sink can be a short snake_case label."
)

_SOURCE_METHOD_HINTS = {
    "get", "args", "query", "param", "params", "form", "json",
    "body", "headers", "header", "cookies", "cookie", "input",
    "read", "recv", "receive", "next", "fetch",
}
_SOURCE_MODULE_HINTS = {
    "flask", "fastapi", "django", "starlette", "aiohttp", "request",
    "requests", "sys", "os",
}

_SINK_METHOD_HINTS = {
    "execute", "executemany", "raw", "query", "run", "system",
    "popen", "spawn", "exec", "eval", "loads", "load",
    "deserialize", "unmarshal", "parse", "render", "template",
    "write", "send", "post", "put",
}
_SINK_MODULE_HINTS = {
    "os", "subprocess", "sqlite3", "psycopg2", "pymysql", "mysql",
    "sqlalchemy", "pickle", "yaml", "jinja2", "mako", "shlex",
}

_OWASP_2025_BY_SEMANTIC: dict[str, tuple[str, ...]] = _FAMILIES_OWASP


@dataclass
class _Candidate:
    cid: str
    language: str
    module: str
    method: str
    count: int
    sample_file: str
    sample_line: int
    sample_snippet: str


def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _cfg_get(obj: Any, name: str, default: Any) -> Any:
    try:
        return getattr(obj, name)
    except AttributeError:
        return default


def _norm_cwe(raw: Any, role: str) -> str:
    # Normalize via the shared canonical form so e.g. ``CWE-0089`` and
    # ``CWE-89`` resolve identically and agree with build_kb's normalized
    # corpus.
    norm = _families_norm_cwe(raw)
    if norm:
        return norm
    return "CWE-20" if role == "source" else "CWE-78"


def _semantic_family(kind: str, cwe: str) -> str:
    """Map a source/sink kind + CWE to the semantic family used downstream."""
    k = (kind or "").lower().strip()
    c = (cwe or "").upper()
    if "79" in c or k in {"xss", "template"}:
        return "html-response"
    if "78" in c or k in {"cmd", "dyn-eval"}:
        return "command-exec"
    if "89" in c or "90" in c or k == "sql":
        return "sql-exec"
    if "918" in c or k == "ssrf":
        return "url-fetch"
    if "22" in c or k == "path":
        return "file-io"
    if "502" in c or k == "deserialize":
        return "deserialization"
    if k in {"credentials", "secret"}:
        return "credentials"
    return k or "other"


def _owasp_labels(family: str) -> frozenset[str]:
    return frozenset(_OWASP_2025_BY_SEMANTIC.get(family, ("A03:2025-Injection",)))


def _collect_candidates(file_indices: list[FileIndex], active_langs: set[str],
                        max_candidates: int) -> list[_Candidate]:
    by_sig: dict[tuple[str, str, str], _Candidate] = {}
    for idx in file_indices:
        for oc in idx.observed_calls:
            if oc.language not in active_langs:
                continue
            module = ""
            if oc.resolved_receiver:
                module = oc.resolved_receiver.split(".")[0]
            elif oc.receiver:
                module = oc.receiver.split(".")[0]
            module = module.strip()
            method = (oc.method or "").strip()
            if not module or not method:
                continue
            sig = (oc.language, module, method)
            cur = by_sig.get(sig)
            if cur is None:
                by_sig[sig] = _Candidate(
                    cid=f"c{len(by_sig) + 1}",
                    language=oc.language,
                    module=module,
                    method=method,
                    count=1,
                    sample_file=oc.file,
                    sample_line=oc.line,
                    sample_snippet=oc.snippet,
                )
            else:
                cur.count += 1
    ordered = sorted(by_sig.values(),
                     key=lambda c: (-c.count, c.language, c.module, c.method))
    return ordered[:max_candidates]


def _build_prompt_batch(batch: list[_Candidate]) -> str:
    payload = [
        {
            "id": c.cid,
            "language": c.language,
            "module": c.module,
            "method": c.method,
            "count": c.count,
            "sample": f"{c.sample_file}:{c.sample_line}: {c.sample_snippet}",
        }
        for c in batch
    ]
    instr = {
        "task": "Classify each API as source, sink, or none for taint seeding.",
        "constraints": [
            "Use only provided IDs.",
            "Prefer role=none when uncertain.",
            "Confidence must be numeric in [0,1].",
        ],
        "output_schema": {
            "results": [
                {
                    "id": "c1",
                    "role": "source|sink|none",
                    "confidence": 0.0,
                    "cwe": "CWE-20",
                    "kind": "network|ipc|file|cli|deserialization|other|<sink_kind>",
                }
            ]
        },
        "calls": payload,
    }
    return json.dumps(instr, ensure_ascii=True, indent=2)


def _parse_results(raw: str) -> list[dict[str, Any]]:
    obj = extract_json(raw)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        rows = obj.get("results")
        if isinstance(rows, list):
            return [x for x in rows if isinstance(x, dict)]
    return []


def _tok(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _heuristic_source_kind(c: _Candidate) -> tuple[bool, str, str]:
    mt = _tok(c.method)
    md = _tok(c.module)
    sn = (c.sample_snippet or "").lower()
    if (mt in _SOURCE_METHOD_HINTS and
            (md in _SOURCE_MODULE_HINTS
             or "request" in sn
             or "header" in sn
             or "cookie" in sn)):
        return True, "network", "CWE-20"
    if mt in {"getenv", "environ"} or "os.environ" in sn:
        return True, "file", "CWE-73"
    if mt in {"argv", "next", "readline"} and ("sys" in md or "stdin" in sn):
        return True, "cli", "CWE-20"
    return False, "", ""


def _heuristic_sink_kind(c: _Candidate) -> tuple[bool, str, str]:
    mt = _tok(c.method)
    md = _tok(c.module)
    sn = (c.sample_snippet or "").lower()
    if mt in {"system", "popen", "spawn", "exec", "eval"} or md in {"os", "subprocess"}:
        return True, "command_injection", "CWE-78"
    if mt in {"execute", "executemany", "raw", "query"}:
        return True, "sql_injection", "CWE-89"
    if mt in {"loads", "load", "deserialize", "unmarshal"} or md in {"pickle", "yaml"}:
        return True, "unsafe_deserialization", "CWE-502"
    if mt in _SINK_METHOD_HINTS and (md in _SINK_MODULE_HINTS or "sql" in sn):
        return True, "unsafe", "CWE-20"
    return False, "", ""


def _append_spec(role: str, cand: _Candidate, kind: str, cwe: str,
                 source_specs: list[MatchSpec], sink_specs: list[MatchSpec],
                 rule_cwe: dict[str, list[str]],
                 seen_sig: set[tuple[str, str, str, str]],
                 suffix: str = "") -> None:
    sig = (role, cand.language, cand.module, cand.method)
    if sig in seen_sig:
        return
    seen_sig.add(sig)
    rule_id = f"llm-{role}:{cand.language}:{cand.module}.{cand.method}{suffix}"
    family = _semantic_family(kind, cwe)
    spec = MatchSpec(
        rule_id=rule_id,
        role=role,
        origin="llm",
        cwe=cwe,
        kind=kind,
        languages=frozenset({cand.language}),
        semantic_family=family,
        owasp_top10_2025=_owasp_labels(family),
        module_attr_module=cand.module,
        module_attr_names=frozenset({cand.method}),
    )
    rule_cwe[rule_id] = [cwe]
    if role == "source":
        source_specs.append(spec)
    else:
        sink_specs.append(spec)


def _seed_seen_sig(source_specs: list[MatchSpec],
                   sink_specs: list[MatchSpec]) -> set[tuple[str, str, str, str]]:
    seen: set[tuple[str, str, str, str]] = set()
    for role, specs in (("source", source_specs), ("sink", sink_specs)):
        for s in specs:
            if not s.has_module_attr():
                continue
            for m in s.module_attr_names:
                seen.add((role, next(iter(s.languages), ""),
                          s.module_attr_module, m))
    return seen


def supplement_with_heuristics(
    file_indices: list[FileIndex],
    active_langs: list[str],
    source_specs: list[MatchSpec],
    sink_specs: list[MatchSpec],
    rule_cwe: dict[str, list[str]],
    min_extra_sources: int = 1,
    min_extra_sinks: int = 0,
    max_extra_specs: int = 10,
) -> tuple[list[MatchSpec], list[MatchSpec], dict[str, list[str]]]:
    """Augment existing specs with deterministic tree-sitter heuristics."""
    if max_extra_specs <= 0:
        return source_specs, sink_specs, rule_cwe

    candidates = _collect_candidates(file_indices, set(active_langs), 400)
    if not candidates:
        return source_specs, sink_specs, rule_cwe

    seen_sig = _seed_seen_sig(source_specs, sink_specs)
    add_src = max(0, int(min_extra_sources))
    add_snk = max(0, int(min_extra_sinks))
    added = 0

    if add_src:
        for cand in candidates:
            ok, kind, cwe = _heuristic_source_kind(cand)
            if not ok:
                continue
            before = len(source_specs)
            _append_spec(
                "source", cand, kind, cwe,
                source_specs, sink_specs, rule_cwe, seen_sig,
                suffix=":h",
            )
            if len(source_specs) > before:
                add_src -= 1
                added += 1
            if add_src <= 0 or added >= max_extra_specs:
                break

    if add_snk and added < max_extra_specs:
        for cand in candidates:
            ok, kind, cwe = _heuristic_sink_kind(cand)
            if not ok:
                continue
            before = len(sink_specs)
            _append_spec(
                "sink", cand, kind, cwe,
                source_specs, sink_specs, rule_cwe, seen_sig,
                suffix=":h",
            )
            if len(sink_specs) > before:
                add_snk -= 1
                added += 1
            if add_snk <= 0 or added >= max_extra_specs:
                break

    return source_specs, sink_specs, rule_cwe


def detect_specs(file_indices: list[FileIndex], active_langs: list[str], cfg
                 ) -> tuple[list[MatchSpec], list[MatchSpec], dict[str, list[str]]]:
    """Infer source/sink MatchSpecs from observed call fingerprints via LLM."""
    step0 = _cfg_get(cfg, "step0", None)
    cg = _cfg_get(step0, "callgraph", None)
    llm_cfg = _cfg_get(cg, "llm", None)

    max_candidates = int(_cfg_get(llm_cfg, "max_candidates", 400) or 400)
    max_batch_candidates = int(_cfg_get(llm_cfg, "max_batch_candidates", 150) or 150)
    min_source_conf = float(_cfg_get(llm_cfg, "min_source_confidence", 0.75) or 0.75)
    min_sink_conf = float(_cfg_get(llm_cfg, "min_sink_confidence", 0.75) or 0.75)
    max_tokens = int(_cfg_get(llm_cfg, "max_tokens", 16000) or 16000)
    failure_mode = str(_cfg_get(llm_cfg, "failure_mode", "empty") or "empty").lower()
    heuristic_enabled = bool(_cfg_get(llm_cfg, "heuristic_supplement", True))
    min_sources = int(_cfg_get(llm_cfg, "min_sources", 1) or 1)
    min_sinks = int(_cfg_get(llm_cfg, "min_sinks", 1) or 1)
    max_heuristic_specs = int(_cfg_get(llm_cfg, "max_heuristic_specs", 10) or 10)

    models = _cfg_get(cfg, "models", None)
    model = _cfg_get(models, "graph_annotate", None)
    if model is None:
        model = _cfg_get(models, "preprocess", None)
    if model is None:
        model = _cfg_get(models, "callgraph_creation", None)
    if model is None:
        model = _cfg_get(models, "deepdive", None)

    if model is None:
        if failure_mode == "fail":
            raise ValueError("step0.callgraph.llm mode requires a configured model")
        print("  [s0/callgraph] llm detection has no model configured; returning empty specs",
              file=sys.stderr)
        return [], [], {}

    candidates = _collect_candidates(file_indices, set(active_langs), max_candidates)
    if not candidates:
        return [], [], {}

    by_id = {c.cid: c for c in candidates}
    source_specs: list[MatchSpec] = []
    sink_specs: list[MatchSpec] = []
    rule_cwe: dict[str, list[str]] = {}
    seen_sig: set[tuple[str, str, str, str]] = set()

    try:
        for i in range(0, len(candidates), max_batch_candidates):
            batch = candidates[i:i + max_batch_candidates]
            user = _build_prompt_batch(batch)
            raw = llm_prompt(
                user,
                model=model,
                system_prompt=_SYSTEM,
                max_tokens=max_tokens,
                tag="s0 callgraph-annotate",
            )
            for row in _parse_results(raw):
                cid = str(row.get("id") or "").strip()
                cand = by_id.get(cid)
                if cand is None:
                    continue
                role = str(row.get("role") or "none").strip().lower()
                conf = _as_float(row.get("confidence"), 0.0)
                if role == "source" and conf < min_source_conf:
                    continue
                if role == "sink" and conf < min_sink_conf:
                    continue
                if role not in ("source", "sink"):
                    continue
                cwe = _norm_cwe(row.get("cwe"), role)
                kind = str(row.get("kind") or ("other" if role == "source" else "unsafe")).strip() or "other"
                _append_spec(
                    role, cand, kind, cwe,
                    source_specs, sink_specs, rule_cwe, seen_sig,
                )
    except Exception as e:  # noqa: BLE001
        if failure_mode == "fail":
            raise
        print(f"  [s0/callgraph] llm detection failed: {e}", file=sys.stderr)
        return [], [], {}

    if heuristic_enabled:
        need_src = max(0, min_sources - len(source_specs))
        need_snk = max(0, min_sinks - len(sink_specs))
        if need_src or need_snk:
            source_specs, sink_specs, rule_cwe = supplement_with_heuristics(
                file_indices,
                active_langs,
                source_specs,
                sink_specs,
                rule_cwe,
                min_extra_sources=need_src,
                min_extra_sinks=need_snk,
                max_extra_specs=max_heuristic_specs,
            )

    return source_specs, sink_specs, rule_cwe
