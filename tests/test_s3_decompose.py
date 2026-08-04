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

"""Behavioral tests for the taint threat-tag matching helper in s3_decompose.

The helper under test is the ``_threat_for(ep)`` closure inside
``_add_taint_chunks``. It associates a taint chunk with a threat by matching
the threat's ``surface`` against the entry function name on a whole-token /
exact basis. The security-relevant behavior:

  * exact (case-insensitive) name match wins outright;
  * otherwise the FIRST threat sharing a whole alphanumeric TOKEN with the
    function name is chosen;
  * it must NOT match a substring buried inside another token, and it must
    NOT match against the file PATH (over-tagging the coverage metric).

``_threat_for`` is a nested closure and cannot be imported, so we drive it
through the public ``_add_taint_chunks`` entry point and read the resulting
chunk's ``threat_id``.
"""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from vvaharness.models import (
    Chunk,
    ContextPackage,
    EntryPoint,
    Sink,
    TaskManifest,
    Threat,
    ThreatModel,
)
from vvaharness.pipeline.stages import s3_decompose


# ─────────────────────────────────────────────────────────────────────────────
# Global-state isolation: _count_loc / _count_chars consult a module-level
# byte cache (_CHARS_CACHE). Reset it so test order never matters.
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _reset_module_state(monkeypatch):
    monkeypatch.setattr(s3_decompose, "_CHARS_CACHE", {}, raising=True)
    yield


def _make_cfg():
    """Minimal cfg with the step3 knobs _add_taint_chunks reads."""
    step3 = SimpleNamespace(
        taint_chunks=True,
        taint_max_hops=8,
        taint_max_chunks=40,
        taint_files_per_hop=5,
        pack_by="loc",
        threat_surface_fallbacks=True,
        threat_fallback_max_files=12,
    )
    return SimpleNamespace(step3=step3)


def _threat(tid: str, surface: str) -> Threat:
    return Threat(
        id=tid,
        threat=f"threat {tid}",
        actor="remote_unauth",
        surface=surface,
        asset="user-data",
        impact="high",
        likelihood="likely",
    )


def _ctx_with(threats, *, fn="handle_login", ep_file="app/login.py",
              sink_fn="run_query", repo_root="/nonexistent-repo") -> ContextPackage:
    """ContextPackage with exactly one entry→sink taint path so that
    _add_taint_chunks emits exactly one taint chunk whose threat_id is the
    output of _threat_for(ep)."""
    ep_node = f"{ep_file}::{fn}"
    sink_node = f"{ep_file}::{sink_fn}"
    return ContextPackage(
        repo_root=repo_root,
        language="python",
        call_graph={ep_node: [sink_node]},
        entry_points=[EntryPoint(file=ep_file, function=fn, kind="network",
                                 reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file=ep_file, line=42, function=sink_fn)],
        all_files=[ep_file],
        threat_model=ThreatModel(threats=threats),
    )


def _run(ctx) -> TaskManifest:
    manifest = TaskManifest(chunks=[], rationale="test")
    n = s3_decompose._add_taint_chunks(manifest, ctx, _make_cfg())
    assert n == 1, f"expected exactly one taint chunk, got {n}"
    return manifest


def _taint_chunk(manifest: TaskManifest) -> Chunk:
    taints = [c for c in manifest.chunks if c.id.startswith("taint-")]
    assert len(taints) == 1
    return taints[0]


# ─────────────────────────────────────────────────────────────────────────────
# Sanity: the harness actually produces a taint chunk we can inspect.
# ─────────────────────────────────────────────────────────────────────────────
def test_taint_chunk_is_emitted_and_anchors_entry_function():
    manifest = _run(_ctx_with([_threat("T1", "handle_login")]))
    chunk = _taint_chunk(manifest)
    assert chunk.focus_entry_points == ["handle_login"]
    assert "app/login.py" in chunk.files


# ─────────────────────────────────────────────────────────────────────────────
# Exact (case-insensitive) match wins.
# ─────────────────────────────────────────────────────────────────────────────
def test_exact_match_assigns_threat_id():
    manifest = _run(_ctx_with([_threat("T1", "handle_login")]))
    assert _taint_chunk(manifest).threat_id == "T1"


def test_exact_match_is_case_insensitive():
    manifest = _run(_ctx_with([_threat("T7", "Handle_Login")],
                              fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T7"


def test_exact_match_beats_an_earlier_token_match():
    # T1 shares the "login" token (token match), but T2 is an exact match.
    # Exact must win even though it appears later in the list.
    threats = [_threat("T1", "login"), _threat("T2", "handle_login")]
    manifest = _run(_ctx_with(threats, fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T2"


# ─────────────────────────────────────────────────────────────────────────────
# Whole-token match (no exact match available).
# ─────────────────────────────────────────────────────────────────────────────
def test_shared_token_match_when_no_exact():
    # function "handle_login" shares token "login" with surface "login_v2".
    manifest = _run(_ctx_with([_threat("T9", "login_v2")], fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T9"


def test_first_token_sharing_threat_wins():
    # Both T1 and T2 share a token with handle_login; the FIRST in list wins.
    threats = [_threat("T1", "do_login"), _threat("T2", "handle_request")]
    manifest = _run(_ctx_with(threats, fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T1"


def test_token_match_is_case_insensitive():
    manifest = _run(_ctx_with([_threat("T3", "USER_LOGIN")], fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T3"


# ─────────────────────────────────────────────────────────────────────────────
# Security-relevant negatives: no substring-in-token, no path matching.
# ─────────────────────────────────────────────────────────────────────────────
def test_substring_inside_a_token_does_not_match():
    # surface "log" is a substring of the token "login" but is NOT a whole
    # token of "handle_login" → must NOT match.
    manifest = _run(_ctx_with([_threat("T5", "log")], fn="handle_login"))
    assert _taint_chunk(manifest).threat_id is None


def test_reverse_substring_does_not_match():
    # function token "auth" is a substring of surface token "authenticate";
    # token equality fails both directions → no match.
    manifest = _run(_ctx_with([_threat("T6", "authenticate")], fn="auth"))
    assert _taint_chunk(manifest).threat_id is None


def test_surface_matching_the_file_path_does_not_match():
    # The entry FILE path contains "login" (app/login.py) but the function is
    # "process". A surface equal to a path component must NOT tag the chunk —
    # matching is against the function NAME only, never the path.
    ctx = _ctx_with([_threat("T8", "login")], fn="process",
                    ep_file="app/login.py", sink_fn="run_query")
    manifest = _run(ctx)
    assert _taint_chunk(manifest).threat_id is None


def test_surface_matching_path_directory_does_not_match():
    ctx = _ctx_with([_threat("T8", "app")], fn="process",
                    ep_file="app/login.py", sink_fn="run_query")
    manifest = _run(ctx)
    assert _taint_chunk(manifest).threat_id is None


# ─────────────────────────────────────────────────────────────────────────────
# Edge cases.
# ─────────────────────────────────────────────────────────────────────────────
def test_empty_surface_is_skipped():
    # An empty-surface threat is ignored; the real token match still wins.
    threats = [_threat("T1", ""), _threat("T2", "login")]
    manifest = _run(_ctx_with(threats, fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T2"


def test_no_threats_yields_none():
    manifest = _run(_ctx_with([]))
    assert _taint_chunk(manifest).threat_id is None


def test_no_matching_threat_yields_none():
    manifest = _run(_ctx_with([_threat("T1", "totally_unrelated")],
                              fn="handle_login"))
    assert _taint_chunk(manifest).threat_id is None


def test_seed_taint_paths_are_promoted_into_taint_chunks():
    ctx = ContextPackage(
        repo_root="/nonexistent-repo",
        language="python",
        call_graph={},
        def_spans={
            "app/api.py::entry": [10, 30],
            "app/db.py::run_query": [40, 70],
        },
        entry_points=[EntryPoint(file="app/api.py", function="entry", kind="network",
                                 reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file="app/db.py", line=55, function="run_query",
                           cwe=["CWE-89"])],
        all_files=["app/api.py", "app/db.py"],
        seed_taint_paths=[["app/api.py:12", "app/db.py:55"]],
        threat_model=ThreatModel(threats=[_threat("T1", "entry")]),
    )
    manifest = TaskManifest(chunks=[], rationale="test")

    n = s3_decompose._add_taint_chunks(manifest, ctx, _make_cfg())

    assert n == 1
    chunk = _taint_chunk(manifest)
    assert chunk.source_ref == "app/api.py:12"
    assert chunk.sink_ref == "app/db.py:55"
    assert "CWE-89" in chunk.sink_cwe


def test_digit_tokens_participate_in_matching():
    # tokens are [a-z0-9]+, so a shared numeric token counts.
    manifest = _run(_ctx_with([_threat("T4", "endpoint_v2")], fn="parse_v2"))
    assert _taint_chunk(manifest).threat_id == "T4"


# ─────────────────────────────────────────────────────────────────────────────
# Cross-check the documented tokenization regex directly so the behavioral
# expectations above are anchored to the same rule the source uses.
# ─────────────────────────────────────────────────────────────────────────────
def test_tokenization_rule_matches_source_intent():
    tok = lambda s: set(re.findall(r"[a-z0-9]+", s.lower()))
    # whole-token overlap exists
    assert tok("handle_login") & tok("login_v2")
    # substring-only does NOT create token overlap
    assert not (tok("handle_login") & tok("log"))
    assert not (tok("auth") & tok("authenticate"))


def test_threat_surface_fallback_adds_supply_chain_probe_chunk(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    app = tmp_path / "src"
    app.mkdir(parents=True)
    (app / "main.py").write_text("print('ok')\n", encoding="utf-8")

    ctx = ContextPackage(
        repo_root=str(tmp_path),
        language="python",
        all_files=[".github/workflows/ci.yml", "src/main.py"],
        threat_model=ThreatModel(threats=[
            Threat(
                id="T10",
                threat="CI/CD workflow tampering in build pipeline",
                actor="supply_chain",
                surface="github_actions",
                asset="release artifact",
                impact="high",
                likelihood="possible",
            )
        ]),
    )
    manifest = TaskManifest(
        chunks=[Chunk(id="spec-iac-01", files=[".github/workflows/ci.yml"], specialist="iac")],
        rationale="test",
    )

    n = s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, _make_cfg())

    assert n == 1
    fallback = next(c for c in manifest.chunks if c.id.startswith("threat-t10-fallback"))
    assert fallback.threat_id == "T10"
    assert ".github/workflows/ci.yml" in fallback.files


def test_threat_surface_fallback_adds_access_control_probe_chunk(tmp_path):
    svc = tmp_path / "src"
    svc.mkdir(parents=True)
    (svc / "authz.py").write_text("def allow(user):\n    return True\n", encoding="utf-8")
    (svc / "main.py").write_text("def run():\n    return 0\n", encoding="utf-8")

    ctx = ContextPackage(
        repo_root=str(tmp_path),
        language="python",
        all_files=["src/authz.py", "src/main.py"],
        threat_model=ThreatModel(threats=[
            Threat(
                id="T7",
                threat="Authorization policy bypass on tenant boundary",
                actor="remote_auth",
                surface="rbac policy",
                asset="tenant data",
                impact="high",
                likelihood="possible",
            )
        ]),
    )
    manifest = TaskManifest(chunks=[], rationale="test")

    n = s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, _make_cfg())

    assert n == 1
    fallback = next(c for c in manifest.chunks if c.id.startswith("threat-t7-fallback"))
    assert fallback.threat_id == "T7"
    assert "src/authz.py" in fallback.files


def test_threat_surface_fallback_skips_when_no_surface_candidates(tmp_path):
    p = tmp_path / "src"
    p.mkdir(parents=True)
    (p / "core.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    ctx = ContextPackage(
        repo_root=str(tmp_path),
        language="python",
        all_files=["src/core.py"],
        threat_model=ThreatModel(threats=[
            Threat(
                id="T99",
                threat="Air-gap side-channel in custom FPGA transport",
                actor="local_user",
                surface="fpga_dma",
                asset="compute node",
                impact="medium",
                likelihood="very_rare",
            )
        ]),
    )
    manifest = TaskManifest(chunks=[], rationale="test")

    n = s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, _make_cfg())

    assert n == 0
    assert all(c.threat_id != "T99" for c in manifest.chunks)
