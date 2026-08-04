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

"""Unit tests for vvaharness.orchestrator.checkpoints — SQLite-backed
checkpoint I/O. Every legitimate per-step payload must round-trip (no
--resume regression), and a hostile or malformed payload must degrade to
"re-run the step" rather than crash or be trusted.
"""
from __future__ import annotations
import json
from pathlib import Path

import pytest

from vvaharness.orchestrator import checkpoints as ck
from vvaharness.orchestrator import store
from vvaharness.pipeline.stages.s0_seed import SeedPackage
from vvaharness.models import (ContextPackage, ThreatModel, TaskManifest,
                                EntryPoint, Sink,
                                Finding, DroppedFinding, FinalReport,
                                RankedFinding, Severity)

RID = "testrun"


@pytest.fixture(autouse=True)
def _state_dir(tmp_path, monkeypatch):
    """Every test gets a fresh, isolated state DB under tmp_path."""
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path))
    yield tmp_path


def _raw_insert(run_id: str, step: str, payload: bytes) -> None:
    """Bypass save_ckpt's serialisation to plant arbitrary bytes — used by
    the malformed/tampered tests."""
    con = store.connect()
    with con:
        con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) "
                    "VALUES (?, '')", (run_id,))
        con.execute("INSERT OR REPLACE INTO checkpoints"
                    "(run_id, step, payload, size) VALUES (?, ?, ?, ?)",
                    (run_id, step, payload, len(payload)))
    con.close()


def _finding() -> Finding:
    return Finding(chunk_id="c1", file="a.py", line_start=1, line_end=2,
                   vuln_class="other", title="t", description="d",
                   code_snippet="x=1", confidence=0.5)


def _dropped() -> DroppedFinding:
    return DroppedFinding(file="a.py", line=1, vuln_class="other",
                           title="t", chunk_id="c1", reason="DUPLICATE")


@pytest.mark.parametrize("step,obj", [
    ("s1", ContextPackage(repo_root="/r", language="python",
                          all_files=["a.py"], notes="n")),
    ("s2", ThreatModel(system_context="sc", open_questions=["q"])),
    ("s3", TaskManifest(chunks=[], rationale="why")),
    ("s4", {"findings": [_finding()], "outcomes": {"c1": "ok"}}),
    ("s7", ([_dropped()], [_finding()], [_dropped()], [_finding()],
            [_dropped()])),
    ("s8", FinalReport(repo_root="/r", summary="s", raw_findings_count=1,
                       chains=[],
                       findings=[RankedFinding(finding=_finding(),
                                               severity=Severity.LOW,
                                               exploitability_notes="e")])),
    ("s9", "/out/report.sarif"),
])
def test_checkpoint_roundtrips_legit_payloads(tmp_path, step, obj):
    ck.save_ckpt(tmp_path, RID, step, obj)
    # Stored payload is JSON.
    con = store.connect()
    raw = con.execute("SELECT payload FROM checkpoints WHERE run_id=? "
                      "AND step=?", (RID, step)).fetchone()[0]
    con.close()
    json.loads(raw)
    got = ck.load_ckpt(tmp_path, RID, step)
    assert got is not None and type(got) is type(obj)
    assert got == obj


def _populated_seed() -> SeedPackage:
    """A SeedPackage with the call-graph / def-span maps filled and a Path
    ``sarif_path`` — the structures that carry the s0 checkpoint's real
    payload."""
    return SeedPackage(
        entry_points=[EntryPoint(file="ctrl.py", function="handle",
                                 kind="network", reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file="dao.py", line=40, function="raw_query")],
        taint_paths=[["ctrl.py:10", "dao.py:40"]],
        rule_cwe={"py.sqli": ["CWE-89"]},
        call_graph={"ctrl.py::handle": ["dao.py::raw_query"]},
        call_graph_files={"handle": ["ctrl.py:10"],
                          "raw_query": ["dao.py:40"]},
        def_spans={"ctrl.py::handle": [10, 20],
                   "dao.py::raw_query": [40, 45]},
        sarif_path=Path("/out/seed.sarif"),
        languages=["python"],
        all_files=["ctrl.py", "dao.py"],
    )


def test_s0_seedpackage_roundtrips_populated(tmp_path):
    """A *populated* SeedPackage must survive the s0 checkpoint round-trip so
    ``--resume`` can skip Step 0. Every persisted map is keyed by a JSON
    object key (a string); a non-JSON-native key (e.g. a ``dict`` keyed by a
    tuple) would ``dump_json`` to a comma-joined string that ``validate_json``
    cannot rebuild, so ``load_ckpt`` would return ``None`` and this test would
    fail on the ``got is not None`` / ``got == seed`` assertions."""
    seed = _populated_seed()
    ck.save_ckpt(tmp_path, RID, "s0", seed)
    # Stored payload is JSON, and every checkpointed dict uses string keys.
    con = store.connect()
    raw = con.execute("SELECT payload FROM checkpoints WHERE run_id=? "
                      "AND step=?", (RID, "s0")).fetchone()[0]
    con.close()
    doc = json.loads(raw)
    for field_name in ("call_graph", "call_graph_files", "def_spans",
                       "rule_cwe"):
        assert all(isinstance(k, str) for k in doc[field_name])
    got = ck.load_ckpt(tmp_path, RID, "s0")
    assert got is not None and type(got) is SeedPackage
    assert got == seed


def test_checkpoint_refuses_malformed_payload(capsys):
    """Non-JSON / corrupt bytes degrade to "re-run", never crash."""
    _raw_insert(RID, "s7", b"\x00not-json\xff")
    assert ck.load_ckpt(None, RID, "s7") is None
    assert "untrusted" in capsys.readouterr().err


def test_tampered_field_fails_validation():
    """Well-formed JSON whose value violates a field validator (list[str]
    field set to a scalar) must be rejected by validate_json — the stage
    re-runs rather than receiving a poisoned object."""
    ctx = ContextPackage(repo_root="/r", language="python",
                         all_files=["a.py"], notes="n")
    doc = json.loads(ctx.model_dump_json())
    doc["all_files"] = "$(touch /tmp/pwned)"
    _raw_insert(RID, "s1", json.dumps(doc).encode())
    assert ck.load_ckpt(None, RID, "s1") is None


def test_oversized_checkpoint_is_refused(monkeypatch, capsys):
    """A payload larger than _CKPT_MAX_BYTES is refused at save time —
    guards against multi-GB resource-exhaustion blobs. Verified by
    shrinking the cap and saving a long-but-valid s9 string."""
    monkeypatch.setattr(ck, "_CKPT_MAX_BYTES", 32)
    ck.save_ckpt(None, RID, "s9", "x" * 2048)
    assert "not persisted" in capsys.readouterr().err
    assert ck.load_ckpt(None, RID, "s9") is None


def test_oversized_row_rejected_by_check_constraint():
    """Defence-in-depth: a direct INSERT that bypasses save_ckpt and lies
    about size still cannot exceed the schema CHECK."""
    import sqlite3
    con = store.connect()
    with pytest.raises(sqlite3.IntegrityError):
        with con:
            con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) "
                        "VALUES (?, '')", (RID,))
            con.execute("INSERT INTO checkpoints(run_id, step, payload, size)"
                        " VALUES (?, 's9', ?, ?)",
                        (RID, b"x", 120 * 1024 * 1024))
    con.close()


def test_no_pickle_import():
    """CWE-502 regression guard: the checkpoints module must never reach
    ``import pickle`` again — JSON is the only payload format. Checked via
    AST so the docstring's prose mention doesn't false-positive."""
    import ast
    import vvaharness.orchestrator.checkpoints as m
    tree = ast.parse(open(m.__file__, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(a.name != "pickle" for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "pickle"


def test_store_bootstrap_idempotent(tmp_path, monkeypatch):
    """connect() creates the DB on first call and skips DDL thereafter —
    no "is this the first time?" branch needed at any call site, and the
    hot path never touches executescript()."""
    p = store.db_path()
    assert p.parent == tmp_path
    assert not p.exists()
    store.connect().close()
    assert p.exists()
    # Second open: user_version already set → _migrate must NOT run.
    called = []
    monkeypatch.setattr(store, "_migrate",
                        lambda *a, **k: called.append(1))
    con = store.connect()
    assert called == []
    assert con.execute("PRAGMA user_version").fetchone()[0] \
        == store._SCHEMA_VERSION
    con.close()


def test_store_connection_pragmas():
    """Concurrency/durability best-practice pragmas are applied on every
    connection (per-connection ones) and persisted (per-DB ones)."""
    con = store.connect()
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert con.execute("PRAGMA synchronous").fetchone()[0] == 1   # NORMAL
    assert con.execute("PRAGMA auto_vacuum").fetchone()[0] == 2   # INCREMENTAL
    assert con.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
    con.close()


def test_register_run_upsert():
    store.register_run(RID, repo_root="/r1", repo_name="m", app_id="A1")
    store.register_run(RID, repo_root="/r2", repo_name="m2", app_id="A2")
    con = store.connect()
    row = con.execute("SELECT repo_root, repo_name, app_id FROM runs "
                      "WHERE run_id=?", (RID,)).fetchone()
    con.close()
    assert row == ("/r2", "m2", "A2")


def test_prune_checkpoints():
    """gc keeps the newest N, drops the rest, and deletes anything past the
    age cutoff regardless of count. dry_run reports without deleting; ON
    DELETE CASCADE removes the per-step blobs with the run row."""
    con = store.connect()
    with con:
        # 4 runs: r0 newest … r3 oldest (10 days old)
        for i, age in enumerate([0, 1, 2, 10]):
            con.execute(
                "INSERT INTO runs(run_id, repo_root, started_at, updated_at)"
                " VALUES (?, '', datetime('now', ?), datetime('now', ?))",
                (f"r{i}", f"-{age} days", f"-{age} days"))
            con.execute(
                "INSERT INTO checkpoints(run_id, step, payload, size) "
                "VALUES (?, 's1', ?, 2)", (f"r{i}", b"{}"))
    con.close()

    # dry-run: nothing removed; "kept" reports the post-gc count, not total
    r = ck.prune_checkpoints(keep_runs=2, max_age_days=5, dry_run=True)
    assert set(r["deleted"]) == {"r2", "r3"} and r["kept"] == 2
    con = store.connect()
    assert con.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 4
    con.close()

    # real run: keep newest 2; r3 also fails age (10d > 5d)
    r = ck.prune_checkpoints(keep_runs=2, max_age_days=5)
    assert set(r["deleted"]) == {"r2", "r3"} and r["kept"] == 2
    con = store.connect()
    left_runs = {x[0] for x in con.execute("SELECT run_id FROM runs")}
    left_ckpt = {x[0] for x in con.execute("SELECT run_id FROM checkpoints")}
    con.close()
    assert left_runs == {"r0", "r1"}
    assert left_ckpt == {"r0", "r1"}   # CASCADE fired


def test_prune_checkpoints_no_root(tmp_path, monkeypatch):
    """No DB yet → prune is a no-op (creates an empty one), not an error."""
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "fresh"))
    r = ck.prune_checkpoints(keep_runs=100, max_age_days=5)
    assert r["kept"] == 0 and r["deleted"] == []


def _ctx_with_graph() -> ContextPackage:
    return ContextPackage(
        repo_root="/r",
        language="python",
        all_files=["ctrl.py", "dao.py"],
        entry_points=[EntryPoint(file="ctrl.py", function="handle",
                                 kind="network", reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file="dao.py", line=40, function="raw_query")],
        call_graph={"ctrl.py::handle": ["dao.py::raw_query"]},
        call_graph_files={
            "handle": ["ctrl.py:10"],
            "raw_query": ["dao.py:40"],
        },
        def_spans={
            "ctrl.py::handle": [10, 20],
            "dao.py::raw_query": [40, 45],
        },
    )


def test_save_callgraph_dedupes_snapshot_and_records_stage_refs():
    ctx = _ctx_with_graph()
    g1 = store.save_callgraph(RID, "s1", ctx)
    g2 = store.save_callgraph(RID, "s2", ctx)
    assert g1 and g1 == g2

    con = store.connect()
    snap = con.execute(
        "SELECT node_count, edge_count, entry_point_count, sink_count "
        "FROM callgraph_snapshots WHERE run_id=? AND graph_id=?",
        (RID, g1),
    ).fetchone()
    refs = con.execute(
        "SELECT step, graph_id FROM callgraph_stage_refs WHERE run_id=? "
        "ORDER BY step",
        (RID,),
    ).fetchall()
    nodes = con.execute(
        "SELECT qnode, is_entry_point, entry_kind, reachable_from_unauth, "
        "is_sink, sink_line FROM callgraph_nodes WHERE run_id=? ORDER BY qnode",
        (RID,),
    ).fetchall()
    edges = con.execute(
        "SELECT caller_qnode, callee_qnode FROM callgraph_edges WHERE run_id=?",
        (RID,),
    ).fetchall()
    con.close()

    assert snap == (2, 1, 1, 1)
    assert refs == [("s1", g1), ("s2", g1)]
    assert nodes == [
        ("ctrl.py::handle", 1, "network", 1, 0, 0),
        ("dao.py::raw_query", 0, "", 0, 1, 40),
    ]
    assert edges == [("ctrl.py::handle", "dao.py::raw_query")]


def test_load_callgraph_roundtrip_from_stage_ref():
    ctx = _ctx_with_graph()
    store.save_callgraph(RID, "s1", ctx)

    loaded = store.load_callgraph(RID, "s1")
    assert loaded is not None
    assert loaded["node_count"] == 2
    assert loaded["edge_count"] == 1
    assert loaded["call_graph"] == {"ctrl.py::handle": ["dao.py::raw_query"],
                                    "dao.py::raw_query": []}
    assert loaded["call_graph_files"] == {
        "handle": ["ctrl.py:10"],
        "raw_query": ["dao.py:40"],
    }
    assert loaded["def_spans"] == {
        "ctrl.py::handle": [10, 20],
        "dao.py::raw_query": [40, 45],
    }


def test_load_callgraph_missing_stage_ref_returns_none():
    assert store.load_callgraph(RID, "s2") is None


def test_reset_run_clears_callgraph_state_too():
    ctx = _ctx_with_graph()
    store.save_callgraph(RID, "s1", ctx)
    ck.save_ckpt(None, RID, "s9", "/tmp/report.sarif")
    cleared = store.reset_run(RID)
    assert cleared == 2

    con = store.connect()
    counts = con.execute(
        "SELECT "
        " (SELECT COUNT(*) FROM checkpoints WHERE run_id=?),"
        " (SELECT COUNT(*) FROM callgraph_snapshots WHERE run_id=?),"
        " (SELECT COUNT(*) FROM callgraph_stage_refs WHERE run_id=?),"
        " (SELECT COUNT(*) FROM callgraph_nodes WHERE run_id=?),"
        " (SELECT COUNT(*) FROM callgraph_edges WHERE run_id=?)",
        (RID, RID, RID, RID, RID),
    ).fetchone()
    con.close()
    assert counts == (0, 0, 0, 0, 0)
