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

"""orchestrator.store — SQLite state store.

Single-file SQLite database under ``$VVAHARNESS_STATE_DIR`` (or
``~/.vvaharness/state``) holding per-run checkpoint blobs and run metadata.
Replaces the per-step JSON files; payloads are still pydantic
``TypeAdapter.dump_json()`` bytes, so the CWE-502 guarantee (no constructor
opcodes, validate-on-load) is preserved unchanged.

The schema is created idempotently on every ``connect()`` — there is no
"first run" branch: ``sqlite3.connect`` creates the file if absent and
``CREATE TABLE IF NOT EXISTS`` is a no-op thereafter. Changing
``$VVAHARNESS_STATE_DIR`` therefore yields a fresh, empty database; the old
file is simply orphaned.
"""
from __future__ import annotations
from collections import defaultdict
import hashlib
import json
import os
import sqlite3
from pathlib import Path

_SCHEMA_VERSION = 2

# auto_vacuum MUST precede the first CREATE TABLE or it is silently ignored;
# journal_mode=WAL persists once set. foreign_keys / busy_timeout /
# synchronous are per-connection and set separately in connect().
_DDL = """
PRAGMA auto_vacuum  = INCREMENTAL;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS runs (
  run_id     TEXT PRIMARY KEY,
  repo_root  TEXT NOT NULL,
  repo_name  TEXT,
  app_id     TEXT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS checkpoints (
  run_id     TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  step       TEXT    NOT NULL,
  payload    BLOB    NOT NULL,
  size       INTEGER NOT NULL CHECK (size <= 104857600),
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (run_id, step)
);

CREATE TABLE IF NOT EXISTS callgraph_snapshots (
    run_id            TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    graph_id          TEXT    NOT NULL,
    node_count        INTEGER NOT NULL DEFAULT 0,
    edge_count        INTEGER NOT NULL DEFAULT 0,
    entry_point_count INTEGER NOT NULL DEFAULT 0,
    sink_count        INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (run_id, graph_id)
);

CREATE TABLE IF NOT EXISTS callgraph_nodes (
    run_id                 TEXT    NOT NULL,
    graph_id               TEXT    NOT NULL,
    qnode                  TEXT    NOT NULL,
    file_path              TEXT    NOT NULL DEFAULT '',
    function_name          TEXT    NOT NULL DEFAULT '',
    start_line             INTEGER NOT NULL DEFAULT 0,
    end_line               INTEGER NOT NULL DEFAULT 0,
    is_entry_point         INTEGER NOT NULL DEFAULT 0,
    entry_kind             TEXT    NOT NULL DEFAULT '',
    reachable_from_unauth  INTEGER NOT NULL DEFAULT 0,
    is_sink                INTEGER NOT NULL DEFAULT 0,
    sink_line              INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, graph_id, qnode),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS callgraph_edges (
    run_id        TEXT NOT NULL,
    graph_id      TEXT NOT NULL,
    caller_qnode  TEXT NOT NULL,
    callee_qnode  TEXT NOT NULL,
    PRIMARY KEY (run_id, graph_id, caller_qnode, callee_qnode),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS callgraph_stage_refs (
    run_id      TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    step        TEXT NOT NULL,
    graph_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (run_id, step),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_runs_updated ON runs(updated_at);
CREATE INDEX IF NOT EXISTS ix_callgraph_stage_refs_graph
    ON callgraph_stage_refs(run_id, graph_id);
CREATE INDEX IF NOT EXISTS ix_callgraph_nodes_file
    ON callgraph_nodes(run_id, file_path, function_name);
CREATE INDEX IF NOT EXISTS ix_callgraph_edges_caller
    ON callgraph_edges(run_id, caller_qnode);
CREATE INDEX IF NOT EXISTS ix_callgraph_edges_callee
    ON callgraph_edges(run_id, callee_qnode);
"""

_DDL_V2 = """
CREATE TABLE IF NOT EXISTS callgraph_snapshots (
    run_id            TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    graph_id          TEXT    NOT NULL,
    node_count        INTEGER NOT NULL DEFAULT 0,
    edge_count        INTEGER NOT NULL DEFAULT 0,
    entry_point_count INTEGER NOT NULL DEFAULT 0,
    sink_count        INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (run_id, graph_id)
);

CREATE TABLE IF NOT EXISTS callgraph_nodes (
    run_id                 TEXT    NOT NULL,
    graph_id               TEXT    NOT NULL,
    qnode                  TEXT    NOT NULL,
    file_path              TEXT    NOT NULL DEFAULT '',
    function_name          TEXT    NOT NULL DEFAULT '',
    start_line             INTEGER NOT NULL DEFAULT 0,
    end_line               INTEGER NOT NULL DEFAULT 0,
    is_entry_point         INTEGER NOT NULL DEFAULT 0,
    entry_kind             TEXT    NOT NULL DEFAULT '',
    reachable_from_unauth  INTEGER NOT NULL DEFAULT 0,
    is_sink                INTEGER NOT NULL DEFAULT 0,
    sink_line              INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, graph_id, qnode),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS callgraph_edges (
    run_id        TEXT NOT NULL,
    graph_id      TEXT NOT NULL,
    caller_qnode  TEXT NOT NULL,
    callee_qnode  TEXT NOT NULL,
    PRIMARY KEY (run_id, graph_id, caller_qnode, callee_qnode),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS callgraph_stage_refs (
    run_id      TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    step        TEXT NOT NULL,
    graph_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (run_id, step),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_callgraph_stage_refs_graph
    ON callgraph_stage_refs(run_id, graph_id);
CREATE INDEX IF NOT EXISTS ix_callgraph_nodes_file
    ON callgraph_nodes(run_id, file_path, function_name);
CREATE INDEX IF NOT EXISTS ix_callgraph_edges_caller
    ON callgraph_edges(run_id, caller_qnode);
CREATE INDEX IF NOT EXISTS ix_callgraph_edges_callee
    ON callgraph_edges(run_id, callee_qnode);
"""


def db_path() -> Path:
    """Resolve the state DB path the same way scan.py resolves the legacy
    ``checkpoints/`` root — keep these in lockstep so ``--resume`` and the
    in-target safety check (scan.py) see the same location."""
    root = Path(os.environ.get("VVAHARNESS_STATE_DIR")
                or Path.home() / ".vvaharness" / "state")
    root.mkdir(parents=True, exist_ok=True)
    return root / "vvaharness.db"


def connect() -> sqlite3.Connection:
    """Open the state DB, ensure the schema exists, and return a connection.

    Concurrency model: WAL gives N readers + 1 writer with no reader/writer
    blocking; ``busy_timeout`` makes a second concurrent writer wait up to
    30 s for the single write lock instead of failing. SQLite has one write
    lock per DB (not per row), so there is no lock-ordering deadlock to
    avoid — the only failure mode is timeout, and our transactions are
    sub-second. ``synchronous=NORMAL`` is the documented WAL companion:
    still crash-safe (the WAL is fsynced on checkpoint), ~10× faster than
    the FULL default, and appropriate for disposable resume-state.

    Cheap enough to call per operation; a fresh connection per call avoids
    cross-thread/process reuse (sqlite3 connections are thread-affine)."""
    con = sqlite3.connect(db_path())
    # Per-connection pragmas — must be set on every handle.
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 30000")
    con.execute("PRAGMA synchronous  = NORMAL")
    # Schema bootstrap — skipped entirely once user_version matches, so the
    # hot path is three pragmas + one integer read; no executescript, no
    # CREATE-IF-NOT-EXISTS lock churn on every save_ckpt().
    have = con.execute("PRAGMA user_version").fetchone()[0]
    if have != _SCHEMA_VERSION:
        _migrate(con, have)
    return con


def _migrate(con: sqlite3.Connection, have: int) -> None:
    if have == 0:
        con.executescript(_DDL)
    elif have < 2:
        con.executescript(_DDL_V2)
    con.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
    con.commit()


def register_run(run_id: str, *, repo_root: str,
                 repo_name: str | None = None,
                 app_id: str | None = None) -> None:
    """Upsert the per-run metadata row. Called once at the top of
    ``scan_repo()`` so ``gc`` can rank runs by recency and so a future
    ``findings`` table has something to FK against."""
    con = connect()
    with con:
        con.execute(
            "INSERT INTO runs(run_id, repo_root, repo_name, app_id) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(run_id) DO UPDATE SET "
            "  repo_root = excluded.repo_root, "
            "  repo_name = excluded.repo_name, "
            "  app_id    = excluded.app_id, "
            "  updated_at = datetime('now')",
            (run_id, repo_root, repo_name, app_id),
        )
    con.close()


def _qnode(file_path: str, function_name: str) -> str:
    file_part = (file_path or "").replace("\\", "/")
    fn_part = function_name or ""
    return f"{file_part}::{fn_part}" if file_part or fn_part else ""


def _split_qnode(qnode: str) -> tuple[str, str]:
    # Split on the LAST "::" to match the canonical q_split in s1_preprocess
    # (rpartition). File paths and qualified member names that themselves
    # contain "::" (C++, C#) must decode identically on the SQLite persistence
    # path and the in-memory path, or a hydrated graph points at the wrong file.
    if "::" not in qnode:
        return "", qnode
    f, _, n = qnode.rpartition("::")
    return f, n


def _line_from_site(site: str) -> int:
    _file, sep, raw = site.rpartition(":")
    if not sep:
        return 0
    try:
        return int(raw)
    except ValueError:
        return 0


def _graph_rows(obj) -> tuple[list[dict], list[tuple[str, str]]] | None:
    call_graph = dict(getattr(obj, "call_graph", {}) or {})
    call_graph_files = dict(getattr(obj, "call_graph_files", {}) or {})
    def_spans = dict(getattr(obj, "def_spans", {}) or {})
    entry_points = list(getattr(obj, "entry_points", ()) or ())
    unsafe_sinks = list(getattr(obj, "unsafe_sinks", ()) or ())
    if not (call_graph or call_graph_files or def_spans or entry_points or unsafe_sinks):
        return None

    entry_meta: dict[str, tuple[str, int]] = {}
    for ep in entry_points:
        qn = _qnode(getattr(ep, "file", ""), getattr(ep, "function", ""))
        if qn:
            entry_meta[qn] = (
                (getattr(ep, "kind", "") or ""),
                1 if bool(getattr(ep, "reachable_from_unauth", False)) else 0,
            )

    sink_meta: dict[str, int] = {}
    for sink in unsafe_sinks:
        qn = _qnode(getattr(sink, "file", ""), getattr(sink, "function", ""))
        if qn:
            line = int(getattr(sink, "line", 0) or 0)
            prev = sink_meta.get(qn)
            sink_meta[qn] = line if prev is None or (line and line < prev) else prev

    qnodes: set[str] = set(call_graph)
    edges: set[tuple[str, str]] = set()
    for caller, callees in call_graph.items():
        if not caller:
            continue
        qnodes.add(caller)
        for callee in callees or ():
            if not callee:
                continue
            qnodes.add(callee)
            edges.add((caller, callee))
    qnodes.update(qn for qn in entry_meta if qn)
    qnodes.update(qn for qn in sink_meta if qn)
    qnodes.update(qn for qn in def_spans if qn)

    node_rows: list[dict] = []
    for qn in sorted(qnodes):
        file_path, function_name = _split_qnode(qn)
        span = def_spans.get(qn) or []
        start_line = int(span[0]) if len(span) >= 1 else 0
        end_line = int(span[1]) if len(span) >= 2 else 0
        if not start_line and function_name:
            for site in call_graph_files.get(function_name, ()):
                site_file, _, _raw = site.rpartition(":")
                if site_file == file_path:
                    start_line = _line_from_site(site)
                    if not end_line:
                        end_line = start_line
                    break
        entry_kind, unauth = entry_meta.get(qn, ("", 0))
        sink_line = sink_meta.get(qn, 0)
        node_rows.append({
            "qnode": qn,
            "file_path": file_path,
            "function_name": function_name,
            "start_line": start_line,
            "end_line": end_line,
            "is_entry_point": 1 if qn in entry_meta else 0,
            "entry_kind": entry_kind,
            "reachable_from_unauth": unauth,
            "is_sink": 1 if qn in sink_meta else 0,
            "sink_line": sink_line,
        })

    return node_rows, sorted(edges)


def save_callgraph(run_id: str, step: str, obj) -> str | None:
    """Persist a normalized callgraph snapshot and bind the current step to it.

    Unlike checkpoint blobs, this path stores rows rather than a single BLOB,
    so large graphs remain resumable and queryable.
    """
    rows = _graph_rows(obj)
    if rows is None:
        return None
    node_rows, edge_rows = rows
    payload = json.dumps({
        "nodes": node_rows,
        "edges": edge_rows,
    }, sort_keys=True, separators=(",", ":")).encode()
    graph_id = hashlib.sha256(payload).hexdigest()[:32]

    con = connect()
    try:
        with con:
            con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) VALUES (?, '')",
                        (run_id,))
            con.execute("UPDATE runs SET updated_at = datetime('now') WHERE run_id = ?",
                        (run_id,))
            exists = con.execute(
                "SELECT 1 FROM callgraph_snapshots WHERE run_id=? AND graph_id=?",
                (run_id, graph_id),
            ).fetchone()
            if exists is None:
                con.execute(
                    "INSERT INTO callgraph_snapshots"
                    "(run_id, graph_id, node_count, edge_count, entry_point_count, sink_count) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        graph_id,
                        len(node_rows),
                        len(edge_rows),
                        sum(r["is_entry_point"] for r in node_rows),
                        sum(r["is_sink"] for r in node_rows),
                    ),
                )
                con.executemany(
                    "INSERT INTO callgraph_nodes"
                    "(run_id, graph_id, qnode, file_path, function_name, start_line, end_line, "
                    " is_entry_point, entry_kind, reachable_from_unauth, is_sink, sink_line) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [(
                        run_id,
                        graph_id,
                        row["qnode"],
                        row["file_path"],
                        row["function_name"],
                        row["start_line"],
                        row["end_line"],
                        row["is_entry_point"],
                        row["entry_kind"],
                        row["reachable_from_unauth"],
                        row["is_sink"],
                        row["sink_line"],
                    ) for row in node_rows],
                )
                con.executemany(
                    "INSERT INTO callgraph_edges"
                    "(run_id, graph_id, caller_qnode, callee_qnode) VALUES (?, ?, ?, ?)",
                    [(run_id, graph_id, caller, callee) for caller, callee in edge_rows],
                )
            con.execute(
                "INSERT OR REPLACE INTO callgraph_stage_refs(run_id, step, graph_id) VALUES (?, ?, ?)",
                (run_id, step, graph_id),
            )
        return graph_id
    finally:
        con.close()


def load_callgraph(run_id: str, step: str) -> dict | None:
    """Load a normalized callgraph snapshot bound to ``(run_id, step)``.

    Returns ``None`` when the step has no bound graph.
    """
    con = connect()
    try:
        ref = con.execute(
            "SELECT graph_id FROM callgraph_stage_refs WHERE run_id=? AND step=?",
            (run_id, step),
        ).fetchone()
        if ref is None:
            return None
        graph_id = ref[0]
        node_rows = con.execute(
            "SELECT qnode, file_path, function_name, start_line, end_line, "
            "is_entry_point, reachable_from_unauth, is_sink "
            "FROM callgraph_nodes WHERE run_id=? AND graph_id=?",
            (run_id, graph_id),
        ).fetchall()
        edge_rows = con.execute(
            "SELECT caller_qnode, callee_qnode FROM callgraph_edges "
            "WHERE run_id=? AND graph_id=?",
            (run_id, graph_id),
        ).fetchall()
    finally:
        con.close()

    node_meta: dict[str, tuple[int, int, int]] = {}
    call_graph_files: dict[str, list[str]] = defaultdict(list)
    def_spans: dict[str, list[int]] = {}
    for (qn, file_path, fn_name, start_line, end_line,
         is_ep, unauth, is_sink) in node_rows:
        node_meta[qn] = (int(is_ep or 0), int(unauth or 0), int(is_sink or 0))
        if fn_name and file_path and start_line:
            site = f"{file_path}:{int(start_line)}"
            sites = call_graph_files[fn_name]
            if site not in sites:
                sites.append(site)
        if start_line or end_line:
            def_spans[qn] = [int(start_line or 0), int(end_line or 0)]

    def _edge_score(caller: str, callee: str) -> tuple[int, int, int, str, str]:
        c_ep, c_unauth, c_sink = node_meta.get(caller, (0, 0, 0))
        t_ep, t_unauth, t_sink = node_meta.get(callee, (0, 0, 0))
        return (
            -max(c_unauth, t_unauth),
            -max(c_ep, t_ep),
            -max(c_sink, t_sink),
            caller,
            callee,
        )

    ordered_edges = sorted(
        {(caller, callee) for caller, callee in edge_rows if caller and callee},
        key=lambda e: _edge_score(e[0], e[1]),
    )

    call_graph: dict[str, list[str]] = defaultdict(list)
    for caller, callee in ordered_edges:
        call_graph[caller].append(callee)

    # Preserve isolated nodes as keys to keep graph shape stable across
    # save/load even when a function currently has no outgoing edge.
    for qn in node_meta:
        call_graph.setdefault(qn, [])

    return {
        "graph_id": graph_id,
        "call_graph": dict(call_graph),
        "call_graph_files": {k: v for k, v in call_graph_files.items()},
        "def_spans": def_spans,
        "node_count": len(node_rows),
        "edge_count": len(ordered_edges),
    }


def reset_run(run_id: str) -> int:
    """Delete every checkpoint row for one run — the fixed s1..s9 steps AND the
    dynamic ``remediate_<idx>`` / ``validate_<id>`` steps.

    Called by a FRESH (non ``--resume``) scan. ``run_id`` is derived purely from
    the repo path, so a rescan of the same project reuses the prior run's rows;
    ``save_ckpt`` (INSERT OR REPLACE) overwrites only the steps the new scan
    reaches, leaving stale rows (steps a stopped run skipped, plus per-finding
    remediate/validate rows whose keys don't recur) for a later ``--resume`` to
    load. Clearing them here makes "fresh scan" mean a genuinely empty slate.

    The ``runs`` metadata row is intentionally kept (``register_run`` upserts
    it just before this call); only its checkpoints are removed. No vacuum is
    issued — the freed pages are immediately reused by this scan's own writes,
    so the per-scan cost is a single DELETE. Returns rows deleted."""
    con = connect()
    try:
        with con:
            cleared = 0
            cur = con.execute("DELETE FROM checkpoints WHERE run_id = ?", (run_id,))
            cleared += cur.rowcount or 0
            cur = con.execute("DELETE FROM callgraph_snapshots WHERE run_id = ?", (run_id,))
            cleared += cur.rowcount or 0
            return cleared
    finally:
        con.close()


def delete_run(run_id: str) -> bool:
    """Fully evict a single run: delete its ``runs`` row, which drops its
    ``checkpoints`` via ON DELETE CASCADE. Reclaims freed pages afterwards
    (unlike :func:`reset_run`, this is an on-demand ``gc`` operation, not a
    per-scan hot path). Returns True if a run row was deleted."""
    con = connect()
    try:
        with con:
            cur = con.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
            deleted = cur.rowcount or 0
        if deleted:
            con.execute("PRAGMA incremental_vacuum")
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return deleted > 0
    finally:
        con.close()
