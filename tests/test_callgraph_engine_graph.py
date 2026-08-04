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

from vvaharness.pipeline.stages.callgraph_engine._graph import build_taint_paths
from vvaharness.pipeline.stages.callgraph_engine._scan import CallSite, FileIndex, FuncDef


def _callsite(*, file: str, line: int, containing_fn: str, role: str, kind: str, method: str = "", cwe: str = "CWE-89") -> CallSite:
    return CallSite(
        file=file,
        line=line,
        receiver="",
        method=method,
        containing_fn=containing_fn,
        snippet="snippet",
        matched_rule=f"{role}-rule",
        cwe=cwe,
        role=role,
        kind=kind,
    )


def test_build_taint_paths_drops_name_only_ambiguous_edges():
    source_idx = FileIndex(
        file="api/controller.py",
        language="python",
        imports={},
        functions=[FuncDef(name="entry", start_line=1, end_line=10)],
        source_hits=[
            _callsite(file="api/controller.py", line=2, containing_fn="entry", role="source", kind="network")
        ],
        call_edges=[("entry", "", "run")],
    )
    sink_a = FileIndex(
        file="db/query.py",
        language="python",
        imports={},
        functions=[FuncDef(name="run", start_line=10, end_line=20)],
        sink_hits=[
            _callsite(file="db/query.py", line=15, containing_fn="run", role="sink", kind="sql", method="execute")
        ],
    )
    sink_b = FileIndex(
        file="net/client.py",
        language="python",
        imports={},
        functions=[FuncDef(name="run", start_line=30, end_line=40)],
        sink_hits=[
            _callsite(file="net/client.py", line=35, containing_fn="run", role="sink", kind="ssrf", method="open")
        ],
    )

    pkg = build_taint_paths([source_idx, sink_a, sink_b], {})

    assert pkg.taint_paths == []


def test_build_taint_paths_applies_source_sink_compatibility():
    idx = FileIndex(
        file="loader.py",
        language="python",
        imports={},
        functions=[FuncDef(name="load", start_line=1, end_line=20)],
        source_hits=[
            _callsite(file="loader.py", line=3, containing_fn="load", role="source", kind="filesystem")
        ],
        sink_hits=[
            _callsite(file="loader.py", line=7, containing_fn="load", role="sink", kind="xss", method="write"),
            _callsite(file="loader.py", line=9, containing_fn="load", role="sink", kind="path", method="open"),
        ],
    )

    pkg = build_taint_paths([idx], {})

    assert pkg.taint_paths == [["loader.py:3", "loader.py:9"]]


def test_build_taint_paths_sink_identity_uses_containing_function():
    idx = FileIndex(
        file="api.py",
        language="python",
        imports={},
        functions=[FuncDef(name="handle", start_line=1, end_line=20)],
        source_hits=[
            _callsite(file="api.py", line=2, containing_fn="handle",
                      role="source", kind="network", method="request")
        ],
        sink_hits=[
            _callsite(file="api.py", line=8, containing_fn="handle",
                      role="sink", kind="sql", method="execute")
        ],
    )

    pkg = build_taint_paths([idx], {})

    assert len(pkg.unsafe_sinks) == 1
    assert pkg.unsafe_sinks[0].function == "handle"