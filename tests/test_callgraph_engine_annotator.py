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
Deterministic tests for the live LLM detection seam ``_annotator``.

These exercise the wired ``detect_specs`` entry point and its pure helpers
without any network / LLM call:

1. ``detect_specs`` returns empty specs when there are no observed calls
   (short-circuits before any model invocation).
2. ``_collect_candidates`` yields nothing for empty input.
3. Pure classification helpers map kinds/CWEs to stable semantic families.
"""

from types import SimpleNamespace

from vvaharness.pipeline.stages.callgraph_engine._annotator import (
    detect_specs,
    _collect_candidates,
    _semantic_family,
    _norm_cwe,
)


def test_detect_specs_empty_input_returns_empty():
    """No file indices -> empty specs, no LLM call, no model required."""
    sources, sinks, rule_cwe = detect_specs([], [], SimpleNamespace())
    assert sources == []
    assert sinks == []
    assert rule_cwe == {}


def test_collect_candidates_empty():
    assert _collect_candidates([], set(), 400) == []


def test_semantic_family_stable_mapping():
    assert _semantic_family("sql", "CWE-89") == "sql-exec"
    assert _semantic_family("cmd", "CWE-78") == "command-exec"
    assert _semantic_family("deserialize", "CWE-502") == "deserialization"
    assert _semantic_family("", "") == "other"


def test_norm_cwe_defaults_by_role():
    assert _norm_cwe("CWE-89", "sink") == "CWE-89"
    assert _norm_cwe("garbage", "source") == "CWE-20"
    assert _norm_cwe("garbage", "sink") == "CWE-78"
