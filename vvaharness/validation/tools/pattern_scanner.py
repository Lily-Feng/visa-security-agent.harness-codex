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

"""Deterministic pattern scanner for validation subagents."""

from __future__ import annotations

from pathlib import Path

from vvaharness.validation.constants.pattern_sets import (
    BUILTIN_RULE,
    DEFAULT_PATTERN_SETS,
    NUL_BYTE,
    SKIP_IN_SCAN,
)
from vvaharness.validation.tools._scope import iter_in_scope_files


def pattern_scan(workspace: Path, pattern_set: str) -> list[dict]:
    """Scan the in-scope workspace with *pattern_set* and return ordered matches.

    Builtin sets: ``secret_exposure``, ``insecure_value``. An unknown set raises
    ValueError so the caller gets a signal rather than a clean-looking empty list.
    """
    if pattern_set not in DEFAULT_PATTERN_SETS:
        raise ValueError(
            f"unknown pattern_set {pattern_set!r}; available: {sorted(DEFAULT_PATTERN_SETS)}"
        )

    description, regex = DEFAULT_PATTERN_SETS[pattern_set]
    matches: list[dict] = []
    for file_path in iter_in_scope_files(workspace, include_tests=False):
        if file_path.name in SKIP_IN_SCAN:
            continue
        try:
            raw_bytes = file_path.read_bytes()
        except OSError:
            continue
        if NUL_BYTE in raw_bytes:
            continue
        text = raw_bytes.decode("utf-8", errors="replace")
        found = list(regex.finditer(text))
        if not found:
            continue
        relative_path = str(file_path.relative_to(workspace))
        matches.extend(
            {
                "file": relative_path,
                "line": text.count("\n", 0, match.start()) + 1,
                "snippet": match.group(0),
                "pattern_set": pattern_set,
                "rule": BUILTIN_RULE,
                "description": description,
            }
            for match in found
        )
    return sorted(matches, key=lambda match: (match["file"], match["line"]))
