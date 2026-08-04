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

"""Shared in-scope file iteration for validation fact tools.

Applies the production ``s1_preprocess`` directory and extension exclusions so
the validation tools skip the same infra/vendor dirs and binary/media files, and
refuses symlinks whose target escapes the workspace (host-file-disclosure guard).
One walk feeds both the secret scanner and the test inventory.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from vvaharness.pipeline.stages.s1_preprocess import (
    _DEFAULT_EXCLUDE_DIRS,
    _DEFAULT_EXCLUDE_EXTS,
)

# The production exclude set mixes infra/vendor dirs with test dirs. The secret
# scan wants both gone (tests aren't production surface); the test inventory
# needs the test dirs kept. Partition the one production set into those groups.
_TEST_DIRS: frozenset[str] = frozenset({
    "test", "tests", "__tests__", "__test__", "e2e", "testdata",
    "fixtures", "__fixtures__", "mocks", "__mocks__", "stubs",
})
_PRODUCTION_EXCLUDE_DIRS: frozenset[str] = frozenset(d.lower() for d in _DEFAULT_EXCLUDE_DIRS)
_INFRA_DIRS: frozenset[str] = _PRODUCTION_EXCLUDE_DIRS - _TEST_DIRS
_EXCLUDE_EXTS: frozenset[str] = frozenset(e.lower() for e in _DEFAULT_EXCLUDE_EXTS)

# _TEST_DIRS must stay a subset of the production set; if production adds a new
# test dir, mirror it here or test_inventory (include_tests) will wrongly skip it.
# A raise, not an assert: asserts are stripped under `python -O`, which would turn
# this guard into a silent behaviour change instead of a startup failure.
if not _TEST_DIRS <= _PRODUCTION_EXCLUDE_DIRS:
    raise RuntimeError(
        "validation _TEST_DIRS drifted from s1_preprocess._DEFAULT_EXCLUDE_DIRS: "
        f"{sorted(_TEST_DIRS - _PRODUCTION_EXCLUDE_DIRS)} missing from the production set"
    )


def _in_excluded_dir(rel_path: Path, excluded_dirs: frozenset[str]) -> bool:
    return any(part.lower() in excluded_dirs for part in rel_path.parts[:-1])


def _has_excluded_ext(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(ext) for ext in _EXCLUDE_EXTS)


def _escapes_workspace(path: Path, root: Path) -> bool:
    """True when *path* is a symlink whose target resolves outside *root*."""
    if not path.is_symlink():  # only symlinks can escape; skip resolve() for the common case
        return False
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return True
    return False


def iter_in_scope_files(workspace: Path, *, include_tests: bool) -> Iterator[Path]:
    """Yield workspace files within the production scan scope.

    Always skips infra/vendor dirs, binary/media extensions, and symlinks that
    escape *workspace*. Test dirs are skipped unless *include_tests* is set.
    """
    root = workspace.resolve()
    excluded_dirs = _INFRA_DIRS if include_tests else (_INFRA_DIRS | _TEST_DIRS)
    for path in workspace.rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(workspace)
        if _in_excluded_dir(rel_path, excluded_dirs):
            continue
        if _has_excluded_ext(rel_path.name):
            continue
        if _escapes_workspace(path, root):
            continue
        yield path
