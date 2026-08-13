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

"""Packaging guard (F34): the internal rule-corpus leak must not recur.

The distribution must never ship org-specific / harvested ``*.kb.yaml`` corpora.
These tests assert on the packaging *allowlist* rather than the working tree so
they are deterministic regardless of any untracked local corpora a developer may
have sitting in ``vvaharness/rules/``.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _REPO_ROOT / "pyproject.toml"


def _package_data_rules() -> list[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    entries = data["tool"]["setuptools"]["package-data"]["vvaharness"]
    return [e for e in entries if e.startswith("rules/")]


def test_no_broad_rules_glob():
    """A broad ``rules/*.yaml`` glob is what let ``custom.kb.yaml`` ship; forbid it."""
    rules = _package_data_rules()
    assert "rules/*.yaml" not in rules, (
        "Broad rules/*.yaml glob would package any dropped-in corpus, including "
        "harvested internal *.kb.yaml files. Use an explicit allowlist."
    )
    yaml_globs = [e for e in rules if e.endswith("*.yaml") or e.endswith("*.yml")]
    assert not yaml_globs, f"No wildcard yaml packaging allowed under rules/: {yaml_globs}"


def test_only_public_corpora_are_packaged():
    """Only the three public, generated/generic corpora may be packaged."""
    allowed = {
        "rules/sources.generated.yaml",
        "rules/sinks.generated.yaml",
        "rules/generic.kb.yaml",
    }
    packaged_yaml = {e for e in _package_data_rules() if e.endswith((".yaml", ".yml"))}
    extra = packaged_yaml - allowed
    assert not extra, f"Unexpected rule corpora in packaging allowlist: {sorted(extra)}"


def test_internal_catalogue_not_tracked():
    """The harvested internal catalogue must not be re-added to the tree."""
    assert not (_REPO_ROOT / "vvaharness" / "rules" / "custom.kb.yaml").exists(), (
        "vvaharness/rules/custom.kb.yaml is a harvested internal review catalogue "
        "and must not exist in the repository (F34)."
    )
