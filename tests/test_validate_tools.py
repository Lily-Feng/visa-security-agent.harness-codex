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

"""Tests for user-configurable reviewer-persona tools (step_validate.allowed_tools).

Covers the full chain: profile step_validate.allowed_tools -> _export_validate_tools (env) ->
load_config (AgentConfig.validate_tools) -> load_agents(tools_override=) ->
SubagentDefinition.tools -> SDK AgentDefinition.tools. The key safety property is that
dropping Bash from the list removes it from every persona.
"""
import os
from types import SimpleNamespace

from vvaharness.backends.harness.claude.options import _to_agent_definition
from vvaharness.validation.config import load_config
from vvaharness.validation.config.settings import _parse_tools
from vvaharness.validation.constants.artifacts import ENV_VALIDATE_TOOLS
from vvaharness.validation.subagents import load_agents

_PERSONAS = ("security-architect", "penetration-tester", "cross-repo-analyzer")


# ── the safety property: dropping Bash removes it from every persona ───────────
def test_override_without_bash_strips_bash_from_all_personas() -> None:
    ag = load_agents(list(_PERSONAS), tools_override=("Read", "Grep", "Glob"))
    for name in _PERSONAS:
        assert "Bash" not in (ag[name].tools or ()), f"{name} still has Bash"
        assert set(ag[name].tools or ()) == {"Read", "Grep", "Glob"}


def test_override_survives_into_sdk_agent_definition() -> None:
    ag = load_agents(["security-architect"], tools_override=("Read", "Grep", "Glob"))
    sdk_tools = _to_agent_definition(ag["security-architect"]).tools or []
    assert "Bash" not in sdk_tools
    assert "Read" in sdk_tools


# ── default (no override): personas keep their .md frontmatter set incl. fact tools ──
def test_no_override_keeps_frontmatter_tools() -> None:
    ag = load_agents(list(_PERSONAS))
    for name in _PERSONAS:
        assert "Bash" not in (ag[name].tools or ()), f"{name} should not have Bash"
        assert {"Read", "Grep", "Glob", "DiffTouched", "PatternScan"}.issubset(
            set(ag[name].tools or ())
        ), f"{name} missing read-only fact tools"


# ── overrides: profile list -> overrides dict -> AgentConfig.validate_tools ───
def test_validate_tools_in_overrides(tmp_path) -> None:
    from vvaharness.validation.cli._model import _apply_model_env
    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(
        "models:\n  validate:\n    orchestrator: {id: gpt-5.5, via: deepagents}\n"
        "step_validate:\n  enabled: true\n  allowed_tools: [Read, Grep, Glob]\n",
        encoding="utf-8",
    )
    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    assert overrides["validate_tools"] == "Read,Grep,Glob"
    assert load_config(overrides=overrides).agent.validate_tools == ("Read", "Grep", "Glob")


def test_absent_tools_not_in_overrides(tmp_path) -> None:
    from vvaharness.validation.cli._model import _apply_model_env
    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(
        "models:\n  validate:\n    orchestrator: {id: gpt-5.5, via: deepagents}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )
    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    assert "validate_tools" not in overrides


def test_unset_env_yields_none_so_personas_inherit(monkeypatch) -> None:
    monkeypatch.delenv(ENV_VALIDATE_TOOLS, raising=False)
    assert load_config().agent.validate_tools is None


# ── _parse_tools ───────────────────────────────────────────────────────────────
def test_parse_tools_splits_strips_and_drops_empties() -> None:
    assert _parse_tools(" Read , Grep ,,Glob ") == ("Read", "Grep", "Glob")
    assert _parse_tools("") is None
    assert _parse_tools("   ") is None
