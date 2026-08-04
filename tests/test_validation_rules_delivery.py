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

"""The validation rules must reach every backend, by one route or the other.

``.claude/rules/`` is injected only for the cli/sdk backends, so a prompt that
tells the model to read those files leaves deepagents/openai with dangling
references and no rules. Those backends get the same files inlined instead.
Offline and deterministic -- no network, no LLM, no subprocess.
"""

from __future__ import annotations

from types import SimpleNamespace

from vvaharness.validation.config.settings import _ASSETS_ROOT
from vvaharness.validation.session.launcher import (
    _injects_claude_config,
    _load_system_prompt,
)
from vvaharness.validation.session.rules import (
    orchestrator_rules_text,
    persona_rules_text,
)
from vvaharness.validation.subagents import load_agents

# Resolved from the package, so the tests do not depend on the working directory.
_PROMPTS_DIR = _ASSETS_ROOT / "prompts"

# Sections with no host-side equivalent -- the reason inlining is needed at all.
SCORING_ONLY_MARKER = "Code-level signals only"
PERSONA_MARKER = "Persona Isolation"
CLAUDE_RULES_PATH = ".claude/rules"


def _config(via: str) -> SimpleNamespace:
    return SimpleNamespace(
        agent=SimpleNamespace(via=via),
        paths=SimpleNamespace(prompts_dir=_PROMPTS_DIR),
    )


_PATH_CFG = SimpleNamespace(system_prompt_file="system.md")


def test_injects_claude_config_only_for_cli_and_sdk() -> None:
    assert _injects_claude_config(_config("cli")) is True
    assert _injects_claude_config(_config("sdk")) is True
    assert _injects_claude_config(_config("deepagents")) is False
    assert _injects_claude_config(_config("openai")) is False


def test_orchestrator_rules_carry_both_files_without_the_licence_header() -> None:
    text = orchestrator_rules_text()
    assert SCORING_ONLY_MARKER in text
    assert "Rotation attestation" in text
    assert PERSONA_MARKER in text
    assert "Copyright 2026 Visa" not in text
    assert text == text.strip()


def test_persona_rules_are_the_adversarial_review_rules_only() -> None:
    text = persona_rules_text()
    assert PERSONA_MARKER in text
    assert SCORING_ONLY_MARKER not in text
    assert "Copyright 2026 Visa" not in text


def test_cli_sdk_prompt_points_at_the_injected_rules_and_does_not_inline() -> None:
    for via in ("cli", "sdk"):
        prompt = _load_system_prompt(_config(via), _PATH_CFG)
        assert prompt is not None
        assert "auto-loaded from `.claude/rules/`" in prompt, via
        assert SCORING_ONLY_MARKER not in prompt, via


def test_other_backends_inline_the_rules_with_no_dangling_path_reference() -> None:
    """A `.claude/rules/...` mention would send the model after a file it never got."""
    for via in ("deepagents", "openai"):
        prompt = _load_system_prompt(_config(via), _PATH_CFG)
        assert prompt is not None
        assert SCORING_ONLY_MARKER in prompt, via
        assert PERSONA_MARKER in prompt, via
        assert CLAUDE_RULES_PATH not in prompt, via


def test_every_backend_gets_a_single_rules_section() -> None:
    for via in ("cli", "sdk", "deepagents", "openai"):
        prompt = _load_system_prompt(_config(via), _PATH_CFG)
        assert prompt is not None
        assert prompt.count("## Rules") == 1, via


def test_prompt_suffix_appends_to_every_persona() -> None:
    base = load_agents()
    suffixed = load_agents(prompt_suffix=persona_rules_text())
    assert set(base) == set(suffixed)
    for name, agent in suffixed.items():
        assert PERSONA_MARKER in agent.prompt, name
        assert agent.prompt.startswith(base[name].prompt.rstrip()), name
        # Only the prompt changes; the rest of the definition is untouched.
        assert agent.name == base[name].name
        assert agent.tools == base[name].tools
        assert agent.response_model is base[name].response_model


def test_prompt_suffix_omitted_leaves_persona_prompts_untouched() -> None:
    base = load_agents()
    for name, agent in load_agents(prompt_suffix=None).items():
        assert agent.prompt == base[name].prompt, name
