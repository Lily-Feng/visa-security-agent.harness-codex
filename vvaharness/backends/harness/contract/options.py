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

"""Harness-level options for one-shot and streaming invocations."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .permissions import PermissionsPolicy
from .subagents import SubagentDefinition
from .tool_policy import ToolPolicy

# Builds the concrete tool objects for a session. Typed loosely so the neutral
# contract need not import the agent SDK's tool/base-model types, and so builders
# may take the allow-list as a keyword. Receives the owning options and the
# resolved allow-list; returns a list of backend tools.
ToolBuilder = Callable[..., list[Any]]

# Default graph name when a consumer does not name its agent graph.
DEFAULT_GRAPH_NAME = "agent"

# Fields shared by every consumer to inject its own semantics into a backend
# without the backend hardwiring them. All default to generic-safe / read-only,
# so a consumer that sets nothing gets a safe read-only session.
#
#   response_model  a Pydantic model *class* for structured output (None = none)
#   tool_builder    builds the session's tools (None = backend's generic readers)
#   fact_tools      extra tool names granted to subagents beyond the policy
#   allow_writes    when False, write/edit tools are denied (read-only)
#   writable_paths  paths writes may target when allow_writes is True
#   skill_root      directory of agent skill packages to load (None = none)
#   graph_name      cosmetic name for the compiled agent graph


@dataclass
class OneShotOptions:
    """Options for a parser-only single-turn invocation."""

    model: str
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    # deepagents backend selector: "openai" | "anthropic"; None => infer from name.
    model_provider: str | None = None
    effort: str | None = None
    max_turns: int = 15
    tool_policy: ToolPolicy | None = None
    system_prompt: str | None = None
    output_schema: Mapping[str, object] | None = None
    cli_path: str | None = None          # absolute path to the claude executable (pin)
    # Injected consumer semantics (see module note).
    response_model: type | None = None
    tool_builder: ToolBuilder | None = None
    fact_tools: tuple[str, ...] = ()
    allow_writes: bool = False
    writable_paths: tuple[str, ...] = ()
    skill_root: Path | None = None
    graph_name: str = DEFAULT_GRAPH_NAME


@dataclass
class StreamingOptions:
    """Options for a full validation session."""

    model: str
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    # deepagents backend selector: "openai" | "anthropic"; None => infer from name.
    model_provider: str | None = None
    effort: str | None = None
    max_turns: int | None = None
    max_budget_usd: float | None = None
    system_prompt: str | None = None
    setting_sources: tuple[str, ...] | None = None
    tool_policy: ToolPolicy | None = None
    permissions: PermissionsPolicy | None = None
    agents: dict[str, SubagentDefinition] = field(default_factory=dict)
    cli_path: str | None = None          # absolute path to the claude executable (pin)
    output_schema: dict[str, object] | None = None
    # Injected consumer semantics (see module note).
    response_model: type | None = None
    tool_builder: ToolBuilder | None = None
    fact_tools: tuple[str, ...] = ()
    allow_writes: bool = False
    writable_paths: tuple[str, ...] = ()
    skill_root: Path | None = None
    graph_name: str = DEFAULT_GRAPH_NAME
