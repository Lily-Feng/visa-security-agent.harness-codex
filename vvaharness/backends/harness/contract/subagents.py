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

"""Harness-owned mirror of SDK ``AgentDefinition``, insulated from SDK imports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SubagentDefinition:
    """SDK-insulated subagent definition for a named agent in a streaming session."""

    name: str
    description: str
    prompt: str
    tools: tuple[str, ...] | None = None
    disallowed_tools: tuple[str, ...] | None = None
    model: str | None = None
    skills: tuple[str, ...] | None = None
    output_schema: dict[str, Any] | None = None
    # Pydantic model *class* for the subagent's structured output (None = none).
    # A class is required to drive DeepAgents' ToolStrategy; output_schema (a dict)
    # cannot. Kept separate so SDK backends that only take a JSON schema still work.
    response_model: type | None = None
