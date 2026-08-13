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

"""Harness-owned message types for streaming sessions.

Consumers iterate over a stream of these and never touch SDK types. The
concrete ``ClaudeHarness`` translates SDK messages into these variants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class HarnessSessionInit:
    """Session-init event carrying the session ID and raw SDK payload."""

    kind: Literal["session_init"] = "session_init"
    session_id: str = ""
    raw: dict[str, object] = field(default_factory=dict)


# Optional provenance tags for backends that stream nested subagents: `agent` is
# the persona name ("validation" for the orchestrator), `namespace` the subgraph
# path. Other backends leave both None.
@dataclass
class HarnessAssistantText:
    """A streamed text block emitted by the assistant."""

    kind: Literal["assistant_text"] = "assistant_text"
    text: str = ""
    agent: str | None = None
    namespace: tuple[str, ...] | None = None


@dataclass
class HarnessToolUse:
    """A tool-invocation request emitted by the assistant."""

    kind: Literal["tool_use"] = "tool_use"
    tool_id: str = ""
    name: str = ""
    input: dict[str, object] = field(default_factory=dict)
    agent: str | None = None
    namespace: tuple[str, ...] | None = None


@dataclass
class HarnessToolResult:
    """The result returned by a tool after a HarnessToolUse."""

    kind: Literal["tool_result"] = "tool_result"
    is_error: bool = False
    content: object = None
    agent: str | None = None
    namespace: tuple[str, ...] | None = None


@dataclass
class HarnessResult:
    """Terminal message marking the end of a streaming session."""

    kind: Literal["result"] = "result"
    subtype: str = ""
    is_error: bool = False
    session_id: str | None = None
    result_text: str | None = None
    structured: object = None
    # Structured-output / model-fallback diagnostics from the terminal result. The
    # only channel that separates the two causes of a structured-output retry
    # failure: schema-validation exhaustion vs a fallback retracting a valid output.
    errors: list[str] | None = None
    # Cumulative session token usage/cost from the SDK ResultMessage.
    usage: dict[str, object] | None = None
    total_cost_usd: float | None = None
    # Backend-specific terminal state; used by DeepAgents for host-side extraction
    # of native subagent reports. Other backends may leave this None.
    state: object = None


HarnessMessage = (
    HarnessSessionInit
    | HarnessAssistantText
    | HarnessToolUse
    | HarnessToolResult
    | HarnessResult
)


@dataclass
class OneShotResult:
    """Result of a single-turn parser-only invocation."""

    is_error: bool = False
    subtype: str = ""
    result_text: str | None = None
    structured: object = None
    # Cumulative session token usage/cost from the SDK ResultMessage.
    usage: dict[str, object] | None = None
    total_cost_usd: float | None = None
