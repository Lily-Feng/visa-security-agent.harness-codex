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

"""Read-only session middleware: redact file content, remove the write tools.

The logical Read/Grep names map to DeepAgents' own ``read_file``/``grep`` tools
(see :mod:`.tools`), which have no redaction hook. This middleware restores the
guarantee ``localtools.execute`` provides for the other backends: file CONTENT is
masked before it re-enters model context, because a provider PII guard would
otherwise reject the request and PII must not egress.

``ExcludeTools`` takes the write tools out of the model's context entirely.
``FilesystemMiddleware`` always offers ``write_file``/``edit_file``, and the
filesystem deny rules cannot be relied on alone: the matcher runs without DOTGLOB
and unmatched paths fail open, so hidden paths stay writable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langchain.agents.middleware.types import AgentMiddleware

from vvaharness.report.redact import redact_counts

if TYPE_CHECKING:
    from collections.abc import Callable

# Native tools whose results carry file content (``glob``/``ls`` return only paths).
CONTENT_TOOLS: frozenset[str] = frozenset({"read_file", "grep"})
# Native mutating tools, withheld from a read-only session.
WRITE_TOOLS: frozenset[str] = frozenset({"write_file", "edit_file"})


def _redact_message(message: Any) -> Any:
    """Mask credential material in a ToolMessage's string content, in place."""
    content = getattr(message, "content", None)
    if isinstance(content, str) and content:
        message.content = redact_counts(content)[0]
    return message


class RedactToolResults(AgentMiddleware):
    """Mask PII/credentials in content-returning native filesystem tool results."""

    def wrap_tool_call(
        self,
        request: Any,
        handler: Callable[[Any], Any],
    ) -> Any:
        result = handler(request)
        if getattr(request, "tool_call", {}).get("name") in CONTENT_TOOLS:
            return _redact_message(result)
        return result

    async def awrap_tool_call(
        self,
        request: Any,
        handler: Callable[[Any], Any],
    ) -> Any:
        result = await handler(request)
        if getattr(request, "tool_call", {}).get("name") in CONTENT_TOOLS:
            return _redact_message(result)
        return result


def _tool_name(tool: Any) -> str | None:
    """Name of a BaseTool or dict-shaped tool spec."""
    name = tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)
    return name if isinstance(name, str) else None


class ExcludeTools(AgentMiddleware):
    """Withhold named tools from the model's request."""

    def __init__(self, excluded: frozenset[str]) -> None:
        super().__init__()
        self._excluded = excluded

    def _filter(self, request: Any) -> Any:
        kept = [t for t in request.tools if _tool_name(t) not in self._excluded]
        return request.override(tools=kept) if len(kept) != len(request.tools) else request

    def wrap_model_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        return handler(self._filter(request))

    async def awrap_model_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        return await handler(self._filter(request))


def read_only_middleware() -> list[AgentMiddleware]:
    """Middleware every read-only agent needs, parent and subagents alike.

    DeepAgents applies ``create_deep_agent(middleware=...)`` to the parent stack
    only, so subagents must be given their own copy or they read unredacted and
    keep the write tools.
    """
    return [RedactToolResults(), ExcludeTools(WRITE_TOOLS)]


__all__ = [
    "CONTENT_TOOLS",
    "WRITE_TOOLS",
    "ExcludeTools",
    "RedactToolResults",
    "read_only_middleware",
]
