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

"""Logical->native tool-name mapping for the DeepAgents backend.

The profile YAML uses backend-agnostic names (Read/Grep/Glob/Edit/Write). This
module maps them onto the tools DeepAgents' FilesystemMiddleware already exposes,
so the model sees exactly one tool per job with one path convention.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from langchain_core.tools import BaseTool

from vvaharness.backends.harness.contract.options import StreamingOptions
from vvaharness.backends.harness.contract.tool_policy import ToolPolicy

if TYPE_CHECKING:
    from collections.abc import Sequence

def _allowed_tool_names(
    options: StreamingOptions, allowed_tools: Sequence[str] | None
) -> set[str]:
    """Resolve the effective allow-list: explicit *allowed_tools* else the policy's."""
    policy = options.tool_policy if options.tool_policy is not None else ToolPolicy()
    return set(allowed_tools if allowed_tools is not None else policy.allowed_tools)


# Logical tool names (the profile YAML vocabulary) mapped to the tools this
# backend natively exposes via DeepAgents' FilesystemMiddleware. Mapped names are
# NOT rebuilt here: the middleware already provides them, so building our own
# would put two tools with different path conventions in front of the model.
LOGICAL_TO_NATIVE: dict[str, str] = {
    "Read": "read_file",
    "Grep": "grep",
    "Glob": "glob",
    "Edit": "edit_file",
    "Write": "write_file",
}


def native_tool_names(
    options: StreamingOptions, allowed_tools: Sequence[str] | None
) -> tuple[str, ...]:
    """Resolve the logical allow-list to the native names this backend exposes."""
    allowed = _allowed_tool_names(options, allowed_tools)
    return tuple(
        native for logical, native in LOGICAL_TO_NATIVE.items() if logical in allowed
    )


def build_tools(
    options: StreamingOptions,
    *,
    allowed_tools: Sequence[str] | None,
) -> list[BaseTool]:
    """Build only the tools DeepAgents does not already provide.

    Logical names in :data:`LOGICAL_TO_NATIVE` resolve to native middleware tools
    (see :func:`native_tool_names`), so nothing is built for them. Consumers that
    need extra tools (e.g. validation's deterministic fact tools) supply a
    ``tool_builder`` that wraps this function and appends their own.
    """
    return []


__all__ = ["LOGICAL_TO_NATIVE", "build_tools", "native_tool_names"]
