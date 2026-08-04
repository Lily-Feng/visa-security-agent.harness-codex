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

"""PermissionsPolicy dataclass + defaults for the deny-by-default validation gate."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ._decision import PermissionDecision
from ._evaluate import evaluate_write

# Tools allowed besides the gated Write (Bash is always denied) — read + orchestration only.
READ_ONLY_TOOLS: frozenset[str] = frozenset({
    "Read", "Grep", "Glob", "Agent", "Task", "TodoWrite", "Skill",
})


@dataclass
class PermissionsPolicy:
    """Declarative deny-by-default permission gate for a validation session.

    Everything not explicitly permitted is denied: Edit/NotebookEdit always; Write only to
    the two output files under the target dir; Bash always denied (no shell execution); the
    read/orchestration tools in ``READ_ONLY_TOOLS`` (and ``mcp__*``); every other tool denied.
    """

    target_dir: Path
    # Deny-all writes by default; a consumer opts specific output filenames in.
    allowed_output_files: frozenset[str] = field(default_factory=frozenset)

    def _evaluate_simple(self, tool_name: str) -> PermissionDecision:
        """Decide non-Write/Bash tools: Edit family denied, read tools allowed, else denied."""
        if tool_name in {"Edit", "NotebookEdit"}:
            return PermissionDecision(
                False, "read-only validation session: Edit/NotebookEdit blocked", True,
            )
        if tool_name in READ_ONLY_TOOLS or tool_name.startswith("mcp__"):
            return PermissionDecision(True)
        return PermissionDecision(
            False, f"tool not permitted in read-only validation session: {tool_name}", True,
        )

    def evaluate(
        self, tool_name: str, input_data: Mapping[str, object]
    ) -> PermissionDecision:
        """Evaluate whether a tool call is permitted under this policy (deny-by-default)."""
        resolved = self.target_dir.resolve()
        if tool_name == "Write":
            return evaluate_write(input_data, resolved, self.allowed_output_files)
        if tool_name == "Bash":
            return PermissionDecision(
                False,
                "Bash is disabled in validation sessions — no shell execution permitted",
                True,
            )
        return self._evaluate_simple(tool_name)
