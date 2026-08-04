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

"""Validation-specific harness policy values (read-only tool allow-list + write gate).

These are the validation-domain values the shared harness contract deliberately
does not own: the read-only tool policy and the two host-owned workspace artifact
names retained in the defence-in-depth permission gate. The generic ``ToolPolicy`` /
``PermissionsPolicy`` classes live in ``vvaharness.backends.harness.contract``; this
module supplies the values.
"""

from __future__ import annotations

from vvaharness.backends.harness.contract.tool_policy import ToolPolicy
from vvaharness.validation.constants.artifacts import (
    SYNTHESIZED_GATES_FILENAME,
    VALIDATION_REPORT_FILENAME,
)

# Read + orchestration tools only; Edit/NotebookEdit/Bash are denied outright.
# No Write: the agent returns its verdict as structured output and the host persists
# every artifact. Granting Write would let an agent-authored validation_report.json
# survive and be scored, which is the self-reported verdict host-side scoring exists
# to prevent.
VALIDATION_POLICY = ToolPolicy(
    allowed_tools=("Read", "Grep", "Glob", "Agent"),
    disallowed_tools=("Write", "Edit", "NotebookEdit", "Bash"),
)

# Defence in depth for the SDK permission callback: if a future adapter exposes Write,
# these are the only workspace files it could target. The current ToolPolicy withholds
# Write entirely; the host creates both artifacts from structured output.
DEFAULT_ALLOWED_OUTPUT_FILES: frozenset[str] = frozenset({
    VALIDATION_REPORT_FILENAME,
    SYNTHESIZED_GATES_FILENAME,
})

__all__ = ["DEFAULT_ALLOWED_OUTPUT_FILES", "VALIDATION_POLICY"]
