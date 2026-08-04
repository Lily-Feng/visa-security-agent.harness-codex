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

"""Constant tool-name vocabularies for the validation agent."""

from __future__ import annotations

# Logical read-only tool names DeepAgents grants to validation subagents: the three
# native readers plus five deterministic fact tools. Claude CLI/SDK personas receive
# their configured built-in reader list; they do not consume this backend-specific field.
DEFAULT_FACT_TOOLS: tuple[str, ...] = (
    "Read",
    "Grep",
    "Glob",
    "DiffTouched",
    "ChangedLines",
    "DiffImpactMap",
    "PatternScan",
    "TestInventory",
)
