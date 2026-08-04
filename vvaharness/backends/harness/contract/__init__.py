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

"""Neutral contract types shared across all backend implementations."""

from __future__ import annotations

from .errors import (
    HarnessCLINotFoundError,
    HarnessConnectionError,
    HarnessError,
    HarnessJSONDecodeError,
    HarnessMessageParseError,
    HarnessProcessError,
)
from .messages import (
    HarnessAssistantText,
    HarnessMessage,
    HarnessResult,
    HarnessSessionInit,
    HarnessToolResult,
    HarnessToolUse,
    OneShotResult,
)
from .options import OneShotOptions, StreamingOptions
from .permissions import (
    PermissionDecision,
    PermissionsPolicy,
)
from .subagents import SubagentDefinition
from .tool_policy import ToolPolicy

__all__ = [
    "HarnessAssistantText",
    "HarnessCLINotFoundError",
    "HarnessConnectionError",
    "HarnessError",
    "HarnessJSONDecodeError",
    "HarnessMessage",
    "HarnessMessageParseError",
    "HarnessProcessError",
    "HarnessResult",
    "HarnessSessionInit",
    "HarnessToolResult",
    "HarnessToolUse",
    "OneShotOptions",
    "OneShotResult",
    "PermissionDecision",
    "PermissionsPolicy",
    "StreamingOptions",
    "SubagentDefinition",
    "ToolPolicy",
]
