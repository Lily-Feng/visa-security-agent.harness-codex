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

"""Shared agent-harness abstraction.

A backend-neutral contract (:class:`Harness`, the ``contract`` dataclasses, and
the ``get_harness`` registry) plus concrete backends (deepagents, claude).
Any consumer — validation, remediation, orchestrator — configures a run purely
through the contract types here; validation-specific values (its output schema,
fact tools, read-only policy) are injected by the caller, never hardwired.
"""

from vvaharness.backends.harness.base import Harness
from vvaharness.backends.harness.contract import (
    HarnessAssistantText,
    HarnessCLINotFoundError,
    HarnessConnectionError,
    HarnessError,
    HarnessJSONDecodeError,
    HarnessMessage,
    HarnessMessageParseError,
    HarnessProcessError,
    HarnessResult,
    HarnessSessionInit,
    HarnessToolResult,
    HarnessToolUse,
    OneShotOptions,
    OneShotResult,
    PermissionDecision,
    PermissionsPolicy,
    StreamingOptions,
    SubagentDefinition,
    ToolPolicy,
)
from vvaharness.backends.harness.registry import get_harness

__all__ = [
    "Harness",
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
    "get_harness",
]
