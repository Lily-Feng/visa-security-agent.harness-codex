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

"""DeepAgents validation backend (additive alternative to claude_agent_sdk).

``DeepAgentHarness`` resolves lazily: an eager import pulls the ``deepagents``
distribution (3.11+) into every sibling import, breaking 3.10 callers that never
select this backend.
"""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vvaharness.backends.harness.deepagents.client import DeepAgentHarness

__all__ = ["DeepAgentHarness"]


def __getattr__(name: str) -> Any:
    """Resolve ``DeepAgentHarness`` on first access (PEP 562)."""
    if name == "DeepAgentHarness":
        from vvaharness.backends.harness.deepagents.client import DeepAgentHarness

        return DeepAgentHarness
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
