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

"""Loop-budget constants for the DeepAgents backend.

Free of ``deepagents`` imports so callers needing only the budget work on 3.10.
"""

from __future__ import annotations

# Extra LangGraph supersteps allowed beyond max_turns, so a long tool loop is not
# truncated mid-flight.
RECURSION_HEADROOM: int = 900

__all__ = ["RECURSION_HEADROOM"]
