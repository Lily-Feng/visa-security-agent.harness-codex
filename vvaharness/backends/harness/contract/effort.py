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

"""Agent reasoning-effort vocabulary passed through to the SDK."""

from __future__ import annotations

from vvaharness.backends.harness.contract._compat import StrEnum


class EffortLevel(StrEnum):
    """Reasoning-effort tier accepted by the agent backend."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"

    @classmethod
    def parse(cls, value: str | None) -> EffortLevel | None:
        """Map a string to an effort tier, returning None when absent or invalid."""
        try:
            return cls(value)
        except ValueError:
            return None
