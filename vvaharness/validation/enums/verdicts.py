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

"""Fix-validation verdict vocabulary emitted by the scoring engine and agent."""

from __future__ import annotations

from enum import StrEnum

__all__ = ["Answer", "FixVerdict"]


class FixVerdict(StrEnum):
    """Outcome of validating a remediation patch against its finding."""

    FIXED = "Fixed"
    PARTIALLY_FIXED = "Partially Fixed"
    NOT_FIXED = "Not Fixed"
    UNVERIFIABLE = "UNVERIFIABLE"

    @classmethod
    def parse(cls, value: str) -> FixVerdict:
        """Map an agent-emitted string to a verdict, defaulting to UNVERIFIABLE."""
        try:
            return cls(value)
        except ValueError:
            return cls.UNVERIFIABLE


class Answer(StrEnum):
    """Tri-state answer flag rendered into a result row."""

    YES = "Yes"
    NO = "No"
    UNKNOWN = "?"
