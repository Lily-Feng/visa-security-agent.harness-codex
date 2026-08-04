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

"""Gate-evaluation enums for the fix-validation scoring path."""

from __future__ import annotations

from enum import StrEnum

__all__ = ["GateName", "GateStatus"]


class GateStatus(StrEnum):
    """Per-gate evaluation outcome reported by the scoring agent."""

    PASS = "pass"  # noqa: S105
    PARTIAL = "partial"
    FAIL = "fail"
    SKIP = "skip"
    # non-str / out-of-vocab status: scored 0.0 and kept in the denominator (fail-closed)
    INVALID = "invalid"

    @classmethod
    def parse(cls, value: object) -> GateStatus:
        """Map an agent status to a GateStatus; non-str/out-of-vocab -> INVALID (fail-closed)."""
        if not isinstance(value, str):
            return cls.INVALID
        try:
            return cls(value.strip().lower())
        except ValueError:
            return cls.INVALID


# Most-severe-first ordering used by deterministic persona synthesis when personas
# disagree. Fail is most conservative; invalid is a last-resort fallback.
_STATUS_CONSERVATIVE_RANK = (
    GateStatus.FAIL,
    GateStatus.PARTIAL,
    GateStatus.PASS,
    GateStatus.SKIP,
    GateStatus.INVALID,
)


class GateName(StrEnum):
    """Canonical gate identifiers for the fix-validation path."""

    ROOT_CAUSE = "root_cause"
    INSTANCE_COVERAGE = "instance_coverage"
    NO_NEW_VULNERABILITIES = "no_new_vulnerabilities"
    SECURITY_BEST_PRACTICES = "security_best_practices"
