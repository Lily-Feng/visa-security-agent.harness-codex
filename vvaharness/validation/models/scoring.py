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

"""Value types shared between the scoring engine and the rest of the package."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import NotRequired

# TypedDict stays on typing_extensions: pydantic requires its variant below 3.12.
from typing_extensions import TypedDict

from vvaharness.validation.enums.gates import GateName, GateStatus
from vvaharness.validation.enums.readiness import MergeReadiness
from vvaharness.validation.enums.verdicts import FixVerdict

__all__ = [
    "EvidenceAnchor",
    "GateResult",
    "MergeReadiness",
    "RawCriterion",
    "RawEvidence",
    "RawExtra",
    "ScoreResult",
    "ScoredGateEntry",
    "ScoringConfig",
    "ValidationScore",
    "VerdictRule",
]

#: Auxiliary input passed through to justifiers.
RawExtra = Mapping[str, object]


@dataclass(frozen=True)
class RawEvidence:
    """Typed view of one evidence item attached to a criterion."""

    file: str = ""
    line: int | None = None
    snippet: str = ""


@dataclass(frozen=True)
class RawCriterion:
    """Typed view of a single gate/criterion emitted by the agent (name-folded across paths)."""

    name: str
    status: str
    summary: str = ""
    details: str = ""
    evidence: tuple[RawEvidence, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class VerdictRule:
    """Threshold-to-label mapping entry in a ScoringConfig."""

    min_score: float
    label: str


@dataclass(frozen=True)
class ScoreResult:
    """Raw output of the scoring engine before verdict mapping."""

    raw_score: float
    verdict_label: str
    justification: str


@dataclass(frozen=True)
class ScoringConfig:
    """Full specification of one scoring path (e.g. fix-validation)."""

    name: str
    criterion_name_field: str
    expected_criteria: frozenset[str]
    weights: dict[str, float]
    status_multiplier: dict[str, float]
    verdicts: tuple[VerdictRule, ...]
    unverifiable_label: str
    justify: Callable[[ScoreResult, list[RawCriterion], RawExtra], str]
    # Gates that may not be skipped/garbled (-> UNVERIFIABLE) and cap the verdict below the
    # top label on FAIL, regardless of the numeric score.
    critical_criteria: frozenset[str] = frozenset()


class ScoredGateEntry(TypedDict):
    """Wire-shape entry for a single scored gate in the JSON output."""

    status: str
    weight: float
    weighted_score: float
    score: NotRequired[float]


@dataclass
class EvidenceAnchor:
    """File/line reference pinning a gate verdict to source evidence."""

    file: str
    line: int | None
    snippet: str


@dataclass
class GateResult:
    """Scored result for a single validation gate."""

    gate: GateName
    status: GateStatus
    summary: str
    evidence: list[EvidenceAnchor]
    details: str


@dataclass
class ValidationScore:
    """Aggregate scoring output for one fix-validation run."""

    raw_score: float
    fix_status: FixVerdict
    justification: str
    gate_results: list[GateResult]
    has_critical_failure: bool
