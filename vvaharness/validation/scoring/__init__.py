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

"""Public scoring API: parse raw gate dicts and return typed ValidationScore results."""

from collections.abc import Mapping

from vvaharness.validation.enums.gates import GateName, GateStatus
from vvaharness.validation.enums.readiness import MergeReadiness
from vvaharness.validation.enums.verdicts import FixVerdict
from vvaharness.validation.models.scoring import (
    EvidenceAnchor,
    GateResult,
    RawCriterion,
    ValidationScore,
)

from ._configs import FIX_CONFIG
from ._engine import _CRITICAL_NOT_CLEAN, parse_raw_criterion
from ._engine import score as _score

__all__ = [
    "EvidenceAnchor",
    "FixVerdict",
    "GateName",
    "GateResult",
    "GateStatus",
    "MergeReadiness",
    "ValidationScore",
    "derive_merge_readiness",
    "score_fix",
]


def _parse_gates(raw: list[Mapping[str, object]]) -> list[RawCriterion]:
    return [parse_raw_criterion(gate, FIX_CONFIG.criterion_name_field) for gate in raw]


def _has_critical_failure(parsed: list[RawCriterion]) -> bool:
    """True when a critical gate is not clean (fail or partial) — the verdict is capped."""
    return any(
        criterion.name in FIX_CONFIG.critical_criteria
        and criterion.status in _CRITICAL_NOT_CLEAN
        for criterion in parsed
    )


def score_fix(gates: list[Mapping[str, object]]) -> ValidationScore:
    """Score a list of raw gate dicts and return a typed ValidationScore."""
    parsed = _parse_gates(gates)
    result = _score(FIX_CONFIG, parsed)
    return ValidationScore(
        raw_score=result.raw_score,
        fix_status=FixVerdict.parse(result.verdict_label),
        justification=result.justification,
        gate_results=_build_gate_results(parsed),
        has_critical_failure=_has_critical_failure(parsed),
    )


def derive_merge_readiness(score: ValidationScore) -> MergeReadiness:
    """Map a ValidationScore's fix_status to a MergeReadiness value."""
    if score.fix_status == FixVerdict.FIXED:
        return MergeReadiness.READY
    if score.fix_status == FixVerdict.PARTIALLY_FIXED:
        return MergeReadiness.READY_WITH_CONDITIONS
    return MergeReadiness.NOT_READY


_VALID_GATE_NAMES = frozenset(gate.value for gate in GateName)


def _build_gate_results(parsed: list[RawCriterion]) -> list[GateResult]:
    # Skip unrecognized gate names: a hallucinated name already forces
    # UNVERIFIABLE in the engine, and GateName(<unknown>) would raise here.
    return [
        GateResult(
            gate=GateName(criterion.name),
            status=GateStatus.parse(criterion.status),
            summary=criterion.summary,
            evidence=[
                EvidenceAnchor(file=anchor.file, line=anchor.line, snippet=anchor.snippet)
                for anchor in criterion.evidence
            ],
            details=criterion.details,
        )
        for criterion in parsed
        if criterion.name in _VALID_GATE_NAMES
    ]
