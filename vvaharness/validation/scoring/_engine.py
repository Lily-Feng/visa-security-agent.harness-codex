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

"""Config-driven scoring engine; re-exports scoring dataclasses for intra-package compat."""

from collections.abc import Mapping

from vvaharness.validation.constants.scoring import (
    SCORE_FLOOR,
    SCORE_PRECISION,
)
from vvaharness.validation.enums.gates import GateStatus
from vvaharness.validation.models.scoring import (
    RawCriterion,
    RawEvidence,
    RawExtra,
    ScoreResult,
    ScoringConfig,
    VerdictRule,
)

__all__ = [
    "RawCriterion",
    "RawEvidence",
    "RawExtra",
    "ScoreResult",
    "ScoringConfig",
    "VerdictRule",
    "parse_raw_criterion",
    "score",
]


def _str_from(entry: Mapping[str, object], key: str, default: str = "") -> str:
    value = entry.get(key, default)
    return value if isinstance(value, str) else default


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _parse_evidence(entry: Mapping[str, object]) -> RawEvidence:
    return RawEvidence(
        file=_str_from(entry, "file"),
        line=_int_or_none(entry.get("line")),
        snippet=_str_from(entry, "snippet"),
    )


def parse_raw_criterion(
    entry: Mapping[str, object], name_field: str,
) -> RawCriterion:
    """Narrow one agent-emitted dict into a typed RawCriterion."""
    evidence_raw = entry.get("evidence", [])
    evidence: tuple[RawEvidence, ...] = ()
    if isinstance(evidence_raw, list):
        evidence = tuple(
            _parse_evidence(e) for e in evidence_raw if isinstance(e, Mapping)
        )
    return RawCriterion(
        name=_str_from(entry, name_field),
        # Canonicalize status at this single choke point so a bad/case-variant
        # agent status can never reach the strict GateStatus enum downstream.
        status=GateStatus.parse(_str_from(entry, "status")).value,
        summary=_str_from(entry, "summary"),
        details=_str_from(entry, "details"),
        evidence=evidence,
    )


def _shape_error(cfg: ScoringConfig, raw: list[RawCriterion]) -> ScoreResult | None:
    """Return an UNVERIFIABLE result when the criteria set is malformed, else None."""
    names: list[str] = [c.name for c in raw]
    provided: set[str] = set(names)
    if provided != cfg.expected_criteria:
        missing = sorted(cfg.expected_criteria - provided)
        return ScoreResult(
            raw_score=0.0,
            verdict_label=cfg.unverifiable_label,
            justification=(
                f"{cfg.unverifiable_label}: Missing criterion evaluations: "
                f"{', '.join(missing)}."
            ),
        )
    if len(names) != len(provided):
        duplicates: list[str] = sorted({n for n in names if names.count(n) > 1})
        return ScoreResult(
            raw_score=0.0,
            verdict_label=cfg.unverifiable_label,
            justification=(
                f"{cfg.unverifiable_label}: Duplicate criterion evaluations: "
                f"{', '.join(duplicates)}."
            ),
        )
    return None


def _renormalized_score(cfg: ScoringConfig, raw: list[RawCriterion]) -> ScoreResult | float:
    """Weighted score over evaluated (non-skip) gates.

    A skip is unevaluated — its weight is dropped from the denominator so it is
    weight-neutral, never an implicit failure. Returns the renormalized float, or an
    UNVERIFIABLE ScoreResult when no gate was evaluated at all.

    Coverage policy proper belongs to ``_critical_gate_error``: a critical gate that is
    skipped or invalid short-circuits to UNVERIFIABLE before this runs, which is a
    stronger guarantee than any aggregate weight threshold. The zero check below is
    therefore the divide-by-zero guard, reachable only for a config with no critical
    gates whose every criterion was skipped.
    """
    earned = 0.0
    active_weight = 0.0
    for c in raw:
        if c.status == GateStatus.SKIP.value:
            continue
        active_weight += cfg.weights[c.name]
        earned += cfg.weights[c.name] * cfg.status_multiplier.get(c.status, SCORE_FLOOR)
    if active_weight <= 0.0:
        return ScoreResult(
            raw_score=0.0,
            verdict_label=cfg.unverifiable_label,
            justification=f"{cfg.unverifiable_label}: no gates were evaluated.",
        )
    # clamp: a weights misconfig must never push the score above 1.0.
    return round(min(earned / active_weight, 1.0), SCORE_PRECISION)


_UNEVALUATED = frozenset({GateStatus.SKIP.value, GateStatus.INVALID.value})
# evaluated but not clean: a critical gate in either state caps the verdict below the top label
_CRITICAL_NOT_CLEAN = frozenset({GateStatus.PARTIAL.value, GateStatus.FAIL.value})


def _critical_gate_error(cfg: ScoringConfig, raw: list[RawCriterion]) -> ScoreResult | None:
    """UNVERIFIABLE when a critical gate is unevaluated (skip) or invalid -- it cannot be waived."""
    for c in raw:
        if c.name in cfg.critical_criteria and c.status in _UNEVALUATED:
            return ScoreResult(
                raw_score=0.0,
                verdict_label=cfg.unverifiable_label,
                justification=(
                    f"{cfg.unverifiable_label}: critical gate '{c.name}' was not evaluated "
                    f"(status '{c.status}')."
                ),
            )
    return None


def _cap_critical_fail(cfg: ScoringConfig, raw: list[RawCriterion], verdict_label: str) -> str:
    """Cap below the top label when a critical gate is not clean (fail or partial).

    A partial earns half credit, so on its own it cannot drop a 3-pass fix below the Fixed
    threshold; capping the label keeps the security gate from being out-weighted regardless
    of the numeric score. (skip/invalid never reach here — they short-circuit to UNVERIFIABLE.)
    """
    if not cfg.verdicts or verdict_label != cfg.verdicts[0].label:
        return verdict_label
    not_clean = any(
        c.name in cfg.critical_criteria and c.status in _CRITICAL_NOT_CLEAN for c in raw
    )
    return cfg.verdicts[1].label if (not_clean and len(cfg.verdicts) > 1) else verdict_label


def _precheck(cfg: ScoringConfig, raw: list[RawCriterion]) -> ScoreResult | None:
    """Fail-closed gates before scoring: malformed criteria set, or an unevaluated critical gate."""
    return _shape_error(cfg, raw) or _critical_gate_error(cfg, raw)


def score(
    cfg: ScoringConfig,
    raw: list[RawCriterion],
    extra: RawExtra | None = None,
) -> ScoreResult:
    """Score a list of parsed criteria against a scoring config."""
    extra = extra or {}
    precheck_error: ScoreResult | None = _precheck(cfg, raw)
    if precheck_error is not None:
        return precheck_error
    scored: ScoreResult | float = _renormalized_score(cfg, raw)
    if isinstance(scored, ScoreResult):
        return scored
    raw_score: float = scored
    verdict_label = _cap_critical_fail(cfg, raw, _apply_verdicts(cfg, raw_score))
    partial = ScoreResult(raw_score=raw_score, verdict_label=verdict_label, justification="")
    justification = cfg.justify(partial, raw, extra)

    return ScoreResult(
        raw_score=raw_score,
        verdict_label=verdict_label,
        justification=justification,
    )


def _apply_verdicts(cfg: ScoringConfig, raw_score: float) -> str:
    for rule in cfg.verdicts:
        if raw_score >= rule.min_score:
            return rule.label
    return cfg.unverifiable_label
