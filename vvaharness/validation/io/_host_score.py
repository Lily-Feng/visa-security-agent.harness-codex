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

"""Deterministic host-side scoring from host-persisted ``synthesized_gates.json``.

Validation sessions return structured gate statuses; depending on the backend,
the in-session orchestrator or host code synthesizes persona results. Host code
writes the gates artifact and computes the verdict here via the canonical
scoring engine, so agent-authored arithmetic is never authoritative.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from vvaharness.validation.constants.artifacts import SYNTHESIZED_GATES_FILENAME
from vvaharness.validation.constants.scoring import SCORE_PRECISION
from vvaharness.validation.enums.gates import GateStatus
from vvaharness.validation.enums.readiness import MergeReadiness
from vvaharness.validation.enums.verdicts import FixVerdict
from vvaharness.validation.scoring import derive_merge_readiness, score_fix
from vvaharness.validation.scoring._configs import FIX_CONFIG

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class HostScore:
    """Deterministic verdict the host computes from the agent's synthesized gates."""

    fix_status: str
    raw_score: float
    merge_readiness: str
    gate_scores: dict[str, dict[str, object]]


def _read_gates_text(workspace_dir: Path) -> str | None:
    """Read synthesized_gates.json; None when absent — the normal, silent fail-closed case."""
    try:
        return (workspace_dir / SYNTHESIZED_GATES_FILENAME).read_text(encoding="utf-8")
    except OSError:
        # No file written: the agent produced no gates. Normal; fail closed silently.
        return None


def _parse_gates_array(text: str) -> list[object] | None:
    """Parse the gates JSON array; None (with a warning) when unparseable or not an array."""
    try:
        data: object = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        log.warning("%s present but unparseable; failing closed", SYNTHESIZED_GATES_FILENAME)
        return None
    if isinstance(data, list):
        return data
    log.warning("%s is not a JSON array; failing closed", SYNTHESIZED_GATES_FILENAME)
    return None


def _gates_by_tracking_id(data: list[object]) -> dict[str, list[Mapping[str, object]]]:
    """Index well-formed entries by tracking_id; drop and count malformed ones."""
    gates_by_id: dict[str, list[Mapping[str, object]]] = {}
    dropped: int = 0
    for entry in data:
        if isinstance(entry, Mapping) and isinstance(entry.get("gates"), list):
            gates_by_id[str(entry.get("tracking_id", ""))] = entry["gates"]
        else:
            dropped += 1
    if dropped:
        log.warning("dropped %d malformed entries from %s", dropped, SYNTHESIZED_GATES_FILENAME)
    return gates_by_id


def load_synthesized_gates(workspace_dir: Path) -> dict[str, list[Mapping[str, object]]]:
    """Map tracking_id -> raw gate dicts from the host-written synthesized_gates.json.

    Returns {} for both an absent and a malformed file, so the caller fails closed
    (recording UNVERIFIABLE) rather than trusting the agent's self-reported verdict.
    An absent file is the normal case and stays silent; a present-but-unparseable or
    non-array payload, and any dropped malformed entry, are logged as warnings.
    """
    text: str | None = _read_gates_text(workspace_dir)
    if text is None:
        return {}
    data: list[object] | None = _parse_gates_array(text)
    if data is None:
        return {}
    return _gates_by_tracking_id(data)


def effective_score(host: HostScore | None) -> HostScore:
    """Return *host* when present, else a fail-closed UNVERIFIABLE verdict.

    The deterministic host recompute is the sole source of the numeric verdict. When it
    is unavailable (no or unparseable synthesized_gates.json), we fail closed to
    UNVERIFIABLE — never the agent's self-reported fix_status. UNVERIFIABLE maps to the
    re-validatable ``needs_review`` DTO status downstream, so the finding is not lost.
    """
    if host is not None:
        return host
    return HostScore(
        fix_status=FixVerdict.UNVERIFIABLE.value,
        raw_score=0.0,
        merge_readiness=MergeReadiness.NOT_READY.value,
        gate_scores={},
    )


def _gate_scores(gates: list[Mapping[str, object]]) -> dict[str, dict[str, object]]:
    """Per-gate {status, weight, weighted_score} computed from the canonical matrix."""
    scores: dict[str, dict[str, object]] = {}
    for gate in gates:
        name = str(gate.get("gate_name", ""))
        # Canonicalise as the engine does, or a variant like "PASS" scores 0 here while
        # the engine scores it 1.0 -- publishing a gate table that contradicts the verdict.
        gate_status = GateStatus.parse(gate.get("status")).value
        weight = FIX_CONFIG.weights.get(name, 0.0)
        multiplier = FIX_CONFIG.status_multiplier.get(gate_status, 0.0)
        scores[name] = {
            "status": gate_status,
            "weight": weight,
            "weighted_score": round(weight * multiplier, SCORE_PRECISION),
        }
    return scores


def host_score_for(
    finding_id: str,
    gates_by_id: dict[str, list[Mapping[str, object]]],
) -> HostScore | None:
    """Deterministically re-score one finding from its synthesized gates; None if unavailable.

    Matches strictly by ``finding_id`` (its own gates only); a missing key returns ``None`` so
    the caller fails closed to UNVERIFIABLE rather than scoring this finding with another's gates.
    """
    gates = gates_by_id.get(finding_id)
    if not gates:
        return None
    score = score_fix(gates)
    return HostScore(
        fix_status=score.fix_status.value,
        raw_score=score.raw_score,
        merge_readiness=derive_merge_readiness(score).value,
        gate_scores=_gate_scores(gates),
    )
