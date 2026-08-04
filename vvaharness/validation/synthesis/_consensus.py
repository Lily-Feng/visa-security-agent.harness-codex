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

"""Deterministic synthesis of persona gate reports into host-owned gate verdicts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from pydantic import BaseModel

from vvaharness.validation.constants.synthesis import (
    CONFIDENCE_FLAGGED,
    CONFIDENCE_HIGH,
    MIN_CONSENSUS_VOTES,
)
from vvaharness.validation.enums.gates import _STATUS_CONSERVATIVE_RANK, GateStatus
from vvaharness.validation.models.persona_report import (
    PersonaGateEntry,
    PersonaReport,
)


class SynthesizedGate(BaseModel):
    """Host-produced gate verdict for one finding."""

    tracking_id: str
    gate_name: str
    status: str
    confidence: str  # CONFIDENCE_HIGH | CONFIDENCE_FLAGGED
    summary: str
    details: str
    evidence: list[dict]
    persona_votes: dict[str, str]


def _most_conservative_status(statuses: Iterable[str]) -> str:
    """Return the most conservative status in *statuses*."""
    present = set(statuses)
    for status in _STATUS_CONSERVATIVE_RANK:
        if status.value in present:
            return status.value
    return GateStatus.INVALID.value


def synthesize_gates_for_finding(
    reports: list[PersonaReport],
    tracking_id: str,
) -> list[SynthesizedGate]:
    """Apply deterministic conservative consensus to persona reports.

    Rules:
      * ``skip`` is an abstention, not an opinion: it is excluded from the tally, so
        personas that did not evaluate a gate can never outvote one that did. Only
        when nobody evaluated it does the gate stay ``skip`` -- which matters because
        the engine drops a skipped gate from both sides of the score, so letting a
        skip majority bury a ``fail`` would erase that failure from the verdict.
      * a single most-common status with 2+ votes -> that status, confidence HIGH
      * a tie for most-common (incl. an even split) -> most conservative of the
        tied statuses, confidence FLAGGED (never an insertion-order winner)
      * one persona / all disagree -> most conservative status, FLAGGED
    """
    by_gate: dict[str, list[tuple[str, PersonaGateEntry]]] = {}
    for report in reports:
        if report.tracking_id != tracking_id:
            continue
        for gate in report.gates:
            by_gate.setdefault(gate.gate_name, []).append((report.persona, gate))

    synthesized: list[SynthesizedGate] = []
    for gate_name, entries in sorted(by_gate.items()):
        # One vote per persona: a report listing the same gate twice would otherwise
        # be last-write-wins, dropping a fail and faking a second agreeing vote.
        votes: dict[str, str] = {}
        for persona, gate in entries:
            prior = votes.get(persona)
            votes[persona] = (
                _most_conservative_status([prior, gate.status]) if prior else gate.status
            )

        evaluated = [s for s in votes.values() if s != GateStatus.SKIP.value]
        if not evaluated:
            chosen_status, confidence = GateStatus.SKIP.value, CONFIDENCE_FLAGGED
        else:
            counter = Counter(evaluated)
            top_frequency = max(counter.values())
            top_statuses = [s for s, freq in counter.items() if freq == top_frequency]
            if len(top_statuses) == 1 and top_frequency >= MIN_CONSENSUS_VOTES:
                chosen_status, confidence = top_statuses[0], CONFIDENCE_HIGH
            else:
                chosen_status = _most_conservative_status(top_statuses)
                confidence = CONFIDENCE_FLAGGED

        summaries: list[str] = []
        details_pieces: list[str] = []
        evidence: list[dict] = []
        for persona, gate in sorted(entries, key=lambda item: item[0]):
            if gate.summary:
                summaries.append(f"{persona}: {gate.summary}")
            if gate.details:
                details_pieces.append(f"{persona}: {gate.details}")
            evidence.extend(
                {
                    "persona": persona,
                    "file": ev.file,
                    "line": ev.line,
                    "snippet": ev.snippet,
                }
                for ev in gate.evidence
            )

        synthesized.append(
            SynthesizedGate(
                tracking_id=tracking_id,
                gate_name=gate_name,
                status=chosen_status,
                confidence=confidence,
                summary=" | ".join(summaries),
                details=" | ".join(details_pieces),
                evidence=sorted(
                    evidence,
                    key=lambda item: (item["file"] or "", item["line"] or 0),
                ),
                persona_votes=dict(sorted(votes.items())),
            )
        )

    return synthesized
