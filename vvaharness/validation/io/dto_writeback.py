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

"""Write the agentic verdict back into the remediation DTO's validation block.

The host persists each session's structured narrative to the per-finding
``validation_report.json`` in the staged workspace. This module folds it back
into the canonical ``remediate_report.json`` sidecar — filling the ``validation``
block (the shape laid out by ``remediation_agent.artifacts.empty_validation``) and
advancing ``status`` — so the DTO carries its own outcome. The terminal status is
three-way: FIXED → ``validated``; NOT_FIXED / PARTIALLY_FIXED → ``validation_failed``
(distinct from a pass, and re-validatable so a corrected patch re-drives next run);
a hard session failure (UNVERIFIABLE) returns the DTO to ``needs_review``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from vvaharness.validation.constants.artifacts import (
    STATUS_NEEDS_REVIEW,
    STATUS_VALIDATED,
    STATUS_VALIDATION_FAILED,
    VALIDATION_REPORT_FILENAME,
)
from vvaharness.validation.enums.verdicts import FixVerdict
from vvaharness.validation.io._host_score import (
    HostScore,
    effective_score,
    host_score_for,
    load_synthesized_gates,
)
from vvaharness.validation.models import FixFindingReport, RemediationReport, ValidationReport

log = logging.getLogger(__name__)

# Marker recorded in the written block, distinct from the empty-on-input sentinel
# emitted by remediation_agent.artifacts.empty_validation.
_BLOCK_SOURCE = "s11 validation"


def _load_verdict(workspace: Path, finding_id: str) -> FixFindingReport:
    """Return the agent's verdict for *finding_id*, or a default UNVERIFIABLE report.

    Reads the workspace ``validation_report.json``; a missing or unreadable file
    (e.g. the session failed before writing one) yields a default FixFindingReport,
    whose ``fix_status`` is UNVERIFIABLE.
    """
    report_path: Path = workspace / VALIDATION_REPORT_FILENAME
    try:
        report: ValidationReport = ValidationReport.from_file(report_path)
    except (OSError, ValueError):
        log.warning("no readable validation report at %s; recording UNVERIFIABLE", report_path)
        return FixFindingReport()
    for finding in report.findings:
        if finding.tracking_id == finding_id:
            return finding
    return report.findings[0] if report.findings else FixFindingReport()


def _validation_block(ff: FixFindingReport, host: HostScore) -> dict[str, object]:
    """Build the DTO ``validation`` block: host-computed numbers, agent narrative.

    The deterministic host verdict (fix_status / raw_score / merge_readiness /
    gate_scores) is authoritative — *host* is already fail-closed via ``effective_score``,
    so an unscored finding records UNVERIFIABLE here. The agent's narrative fields are
    always kept.
    """
    return {
        "_source": _BLOCK_SOURCE,
        "fix_status": host.fix_status,
        "raw_score": host.raw_score,
        "merge_readiness": host.merge_readiness,
        "gate_scores": host.gate_scores,
        "justification": ff.justification,
        "conditions_for_full_fix": list(ff.conditions_for_full_fix),
        "recommendations": list(ff.recommendations),
    }


def _terminal_status(fix_status: str) -> str:
    """Map a verdict to the DTO status (three-way).

    FIXED → validated; NOT_FIXED / PARTIALLY_FIXED → validation_failed (a real but
    non-passing verdict); UNVERIFIABLE — including any unparseable status, which
    FixVerdict.parse maps to UNVERIFIABLE — → needs_review.
    """
    verdict: FixVerdict = FixVerdict.parse(fix_status)
    if verdict is FixVerdict.UNVERIFIABLE:
        return STATUS_NEEDS_REVIEW
    if verdict is FixVerdict.FIXED:
        return STATUS_VALIDATED
    return STATUS_VALIDATION_FAILED


def _load_raw_dto(path: Path) -> dict[str, object] | None:
    """Read the DTO as a raw dict (preserving unmodeled fields), or None on failure."""
    try:
        loaded: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("could not read DTO for write-back at %s", path)
        return None
    return loaded if isinstance(loaded, dict) else None


def _dump_raw_dto(path: Path, dto: dict[str, object]) -> bool:
    """Write the DTO dict back to *path*; return True on success."""
    try:
        path.write_text(json.dumps(dto, indent=2) + "\n", encoding="utf-8")
    except OSError:
        log.warning("could not write DTO verdict back to %s", path)
        return False
    return True


def write_back_validation(
    report: RemediationReport, workspace: Path, *, session_failed: bool = False
) -> str | None:
    """Fold the workspace verdict into the DTO's validation block + status.

    Returns the written status, or None if there is no source path to write to or
    the DTO file could not be read/written.

    *session_failed* marks a hard session/agent failure. It discards the host score so the
    already fail-closed ``effective_score`` path records UNVERIFIABLE → ``needs_review``,
    even if a partial ``synthesized_gates.json`` survived in the workspace. Defence in
    depth: the launcher no longer writes artifacts for a failed session.
    """
    dto_path: Path | None = report.source_path
    if dto_path is None:
        return None
    dto: dict[str, object] | None = _load_raw_dto(dto_path)
    if dto is None:
        return None
    verdict: FixFindingReport = _load_verdict(workspace, report.finding_id)
    host = effective_score(
        None if session_failed
        else host_score_for(report.finding_id, load_synthesized_gates(workspace))
    )
    status: str = _terminal_status(host.fix_status)
    dto["validation"] = _validation_block(verdict, host)
    dto["status"] = status
    return status if _dump_raw_dto(dto_path, dto) else None
