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

"""Collect fix-validation results from the agent session output."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from vvaharness.validation.constants.artifacts import (
    DEFAULT_SEVERITY,
    MANIFEST_FILENAME,
    VALIDATION_REPORT_FILENAME,
)
from vvaharness.validation.constants.paths import ValidationPath
from vvaharness.validation.enums.verdicts import Answer, FixVerdict
from vvaharness.validation.io._host_score import (
    HostScore,
    effective_score,
    host_score_for,
    load_synthesized_gates,
)
from vvaharness.validation.models import (
    FixFindingReport,
    Manifest,
    ValidationReport,
    ValidationResult,
)

if TYPE_CHECKING:
    from vvaharness.validation.models import ManifestFinding

log = logging.getLogger(__name__)

# Drop affected-file entries shorter than this (junk / placeholder fragments).
_MIN_AFFECTED_FILE_LEN = 3


def _files_needing_fixes(report: FixFindingReport) -> str:
    """Prefer the agent's full-fix conditions, falling back to the explicit field."""
    if report.conditions_for_full_fix:
        return "; ".join(report.conditions_for_full_fix)
    return report.files_needing_fixes


def _build_result(
    report: FixFindingReport,
    finding_number: int,
    host: HostScore | None = None,
) -> ValidationResult:
    """Build a host-facing ValidationResult from one agent fix finding.

    The deterministic host recompute is the sole source of the numeric verdict
    (fix_status / raw_score / merge_readiness / gate_scores). When the host could not
    score the finding from synthesized_gates.json, ``effective_score`` fails closed to
    UNVERIFIABLE rather than trusting the agent's self-report. The agent's narrative
    (justification, recommendations, files_needing_fixes) is always preserved.
    """
    host = effective_score(host)
    fix_status = host.fix_status
    raw_score = host.raw_score
    merge_readiness = host.merge_readiness
    gate_scores = host.gate_scores
    status = FixVerdict.parse(fix_status)
    return ValidationResult(
        finding_number=finding_number,
        tracking_id=report.tracking_id,
        finding_title=report.finding_title,
        finding_description=report.finding_description,
        affected_files=report.affected_files,
        fixed=Answer.YES if status is FixVerdict.FIXED else Answer.NO,
        partially_fixed=Answer.YES if status is FixVerdict.PARTIALLY_FIXED else Answer.NO,
        not_fixed=Answer.YES if status is FixVerdict.NOT_FIXED else Answer.NO,
        files_needing_fixes=_files_needing_fixes(report),
        reason_for_decision=(
            f"{fix_status} (score: {raw_score}). {report.justification}"
        ),
        severity=report.severity,
        pr_merge_readiness=merge_readiness,
        recommendations="; ".join(report.recommendations),
        fix_confidence=raw_score,
        gate_results_json=json.dumps(gate_scores) if gate_scores else "",
        justification=report.justification,
        validation_path=ValidationPath.FIX_VALIDATION,
    )


def collect_results(
    workspace_dir: Path,
    finding_number_start: int = 0,
) -> list[ValidationResult]:
    """Parse validation_report.json into per-finding ValidationResults.

    The verdict (fix_status / raw_score / merge_readiness) is recomputed host-side from the
    host-persisted synthesized_gates.json via the deterministic scoring engine; when those
    gates are unavailable the verdict fails closed to UNVERIFIABLE, never the agent's
    self-reported number.
    """
    report_path = workspace_dir / VALIDATION_REPORT_FILENAME
    try:
        report = ValidationReport.from_file(report_path)
    except (json.JSONDecodeError, OSError, ValueError):
        log.warning("Could not read validation report at %s", report_path)
        return []

    gates_by_id = load_synthesized_gates(workspace_dir)
    return [
        _build_result(
            finding, finding_number_start + i, host_score_for(finding.tracking_id, gates_by_id)
        )
        for i, finding in enumerate(report.findings)
    ]


def _filter_affected_files(affected: list[str]) -> str:
    """Drop comment markers and sub-threshold fragments, then join."""
    kept = [
        f for f in affected
        if not f.startswith("//") and len(f) > _MIN_AFFECTED_FILE_LEN
    ]
    return ", ".join(kept)


def _load_manifest(workspace_dir: Path) -> Manifest | None:
    """Load Manifest from workspace; return None on any parse/IO failure."""
    try:
        return Manifest.from_file(workspace_dir / MANIFEST_FILENAME)
    except (json.JSONDecodeError, OSError, ValueError):
        return None


def collect_and_enrich(
    workspace_dir: Path,
    finding_number_start: int = 0,
) -> list[ValidationResult]:
    """Collect results and enrich blank fields from manifest.json."""
    results = collect_results(workspace_dir, finding_number_start)
    if not results:
        return results
    manifest = _load_manifest(workspace_dir)
    if manifest is None or manifest.finding is None:
        return results
    for r in results:
        _enrich_result(r, manifest.finding, manifest.jira_key)
    return results


def _enrich_tracking_id(r: ValidationResult, finding: ManifestFinding, jira_key: str) -> None:
    """Fill tracking_id when blank or defaulting to the JIRA key."""
    if not r.tracking_id or r.tracking_id == jira_key:
        r.tracking_id = finding.tracking_id or jira_key


def _enrich_result(r: ValidationResult, finding: ManifestFinding, jira_key: str) -> None:
    """Fill blank fields on a single result from the manifest finding."""
    if not r.finding_title:
        r.finding_title = finding.title
    if not r.finding_description:
        r.finding_description = finding.category.replace("\\n", " ").strip()
    if r.severity == DEFAULT_SEVERITY and finding.severity:
        r.severity = finding.severity
    if not r.affected_files:
        r.affected_files = _filter_affected_files(finding.affected_files)
    _enrich_tracking_id(r, finding, jira_key)
