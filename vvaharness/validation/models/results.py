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

"""Host-side validation result models and the agent report contract."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vvaharness.report.redact import redact
from vvaharness.validation.constants.artifacts import DEFAULT_SEVERITY
from vvaharness.validation.constants.paths import ValidationPath
from vvaharness.validation.enums.readiness import MergeReadiness
from vvaharness.validation.enums.verdicts import Answer, FixVerdict


class RunMetadata(BaseModel):
    """Per-run counters surfaced to the caller."""

    model_config = ConfigDict(extra="forbid")

    total_findings: int = 0
    findings_processed: int = 0
    findings_failed: int = 0
    errors: list[str] = Field(default_factory=list)


class ValidationResult(BaseModel):
    """The host-facing, rendered result for a single validated finding."""

    model_config = ConfigDict(extra="forbid")

    finding_number: int
    tracking_id: str
    finding_title: str
    finding_description: str
    affected_files: str
    fixed: str
    partially_fixed: str
    not_fixed: str
    files_needing_fixes: str
    reason_for_decision: str
    severity: str
    pr_merge_readiness: str
    recommendations: str
    fix_confidence: float = 0.0
    gate_results_json: str = ""
    justification: str = ""
    validation_path: str = ""


class FixFindingReport(BaseModel):
    """One finding as emitted by the agent in ``validation_report.json``."""

    model_config = ConfigDict(extra="ignore")

    tracking_id: str = ""
    finding_title: str = ""
    finding_description: str = ""
    affected_files: str = ""
    severity: str = DEFAULT_SEVERITY
    fix_status: str = FixVerdict.UNVERIFIABLE.value
    raw_score: float = 0.0
    justification: str = ""
    merge_readiness: str = MergeReadiness.NOT_READY.value
    gate_scores: dict[str, object] = Field(default_factory=dict)
    conditions_for_full_fix: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    files_needing_fixes: str = ""

    @field_validator("raw_score")
    @classmethod
    def _clamp_raw_score(cls, value: float) -> float:
        """Clamp the agent-reported score into [0.0, 1.0].

        Clamping (not strict ``Field(ge, le)``) bounds an out-of-range value without
        raising: a raise here would propagate through ``ValidationReport.from_file``,
        which the collector catches as ``[]`` — dropping every finding in the report.
        """
        return min(1.0, max(0.0, value))

    @field_validator("merge_readiness")
    @classmethod
    def _coerce_merge_readiness(cls, value: str) -> str:
        """Coerce an unrecognized readiness string to the fail-closed NOT_READY value."""
        try:
            return MergeReadiness(value).value
        except ValueError:
            return MergeReadiness.NOT_READY.value

    @model_validator(mode="after")
    def _redact_narrative(self) -> FixFindingReport:
        """Mask any secret/PII the agent echoed into free-text before it reaches disk.

        Runs at the parse boundary so both the DTO write-back and the combined report inherit
        redacted text. Identifiers (title/tracking_id) are left intact for heading matching.
        """
        self.justification = redact(self.justification)
        self.finding_description = redact(self.finding_description)
        self.affected_files = redact(self.affected_files)
        self.files_needing_fixes = redact(self.files_needing_fixes)
        self.conditions_for_full_fix = [redact(c) for c in self.conditions_for_full_fix]
        self.recommendations = [redact(r) for r in self.recommendations]
        return self


class ValidationReport(BaseModel):
    """The agent-to-host report document (``validation_report.json``)."""

    model_config = ConfigDict(extra="ignore")

    findings: list[FixFindingReport] = Field(default_factory=list)

    @classmethod
    def from_file(cls, path: Path) -> ValidationReport:
        """Parse the agent report from disk."""
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))


def make_unverifiable(
    tracking_id: str, title: str, reason: str, finding_number: int = 0
) -> ValidationResult:
    """Build an UNVERIFIABLE result for a finding that could not be validated."""
    return ValidationResult(
        finding_number=finding_number,
        tracking_id=tracking_id,
        finding_title=title,
        finding_description="",
        affected_files="",
        fixed=Answer.UNKNOWN,
        partially_fixed=Answer.UNKNOWN,
        not_fixed=Answer.UNKNOWN,
        files_needing_fixes="",
        reason_for_decision=f"UNVERIFIABLE: {reason}",
        severity=DEFAULT_SEVERITY,
        pr_merge_readiness=MergeReadiness.NOT_READY.value,
        recommendations=f"Manual review required: {reason}",
        validation_path=ValidationPath.FIX_VALIDATION,
    )
