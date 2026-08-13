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

"""Strict structured-output schema for the read-only DeepAgents validation session."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class GateEntry(BaseModel):
    """One gate verdict for a single finding."""

    model_config = ConfigDict(extra="ignore")

    gate_name: str
    # skip is legal: the rules instruct it for unevaluated gates and the scoring
    # engine treats it as weight-neutral. Narrowing it here would force the model
    # to invent pass/fail for a gate nobody assessed.
    status: Literal["pass", "partial", "fail", "skip"]
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    details: str = ""


class SynthesizedGatesEntry(BaseModel):
    """Synthesized gates for one finding, keyed by tracking_id."""

    model_config = ConfigDict(extra="ignore")

    tracking_id: str
    gates: list[GateEntry]


class OutputFinding(BaseModel):
    """Single finding block emitted by the validation agent."""

    model_config = ConfigDict(extra="ignore")

    tracking_id: str
    finding_title: str
    finding_description: str
    affected_files: str
    severity: str = "Medium"
    fix_status: str = "UNVERIFIABLE"
    raw_score: float = Field(ge=0.0, le=1.0, default=0.0)
    justification: str = ""
    merge_readiness: str = "Not Ready"
    gate_scores: dict[str, object] = Field(default_factory=dict)
    conditions_for_full_fix: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    files_needing_fixes: str = ""

    @field_validator("affected_files", "files_needing_fixes", mode="before")
    @classmethod
    def _coerce_csv(cls, v: object) -> object:
        # The schema hint says "comma,separated,files", but gpt-5.5 (and peers)
        # frequently emit a JSON list here. Join it to the declared string form
        # instead of failing structured-output validation.
        if isinstance(v, (list, tuple)):
            return ",".join(str(x) for x in v)
        return v


class ValidationOutput(BaseModel):
    """Top-level structured response from any validation Harness backend.

    The host (not the agent) writes ``validation_report.json`` and
    ``synthesized_gates.json`` from this payload.
    """

    model_config = ConfigDict(extra="ignore")

    target_jira_status: str
    findings: list[OutputFinding]
    synthesized_gates: list[SynthesizedGatesEntry]
