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

"""Pydantic wire shapes for native DeepAgents persona reports."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceAnchor(BaseModel):
    """File/line reference pinning a gate verdict to source evidence."""

    file: str = ""
    line: int | None = None
    snippet: str = ""

    @field_validator("file", "snippet", mode="before")
    @classmethod
    def _none_to_empty(cls, v: object) -> object:
        # Models sometimes emit a non-file-anchored evidence item with null here.
        return "" if v is None else v


class PersonaGateEntry(BaseModel):
    """One gate verdict emitted by a single persona."""

    # Tolerate stray fields: gpt-5.5 and peers occasionally add keys not in the
    # schema. Dropping them is safer than aborting the whole validation stream.
    model_config = ConfigDict(extra="ignore")

    gate_name: str
    status: str
    summary: str
    details: str = ""
    evidence: list[EvidenceAnchor] = Field(default_factory=list)

    @field_validator("status")
    @classmethod
    def _canonical_status(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in {"pass", "partial", "fail", "skip"}:
            raise ValueError(f"invalid gate status: {v!r}")
        return normalized


class PersonaReport(BaseModel):
    """Structured response from one validation subagent / persona."""

    # A persona must NOT emit synthesis-level fields (e.g. files_needing_fixes);
    # the host derives those. Ignore rather than forbid so a model that appends
    # one does not crash the run.
    model_config = ConfigDict(extra="ignore")

    persona: str
    tracking_id: str
    gates: list[PersonaGateEntry]
