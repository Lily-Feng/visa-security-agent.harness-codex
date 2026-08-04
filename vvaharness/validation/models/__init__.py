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

"""Pydantic data contracts and value types for the validation agent."""

from __future__ import annotations

from vvaharness.validation.models.dto import (
    DtoFinding,
    DtoPatch,
    RemediationReport,
)
from vvaharness.validation.models.manifest import Manifest, ManifestFinding
from vvaharness.validation.models.persona_report import (
    EvidenceAnchor as PersonaEvidenceAnchor,
)
from vvaharness.validation.models.persona_report import (
    PersonaGateEntry,
    PersonaReport,
)
from vvaharness.validation.models.plans import FixValidationPlan
from vvaharness.validation.models.results import (
    FixFindingReport,
    RunMetadata,
    ValidationReport,
    ValidationResult,
    make_unverifiable,
)
from vvaharness.validation.models.scoring import (
    EvidenceAnchor,
    GateResult,
    RawCriterion,
    RawEvidence,
    RawExtra,
    ScoredGateEntry,
    ScoreResult,
    ScoringConfig,
    ValidationScore,
    VerdictRule,
)

__all__ = [
    "DtoFinding",
    "DtoPatch",
    "EvidenceAnchor",
    "FixFindingReport",
    "FixValidationPlan",
    "GateResult",
    "Manifest",
    "ManifestFinding",
    "PersonaEvidenceAnchor",
    "PersonaGateEntry",
    "PersonaReport",
    "RawCriterion",
    "RawEvidence",
    "RawExtra",
    "RemediationReport",
    "RunMetadata",
    "ScoreResult",
    "ScoredGateEntry",
    "ScoringConfig",
    "ValidationReport",
    "ValidationResult",
    "ValidationScore",
    "VerdictRule",
    "make_unverifiable",
]
