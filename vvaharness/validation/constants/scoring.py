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

"""Canonical scoring weights and thresholds used directly by the scoring engine."""

from vvaharness.validation.enums.gates import GateName, GateStatus

# --- Fix Validation ---

# Four renormalized gates (branch_targeting dropped; agent must emit exactly these keys).
GATE_WEIGHTS: dict[str, float] = {
    GateName.ROOT_CAUSE.value: 0.43,
    GateName.INSTANCE_COVERAGE.value: 0.2467,
    GateName.NO_NEW_VULNERABILITIES.value: 0.1867,
    GateName.SECURITY_BEST_PRACTICES.value: 0.1366,
}

THRESHOLD_FIXED = 0.80
THRESHOLD_PARTIAL = 0.50

# --- Shared ---

# SKIP is weight-neutral: a skipped gate is treated as unevaluated and dropped from the
# renormalization denominator in the engine, so it neither earns nor drags credit. Its
# 0.0 multiplier here is the fallback for any code path that does not renormalize.
STATUS_MULTIPLIER: dict[str, float] = {
    GateStatus.PASS.value: 1.0,
    GateStatus.PARTIAL.value: 0.5,
    GateStatus.FAIL.value: 0.0,
    GateStatus.SKIP.value: 0.0,
}

# Score floor constant (minimum possible score, floor of VerdictRule and fallback default).
SCORE_FLOOR: float = 0.0

# JSON field name used by the scoring agent to identify a gate criterion.
CRITERION_NAME_FIELD: str = "gate_name"

# Decimal precision for rounded scores (engine output and wire shape).
SCORE_PRECISION: int = 4

# Scale factor to convert a 0.0-1.0 score to a 0-100 confidence percentage.
CONFIDENCE_PERCENT_SCALE: int = 100

# Maximum evidence anchors included in the justification string.
MAX_EVIDENCE_ANCHORS: int = 5
