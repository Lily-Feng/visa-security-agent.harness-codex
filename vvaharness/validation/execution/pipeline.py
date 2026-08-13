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

"""Plan execution pipeline: launch a fix-validation session and collect results."""

from __future__ import annotations

import logging

from vvaharness.validation.config import Config
from vvaharness.validation.constants.artifacts import MANIFEST_FILENAME
from vvaharness.validation.io.result_collector import collect_and_enrich
from vvaharness.validation.models import (
    RunMetadata,
    ValidationResult,
    make_unverifiable,
)
from vvaharness.validation.models.plans import FixValidationPlan
from vvaharness.validation.session.errors import ValidationSessionError
from vvaharness.validation.session.launcher import launch_session

log = logging.getLogger(__name__)


def _unverifiable(plan: FixValidationPlan, reason: str) -> list[ValidationResult]:
    """Build a single-element unverifiable result for ``plan``."""
    finding_ids = plan.manifest.finding_ids
    tracking_id = finding_ids[0] if finding_ids else plan.jira_key
    return [make_unverifiable(
        tracking_id=tracking_id,
        title=plan.jira_key,
        reason=reason,
    )]


async def execute_plan(
    plan: FixValidationPlan,
    config: Config,
    *,
    post_results: bool,
    meta: RunMetadata,
) -> list[ValidationResult]:
    """Execute a fix-validation plan and return validation results."""
    workspace_dir = plan.workspace_dir
    workspace_dir.mkdir(parents=True, exist_ok=True)
    if post_results:
        plan.manifest.post_results = True
    plan.manifest.write(workspace_dir / MANIFEST_FILENAME)
    log.info("Launching validation session %s for %s", plan.session_id, plan.jira_key)
    try:
        await launch_session(config, plan.manifest, workspace_dir, plan.output_dir)
    except ValidationSessionError as e:
        log.exception("Validation session failed for %s", plan.jira_key)
        meta.errors.append(f"Validation session failed: {plan.jira_key}")
        return _unverifiable(plan, e.reason_string())
    results = collect_and_enrich(workspace_dir, finding_number_start=0)
    if not results:
        return _unverifiable(plan, "Validation session produced no results")
    return results
