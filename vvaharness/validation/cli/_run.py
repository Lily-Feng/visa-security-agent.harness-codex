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

"""Core validation execution: run_validation() and _validate_one()."""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from vvaharness.report.redact import redact
from vvaharness.validation.cli._patterns import _UNSAFE
from vvaharness.validation.config import Config
from vvaharness.validation.constants.artifacts import (
    CMD_PREVIEW_LEN,
    LOGGING_DIRNAME,
    ORCHESTRATOR_LOG_DIRNAME,
    SESSION_LOG_FILENAME,
    VALIDATABLE_STATUSES,
    VALIDATE_ALIAS_S11,
    VALIDATION_SESSION_LOG_PREFIX,
)
from vvaharness.validation.execution.pipeline import execute_plan
from vvaharness.validation.ingest.dto_loader import discover_reports, select_reports
from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.ingest.manifest_builder import build_manifest
from vvaharness.validation.ingest.workspace import assert_remediation_applied, stage_workspace
from vvaharness.validation.io.dto_writeback import write_back_validation
from vvaharness.validation.models import RemediationReport, RunMetadata, ValidationResult
from vvaharness.validation.models.plans import FixValidationPlan
from vvaharness.validation.report import augment_reports

# Prefix that ``make_unverifiable`` stamps on ``reason_for_decision`` for a result that
# represents a hard failure (session/agent error) rather than a real verdict.
_UNVERIFIABLE_PREFIX = "UNVERIFIABLE:"


def _is_hard_failure(result: ValidationResult | None) -> bool:
    """True when *result* is a session/agent failure rather than a real verdict.

    ``make_unverifiable`` stamps ``_UNVERIFIABLE_PREFIX`` on ``reason_for_decision`` for
    every such result, which is how a ValidationSessionError surfaces here. A missing
    result counts as a failure. Single definition shared by the DTO write-back (which must
    fail closed) and the exit-code accounting, so the two cannot drift apart.
    """
    if result is None:
        return True
    return result.reason_for_decision.startswith(_UNVERIFIABLE_PREFIX)


def _safe(finding_id: str) -> str:
    """Return a filesystem-safe version of a finding id (max 80 chars)."""
    return _UNSAFE.sub("_", finding_id)[:CMD_PREVIEW_LEN]


def _step_key(finding_id: str) -> str:
    """Collision-free resume-checkpoint step for a finding.

    Keyed on a full-fidelity sha256 of the id (``_safe`` is lossy: it sanitizes + truncates to
    80 chars, so distinct ids could collapse onto one ``(run_id, step)`` checkpoint).
    """
    return "validate_" + hashlib.sha256(finding_id.encode("utf-8")).hexdigest()


def _session_log_dest(workspace: Path, report: RemediationReport) -> tuple[Path, Path] | None:
    """Resolve the (source, destination) paths for the session log, or None if unavailable."""
    if report.source_path is None:
        print(
            f"  [{VALIDATE_ALIAS_S11}] WARN: no report path for {report.finding_id}; log skipped",
            file=sys.stderr,
        )
        return None
    src = workspace / LOGGING_DIRNAME / ORCHESTRATOR_LOG_DIRNAME / SESSION_LOG_FILENAME
    if not src.exists():
        return None
    fname = f"{VALIDATION_SESSION_LOG_PREFIX}{_safe(report.finding_id)}.jsonl"
    return src, report.source_path.parent / fname


def _persist_session_log(workspace: Path, report: RemediationReport) -> Path | None:
    """Persist the redacted session transcript next to the finding's remediate_report.json.

    Scoped to the orchestrator ``session.jsonl`` only — no s11/ tree, no report copies.
    Redaction happens in memory and only redacted bytes are ever written, so a decode/IO
    failure cannot leave an unredacted artifact behind. Best-effort audit artifact: on any
    failure the partial destination is removed and None is returned, never raising.
    """
    resolved = _session_log_dest(workspace, report)
    if resolved is None:
        return None
    src, dest = resolved
    try:
        dest.write_text(
            redact(src.read_text(encoding="utf-8", errors="replace")), encoding="utf-8"
        )
    except (OSError, ValueError):
        dest.unlink(missing_ok=True)
        return None
    return dest


def _print_result(result: ValidationResult) -> None:
    """Print a one-line verdict summary for a completed validation."""
    verdict = result.reason_for_decision or result.fixed
    print(f"[{result.tracking_id}] verdict={verdict} score={result.fix_confidence}")
    if result.justification:
        print(f"    justification: {result.justification}")


def _validate_one(
    report: RemediationReport,
    run: ValidationRun,
) -> ValidationResult | None:
    """Stage, validate, persist the run record, and return the result (or None on gate failure)."""
    session_id = uuid.uuid4().hex
    manifest = build_manifest(report, session_id=session_id)
    workspace = run.workspace_root / _safe(report.finding_id)
    try:
        assert_remediation_applied(run.repo, report.patch.files_touched)
    except IngestError as exc:
        print(f"refusing {report.finding_id}: {exc}", file=sys.stderr)
        return None
    stage_workspace(run.repo, workspace, report.patch.diff)
    plan = FixValidationPlan(
        jira_key=report.finding_id,
        session_id=session_id,
        manifest=manifest,
        workspace_dir=workspace,
        output_dir=workspace,
    )
    results = asyncio.run(
        execute_plan(plan, run.config, post_results=False, meta=RunMetadata(total_findings=1))
    )
    result = results[0] if results else None
    record = _persist_session_log(workspace, report)
    if record is not None:
        print(f"  [{VALIDATE_ALIAS_S11}] session log → {record}", file=sys.stderr)
    status = write_back_validation(
        report, workspace, session_failed=_is_hard_failure(result)
    )
    if status is not None:
        print(
            f"  [{VALIDATE_ALIAS_S11}] DTO updated → {report.finding_id}: status={status}",
            file=sys.stderr,
        )
    shutil.rmtree(workspace, ignore_errors=True)
    return result


def _resume_hit(run: ValidationRun, step: str) -> ValidationResult | None:
    """Return the cached ValidationResult for a prior run of *step*, or None to re-run."""
    from vvaharness.orchestrator.checkpoints import load_ckpt
    return load_ckpt(run.workspace_root, run.run_id, step)


def _process_report(report: RemediationReport, run: ValidationRun) -> ValidationResult | None:
    """Validate (or resume) one finding; checkpoint a fresh result. None on gate failure."""
    step = _step_key(report.finding_id)
    if run.resume:
        cached = _resume_hit(run, step)
        # Reuse only when the cached verdict is for THIS finding (defense-in-depth against a
        # stale/foreign checkpoint); otherwise re-validate rather than substitute a verdict.
        if cached is not None and cached.tracking_id == report.finding_id:
            print(
                f"  [{VALIDATE_ALIAS_S11}] resume: {report.finding_id} already validated",
                file=sys.stderr,
            )
            return cached
    result = _validate_one(report, run)
    if result is not None:
        from vvaharness.orchestrator.checkpoints import save_ckpt
        save_ckpt(run.workspace_root, run.run_id, step, result)
    return result


def _run_reports(
    reports: list[RemediationReport], run: ValidationRun,
) -> tuple[int, list[tuple[RemediationReport, ValidationResult]]]:
    """Run (or resume) validation per report; return (exit_code, validated pairs)."""
    failures = 0
    pairs: list[tuple[RemediationReport, ValidationResult]] = []
    for report in reports:
        result = _process_report(report, run)
        if result is None:
            failures += 1  # refused before validation; _validate_one already explained why
            continue
        if _is_hard_failure(result):
            # A hard failure (agent/session error) — surface it as FAILED, don't pass it
            # off as a normal verdict, and make the run exit non-zero.
            print(f"FAILED: {report.finding_id} — {result.reason_for_decision}", file=sys.stderr)
            failures += 1
        else:
            _print_result(result)
        pairs.append((report, result))
    return (1 if failures else 0), pairs


@dataclass(frozen=True)
class Selection:
    """What to validate: explicit finding ids, or the validatable set capped top-N by CVSS."""

    finding_ids: list[str] | None = None
    max_findings: int | None = None
    resume: bool = False


@dataclass(frozen=True)
class ValidationRun:
    """Shared state of one validation run, threaded through the per-finding loop.

    Carries staging locations, the agent config, and the SQLite checkpoint identity.
    """

    repo: Path
    workspace_root: Path
    config: Config
    run_id: str
    resume: bool = False


def _cleanup_workspace(workspace_root: Path) -> None:
    """Remove the ephemeral staging tree, surfacing real failures instead of swallowing them.

    Drops ``ignore_errors`` so a genuine failure (e.g. a permissions problem) is reported as
    a WARN rather than silently ignored; an already-absent tree is treated as clean. Lives in
    its own function so ``run_validation`` keeps a single try/except.
    """
    try:
        shutil.rmtree(workspace_root)
    except FileNotFoundError:
        pass  # already removed: nothing to clean
    except OSError as exc:
        print(
            f"  [{VALIDATE_ALIAS_S11}] WARN: could not remove workspace {workspace_root}: {exc}",
            file=sys.stderr,
        )


def _empty_selection_rc(repo: Path) -> int:
    """Exit code when no validatable reports were selected.

    DTOs exist but are all terminal (e.g. an idempotent re-run after everything is
    `validated`) → 0, nothing to do; no DTOs at all → 1, a real misconfiguration.
    """
    if discover_reports(repo):
        print(
            f"validation: nothing to validate — all findings under {repo} are already "
            "in a terminal state",
            file=sys.stderr,
        )
        return 0
    valid = " / ".join(VALIDATABLE_STATUSES)
    print(
        f"validation cannot run: no findings with a validatable status ({valid}) under {repo}",
        file=sys.stderr,
    )
    return 1


def run_validation(
    *,
    repo: Path,
    selection: Selection,
    workspace_root: Path,
    config: Config,
    report_md: Path | None = None,
) -> int:
    """Validate each validatable finding in sequence; return 0 if all succeeded."""
    try:
        reports = select_reports(repo, selection.finding_ids, selection.max_findings)
    except IngestError as exc:
        print(f"ingest error: {exc}", file=sys.stderr)
        return 1
    if not reports:
        return _empty_selection_rc(repo)
    # SQLite resume layer (lazy import keeps the validation package standalone-runnable):
    # register the run so s10/s11 checkpoints share one run row, then run per finding.
    from vvaharness.orchestrator.checkpoints import run_id_for
    from vvaharness.orchestrator.store import register_run
    run_id = run_id_for(repo)
    register_run(run_id, repo_root=str(repo.resolve()))
    run = ValidationRun(
        repo=repo,
        workspace_root=workspace_root,
        config=config,
        run_id=run_id,
        resume=selection.resume,
    )
    rc, pairs = _run_reports(reports, run)
    augment_reports(repo, pairs, report_md)  # best-effort: write results into the combined report
    # Remove the ephemeral staging tree entirely (per-finding workspaces already rmtree'd);
    # checkpoints live in the SQLite state store, not here, so this is safe for --resume.
    _cleanup_workspace(workspace_root)
    return rc
