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

"""Tests for the DTO verdict write-back (distinct re-validatable failed status).

Covers the three-way ``_terminal_status`` map and the end-to-end
``write_back_validation`` fold of the host verdict into ``remediate_report.json``,
plus the re-validatability of the written ``validation_failed`` status.
"""
import json
from collections.abc import Mapping
from pathlib import Path

from vvaharness.validation.constants.artifacts import (
    STATUS_NEEDS_REVIEW,
    STATUS_VALIDATED,
    STATUS_VALIDATION_FAILED,
    SYNTHESIZED_GATES_FILENAME,
    VALIDATION_REPORT_FILENAME,
)
from vvaharness.validation.ingest.dto_loader import _is_validatable, select_reports
from vvaharness.validation.io.dto_writeback import _terminal_status, write_back_validation
from vvaharness.validation.models import RemediationReport

_ALL_FAIL: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "fail"},
    {"gate_name": "instance_coverage", "status": "fail"},
    {"gate_name": "no_new_vulnerabilities", "status": "fail"},
    {"gate_name": "security_best_practices", "status": "fail"},
]


_ALL_PASS: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "pass"},
    {"gate_name": "instance_coverage", "status": "pass"},
    {"gate_name": "no_new_vulnerabilities", "status": "pass"},
    {"gate_name": "security_best_practices", "status": "pass"},
]


def _write_gates(ws: Path, tracking_id: str, gates: list[Mapping[str, object]]) -> None:
    (ws / SYNTHESIZED_GATES_FILENAME).write_text(
        json.dumps([{"tracking_id": tracking_id, "gates": gates}])
    )


def _write_report(ws: Path, findings: list[dict]) -> None:
    (ws / VALIDATION_REPORT_FILENAME).write_text(json.dumps({"findings": findings}))


def _write_dto(repo: Path, name: str, finding_id: str, status: str) -> Path:
    sub = repo / "security-remediation" / name
    sub.mkdir(parents=True)
    path = sub / "remediate_report.json"
    path.write_text(json.dumps({
        "finding_id": finding_id, "status": status,
        "finding": {"title": "t", "cvss_score": "7.5"}, "patch": {"diff": "x"},
    }), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# _terminal_status — three-way map
# ---------------------------------------------------------------------------


def test_terminal_status_fixed_is_validated() -> None:
    assert _terminal_status("Fixed") == STATUS_VALIDATED


def test_terminal_status_not_fixed_is_validation_failed() -> None:
    assert _terminal_status("Not Fixed") == STATUS_VALIDATION_FAILED


def test_terminal_status_partially_fixed_is_validation_failed() -> None:
    assert _terminal_status("Partially Fixed") == STATUS_VALIDATION_FAILED


def test_terminal_status_unverifiable_is_needs_review() -> None:
    assert _terminal_status("UNVERIFIABLE") == STATUS_NEEDS_REVIEW


def test_terminal_status_garbage_is_needs_review() -> None:
    # An unparseable verdict maps to UNVERIFIABLE -> needs_review, never validation_failed.
    assert _terminal_status("nonsense-status") == STATUS_NEEDS_REVIEW


# ---------------------------------------------------------------------------
# write_back_validation — end-to-end fold into the DTO
# ---------------------------------------------------------------------------


def test_write_back_failing_verdict_sets_validation_failed(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    dto_path = _write_dto(tmp_path, "01_finding", "F-1", "awaiting_validation")
    _write_report(ws, [{
        "tracking_id": "F-1", "fix_status": "Not Fixed", "raw_score": 0.0,
        "justification": "agent narrative",
    }])
    _write_gates(ws, "F-1", _ALL_FAIL)

    report = RemediationReport.from_file(dto_path)
    written = write_back_validation(report, ws)

    assert written == STATUS_VALIDATION_FAILED
    dto = json.loads(dto_path.read_text(encoding="utf-8"))
    assert dto["status"] == STATUS_VALIDATION_FAILED
    # The true tri-state survives in the validation sub-block (host verdict).
    assert dto["validation"]["fix_status"] == "Not Fixed"
    assert dto["validation"]["justification"] == "agent narrative"


def test_write_back_redacts_secret_in_justification(tmp_path: Path) -> None:
    # A secret the agent echoed into its narrative is masked in the DTO validation block on disk.
    ws = tmp_path / "workspace"
    ws.mkdir()
    dto_path = _write_dto(tmp_path, "01_finding", "F-1", "awaiting_validation")
    _write_report(ws, [{
        "tracking_id": "F-1", "fix_status": "Not Fixed", "raw_score": 0.0,
        "justification": "still hardcodes AKIAIOSFODNN7EXAMPLE",
    }])
    _write_gates(ws, "F-1", _ALL_FAIL)

    write_back_validation(RemediationReport.from_file(dto_path), ws)

    dto = json.loads(dto_path.read_text(encoding="utf-8"))
    assert "[REDACTED-AWS-KEY]" in dto["validation"]["justification"]
    assert "AKIAIOSFODNN7EXAMPLE" not in dto["validation"]["justification"]


def test_write_back_absent_gates_fails_closed(tmp_path: Path) -> None:
    # Agent self-reports Fixed but writes no synthesized_gates.json → the host cannot
    # recompute, so the verdict fails closed to UNVERIFIABLE and the DTO returns to the
    # re-validatable needs_review status, never validated.
    ws = tmp_path / "workspace"
    ws.mkdir()
    dto_path = _write_dto(tmp_path, "01_finding", "F-1", "awaiting_validation")
    _write_report(ws, [{
        "tracking_id": "F-1", "fix_status": "Fixed", "raw_score": 0.99,
        "justification": "agent narrative",
    }])
    # Deliberately no _write_gates(...) call.

    report = RemediationReport.from_file(dto_path)
    written = write_back_validation(report, ws)

    assert written == STATUS_NEEDS_REVIEW
    dto = json.loads(dto_path.read_text(encoding="utf-8"))
    assert dto["status"] == STATUS_NEEDS_REVIEW
    assert dto["validation"]["fix_status"] == "UNVERIFIABLE"
    assert dto["validation"]["raw_score"] == 0.0
    # Agent narrative is still preserved alongside the fail-closed numbers.
    assert dto["validation"]["justification"] == "agent narrative"


def test_write_back_session_failed_fails_closed_despite_passing_gates(tmp_path: Path) -> None:
    # Gates are present and all passing -- without the guard this folds a terminal
    # "validated" into the DTO for a session that actually failed, and validated is
    # excluded from re-validation. session_failed discards the host score so the verdict
    # fails closed to UNVERIFIABLE -> needs_review.
    ws = tmp_path / "workspace"
    ws.mkdir()
    dto_path = _write_dto(tmp_path, "01_finding", "F-1", "awaiting_validation")
    _write_report(ws, [{
        "tracking_id": "F-1", "fix_status": "Fixed", "raw_score": 0.99,
        "justification": "agent narrative",
    }])
    _write_gates(ws, "F-1", _ALL_PASS)

    report = RemediationReport.from_file(dto_path)
    # Same inputs without the flag are a clean pass -- the flag alone changes the outcome.
    assert write_back_validation(report, ws) == STATUS_VALIDATED

    written = write_back_validation(report, ws, session_failed=True)

    assert written == STATUS_NEEDS_REVIEW
    dto = json.loads(dto_path.read_text(encoding="utf-8"))
    assert dto["status"] == STATUS_NEEDS_REVIEW
    assert dto["validation"]["fix_status"] == "UNVERIFIABLE"
    assert dto["validation"]["raw_score"] == 0.0
    # Agent narrative is still preserved alongside the fail-closed numbers.
    assert dto["validation"]["justification"] == "agent narrative"


def test_write_back_no_source_path_returns_none(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    # A report parsed without from_file has no source_path -> nothing to write back.
    report = RemediationReport.model_validate(
        {"finding_id": "F-1", "status": "awaiting_validation"}
    )
    assert write_back_validation(report, ws) is None


# ---------------------------------------------------------------------------
# Re-validation — a validation_failed DTO is re-selectable on the next run
# ---------------------------------------------------------------------------


def test_validation_failed_is_validatable(tmp_path: Path) -> None:
    dto_path = _write_dto(tmp_path, "01_finding", "F-1", STATUS_VALIDATION_FAILED)
    report = RemediationReport.from_file(dto_path)
    assert _is_validatable(report) is True


def test_validation_failed_dto_selected_for_revalidation(tmp_path: Path) -> None:
    _write_dto(tmp_path, "01_failed", "VF-1", STATUS_VALIDATION_FAILED)
    _write_dto(tmp_path, "02_validated", "V-1", STATUS_VALIDATED)  # terminal pass; excluded

    ids = {r.finding_id for r in select_reports(tmp_path, None, None)}

    assert ids == {"VF-1"}  # failed re-drives; validated does not
