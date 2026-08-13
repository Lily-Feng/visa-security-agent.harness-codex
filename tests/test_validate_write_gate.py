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

"""Regression tests for the validation Write permission gate path anchoring."""

from pathlib import Path

from vvaharness.backends.harness.contract.permissions import PermissionsPolicy
from vvaharness.validation.constants.policy import DEFAULT_ALLOWED_OUTPUT_FILES
from vvaharness.validation.constants.artifacts import VALIDATION_REPORT_FILENAME


def _decide(target_dir: Path, file_path: str) -> bool:
    decision = PermissionsPolicy(
        target_dir=target_dir, allowed_output_files=DEFAULT_ALLOWED_OUTPUT_FILES
    ).evaluate("Write", {"file_path": file_path})
    return decision.allow


def test_relative_report_allowed_when_host_cwd_differs(tmp_path, monkeypatch):
    # The core regression: host cwd is elsewhere, agent writes a bare filename.
    workspace = tmp_path / "ws"
    workspace.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert _decide(workspace, VALIDATION_REPORT_FILENAME) is True


def test_absolute_report_inside_workspace_allowed(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    assert _decide(workspace, str(workspace / VALIDATION_REPORT_FILENAME)) is True


def test_parent_escape_denied(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    assert _decide(workspace, f"../{VALIDATION_REPORT_FILENAME}") is False


def test_absolute_outside_workspace_denied(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    assert _decide(workspace, str(tmp_path / VALIDATION_REPORT_FILENAME)) is False


def test_subdir_write_denied(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    assert _decide(workspace, f"sub/{VALIDATION_REPORT_FILENAME}") is False


def test_disallowed_filename_denied(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    assert _decide(workspace, "arbitrary.txt") is False
