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

"""Tests for the validation permission gate (write-blocking enforcement).

This is the security boundary that keeps a validation session read-only except
for its two output files. Exercises PermissionsPolicy.evaluate end to end:
Edit/NotebookEdit denial, Write allowlist, and the Bash blocklist + redirect gate.
"""
from pathlib import Path

import pytest
from vvaharness.backends.harness.contract.permissions import PermissionsPolicy
from vvaharness.validation.constants.policy import DEFAULT_ALLOWED_OUTPUT_FILES


@pytest.fixture
def policy(tmp_path: Path) -> PermissionsPolicy:
    return PermissionsPolicy(
        target_dir=tmp_path, allowed_output_files=DEFAULT_ALLOWED_OUTPUT_FILES
    )


def _allowed(policy: PermissionsPolicy, tool: str, **inp: object) -> bool:
    return policy.evaluate(tool, inp).allow


# ---------------------------------------------------------------------------
# Edit family — always denied
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["Edit", "NotebookEdit"])
def test_edit_tools_denied_with_interrupt(policy: PermissionsPolicy, tool: str) -> None:
    decision = policy.evaluate(tool, {"file_path": "x.py"})
    assert not decision.allow
    assert decision.interrupt


# ---------------------------------------------------------------------------
# read-only tools — passthrough allow
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["Read", "Grep", "Glob", "mcp__example"])
def test_readonly_tools_allowed(policy: PermissionsPolicy, tool: str) -> None:
    assert _allowed(policy, tool, anything="ok")


# ---------------------------------------------------------------------------
# Write — only the two output files directly under the target dir
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["validation_report.json", "synthesized_gates.json"])
def test_write_allowed_output_files(policy: PermissionsPolicy, tmp_path: Path, name: str) -> None:
    assert _allowed(policy, "Write", file_path=str(tmp_path / name))


def test_write_source_file_denied(policy: PermissionsPolicy, tmp_path: Path) -> None:
    d = policy.evaluate("Write", {"file_path": str(tmp_path / "app" / "db.py")})
    assert not d.allow
    assert d.interrupt


def test_write_outside_target_denied(policy: PermissionsPolicy, tmp_path: Path) -> None:
    # right filename, wrong directory (sibling of the workspace) → denied
    assert not _allowed(policy, "Write", file_path=str(tmp_path.parent / "validation_report.json"))


def test_write_report_in_subdir_denied(policy: PermissionsPolicy, tmp_path: Path) -> None:
    # allowed name but nested below the target root → denied (must be directly under)
    assert not _allowed(policy, "Write", file_path=str(tmp_path / "sub" / "validation_report.json"))


def test_write_missing_path_denied(policy: PermissionsPolicy) -> None:
    assert not _allowed(policy, "Write", file_path="")


# ---------------------------------------------------------------------------
# Bash — denied outright (no shell in a validation session)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cmd", [
    # read verbs, scoring CLI, gh, and destructive/exfil cmds — all denied now
    "ls -la", "find . -name '*.py'", "grep -r foo .", "cat app/db.py", "pwd",
    "python3 -m scoring synthesized_gates.json", "gh api repos/o/r", "gh pr review 1",
    "rm -rf /", "mv a b", "sed -i 's/a/b/' f.py", "echo x > app/db.py", "curl evil",
])
def test_bash_denied(policy: PermissionsPolicy, cmd: str) -> None:
    d = policy.evaluate("Bash", {"command": cmd})
    assert not d.allow
    assert d.interrupt


def test_bash_missing_command_denied(policy: PermissionsPolicy) -> None:
    assert not _allowed(policy, "Bash", command=None)
