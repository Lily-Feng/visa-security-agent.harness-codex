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
"""s11_validate — thin wrapper that hooks the validation package into the pipeline.

The validation package (`vvaharness/validation/`) is the engine; this module is
only the pipeline-stage entry point that calls it with the right argv.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vvaharness.config import Config


def run(  # noqa: PLR0913  # signature is the orchestrator's keyword contract (scan.py)
    repo: Path | str,
    *,
    cfg: Config,  # noqa: ARG001  # orchestrator passes cfg=cfg; keep the keyword accepted
    config_path: str,
    finding_ids: list[str] | None = None,
    resume: bool = False,
    report_md: Path | str | None = None,
) -> int:
    """Run the s11 agentic validator against awaiting remediate_report.json files.

    An empty ``config_path`` makes the validator resolve its packaged default
    profile instead (logged downstream, not silent).

    ``--all`` is deliberately NOT passed. It is an operator override that would
    make ``step_validate.max_findings`` dead config in-scan, and would also
    re-validate needs_review / validation_failed DTOs left by earlier scans.
    """
    from vvaharness.validation.cli import main as validate_main
    argv = ["--repo", str(repo)]
    for flag, value in (("--config", config_path), ("--scan-report", report_md)):
        if value:
            argv += [flag, str(value)]
    for finding_id in finding_ids or ():
        argv += ["--finding", finding_id]
    if resume:
        argv.append("--resume")
    return validate_main(argv)
