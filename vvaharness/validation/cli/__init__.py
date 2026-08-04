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

"""The validation CLI entry point for ``vvaharness validate``."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from vvaharness.config import is_network_path
from vvaharness.orchestrator import _default_config
from vvaharness.validation.cli._model import _apply_model_env, _check_persona_vendors
from vvaharness.validation.cli._parser import _build_parser
from vvaharness.validation.cli._run import Selection, run_validation
from vvaharness.validation.config import load_config
from vvaharness.validation.constants.artifacts import REMEDIATION_DIRNAME, WORKSPACE_DIRNAME
from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.session.errors import ValidationSessionError

# Failures we can describe cleanly to the operator (no raw traceback).
_KNOWN_ERRORS = (
    IngestError,
    ValidationSessionError,
    ValidationError,
    FileNotFoundError,
    OSError,
    yaml.YAMLError,
)


def _resolve_selection(args: object, config: object) -> Selection:
    """Resolve what to validate from args + config.

    ``--finding`` ids win (those exact ids, no cap); ``--all`` validates every
    validatable finding (awaiting_validation / needs_review / validation_failed, no cap);
    otherwise the validatable set is capped to the top-N by CVSS, where N is
    ``--max-findings`` if given else ``step_validate.max_findings``.
    """
    resume = bool(getattr(args, "resume", False))
    findings = getattr(args, "findings", None)
    if findings:
        return Selection(finding_ids=findings, resume=resume)
    if getattr(args, "all", False):
        return Selection(resume=resume)
    flag_max = getattr(args, "max_findings", None)
    cap = flag_max if flag_max is not None else getattr(config, "max_findings", None)
    return Selection(max_findings=cap, resume=resume)


def _resolve_config_path(args: object) -> str:
    """Return the config path to load: the given --config, else the packaged default.

    The fallback is explicit and printed (never silent): the in-pipeline s11 stage
    always forwards the scan's --config, so this default only applies to a standalone
    ``vvaharness validate`` invoked with no --config.
    """
    config = getattr(args, "config", None)
    if config:
        return str(config)
    default = str(_default_config())
    print(f"validate: no --config given; using default profile {default}", file=sys.stderr)
    return default


def _is_nonempty_dir(path: Path) -> bool:
    """True when *path* is an existing directory that already contains entries."""
    return path.is_dir() and any(path.iterdir())


def _check_path_guards(args: object) -> str | None:
    """Return an operator-facing error message if any path arg is invalid, else None.

    Guards UNC/network paths (before any OS probe) and a non-empty explicit workspace
    (ephemeral; the harness removes it on completion).
    """
    for _arg_name, _path in (
        ("--workspace", getattr(args, "workspace", None)),
        ("--repo", getattr(args, "repo", None)),
    ):
        if _path is not None and is_network_path(_path):
            return (
                f"validate: {_arg_name} {_path!r} is a network/UNC path; "
                f"refusing (reading it could leak credentials over SMB)"
            )
    workspace: Path | None = getattr(args, "workspace", None)
    if workspace is not None:
        repo: Path = getattr(args, "repo")  # noqa: B009  # args typed as object
        ws_root: Path = workspace or (repo / REMEDIATION_DIRNAME / WORKSPACE_DIRNAME)
        if _is_nonempty_dir(ws_root):
            return (
                f"validate: --workspace {ws_root} is not empty; it is treated as ephemeral "
                f"and removed on completion. Pass a new or empty path."
            )
    return None


def _dispatch(argv: list[str] | None) -> int:
    """Parse args, resolve model, build config, and run validation; return exit code."""
    args = _build_parser().parse_args(argv)
    rc, overrides = _apply_model_env(_resolve_config_path(args))
    if rc != 0:
        return rc
    # Both refusals run before load_config, so nothing is staged and nothing spent.
    # The backend itself needs no gate: _apply_model_env has already routed legacy
    # `via: openai` to DeepAgents, and any other unknown value is reported by the
    # config layer, which has the field context this boundary lacks.
    for code, err in ((2, _check_persona_vendors(overrides)), (1, _check_path_guards(args))):
        if err:
            print(err, file=sys.stderr)
            return code
    config = load_config(overrides=overrides)
    # Resolve to absolute (after the UNC guard) so subprocess cwd, the Write gate, and
    # the report reader agree on one path regardless of the launch directory.
    repo: Path = args.repo.resolve()
    workspace_root: Path = (
        args.workspace or (repo / REMEDIATION_DIRNAME / WORKSPACE_DIRNAME)
    ).resolve()
    return run_validation(
        repo=repo,
        selection=_resolve_selection(args, config),
        workspace_root=workspace_root,
        config=config,
        report_md=args.scan_report,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI boundary: dispatch and turn any failure into a clean message + non-zero exit.

    Never lets a raw traceback reach the operator — known failures print their reason,
    anything unexpected is reported with its type so it's still actionable.
    """
    try:
        return _dispatch(argv)
    except _KNOWN_ERRORS as e:
        print(f"validate: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # CLI boundary must not surface a bare traceback
        print(f"validate: unexpected error ({type(e).__name__}): {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
