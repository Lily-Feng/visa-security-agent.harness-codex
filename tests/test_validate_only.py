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

"""Unit tests for the s11 pipeline stage (s11_validate) and the scan.py opt-in block.

Fully offline/deterministic: validation.cli.main is monkeypatched so no model
SDK, network, or LLM call is made.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from vvaharness import config as config_mod
from vvaharness.pipeline.stages import s11_validate


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _cfg(step_validate: dict | None = None) -> config_mod.Config:
    data: dict = {"models": {"validate": {"id": "x", "via": "cli"}}}
    if step_validate is not None:
        data["step_validate"] = step_validate
    return config_mod.Config(data)


# ---------------------------------------------------------------------------
# s11_validate.run — argv construction
# ---------------------------------------------------------------------------


def test_run_passes_repo_config_without_all(tmp_path: Path) -> None:
    """run() with no finding_ids sends --repo + --config and NO --all.

    Omitting --all is what lets step_validate.max_findings apply in-scan; passing it
    would uncap the selection and make the profile budget dead config.
    """
    seen: list[list[str]] = []

    with patch("vvaharness.validation.cli.main", side_effect=lambda a: seen.append(a) or 0):
        rc = s11_validate.run(tmp_path, cfg=_cfg(), config_path="prof.yaml")

    assert rc == 0
    assert seen[0][:2] == ["--repo", str(tmp_path)]
    # The scan's profile is forwarded so s11 reads the same config (F21).
    assert "--config" in seen[0]
    assert seen[0][seen[0].index("--config") + 1] == "prof.yaml"
    assert "--all" not in seen[0]
    assert "--finding" not in seen[0]


def test_profile_max_findings_reaches_selection(tmp_path: Path) -> None:
    """The in-scan argv (no --finding, no --all) resolves to a capped Selection.

    End-to-end over the real parser + _resolve_selection: the profile's
    step_validate.max_findings arrives as the config cap, so the top-N budget the
    scan configured is the one validation enforces.
    """
    from vvaharness.validation.cli import _resolve_selection
    from vvaharness.validation.cli._parser import _build_parser

    seen: list[list[str]] = []
    with patch("vvaharness.validation.cli.main", side_effect=lambda a: seen.append(a) or 0):
        s11_validate.run(tmp_path, cfg=_cfg({"max_findings": 20}), config_path="prof.yaml")

    args = _build_parser().parse_args(seen[0])
    selection = _resolve_selection(args, SimpleNamespace(max_findings=20))

    assert selection.finding_ids is None
    assert selection.max_findings == 20


def test_run_empty_config_path_falls_back_to_default(tmp_path: Path) -> None:
    """An empty config_path omits --config so the validator uses its packaged default (F21)."""
    seen: list[list[str]] = []

    with patch("vvaharness.validation.cli.main", side_effect=lambda a: seen.append(a) or 0):
        s11_validate.run(tmp_path, cfg=_cfg(), config_path="")

    assert "--config" not in seen[0]


def test_run_passes_finding_ids(tmp_path: Path) -> None:
    """run() with finding_ids sends --finding per id."""
    seen: list[list[str]] = []

    with patch("vvaharness.validation.cli.main", side_effect=lambda a: seen.append(a) or 0):
        rc = s11_validate.run(tmp_path, cfg=_cfg(), config_path="prof.yaml", finding_ids=["F-1", "F-2"])

    assert rc == 0
    argv = seen[0]
    assert "--finding" in argv
    assert argv[argv.index("--finding") + 1] == "F-1"
    # second --finding
    second = argv.index("--finding", argv.index("--finding") + 1)
    assert argv[second + 1] == "F-2"
    assert "--all" not in argv


def test_run_propagates_nonzero_exit(tmp_path: Path) -> None:
    """run() returns whatever exit code validation.cli.main returns."""
    with patch("vvaharness.validation.cli.main", return_value=3):
        rc = s11_validate.run(tmp_path, cfg=_cfg(), config_path="prof.yaml")
    assert rc == 3


# ---------------------------------------------------------------------------
# scan._run_validation — opt-in wiring
# ---------------------------------------------------------------------------


def test_scan_run_validation_calls_s11(tmp_path: Path) -> None:
    """_run_validation delegates to s11_validate.run with repo + cfg."""
    from vvaharness.orchestrator import scan

    called: dict[str, object] = {}

    def _fake_run(
        repo: Path, *, cfg: object, config_path: str,
        finding_ids: object = None, resume: bool = False, report_md: object = None,
    ) -> int:
        called["repo"] = repo
        called["cfg"] = cfg
        called["config_path"] = config_path
        called["resume"] = resume
        called["report_md"] = report_md
        return 0

    with patch.object(s11_validate, "run", side_effect=_fake_run):
        scan._run_validation(tmp_path, _cfg(), config_path="prof.yaml", report_md=tmp_path / "r.md")

    assert called["repo"] == tmp_path
    # _run_validation forwards the scan's --config so s11 reads the same profile (F21).
    assert called["config_path"] == "prof.yaml"
    assert called["report_md"] == tmp_path / "r.md"  # canonical report threaded through


def test_scan_run_validation_warns_on_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """_run_validation prints a WARN to stderr when s11 returns non-zero."""
    from vvaharness.orchestrator import scan

    with patch.object(s11_validate, "run", return_value=2):
        scan._run_validation(tmp_path, _cfg(), config_path="prof.yaml")

    captured = capsys.readouterr()
    assert "[s11] WARN" in captured.err


# ---------------------------------------------------------------------------
# scan._validate_preflight — the s11 gate
# ---------------------------------------------------------------------------
# Symmetrical with _remediate_preflight: startup preflight only WARNs when a
# post-scan role's credential is missing, so this gate is what turns that gap into
# `[s11] DISABLED` while the rest of the scan completes.


def _val_cfg(orchestrator: object) -> SimpleNamespace:
    return SimpleNamespace(
        models=SimpleNamespace(validate=SimpleNamespace(orchestrator=orchestrator)))


def _credential(monkeypatch: pytest.MonkeyPatch, *, ready: bool, detail: str) -> None:
    """Pin the backend-credential answer. Patched on the environment module because
    _validate_preflight imports the helper at call time (circular-import avoidance)."""
    from vvaharness.util import environment
    monkeypatch.setattr(environment, "_backend_credential_ok",
                        lambda *_a, **_k: (ready, detail))


def test_validate_preflight_blocks_when_role_missing() -> None:
    from vvaharness.orchestrator import scan

    err = scan._validate_preflight(_val_cfg(None))
    assert err and "models.validate.orchestrator" in err


def test_validate_preflight_routes_legacy_openai_to_deepagents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`via: openai` is no longer refused outright — it is checked as DeepAgents.

    The credential probe must see the backend s11 will actually run on, so a role
    spelled `via: openai` passes preflight once the DeepAgents/OpenAI credential is
    present, instead of aborting on the selector alone.
    """
    from vvaharness.orchestrator import scan

    _credential(monkeypatch, ready=True, detail="credential present")
    err = scan._validate_preflight(
        _val_cfg(SimpleNamespace(id="gpt-5.5", via="openai")))
    assert err is None


def test_validate_preflight_reports_routed_backend_on_credential_gap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The message names the routed backend, not the profile spelling, so the operator
    # is pointed at the credential that is actually missing.
    from vvaharness.orchestrator import scan

    _credential(monkeypatch, ready=False, detail="OPENAI_API_KEY not set")
    err = scan._validate_preflight(
        _val_cfg(SimpleNamespace(id="gpt-5.5", via="openai")))
    assert err and "via:deepagents" in err and "OPENAI_API_KEY" in err


def test_validate_preflight_blocks_when_credential_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vvaharness.orchestrator import scan

    _credential(monkeypatch, ready=False, detail="OPENAI_API_KEY not set")
    err = scan._validate_preflight(
        _val_cfg(SimpleNamespace(id="gpt-5.5", via="deepagents", provider="openai")))
    assert err and "via:deepagents" in err and "OPENAI_API_KEY not set" in err


def test_validate_preflight_passes_with_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vvaharness.orchestrator import scan

    _credential(monkeypatch, ready=True, detail="credential present")
    assert scan._validate_preflight(
        _val_cfg(SimpleNamespace(id="gpt-5.5", via="deepagents",
                                 provider="openai"))) is None
