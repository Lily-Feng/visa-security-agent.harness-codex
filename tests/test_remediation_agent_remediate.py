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

"""Tests for the Remediation Agent remediation command.

The backend model call is monkeypatched everywhere so the suite is token-free
and deterministic — we patch the single seam ``plugin_runner._invoke`` (and,
for the wiring test, ``backends.llm.agentic``) to return a canned structured
verdict instead of spending API budget.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from vvaharness import config as config_mod
from vvaharness.remediation_agent import remediate
from vvaharness.remediation_agent import plugin_runner
from vvaharness.remediation_agent import prompts
from vvaharness.remediation_agent import interactive
from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.backends.harness import HarnessResult
from vvaharness.remediation_agent.report_parser import (
    DONE_MARKER, find_scan_dir, latest_report, parse_findings, mark_done)


_SAMPLE_REPORT = """# Agentic SAST — app

## Findings (3)

### 1. [CRITICAL] Stored JQL injection via unescaped DB-sourced space_key
**Class:** CWE-943
**File:** `routers/jira.py:174-174`

#### Description
blah blah

### 2. [HIGH] JQL injection via unsanitized `spaces` and `label` query params
**Class:** CWE-943
**File:** `routers/jira.py:324-127`

### 3. [MEDIUM] 409 response discloses internal UUID and JIRA ID
**Class:** CWE-209
**File:** `routers/pr_status.py:64-71`
"""


def _canned_verdict_json(finding_index: int = 0) -> str:
    return json.dumps({
        "finding_index": finding_index,
        "verdict": "Fixed",
        "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
        "root_cause": "interpolated user input into JQL at routers/jira.py:174",
        "changes": [{"file": "routers/jira.py", "summary": "parameterized JQL"}],
        "remaining_risks": [],
        "recommendations": [],
        "summary": "Applied minimal parameterization fix.",
    })


@pytest.fixture
def cfg():
    # The packaged default profile carries a models.remediate role + step_remediate.
    # Force the policy gate OFF by default so the token-free happy-path tests are
    # deterministic regardless of whether the active profile ships
    # enforce_policy: true — the dedicated policy tests opt back in explicitly.
    from vvaharness.orchestrator import _default_config
    cfg = config_mod.load(str(_default_config()))
    cfg._data.setdefault("step_remediate", {})["enforce_policy"] = False
    cfg._data["models"]["remediate"]["via"] = "cli"  # token-free tests stub the cli agentic seam
    return cfg



@pytest.fixture(autouse=True)
def _no_model_calls(monkeypatch):
    """Patch the single model-call seam so no test spends tokens.

    The stub mirrors the REAL ``_invoke`` signature — including the keyword-only
    ``pre``/``ctx`` arguments the policy ALLOW path passes — so the suite is
    robust whether or not ``step_remediate.enforce_policy`` is on in the active
    profile (an enforced + allowed finding routes through ``_invoke(pre=, ctx=)``)."""
    monkeypatch.setattr(
        plugin_runner, "_invoke",
        lambda finding, cfg, repo, mode, verbose=False, *, pre=None, ctx=None:
        _canned_verdict_json())




def _make_scan(tmp_path, *, with_report=True):
    repo = tmp_path / "target"
    repo.mkdir()
    if with_report:
        scan = repo / "security-scan"
        scan.mkdir()
        (scan / "app_20260618T032453Z_report.md").write_text(
            _SAMPLE_REPORT, encoding="utf-8")
    return repo


# ─────────────────────────── parsing ────────────────────────────────────────

def test_parse_findings_extracts_headers_files_and_body():
    findings = parse_findings(_SAMPLE_REPORT)
    assert [f.index for f in findings] == [1, 2, 3]
    assert [f.severity for f in findings] == ["CRITICAL", "HIGH", "MEDIUM"]
    assert findings[0].file == "routers/jira.py:174-174"
    assert findings[2].file == "routers/pr_status.py:64-71"
    # full block captured for the agent prompt
    assert "Description" in findings[0].body
    assert findings[0].body.startswith("### 1.")
    assert "[CRITICAL]" in findings[0].label


def test_finding_slug_is_stable_and_safe():
    findings = parse_findings(_SAMPLE_REPORT)
    assert findings[0].slug.startswith("01_")
    assert "/" not in findings[0].slug and " " not in findings[0].slug


def test_find_scan_dir_and_latest_report(tmp_path):
    repo = _make_scan(tmp_path)
    scan_dir = find_scan_dir(repo)
    assert scan_dir is not None and scan_dir.name == "security-scan"
    assert latest_report(scan_dir).name.endswith("_report.md")


# ─────────────────────────── prompts / structured output ────────────────────

def test_build_user_includes_finding_body():
    f = parse_findings(_SAMPLE_REPORT)[0]
    user = prompts.build_user(f, "/repo", mode="fix")
    assert "routers/jira.py" in user
    assert "MODE: fix" in user
    assert f.body in user


def test_system_prompt_embeds_schema():
    assert "JSON Schema" in prompts.SYSTEM
    assert "verdict" in prompts.SYSTEM  # schema field name present


def test_deepagents_profile_enables_remediation_with_safe_tools():
    profiles_dir = Path(config_mod.__file__).resolve().parent / "profiles"
    profile = config_mod.load(str(profiles_dir / "default.yaml"))
    assert profile.models.remediate.via == "deepagents"
    assert profile.models.remediate.provider == "anthropic"
    assert profile.step_remediate.enabled is True
    assert profile.step_remediate.enforce_policy is True
    assert profile.step_remediate.allowed_tools == [
        "Read", "Glob", "Grep", "Edit", "Write",
    ]
    assert "Bash" not in profile.step_remediate.allowed_tools


def test_remediation_verdict_validates_canned_json():
    v = RemediationVerdict.model_validate(json.loads(_canned_verdict_json(1)))
    assert v.verdict == "Fixed"
    assert v.gates.source == "pass"


def test_coerce_salvages_verdict_missing_summary():
    # Real failure mode: agent returned a complete verdict but omitted `summary`.
    data = {
        "finding_index": 33,
        "verdict": "Fixed",
        "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
        "root_cause": "TOCTOU between check and update at workflow_service.py:153",
        "changes": [{"file": "services/workflow_service.py",
                     "summary": "wrapped in SELECT ... FOR UPDATE"}],
    }
    v = RemediationVerdict.coerce(data, finding_index=33)
    # the real content is preserved — NOT discarded into Needs Review
    assert v.verdict == "Fixed"
    assert v.finding_index == 33
    assert v.gates.source == "pass"
    assert v.changes[0].file == "services/workflow_service.py"
    assert v.summary == ""  # missing field defaults, doesn't nuke the verdict


def test_coerce_normalises_unknown_verdict():
    v = RemediationVerdict.coerce(
        {"verdict": "TotallyFixed", "summary": "x"}, finding_index=1)
    assert v.verdict == "Needs Review"
    assert v.summary == "x"


def test_coerce_non_dict_degrades_safely():
    v = RemediationVerdict.coerce(["not", "a", "dict"], finding_index=2)
    assert v.verdict == "Needs Review"
    assert v.finding_index == 2


def test_coerce_accepts_native_structured_verdict():
    finding = parse_findings(_SAMPLE_REPORT)[0]
    verdict = RemediationVerdict(verdict="Fixed", summary="native")
    out = plugin_runner._coerce_verdict(verdict, finding)
    assert out is verdict
    assert out.finding_index == finding.index



# ─────────────────────────── error paths ────────────────────────────────────

def test_remediate_missing_repo_arg(cfg):
    assert remediate(None, cfg=cfg) == 2


def test_remediate_requires_cfg():
    assert remediate("/tmp", cfg=None) == 2


def test_remediate_nonexistent_path(tmp_path, cfg):
    assert remediate(str(tmp_path / "nope"), cfg=cfg) == 1


def test_remediate_no_scan_dir(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path, with_report=False)
    assert remediate(str(repo), cfg=cfg) == 1
    assert "security-scan" in capsys.readouterr().err


def test_remediate_no_report(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path, with_report=False)
    (repo / "security-scan").mkdir()
    assert remediate(str(repo), cfg=cfg) == 1
    assert "_report.md" in capsys.readouterr().err


def test_remediate_invalid_mode(tmp_path, cfg):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), ["--mode", "bogus"], cfg=cfg) == 2


def test_remediate_invalid_top(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), ["--top", "0"], cfg=cfg) == 2
    assert "--top" in capsys.readouterr().err


# ─────────────────────────── --top N selection (by CVSS) ────────────────────

# Report where the band ordering and the CVSS-score ordering DIFFER, so a
# correct --top must select by score, not by report position. Finding 3
# (MEDIUM) carries the highest numeric CVSS, finding 1 (CRITICAL) the lowest.
_SCORED_REPORT = """# Agentic SAST — app

## Findings (3)

### 1. [CRITICAL] low-score critical
**Class:** CWE-89
**File:** `a.py:1-1`
**CVSS 3.1:** **4.0** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N`

### 2. [HIGH] mid-score high
**Class:** CWE-89
**File:** `b.py:2-2`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`

### 3. [MEDIUM] top-score medium
**Class:** CWE-89
**File:** `c.py:3-3`
**CVSS 3.1:** **9.8** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
"""


def _make_scored_scan(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    scan = repo / "security-scan"
    scan.mkdir()
    (scan / "app_20260618T032453Z_report.md").write_text(
        _SCORED_REPORT, encoding="utf-8")
    return repo


def test_remediate_top_selects_highest_cvss_only(tmp_path, cfg, capsys):
    repo = _make_scored_scan(tmp_path)
    assert remediate(str(repo), ["--top", "2"], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "selecting top 2 of 3 finding(s) by CVSS score" in err
    assert "2/2 findings processed" in err

    rem = repo / "security-remediation"
    findings = parse_findings(_SCORED_REPORT)
    # findings[2] (9.8) and findings[1] (6.5) are the two highest → remediated;
    # findings[0] (4.0) is skipped (no artefact folder).
    assert (rem / findings[2].slug / "remediate_report.json").is_file()
    assert (rem / findings[1].slug / "remediate_report.json").is_file()
    assert not (rem / findings[0].slug).exists()


def test_remediate_top_larger_than_findings_is_noop(tmp_path, cfg, capsys):
    repo = _make_scored_scan(tmp_path)
    assert remediate(str(repo), ["--top", "10"], cfg=cfg) == 0
    err = capsys.readouterr().err
    # N >= count: no selection message, every finding processed.
    assert "selecting top" not in err
    assert "3/3 findings processed" in err


# ───── profile-driven cap (standalone `remediate`, NO --top flag) ────────────

def _set_top_n_findings(cfg, value):
    """Mutate the loaded Config's step_remediate.top_n_findings in place so a
    test can exercise the profile-driven cap without a bespoke YAML file."""
    sr = cfg._data.setdefault("step_remediate", {})
    sr["top_n_findings"] = value
    return cfg


def test_remediate_honors_profile_top_n_findings_without_flag(tmp_path, cfg, capsys):
    # The standalone `remediate` command (run detached from a scan, no --top)
    # must still apply the profile's step_remediate.top_n_findings cap.
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, 2)
    assert remediate(str(repo), [], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "selecting top 2 of 3 finding(s) by CVSS score" in err
    assert "2/2 findings processed" in err

    rem = repo / "security-remediation"
    findings = parse_findings(_SCORED_REPORT)
    # Only the two highest-CVSS findings are remediated; the 4.0 is skipped.
    assert (rem / findings[2].slug / "remediate_report.json").is_file()
    assert (rem / findings[1].slug / "remediate_report.json").is_file()
    assert not (rem / findings[0].slug).exists()


def test_remediate_cli_top_overrides_profile_cap(tmp_path, cfg, capsys):
    # --top on the CLI overrides a numeric profile cap for that run.
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, 1)               # profile says 1 ...
    assert remediate(str(repo), ["--top", "2"], cfg=cfg) == 0  # ... CLI says 2
    err = capsys.readouterr().err
    assert "selecting top 2 of 3 finding(s) by CVSS score" in err
    assert "2/2 findings processed" in err


@pytest.mark.parametrize("wildcard", ["all", "*"])
def test_remediate_profile_wildcard_remediates_every_finding(tmp_path, cfg,
                                                             capsys, wildcard):
    # top_n_findings: all/* in the profile → no cap, every finding remediated.
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, wildcard)
    assert remediate(str(repo), [], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "selecting top" not in err          # no narrowing
    assert "3/3 findings processed" in err


def test_remediate_cli_top_all_overrides_numeric_profile(tmp_path, cfg, capsys):
    # --top all overrides a numeric profile cap → remediate every finding.
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, 1)
    assert remediate(str(repo), ["--top", "all"], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "selecting top" not in err
    assert "3/3 findings processed" in err



# ─────────────────────────── happy path / artefacts / checkpoints ───────────

def test_remediate_happy_path(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "identified 3 SAST issue(s)" in err
    assert "3/3 findings processed" in err
    assert "model:" in err  # banner printed


def test_remediate_writes_artifacts(tmp_path, cfg):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    rem = repo / "security-remediation"
    for f in parse_findings(_SAMPLE_REPORT):
        d = rem / f.slug
        # Evidence artefacts now live under evidence/ ...
        assert (d / "evidence" / "triage.json").is_file()
        assert (d / "evidence" / "summary.md").is_file()
        data = json.loads((d / "evidence" / "triage.json").read_text())
        assert data["finding_index"] == f.index
        assert data["verdict"] == "Fixed"
        # ... and the canonical report sits at the finding root.
        report = d / "remediate_report.json"
        assert report.is_file()
        rep = json.loads(report.read_text())
        assert rep["schema_version"] == "1.0"
        assert rep["finding"]["title"] == f.title
        assert rep["status"] == "awaiting_validation"
        assert rep["patch"]["files_touched"] == ["routers/jira.py"]


def test_remediate_report_schema_shape(tmp_path, cfg):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    rem = repo / "security-remediation"
    f1 = parse_findings(_SAMPLE_REPORT)[0]
    rep = json.loads((rem / f1.slug / "remediate_report.json").read_text())
    # top-level keys required by the schema
    assert set(rep) >= {
        "schema_version", "finding_id", "attempt", "max_attempts",
        "status", "finding", "patch", "validation"}
    assert rep["attempt"] == 1 and rep["max_attempts"] == 2
    assert rep["finding_id"].endswith("routers/jira.py-174")
    assert rep["finding"]["cwe"] == "CWE-943"
    assert rep["finding"]["line_start"] == 174
    assert rep["patch"]["remediation_summary"]
    # validation block is laid out but empty — remediation never scores it.
    val = rep["validation"]
    assert set(val) >= {
        "fix_status", "raw_score", "merge_readiness", "gate_scores",
        "justification", "conditions_for_full_fix", "recommendations"}
    assert val["fix_status"] is None
    assert val["raw_score"] is None
    assert val["merge_readiness"] is None
    assert val["gate_scores"] is None
    assert val["justification"] is None
    assert val["conditions_for_full_fix"] == []
    assert val["recommendations"] == []




def test_diff_patch_written_for_changed_files(tmp_path, cfg, monkeypatch):
    """When the verdict reports changed files in a git repo, a diff.patch is
    written capturing exactly those edits."""
    import subprocess
    from vvaharness.remediation_agent import artifacts as _artifacts
    from vvaharness.remediation_agent.models import RemediationVerdict, Gates

    repo = tmp_path / "gitrepo"
    repo.mkdir()
    (repo / "routers").mkdir()
    target = repo / "routers" / "jira.py"
    target.write_text("jql = f'... {space} ...'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-qm", "init"],
                   check=True, capture_output=True)
    # the "agent" edits the file
    target.write_text("jql = 'parameterized'\n", encoding="utf-8")

    v = RemediationVerdict(
        finding_index=1, verdict="Fixed", gates=Gates(),
        changes=[{"file": "routers/jira.py", "summary": "parameterized"}],
        summary="x")
    out = tmp_path / "out"
    _artifacts.write_verdict(out, v, meta={"mode": "fix"}, repo=repo)

    patch = out / "evidence" / "diff.patch"
    assert patch.is_file()
    body = patch.read_text()
    assert "routers/jira.py" in body and "parameterized" in body
    assert json.loads(
        (out / "evidence" / "triage.json").read_text())["diff_captured"] is True


def test_no_diff_patch_when_not_git_and_no_snapshot(tmp_path):
    """Non-git target with NO pre-edit snapshot supplied → no patch (the
    runner always supplies a snapshot; this is the bare edge case)."""
    from vvaharness.remediation_agent import artifacts as _artifacts
    from vvaharness.remediation_agent.models import RemediationVerdict, Gates
    v = RemediationVerdict(finding_index=1, verdict="Needs Review",
                           gates=Gates(), summary="x",
                           changes=[{"file": "a.py", "summary": "y"}])
    out = tmp_path / "out"
    _artifacts.write_verdict(out, v, meta={"mode": "fix"}, repo=tmp_path)
    assert not (out / "evidence" / "diff.patch").exists()
    assert json.loads(
        (out / "evidence" / "triage.json").read_text())["diff_captured"] is False


def test_synth_diff_patch_written_for_non_git_target(tmp_path):
    """Non-git target: a pre-edit snapshot + on-disk edit yields a synthesized
    unified diff written to evidence/diff.patch (no git involved)."""
    from vvaharness.remediation_agent import artifacts as _artifacts
    from vvaharness.remediation_agent.models import RemediationVerdict, Gates

    repo = tmp_path / "plainrepo"  # NOT a git repo
    (repo / "routers").mkdir(parents=True)
    target = repo / "routers" / "jira.py"
    target.write_text("jql = f'... {space} ...'\n", encoding="utf-8")

    # Runner snapshots BEFORE the agent edits ...
    before = _artifacts.snapshot_files(repo, ["routers/jira.py:174-174"])
    # ... then the "agent" edits the file in place.
    target.write_text("jql = 'parameterized'\n", encoding="utf-8")

    v = RemediationVerdict(
        finding_index=1, verdict="Fixed", gates=Gates(),
        changes=[{"file": "routers/jira.py", "summary": "parameterized"}],
        summary="x")
    out = tmp_path / "out"
    _artifacts.write_verdict(out, v, meta={"mode": "fix"}, repo=repo,
                             before_snapshot=before)

    patch = out / "evidence" / "diff.patch"
    assert patch.is_file()
    body = patch.read_text()
    assert "not a git repository" in body          # synthesized-diff marker
    assert "routers/jira.py" in body
    assert "-jql = f'... {space} ...'" in body
    assert "+jql = 'parameterized'" in body
    assert json.loads(
        (out / "evidence" / "triage.json").read_text())["diff_captured"] is True


def test_synth_diff_renders_new_file(tmp_path):
    """A file the agent creates (absent in the snapshot) renders as an added
    file in the synthesized diff."""
    from vvaharness.remediation_agent.artifacts.diff import synth_unified_diff

    repo = tmp_path / "plainrepo"
    repo.mkdir()
    # snapshot taken when the file did not exist yet (value None = absent)
    snap = {"new.py": None}

    (repo / "new.py").write_text("print('hello')\n", encoding="utf-8")

    diff = synth_unified_diff(repo, snap)
    assert diff is not None
    assert "/dev/null" in diff
    assert "b/new.py" in diff
    assert "+print('hello')" in diff


def test_synth_diff_none_when_unchanged(tmp_path):
    from vvaharness.remediation_agent.artifacts.diff import snapshot_files, synth_unified_diff
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    before = snapshot_files(repo, ["a.py"])
    # no edit happens
    assert synth_unified_diff(repo, before) is None



def test_remediate_reuses_scan_checkpoint_dir(tmp_path, cfg):
    """Checkpoints land in the shared scan-pipeline checkpoint store (the same
    SQLite state store + run_id the scan pipeline uses), NOT a private
    security-remediation/checkpoints folder."""
    from vvaharness.orchestrator.checkpoints import load_ckpt, run_id_for
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    run_id = run_id_for(repo)
    ckpts = [load_ckpt(repo / "checkpoints", run_id, f"remediate_{i}")
             for i in (1, 2, 3)]
    assert all(c is not None for c in ckpts)
    assert not (repo / "security-remediation" / "checkpoints").exists()



def test_remediate_resume_skips_checkpointed(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    capsys.readouterr()
    assert remediate(str(repo), ["--resume"], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "cached" in err
    assert "3/3 findings processed" in err


# ─────────────────────────── end-to-end wiring (backend seam) ───────────────

def test_apply_plugin_wires_backend_and_validates(tmp_path, cfg, monkeypatch):
    """Patch backends.llm.agentic itself to prove the runner calls the backend
    and validates its structured output into triage.json."""
    calls = {}

    def fake_agentic(user, *, model, **kw):
        calls["model"] = model
        calls["cwd"] = kw.get("cwd")
        return _canned_verdict_json()

    monkeypatch.setattr(plugin_runner, "agentic", fake_agentic)
    # Use the real _invoke (undo the autouse stub) for this one test.
    monkeypatch.undo()
    monkeypatch.setattr(plugin_runner, "agentic", fake_agentic)

    finding = parse_findings(_SAMPLE_REPORT)[0]
    out = tmp_path / "out"
    rec = plugin_runner.apply_plugin(finding, out, cfg=cfg, repo=tmp_path,
                                     mode="fix")
    assert rec["verdict"] == "Fixed"
    assert calls["cwd"] == str(tmp_path)
    assert (out / "evidence" / "triage.json").is_file()
    assert (out / "remediate_report.json").is_file()


def test_invoke_routes_deepagents_through_hoisted_harness(
        tmp_path, cfg, monkeypatch):
    calls = {}

    class FakeHarness:
        def run_streaming(self, prompt, options):
            calls["prompt"] = prompt
            calls["options"] = options

            async def messages():
                yield HarnessResult(
                    subtype="success",
                    structured=json.loads(_canned_verdict_json()),
                )
            return messages()

    monkeypatch.undo()
    cfg._data["models"]["remediate"] = {
        "id": "gpt-5.5", "via": "deepagents",
    }
    monkeypatch.setattr(plugin_runner, "get_harness", lambda via: FakeHarness())
    monkeypatch.setattr(
        plugin_runner, "agentic",
        lambda *args, **kwargs: pytest.fail("legacy dispatcher was called"),
    )

    finding = parse_findings(_SAMPLE_REPORT)[0]
    raw = plugin_runner._invoke(finding, cfg, tmp_path, "fix")
    options = calls["options"]
    assert raw["verdict"] == "Fixed"
    assert calls["prompt"].startswith(
        "REPOSITORY ROOT: / (DeepAgents virtual workspace root)"
    )
    assert str(tmp_path.resolve()) not in calls["prompt"]
    assert options.model == "gpt-5.5"
    assert options.cwd == tmp_path
    assert options.response_model is RemediationVerdict
    assert options.allow_writes is True
    assert options.writable_paths == (str(tmp_path.resolve()),)
    assert "Bash" in options.tool_policy.disallowed_tools


def test_virtualize_deepagents_prompt_preserves_finding_content(tmp_path):
    original = (
        f"REPOSITORY ROOT: {tmp_path}\n"
        "MODE: fix\nPRIMARY FILE: services/workflow_service.py\n"
    )
    virtual = plugin_runner._virtualize_deepagents_prompt(original)
    assert str(tmp_path) not in virtual
    assert "MODE: fix" in virtual
    assert "PRIMARY FILE: services/workflow_service.py" in virtual


def test_invoke_deepagents_report_only_is_read_only(tmp_path, cfg, monkeypatch):
    captured = {}

    class FakeHarness:
        def run_streaming(self, prompt, options):
            captured["options"] = options

            async def messages():
                yield HarnessResult(subtype="success", result_text=_canned_verdict_json())
            return messages()

    monkeypatch.undo()
    cfg._data["models"]["remediate"] = {
        "id": "gpt-5.5", "via": "deepagents",
    }
    monkeypatch.setattr(plugin_runner, "get_harness", lambda via: FakeHarness())
    finding = parse_findings(_SAMPLE_REPORT)[0]
    plugin_runner._invoke(finding, cfg, tmp_path, "report-only")
    assert captured["options"].allow_writes is False
    assert captured["options"].writable_paths == ()


def test_run_sync_bridges_an_active_event_loop():
    async def value():
        return 42

    async def caller():
        return plugin_runner._run_sync(value())

    assert asyncio.run(caller()) == 42


def test_run_sync_propagates_threaded_exception():
    error = RuntimeError("boom")

    async def fail():
        raise error

    async def caller():
        with pytest.raises(RuntimeError, match="boom") as caught:
            plugin_runner._run_sync(fail())
        assert caught.value is error

    asyncio.run(caller())


@pytest.mark.parametrize("via", ["cli", "sdk", "openai"])
def test_invoke_keeps_legacy_routes(tmp_path, cfg, monkeypatch, via):
    calls = []
    monkeypatch.undo()
    cfg._data["models"]["remediate"] = {"id": "model", "via": via}
    monkeypatch.setattr(
        plugin_runner, "agentic",
        lambda *args, **kwargs: calls.append(kwargs["model"]) or _canned_verdict_json(),
    )
    finding = parse_findings(_SAMPLE_REPORT)[0]
    plugin_runner._invoke(finding, cfg, tmp_path, "fix")
    assert len(calls) == 1
    assert calls[0].id == "model"
    assert calls[0].via == via



def test_verbose_dumps_prompt_and_response(tmp_path, cfg, monkeypatch, capsys):
    """--verbose echoes the prompt and the raw model response to stderr."""
    monkeypatch.setattr(plugin_runner, "agentic",
                        lambda user, *, model, **kw: _canned_verdict_json())
    monkeypatch.undo()
    monkeypatch.setattr(plugin_runner, "agentic",
                        lambda user, *, model, **kw: _canned_verdict_json())

    finding = parse_findings(_SAMPLE_REPORT)[0]
    plugin_runner.apply_plugin(finding, tmp_path / "out", cfg=cfg,
                               repo=tmp_path, mode="fix", verbose=True)
    err = capsys.readouterr().err
    assert "PROMPT →" in err
    assert "FINAL VERDICT ←" in err
    assert "verdict" in err  # the raw response block is present



def test_verbose_flag_announced(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), ["--verbose"], cfg=cfg) == 0
    assert "verbose:" in capsys.readouterr().err


def test_verbose_dumps_policy_and_playbook_when_enforced(
        tmp_path, cfg, capsys, monkeypatch):
    """With the policy gate enabled, --verbose must explicitly surface the
    per-finding policy DECISION and the resolved PLAYBOOK STRATEGY that were
    ingested for the finding (not just bury them inside the prompt dump)."""
    from vvaharness.remediation_agent import policy as _policy

    # The enforce path calls _invoke(..., pre=, ctx=); the autouse stub doesn't
    # accept those kwargs, so override it with a compatible canned seam.
    monkeypatch.setattr(
        plugin_runner, "_invoke",
        lambda finding, cfg, repo, mode, verbose=False, *, pre=None, ctx=None:
        _canned_verdict_json())


    # CWE-89 in a non-sensitive path is allow:auto with a playbook strategy.
    report = (
        "# Agentic SAST — app\n\n"
        "## Findings (1)\n\n"
        "### 1. [HIGH] SQL injection in query builder\n"
        "**Class:** CWE-89\n"
        "**File:** `app/db.py:10-10`\n\n"
        "#### Description\nblah\n")
    finding = parse_findings(report)[0]

    # Enable the policy gate and build a real context (gate + playbook).
    cfg._data.setdefault("step_remediate", {})["enforce_policy"] = True
    # The profile's policy/playbook paths are relative to the config dir; the
    # packaged profile has no inputs/ tree next to it, so clear them and let the
    # gate/playbook fall back to their shipped defaults (repo-root inputs/).
    cfg._data["step_remediate"]["policy_file"] = None
    cfg._data["step_remediate"]["playbook_file"] = None
    ctx = _policy.build_context(cfg, tmp_path)
    assert ctx.enabled

    plugin_runner.apply_plugin(finding, tmp_path / "out", cfg=cfg,
                               repo=tmp_path, mode="fix", verbose=True,
                               policy_ctx=ctx)
    err = capsys.readouterr().err
    assert "POLICY → finding 1" in err
    assert "CWE-89" in err
    assert "decision:" in err
    assert "PLAYBOOK STRATEGY → finding 1" in err


def test_verbose_states_policy_disabled_when_not_enforced(
        tmp_path, cfg, capsys):
    """When the policy gate is OFF (the default), --verbose must say so
    explicitly so the absence of POLICY/PLAYBOOK blocks is never ambiguous —
    pointing the user at the step_remediate.enforce_policy toggle."""
    finding = parse_findings(_SAMPLE_REPORT)[0]
    # No policy_ctx passed → enforcement disabled.
    plugin_runner.apply_plugin(finding, tmp_path / "out", cfg=cfg,
                               repo=tmp_path, mode="fix", verbose=True)
    err = capsys.readouterr().err
    assert "enforcement disabled" in err
    assert "enforce_policy" in err
    # ... and no policy/playbook blocks were printed.
    assert "POLICY → finding" not in err
    assert "PLAYBOOK STRATEGY" not in err




def test_stream_trace_renders_tool_calls_and_text(capsys):
    """The live-trace renderer turns stream-json events into concise lines:
    tool calls (🔧), assistant text (💬), and tool results (↩)."""
    from vvaharness.backends.claude_cli import stream_trace
    import sys as _sys

    # tool_use + text in one assistant event
    stream_trace(json.dumps({
        "type": "assistant",
        "message": {"content": [
            {"type": "text", "text": "Looking at routers/jira.py"},
            {"type": "tool_use", "name": "Read",
             "input": {"file_path": "routers/jira.py"}},
        ]},
    }), out=_sys.stderr)
    # tool_result coming back
    stream_trace(json.dumps({
        "type": "user",
        "message": {"content": [
            {"type": "tool_result", "content": [{"type": "text", "text": "x" * 50}]},
        ]},
    }), out=_sys.stderr)

    err = capsys.readouterr().err
    assert "🔧 Read(" in err
    assert "💬 Looking at routers/jira.py" in err
    assert "↩ tool result (50 chars)" in err


def test_stream_trace_ignores_junk(capsys):
    from vvaharness.backends.claude_cli import stream_trace
    import sys as _sys
    stream_trace("not json", out=_sys.stderr)
    stream_trace("", out=_sys.stderr)
    assert capsys.readouterr().err == ""




# ─────────────────────────── done marker (report .md) ───────────────────────

def test_mark_done_roundtrip_and_idempotent(tmp_path):
    report = tmp_path / "r.md"
    report.write_text(_SAMPLE_REPORT, encoding="utf-8")
    findings = parse_findings(_SAMPLE_REPORT)
    # mark finding 1 done
    assert mark_done(report, findings[0]) is True
    txt = report.read_text()
    assert DONE_MARKER in txt
    # re-parse: only finding 1 is done, title is clean (marker stripped)
    reparsed = parse_findings(txt)
    assert reparsed[0].done is True
    assert "remediation-agent:done" not in reparsed[0].title
    assert reparsed[1].done is False
    # idempotent: second mark is a no-op
    assert mark_done(report, findings[0]) is False
    assert report.read_text().count(DONE_MARKER) == 1


# ─────────────────────────── interactive: selection parsing ─────────────────

def test_parse_selection_variants():
    findings = parse_findings(_SAMPLE_REPORT)
    assert interactive.parse_selection("q", findings) is None
    assert interactive.parse_selection("", findings) is None
    assert interactive.parse_selection("all", findings) == [0, 1, 2]
    assert interactive.parse_selection("1,3", findings) == [0, 2]
    assert interactive.parse_selection("1-3", findings) == [0, 1, 2]
    assert interactive.parse_selection("2 bogus 9", findings) == [1]


def test_parse_selection_pending_excludes_done():
    findings = parse_findings(_SAMPLE_REPORT)
    findings[0].done = True
    assert interactive.parse_selection("pending", findings) == [1, 2]


# ─────────────────────────── interactive: key decoding ──────────────────────

def test_decode_key_tokens():
    assert interactive.decode_key("\x1b[A") == interactive.UP
    assert interactive.decode_key("\x1b[B") == interactive.DOWN
    assert interactive.decode_key("k") == interactive.UP
    assert interactive.decode_key("j") == interactive.DOWN
    assert interactive.decode_key("\r") == interactive.ENTER
    assert interactive.decode_key("q") == interactive.QUIT
    assert interactive.decode_key("\x1b") == interactive.QUIT
    assert interactive.decode_key("x") == interactive.OTHER


def test_render_rows_marks_done():
    findings = parse_findings(_SAMPLE_REPORT)
    findings[1].done = True
    rows = interactive.render_rows(findings)
    assert "✅" in rows[1]
    assert "✅" not in rows[0]


# ─────────────────────────── interactive: end-to-end (non-TTY fallback) ──────

def test_interactive_fallback_select_then_quit(tmp_path, cfg, monkeypatch, capsys):
    """Non-TTY path: scripted input picks issue 1 then quits. Asserts the
    artifacts + checkpoint exist and the report header now carries the done
    marker."""
    repo = _make_scan(tmp_path)

    answers = iter(["1", "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))

    rc = remediate(str(repo), ["--interactive"], cfg=cfg)
    assert rc == 0

    rem = repo / "security-remediation"
    f1 = parse_findings(_SAMPLE_REPORT)[0]
    assert (rem / f1.slug / "evidence" / "triage.json").is_file()
    assert (rem / f1.slug / "remediate_report.json").is_file()
    from vvaharness.orchestrator.checkpoints import load_ckpt, run_id_for
    run_id = run_id_for(repo)
    assert load_ckpt(repo / "checkpoints", run_id, "remediate_1") is not None
    assert load_ckpt(repo / "checkpoints", run_id, "remediate_2") is None


    # report marked done for finding 1 only
    report = latest_report(repo / "security-scan")
    reparsed = parse_findings(report.read_text())
    assert reparsed[0].done is True
    assert reparsed[1].done is False

    err = capsys.readouterr().err
    assert "1 remediated this session" in err


def test_interactive_ignores_profile_top_n_and_shows_full_list(
        tmp_path, cfg, monkeypatch, capsys):
    """Interactive mode is a manual picker, so a profile-driven
    step_remediate.top_n_findings cap must NOT pre-truncate the list — the user
    must see (and be able to pick) EVERY finding. Here the profile caps at 1 but
    all 3 findings must be offered; selecting "all" remediates all 3."""
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, 1)               # profile caps at 1 ...

    answers = iter(["all", "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))

    rc = remediate(str(repo), ["--interactive"], cfg=cfg)
    assert rc == 0

    err = capsys.readouterr().err
    # The cap is ignored: no narrowing message, full list identified.
    assert "selecting top" not in err
    assert "identified 3 SAST issue(s)" in err

    # ... and every finding was remediable (full list shown), all 3 picked.
    rem = repo / "security-remediation"
    findings = parse_findings(_SCORED_REPORT)
    for f in findings:
        assert (rem / f.slug / "remediate_report.json").is_file()
    assert "3 remediated this session" in err


def test_interactive_still_honors_explicit_cli_top(
        tmp_path, cfg, monkeypatch, capsys):
    """An explicit ``--top N`` on the CLI is still honored in interactive mode
    (only the profile-driven cap is ignored). With --top 2, only the 2
    highest-CVSS findings are offered."""
    repo = _make_scored_scan(tmp_path)

    answers = iter(["all", "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))

    rc = remediate(str(repo), ["--interactive", "--top", "2"], cfg=cfg)
    assert rc == 0

    err = capsys.readouterr().err
    assert "selecting top 2 of 3 finding(s) by CVSS score" in err
    assert "identified 2 SAST issue(s)" in err

    rem = repo / "security-remediation"
    findings = parse_findings(_SCORED_REPORT)
    # the two highest-CVSS (9.8, 6.5) remediated; the 4.0 was never offered.
    assert (rem / findings[2].slug / "remediate_report.json").is_file()
    assert (rem / findings[1].slug / "remediate_report.json").is_file()
    assert not (rem / findings[0].slug).exists()


def test_remediate_report_json_stays_valid_with_secret_in_fields(tmp_path):
    """Regression: redaction must not corrupt the JSON DTO.

    Earlier the writer redacted the already-serialised JSON string, so a secret
    pattern matching across JSON quotes/escapes mangled the escaping and the
    file no longer parsed (report augmentation logged "could not read
    remediation DTO"). The writer now redacts the structure BEFORE serialising
    (redact_tree), so the encoder owns all escaping. This builds a finding body
    that contains a credential and asserts the resulting remediate_report.json
    parses AND has the secret masked."""
    from vvaharness.remediation_agent import artifacts
    from vvaharness.remediation_agent.report_parser import Finding

    # A code snippet carrying a token-bearing URL, as the scan report would.
    body = (
        "### 1. [HIGH] Git token embedded in subprocess argv\n"
        "**Class:** CWE-312\n"
        "**File:** `app/clone.py:10`\n\n"
        "#### Description\n"
        'url = "https://x-access-token:ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789@host/r.git"\n'
    )
    finding = Finding(index=1, severity="HIGH",
                      title="Git token embedded in subprocess argv",
                      file="app/clone.py", body=body)
    verdict = RemediationVerdict(
        finding_index=1, verdict="Fixed",
        root_cause="token in argv",
        summary="moved token to env",
    )
    out_dir = tmp_path / "01_git-token"
    artifacts.write_verdict(out_dir, verdict, meta={"mode": "fix"},
                            finding=finding)

    dto_path = out_dir / "remediate_report.json"
    # Must parse — this is the exact failure mode the bug produced.
    dto = json.loads(dto_path.read_text(encoding="utf-8"))
    # And the credential must be masked, not echoed verbatim.
    raw = dto_path.read_text(encoding="utf-8")
    assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" not in raw
    assert dto["patch"]["remediation_summary"] == "moved token to env"
