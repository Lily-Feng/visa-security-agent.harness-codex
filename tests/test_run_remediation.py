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

# START GENAI
"""Tests for the in-pipeline remediation wiring and the shared per-finding loop.

F11: the default-on auto-editing in-pipeline path
(``orchestrator.scan._run_remediation``) adapts the scan's ranked findings,
applies the top-N cap, and DELEGATES the per-finding loop to the SAME
``runner.process_findings`` the standalone ``remediate`` command uses — one loop,
not two. These tests lock:

  * the delegation contract — top-N cap, ranked->RA conversion, fix mode, resume
    threading, shared ckpt_dir/run_id via Layout, and binding the EXACT scan
    report for augmentation (MV-06);
  * the canonical loop's invariants in ``runner.remediate_one`` — resume-skip and
    per-finding failure-isolation — which now serve BOTH entry points.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.orchestrator import scan
from vvaharness.remediation_agent import runner
from vvaharness.remediation_agent.discovery import Layout
from vvaharness.remediation_agent.options import RemediateOptions
from vvaharness.remediation_agent.report_parser import Finding as RAFinding


# ───────────────────────── _run_remediation delegation ──────────────────────

def _ranked(title: str, score: float, *, severity: str = "HIGH"):
    """Minimal stand-in for a pipeline RankedFinding — only the attributes that
    ``_ranked_to_ra_finding`` and the top-N ``score_of`` actually read."""
    finding = SimpleNamespace(
        title=title, file="app/db.py", line_start=10, line_end=10,
        cwe="CWE-89", vuln_class=SimpleNamespace(value="injection"),
        description="desc", source_ref=None, sink_ref=None, code_snippet=None,
        cvss_score=score)
    return SimpleNamespace(finding=finding,
                           severity=SimpleNamespace(value=severity))


@pytest.fixture
def cfg():
    # top_n_findings None → no profile cap; tests pass an explicit --top where
    # the cap itself is under test. Provide a minimal models.remediate spec so
    # the orchestrator backend resolution succeeds.
    return SimpleNamespace(
        step_remediate=SimpleNamespace(top_n_findings=None),
        models=SimpleNamespace(remediate=SimpleNamespace(id="claude-opus-4-8", via="cli")),
    )


def _capture_process_findings(monkeypatch):
    """Replace runner.process_findings with a recorder so the delegation
    contract can be asserted without running the real agent loop."""
    calls: dict = {}

    def fake(findings, *, layout, cfg, repo_path, opts, report=None):
        calls.update(findings=findings, layout=layout, cfg=cfg,
                     repo_path=repo_path, opts=opts, report=report)
        return 0

    monkeypatch.setattr(
        "vvaharness.remediation_agent.runner.process_findings", fake)
    return calls


def test_run_remediation_delegates_to_process_findings(tmp_path, cfg, monkeypatch):
    calls = _capture_process_findings(monkeypatch)
    report = SimpleNamespace(findings=[_ranked("SQLi", 9.0), _ranked("XSS", 5.0)])
    ckpt = tmp_path / "ck"

    scan._run_remediation(report, tmp_path, cfg, ckpt, "run-1",
                          resume=False, top=None,
                          report_md=tmp_path / "report.md")

    # Both findings delegated, adapted to the RA Finding shape, in CVSS order.
    assert [f.title for f in calls["findings"]] == ["SQLi", "XSS"]
    assert all(isinstance(f, RAFinding) for f in calls["findings"])
    # Fix mode is forced (the in-pipeline path always auto-edits).
    assert calls["opts"].mode == "fix"
    assert calls["opts"].resume is False
    # Scan's ckpt_dir/run_id threaded through Layout → shared resume state.
    assert calls["layout"].ckpt_dir == ckpt
    assert calls["layout"].run_id == "run-1"
    assert calls["layout"].rem_dir == tmp_path / "security-remediation"
    # The EXACT scan report is bound for augmentation (MV-06), not a glob.
    assert calls["report"] == tmp_path / "report.md"
    assert calls["repo_path"] == tmp_path


def test_run_remediation_applies_top_n_cap(tmp_path, cfg, monkeypatch):
    calls = _capture_process_findings(monkeypatch)
    report = SimpleNamespace(findings=[
        _ranked("low", 3.0), _ranked("high", 9.0), _ranked("mid", 6.0)])

    scan._run_remediation(report, tmp_path, cfg, tmp_path / "ck", "run-1", top=2)

    # Only the 2 highest-CVSS findings are delegated, highest first.
    assert [f.title for f in calls["findings"]] == ["high", "mid"]


def test_run_remediation_threads_resume_flag(tmp_path, cfg, monkeypatch):
    calls = _capture_process_findings(monkeypatch)
    report = SimpleNamespace(findings=[_ranked("SQLi", 9.0)])

    scan._run_remediation(report, tmp_path, cfg, tmp_path / "ck", "run-1",
                          resume=True)

    assert calls["opts"].resume is True


# ───────────────────── canonical loop: runner.remediate_one ──────────────────

def _ra_finding(idx: int = 1) -> RAFinding:
    return RAFinding(index=idx, severity="HIGH", title="SQLi in db",
                     file="app/db.py:10", body="body")


def _layout(tmp_path) -> Layout:
    return Layout(rem_dir=tmp_path / "rem", ckpt_dir=tmp_path / "ck",
                  run_id="run-1")


def test_remediate_one_resume_skips_checkpointed(tmp_path, monkeypatch):
    """A checkpoint whose recorded identity MATCHES the current finding is
    skipped on --resume: the agent is never invoked, and it counts processed."""
    finding = _ra_finding()
    calls = {"applied": 0}
    # Authentic cache hit: the record carries this finding's identity.
    cached = {"verdict": "Fixed", "finding_id": runner._finding_identity(finding)}
    monkeypatch.setattr(runner, "load_ckpt", lambda *a, **k: cached)
    monkeypatch.setattr(
        runner, "apply_plugin",
        lambda *a, **k: calls.__setitem__("applied", calls["applied"] + 1))

    ok = runner.remediate_one(
        finding, idx=1, total=1, layout=_layout(tmp_path), cfg=object(),
        repo_path=tmp_path, opts=RemediateOptions(resume=True, mode="fix"))

    assert ok is True
    assert calls["applied"] == 0  # agent NOT run for an authenticated cache hit


def test_remediate_one_resume_reruns_on_identity_mismatch(tmp_path, monkeypatch):
    """MV-39: a checkpoint that EXISTS but whose recorded identity does
    NOT match the current finding (a reordered prior run on the same repo path,
    or a tampered state DB) must NOT be treated as done — the finding is
    re-remediated rather than silently counted processed."""
    applied = []
    monkeypatch.setattr(   # exists, but bound to a different finding
        runner, "load_ckpt",
        lambda *a, **k: {"verdict": "Fixed", "finding_id": "someone-elses-hash"})
    monkeypatch.setattr(runner, "save_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(
        runner, "apply_plugin",
        lambda finding, *a, **k: (applied.append(finding.index), {"ok": True})[1])

    ok = runner.remediate_one(
        _ra_finding(), idx=1, total=1, layout=_layout(tmp_path), cfg=object(),
        repo_path=tmp_path, opts=RemediateOptions(resume=True, mode="fix"))

    assert ok is True
    assert applied == [_ra_finding().index]  # re-ran, did not trust the cache


def test_remediate_one_isolates_failure(tmp_path, monkeypatch):
    """A finding whose remediation raises does NOT abort the run: remediate_one
    swallows the error and returns False so the caller continues."""
    def boom(*a, **k):
        raise RuntimeError("agent exploded")

    monkeypatch.setattr(runner, "load_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(runner, "apply_plugin", boom)

    ok = runner.remediate_one(
        _ra_finding(), idx=1, total=1, layout=_layout(tmp_path), cfg=object(),
        repo_path=tmp_path, opts=RemediateOptions(resume=False, mode="fix"))

    assert ok is False  # failure reported, no exception propagated


# ─────────────────────────── preflight gate ─────────────────────────────────
# _remediate_preflight is the call-site gate (scan.py) that decides whether the
# in-pipeline remediation step runs at all — independent of the loop above. It
# refuses when no models.remediate role is configured, when that role's backend
# credential is missing (startup preflight only WARNs on a post-scan gap, so this
# is where it becomes a skip), or when HEAD moved since the scan report was built
# (stale line numbers → a patch would land on the wrong code), unless --force
# overrides.

def _report(git_sha=None):
    return SimpleNamespace(findings=[], git_sha=git_sha)


def _credential(monkeypatch, ready=True, detail="credential present"):
    """Pin the backend-credential answer so the HEAD/role cases below exercise only
    their own logic. Patched on the environment module because _remediate_preflight
    imports the helper at call time (circular-import avoidance)."""
    from vvaharness.util import environment
    monkeypatch.setattr(environment, "_backend_credential_ok",
                        lambda *_a, **_k: (ready, detail))


def test_preflight_blocks_when_remediate_role_missing(tmp_path):
    cfg = SimpleNamespace(models=SimpleNamespace(remediate=None))
    args = SimpleNamespace(force=False)
    err = scan._remediate_preflight(cfg, args, tmp_path, _report())
    assert err and "models.remediate" in err


def test_preflight_blocks_when_credential_missing(tmp_path, monkeypatch):
    """A credential gap disables s10 (scan continues) instead of aborting."""
    cfg = SimpleNamespace(models=SimpleNamespace(remediate="x"))
    args = SimpleNamespace(force=False)
    _credential(monkeypatch, ready=False, detail="`claude` CLI not on PATH")
    monkeypatch.setattr(scan, "_head_sha", lambda _repo: "a" * 40)
    err = scan._remediate_preflight(cfg, args, tmp_path, _report(git_sha="a" * 40))
    assert err and "via:cli" in err and "not on PATH" in err


def test_preflight_blocks_when_head_moved(tmp_path, monkeypatch):
    cfg = SimpleNamespace(models=SimpleNamespace(remediate="x"))
    args = SimpleNamespace(force=False)
    _credential(monkeypatch)
    monkeypatch.setattr(scan, "_head_sha", lambda _repo: "b" * 40)
    err = scan._remediate_preflight(cfg, args, tmp_path, _report(git_sha="a" * 40))
    assert err and "HEAD moved" in err


def test_preflight_head_move_overridden_by_force(tmp_path, monkeypatch):
    cfg = SimpleNamespace(models=SimpleNamespace(remediate="x"))
    args = SimpleNamespace(force=True)
    _credential(monkeypatch)
    monkeypatch.setattr(scan, "_head_sha", lambda _repo: "b" * 40)
    assert scan._remediate_preflight(
        cfg, args, tmp_path, _report(git_sha="a" * 40)) is None


def test_preflight_passes_when_sha_matches(tmp_path, monkeypatch):
    cfg = SimpleNamespace(models=SimpleNamespace(remediate="x"))
    args = SimpleNamespace(force=False)
    _credential(monkeypatch)
    monkeypatch.setattr(scan, "_head_sha", lambda _repo: "a" * 40)
    assert scan._remediate_preflight(
        cfg, args, tmp_path, _report(git_sha="a" * 40)) is None
# END GENAI
