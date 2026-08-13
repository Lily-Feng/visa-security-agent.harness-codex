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

"""Offline unit tests for the startup connectivity probe (check_backends).

A via:cli model that responds but whose reply exceeds the tiny preflight
max_tokens cap surfaces as an error, yet it is reachable — the probe must count
it as a pass. Genuine credential/connectivity failures must still fail. No real
network or subprocess: the probe call and model-role resolution are monkeypatched.
"""
from types import SimpleNamespace

import pytest

from vvaharness import orchestrator
from vvaharness.orchestrator import preflight as pf
import vvaharness.backends.llm as llm


# ─────────────────────────────────────────────────────────────────────────────
# _reachable_despite_token_cap — the decision helper
# ─────────────────────────────────────────────────────────────────────────────

def test_reachable_despite_token_cap_matches_cli_message():
    msg = ("claude CLI failed: API Error: Claude's response exceeded the 4 "
           "output token maximum. To configure this behavior, set the "
           "CLAUDE_CODE_MAX_OUTPUT_TOKENS environment variable. (rc=1)")
    assert orchestrator._reachable_despite_token_cap(msg) is True


@pytest.mark.parametrize("msg", [
    "401 Invalid authentication credentials",
    "model_name 'x' is not a valid LLM model",
    "connection error: CERTIFICATE_VERIFY_FAILED",
    "",
    None,
])
def test_reachable_despite_token_cap_rejects_other_errors(msg):
    assert orchestrator._reachable_despite_token_cap(msg) is False


# ─────────────────────────────────────────────────────────────────────────────
# check_backends — end-to-end probe classification
# ─────────────────────────────────────────────────────────────────────────────

def _force_single_cli_role(monkeypatch):
    """Make check_backends see exactly one via:cli role, with `claude` on PATH,
    so the live probe is the only thing under test."""
    # check_backends/probe_backends live in the preflight submodule and resolve
    # these names through preflight's own bindings (confirmed via cartograph),
    # so patch them there.
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [("threatmodel", "model-node")])
    monkeypatch.setattr(orchestrator.preflight, "resolve_model",
                        lambda m: ("test-model", "cli", {}))
    monkeypatch.setattr(orchestrator.shutil, "which", lambda name: "/usr/bin/claude")
    # The live probe is what's under test here — present a gateway so the new
    # JWT-without-base_url fast-fail gate doesn't short-circuit before it.
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://test-gateway.example/")


def test_check_backends_token_cap_counts_as_reachable(monkeypatch):
    _force_single_cli_role(monkeypatch)

    def fake_probe(*a, **k):
        raise RuntimeError("claude CLI failed: API Error: Claude's response "
                           "exceeded the 4 output token maximum (rc=1)")

    monkeypatch.setattr(llm, "prompt", fake_probe)
    assert orchestrator.check_backends(cfg=object()) is True


def test_check_backends_genuine_auth_error_still_fails(monkeypatch):
    _force_single_cli_role(monkeypatch)

    def fake_probe(*a, **k):
        raise RuntimeError("claude CLI failed: 401 Invalid authentication "
                           "credentials (rc=1)")

    monkeypatch.setattr(llm, "prompt", fake_probe)
    assert orchestrator.check_backends(cfg=object()) is False


def test_configure_backends_resolves_ca_cert(monkeypatch, tmp_path):
    """Regression: configure_backends resolves sdk/openai/cli ca_cert via
    _resolve_against (which moved to config_paths during the orchestrator
    split). A missing import previously raised NameError on the ca_cert branch
    when a profile set sdk.ca_cert (e.g. switching to an Opus SDK model behind
    a gateway). Exercises that exact path."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import preflight as pf
    captured = {}
    monkeypatch.setattr(pf.sdk, "configure", lambda **kw: captured.update(kw))
    monkeypatch.setattr(pf.oai, "configure", lambda **kw: None)
    monkeypatch.setattr(pf.cli, "configure", lambda **kw: None)
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("models:\n  deepdive: {id: x, via: sdk}\n"
                        "sdk:\n  ca_cert: certs/ca.pem\n", encoding="utf-8")
    cfg = config_mod.load(cfg_file)
    pf.configure_backends(cfg, tmp_path)              # must not raise NameError
    assert captured["ca_cert"] == str(tmp_path / "certs" / "ca.pem")

def _agentic_role(monkeypatch, role, via):
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [(role, "model-node")])
    monkeypatch.setattr(orchestrator.preflight, "resolve_model",
                        lambda m: ("test-model", via, {}))
    monkeypatch.setattr(llm, "prompt", lambda *a, **k: "ok")


def test_agentic_probe_raise_fails_preflight(monkeypatch):
    _agentic_role(monkeypatch, "preprocess", "sdk")

    def boom(*a, **k):
        raise NotImplementedError("Bash tool not supported by sdk backend")

    monkeypatch.setattr(llm, "agentic", boom)
    assert orchestrator.preflight.probe_backends(cfg=object()) is False


def test_agentic_probe_empty_reply_is_not_failure(monkeypatch):
    _agentic_role(monkeypatch, "verify", "cli")
    monkeypatch.setattr(llm, "agentic", lambda *a, **k: "")  # tool_use-only turn
    assert orchestrator.preflight.probe_backends(cfg=object()) is True


def test_agentic_probe_skips_prompt_only_roles(monkeypatch):
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [("threatmodel", "m"), ("decompose", "m")])
    monkeypatch.setattr(orchestrator.preflight, "resolve_model",
                        lambda m: ("test-model", "sdk", {}))
    monkeypatch.setattr(llm, "prompt", lambda *a, **k: "ok")
    calls = {"n": 0}

    def rec(*a, **k):
        calls["n"] += 1
        return "ok"

    monkeypatch.setattr(llm, "agentic", rec)
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert calls["n"] == 0  # agentic() never probed for prompt-only roles


def test_deepagents_role_uses_hoisted_harness_probe(monkeypatch):
    from vvaharness.backends import harness as harness_pkg

    monkeypatch.setattr(
        orchestrator.preflight, "_iter_model_roles",
        lambda cfg: [("remediate", SimpleNamespace(id="gpt-5.5", via="deepagents"))],
    )
    monkeypatch.setattr(
        orchestrator.preflight, "resolve_model",
        lambda model: ("gpt-5.5", "deepagents", {}),
    )
    monkeypatch.setattr(
        llm, "prompt",
        lambda *args, **kwargs: pytest.fail("legacy dispatcher was called"),
    )
    captured = {}

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            captured["prompt"] = prompt
            captured["options"] = options
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(harness_pkg, "get_harness", lambda via: FakeHarness())
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert captured["options"].model == "gpt-5.5"
    assert captured["options"].allow_writes is False


def test_deepagents_is_rejected_for_scan_roles(monkeypatch, capsys):
    monkeypatch.setattr(
        orchestrator.preflight, "_iter_model_roles",
        lambda cfg: [("deepdive", SimpleNamespace(id="gpt-5.5", via="deepagents"))],
    )
    assert orchestrator.preflight.probe_backends(cfg=object()) is False
    assert "unsupported role(s): deepdive" in capsys.readouterr().err


# ─────────────────────────────────────────────────────────────────────────────
# Credential-gap classification — post-scan roles degrade, detection roles abort
# ─────────────────────────────────────────────────────────────────────────────
# S10/S11 are individually opt-in and run after detection finishes, so a missing
# credential for one of them must not stop S1-S9 from running: preflight WARNs and
# the scan's own [s10]/[s11] gates skip the stage. A credential shared with any
# detection role stays fatal — a scan that cannot detect must not start.


def _roles_on(monkeypatch, roles, via):
    """Present exactly *roles*, all resolving to *via*, and neutralize the probe so
    only the credential classification is under test."""
    monkeypatch.setattr(
        pf, "_iter_model_roles",
        lambda _cfg: [(r, SimpleNamespace(id="test-model", via=via)) for r in roles])
    monkeypatch.setattr(pf, "resolve_model",
                        lambda _m: ("test-model", via, {}))
    monkeypatch.setattr(pf, "probe_backends", lambda _cfg: True)
    # Present a gateway so the JWT-without-base_url fast-fail can't short-circuit.
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://test-gateway.example/")


def test_post_scan_only_cli_gap_warns_and_continues(monkeypatch, capsys):
    _roles_on(monkeypatch, ["validate"], "cli")
    monkeypatch.setattr(orchestrator.shutil, "which", lambda _name: None)

    assert orchestrator.check_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert "WARN" in err and "will be skipped" in err
    assert "ERROR" not in err


def test_detection_role_cli_gap_still_aborts(monkeypatch, capsys):
    _roles_on(monkeypatch, ["deepdive"], "cli")
    monkeypatch.setattr(orchestrator.shutil, "which", lambda _name: None)

    assert orchestrator.check_backends(cfg=object()) is False
    assert "ERROR: `claude` CLI not found" in capsys.readouterr().err


def test_gap_shared_with_detection_role_stays_fatal(monkeypatch, capsys):
    """One credential, two consumers: the detection role decides."""
    _roles_on(monkeypatch, ["deepdive", "validate"], "cli")
    monkeypatch.setattr(orchestrator.shutil, "which", lambda _name: None)

    assert orchestrator.check_backends(cfg=object()) is False
    assert "ERROR: `claude` CLI not found" in capsys.readouterr().err


def test_post_scan_deepagents_gap_warns_and_continues(monkeypatch, capsys):
    from vvaharness.util import environment

    _roles_on(monkeypatch, ["remediate", "validate"], "deepagents")
    monkeypatch.setattr(environment, "_backend_credential_ok",
                        lambda *_a, **_k: (False, "OPENAI_API_KEY not set"))

    assert orchestrator.check_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert "WARN: DeepAgents test-model: OPENAI_API_KEY not set" in err
    assert "remediate, validate" in err
    assert "ERROR" not in err


def test_probe_failure_on_post_scan_role_only_warns(monkeypatch, capsys):
    """An unreachable model that only S10/S11 use degrades that stage, not the scan."""
    monkeypatch.setattr(
        pf, "_iter_model_roles",
        lambda _cfg: [("validate", SimpleNamespace(id="test-model", via="sdk"))])
    monkeypatch.setattr(pf, "resolve_model",
                        lambda _m: ("test-model", "sdk", {}))

    def boom(*_a, **_k):
        raise RuntimeError("401 Invalid authentication credentials")

    monkeypatch.setattr(llm, "prompt", boom)
    assert pf.probe_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert "WARN" in err and "will be skipped" in err
    assert "FAILED" not in err
    # The closing summary must not contradict the WARN above it: an operator (or a
    # log scraper) reading only the summary would otherwise conclude every backend
    # was reachable when one was just reported unreachable.
    assert "all model backends reachable" not in err
    assert "detection backends reachable ✓" in err and "validate unreachable" in err


def test_probe_summary_says_all_reachable_when_nothing_skipped(monkeypatch, capsys):
    """The unqualified summary survives for a fully clean probe (guards the branch
    order in probe_backends: a skipped-stage summary must not swallow this one)."""
    monkeypatch.setattr(
        pf, "_iter_model_roles",
        lambda _cfg: [("deepdive", SimpleNamespace(id="test-model", via="sdk"))])
    monkeypatch.setattr(pf, "resolve_model",
                        lambda _m: ("test-model", "sdk", {}))
    monkeypatch.setattr(llm, "prompt", lambda *_a, **_k: "ok")

    assert pf.probe_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert "all model backends reachable ✓" in err
    assert "WARN" not in err
