# Copyright 2026 Visa, Inc.
# Modifications Copyright 2026 Lily Feng.
# Modified by Lily Feng in 2026 for native Codex support.
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

"""Unit tests for vvaharness.backends.llm dispatcher (resolve/prompt/agentic)."""
import types

import pytest

from vvaharness.backends import llm


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class _Cfg:
    """Minimal stand-in for a model config node with attribute access."""

    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, v)


def _make_recording_backend():
    """Return (module-like backend, calls list) recording prompt/agentic calls."""
    calls = []
    backend = types.SimpleNamespace()

    def _prompt(user_prompt, *, model, **kw):
        calls.append(("prompt", user_prompt, model, kw))
        return "PROMPT_RESULT"

    def _agentic(user_prompt, *, model, **kw):
        calls.append(("agentic", user_prompt, model, kw))
        return "AGENTIC_RESULT"

    backend.prompt = _prompt
    backend.agentic = _agentic
    return backend, calls


@pytest.fixture
def patched_backends(monkeypatch):
    """Patch cli/sdk/oai references in the dispatcher with recording fakes.

    The dispatcher captured the backend modules at import-time into the
    private _BACKENDS dict, so we must patch that mapping (and the module
    attrs for completeness) to keep the suite isolated.
    """
    cli_b, cli_calls = _make_recording_backend()
    sdk_b, sdk_calls = _make_recording_backend()
    oai_b, oai_calls = _make_recording_backend()
    codex_b, codex_calls = _make_recording_backend()

    monkeypatch.setattr(llm, "cli", cli_b)
    monkeypatch.setattr(llm, "sdk", sdk_b)
    monkeypatch.setattr(llm, "oai", oai_b)
    monkeypatch.setattr(llm, "codex", codex_b)
    monkeypatch.setitem(llm._BACKENDS, "cli", cli_b)
    monkeypatch.setitem(llm._BACKENDS, "sdk", sdk_b)
    monkeypatch.setitem(llm._BACKENDS, "openai", oai_b)
    monkeypatch.setitem(llm._BACKENDS, "codex", codex_b)

    return {
        "cli": (cli_b, cli_calls),
        "sdk": (sdk_b, sdk_calls),
        "openai": (oai_b, oai_calls),
        "codex": (codex_b, codex_calls),
    }


# --------------------------------------------------------------------------
# resolve()
# --------------------------------------------------------------------------
def test_resolve_bare_string_routes_to_cli():
    model_id, via, extras = llm.resolve("claude-opus-example")
    assert model_id == "claude-opus-example"
    assert via == "cli"
    assert extras == {}


def test_resolve_id_via_form():
    cfg = _Cfg(id="claude-opus-example", via="sdk")
    model_id, via, extras = llm.resolve(cfg)
    assert model_id == "claude-opus-example"
    assert via == "sdk"
    assert extras == {}


def test_resolve_defaults_via_to_cli_when_absent():
    cfg = _Cfg(id="some-model")
    model_id, via, extras = llm.resolve(cfg)
    assert model_id == "some-model"
    assert via == "cli"
    assert extras == {}


def test_resolve_falsy_via_defaults_to_cli():
    cfg = _Cfg(id="some-model", via=None)
    _, via, _ = llm.resolve(cfg)
    assert via == "cli"


def test_resolve_collects_temperature_extra():
    cfg = _Cfg(id="m", via="sdk", temperature=0.5)
    _, _, extras = llm.resolve(cfg)
    assert extras == {"temperature": 0.5}
    assert isinstance(extras["temperature"], float)


def test_resolve_collects_thinking_budget_and_betas():
    cfg = _Cfg(id="m", via="sdk", thinking_budget=1024, betas=["beta-a", "beta-b"])
    _, _, extras = llm.resolve(cfg)
    assert extras["thinking_budget"] == 1024
    assert isinstance(extras["thinking_budget"], int)
    assert extras["betas"] == ["beta-a", "beta-b"]


def test_resolve_zero_thinking_budget_is_dropped():
    # Source uses `if tb:` so 0 (falsy) must not appear in extras.
    cfg = _Cfg(id="m", via="sdk", thinking_budget=0)
    _, _, extras = llm.resolve(cfg)
    assert "thinking_budget" not in extras


def test_resolve_missing_id_raises():
    cfg = _Cfg(via="sdk")  # no .id
    with pytest.raises(ValueError):
        llm.resolve(cfg)


# --------------------------------------------------------------------------
# prompt() dispatch
# --------------------------------------------------------------------------
def test_prompt_bare_string_dispatches_to_cli(patched_backends):
    out = llm.prompt("hello", model="claude-opus-example")
    assert out == "PROMPT_RESULT"

    _, cli_calls = patched_backends["cli"]
    _, sdk_calls = patched_backends["sdk"]
    assert len(cli_calls) == 1
    assert sdk_calls == []
    kind, up, model_id, kw = cli_calls[0]
    assert kind == "prompt"
    assert up == "hello"
    assert model_id == "claude-opus-example"


def test_prompt_sdk_dispatch(patched_backends):
    cfg = _Cfg(id="claude-opus-example", via="sdk")
    out = llm.prompt("hi", model=cfg)
    assert out == "PROMPT_RESULT"

    _, sdk_calls = patched_backends["sdk"]
    _, cli_calls = patched_backends["cli"]
    assert len(sdk_calls) == 1
    assert cli_calls == []
    assert sdk_calls[0][2] == "claude-opus-example"


def test_prompt_openai_dispatch(patched_backends):
    cfg = _Cfg(id="gpt-example", via="openai")
    out = llm.prompt("hi", model=cfg)
    assert out == "PROMPT_RESULT"

    _, oai_calls = patched_backends["openai"]
    assert len(oai_calls) == 1
    assert oai_calls[0][2] == "gpt-example"


def test_prompt_codex_dispatch(patched_backends):
    cfg = _Cfg(id="gpt-example", via="codex")
    out = llm.prompt("hi", model=cfg, temperature=0.4)
    assert out == "PROMPT_RESULT"

    _, calls = patched_backends["codex"]
    assert len(calls) == 1
    assert calls[0][2] == "gpt-example"
    assert "temperature" not in calls[0][3]


def test_prompt_cli_drops_sdk_only_kwargs(patched_backends):
    # CLI backend has no temperature/thinking/betas flags; dispatcher must strip them.
    llm.prompt(
        "x",
        model="bare-model",
        temperature=0.7,
        thinking_budget=99,
        betas=["b"],
        keep_me="yes",
    )
    _, cli_calls = patched_backends["cli"]
    kw = cli_calls[0][3]
    assert "temperature" not in kw
    assert "thinking_budget" not in kw
    assert "betas" not in kw
    assert kw["keep_me"] == "yes"


def test_prompt_extras_applied_to_sdk(patched_backends):
    cfg = _Cfg(id="m", via="sdk", temperature=0.25)
    llm.prompt("x", model=cfg)
    _, sdk_calls = patched_backends["sdk"]
    kw = sdk_calls[0][3]
    assert kw["temperature"] == 0.25


def test_prompt_caller_kwarg_overrides_extras(patched_backends):
    # extras use setdefault, so an explicit caller kwarg wins.
    cfg = _Cfg(id="m", via="sdk", temperature=0.25)
    llm.prompt("x", model=cfg, temperature=0.99)
    _, sdk_calls = patched_backends["sdk"]
    kw = sdk_calls[0][3]
    assert kw["temperature"] == 0.99


def test_prompt_unknown_via_raises(patched_backends):
    cfg = _Cfg(id="m", via="bogus")
    with pytest.raises(ValueError) as ei:
        llm.prompt("x", model=cfg)
    assert "bogus" in str(ei.value)
    # Nothing should have been dispatched.
    for _, calls in patched_backends.values():
        assert calls == []


# --------------------------------------------------------------------------
# agentic() dispatch
# --------------------------------------------------------------------------
def test_agentic_bare_string_dispatches_to_cli(patched_backends):
    out = llm.agentic("go", model="bare-model")
    assert out == "AGENTIC_RESULT"
    _, cli_calls = patched_backends["cli"]
    assert len(cli_calls) == 1
    kind, up, model_id, _ = cli_calls[0]
    assert kind == "agentic"
    assert up == "go"
    assert model_id == "bare-model"


def test_agentic_sdk_dispatch(patched_backends):
    cfg = _Cfg(id="claude-opus-example", via="sdk")
    out = llm.agentic("go", model=cfg)
    assert out == "AGENTIC_RESULT"
    _, sdk_calls = patched_backends["sdk"]
    assert len(sdk_calls) == 1
    assert sdk_calls[0][0] == "agentic"
    assert sdk_calls[0][2] == "claude-opus-example"


def test_agentic_codex_keeps_stream_callback(patched_backends):
    cfg = _Cfg(id="gpt-example", via="codex")
    cb = lambda line: None
    llm.agentic("go", model=cfg, stream_cb=cb)
    _, calls = patched_backends["codex"]
    assert calls[0][3]["stream_cb"] is cb


def test_agentic_passes_kwargs_through_unmodified(patched_backends):
    # agentic() does NOT strip sdk-only kwargs nor apply extras.
    cfg = _Cfg(id="m", via="sdk", temperature=0.5)
    llm.agentic("go", model=cfg, temperature=0.7, extra="z")
    _, sdk_calls = patched_backends["sdk"]
    kw = sdk_calls[0][3]
    assert kw["temperature"] == 0.7
    assert kw["extra"] == "z"


def test_agentic_unknown_via_raises(patched_backends):
    cfg = _Cfg(id="m", via="nope")
    with pytest.raises(ValueError) as ei:
        llm.agentic("go", model=cfg)
    assert "nope" in str(ei.value)
    for _, calls in patched_backends.values():
        assert calls == []
