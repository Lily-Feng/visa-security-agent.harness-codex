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

"""
Backend dispatcher. All step files import prompt()/agentic() from HERE,
not from backends.claude_cli or backends.sdk directly.

Routing is decided by the model config node passed in via `model=`:

    cfg.models.deepdive  →  {id: "claude-opus-4-6", via: "sdk", temperature: 1.0}
    cfg.models.verify    →  {id: "claude-opus-4-6", via: "sdk"}
    cfg.models.legacy    →  "claude-opus-4-6"      # bare string ⇒ cli

Steps don't need to know which backend they're hitting — they pass the
whole config node and the dispatcher unpacks it.
"""
from __future__ import annotations

from typing import Any

from vvaharness.backends import claude_cli as cli
from vvaharness.backends import codex_cli as codex
from vvaharness.backends import oai, sdk

# Re-export so existing `from backends.claude_cli import parse_json_response, TOKENS`
# call sites can switch to `from backends.llm import ...` uniformly.
from vvaharness.backends.claude_cli import parse_json_response  # noqa: F401
from vvaharness.util.tokens import TOKENS  # noqa: F401

# The hoisted DeepAgents harness is integrated only at the two post-scan seams.
# S1–S9 continue to use the legacy prompt/agentic dispatcher backends.
DEEPAGENTS_ROLES = frozenset({"remediate", "validate"})

# Roles that run AFTER detection completes (S10 remediate, S11 validate) and are
# individually profile-controlled. A missing credential for one of these degrades
# that stage only, so startup preflight warns instead of aborting the whole scan;
# the S10/S11 gates in orchestrator.scan then disable the stage. Same members as
# DEEPAGENTS_ROLES today but a different question — which backend a role may use vs.
# when in the pipeline it runs — so the two are kept separate on purpose.
POST_SCAN_ROLES = frozenset({"remediate", "validate"})


def resolve(model_cfg: Any) -> tuple[str, str, dict]:
    """
    Normalize a model config node into (model_id, backend, extras).

    Accepts:
      - bare string                       → (str, "cli", {})
      - Config / object with .id / .via   → (.id, .via or "cli", {temperature: ...})
    """
    if isinstance(model_cfg, str):
        return model_cfg, "cli", {}

    model_id = getattr(model_cfg, "id", None)
    if model_id is None:
        raise ValueError(
            f"Model config must be a string or have an `id` field: got {model_cfg!r}"
        )
    via = getattr(model_cfg, "via", None) or "cli"
    extras: dict = {}
    temp = getattr(model_cfg, "temperature", None)
    if temp is not None:
        extras["temperature"] = float(temp)
    tb = getattr(model_cfg, "thinking_budget", None)
    if tb:
        extras["thinking_budget"] = int(tb)
    betas = getattr(model_cfg, "betas", None)
    if betas:
        extras["betas"] = list(betas)
    return model_id, via, extras


_BACKENDS = {"cli": cli, "codex": codex, "sdk": sdk, "openai": oai}


def prompt(user_prompt: str, *, model: Any, **kw) -> str:
    model_id, via, extras = resolve(model)
    backend = _BACKENDS.get(via)
    if backend is None:
        raise ValueError(f"Unknown backend `via: {via}` for model {model_id}")
    if via in {"cli", "codex"}:
        # CLI backends have no per-call temperature/thinking flags; silently
        # drop API-backend-only kwargs. Codex reasoning effort is configured in
        # the profile's top-level `codex:` block.
        kw.pop("temperature", None)
        kw.pop("thinking_budget", None)
        kw.pop("betas", None)
    else:
        # extras (e.g. temperature) win unless the caller passed one explicitly.
        for k, v in extras.items():
            kw.setdefault(k, v)
    return backend.prompt(user_prompt, model=model_id, **kw)


def agentic(user_prompt: str, *, model: Any, **kw) -> str:
    model_id, via, _ = resolve(model)
    backend = _BACKENDS.get(via)
    if backend is None:
        raise ValueError(f"Unknown backend `via: {via}` for model {model_id}")
    # `stream_cb` (live trace) is implemented by subprocess backends only; drop
    # it for sdk/openai so passing it never raises a TypeError there.
    if via not in {"cli", "codex"}:
        kw.pop("stream_cb", None)
    return backend.agentic(user_prompt, model=model_id, **kw)


def aborted() -> bool:
    """Whether either subprocess backend has been cooperatively aborted."""
    return cli.aborted() or codex.aborted()


def abort() -> int:
    """Abort all in-flight subprocess backends; return processes signalled."""
    return cli.abort() + codex.abort()


def reset_abort() -> None:
    """Reset process-global abort state between repositories/batch items."""
    cli.reset_abort()
    codex.reset_abort()
