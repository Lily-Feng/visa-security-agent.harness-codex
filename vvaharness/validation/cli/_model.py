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

"""Model-resolution logic for the ``vvaharness validate`` command."""

from __future__ import annotations

import sys
from pathlib import Path

from vvaharness import config as harness_config
from vvaharness.backends import llm
from vvaharness.validation.cli._parser import _tunable_overrides
from vvaharness.validation.constants.artifacts import (
    BACKEND_DEEPAGENTS,
    BACKEND_OPENAI,
    PROVIDER_ANTHROPIC,
    PROVIDER_OPENAI,
)

_PERSONA_FIELDS: dict[str, str] = {
    "security_architect": "security_architect_model",
    "penetration_tester": "penetration_tester_model",
    "cross_repo_analyzer": "cross_repo_analyzer_model",
}


def _validate_model_spec(cfg: object) -> object | None:
    """Return ``cfg.models.validate.orchestrator``, or None when undefined."""
    models = getattr(cfg, "models", None)
    if models is None:
        return None
    validate = getattr(models, "validate", None)
    if validate is None:
        return None
    return getattr(validate, "orchestrator", None)


def _normalize_validate_backend(via: str, provider: str | None) -> tuple[str, str | None]:
    """Route a legacy ``via: openai`` validate role onto the DeepAgents harness.

    ``via: openai`` is a live selector for detection (S1-S9) and report-only
    remediation, both served by the ``backends/oai.py`` dispatcher. That dispatcher has
    no agentic Harness implementation, so the validation panel cannot run on it
    directly. Rather than refusing the value — which made one profile spelling mean
    "supported" at some stages and "fatal" at others — it is mapped onto DeepAgents
    with the OpenAI provider, which is the same pair ``default.yaml`` ships as
    ``{via: deepagents, provider: openai}``.

    An explicit ``provider:`` wins, matching the precedence in
    ``util.environment._backend_credential_ok``. Every other *via* passes through
    untouched, so ``cli`` / ``sdk`` / ``deepagents`` behaviour is unchanged.

    Args:
        via: The validate role's resolved backend selector.
        provider: The role's explicit DeepAgents provider, or None to infer.

    Returns:
        The ``(via, provider)`` pair the validation config layer should use.
    """
    if via != BACKEND_OPENAI:
        return via, provider
    return BACKEND_DEEPAGENTS, provider or PROVIDER_OPENAI


def _routes_to_anthropic(model_id: str, provider: str | None) -> bool:
    """True when a (model, provider) pair resolves to the Anthropic model class.

    Mirrors the DeepAgents model builder: an explicit *provider* decides, and with no
    provider the model name does. The split is Anthropic vs everything else — any
    non-Anthropic pair is served by an OpenAI-compatible endpoint, and there is no
    third route — so this is a complete classification, not a guess about unfamiliar
    model ids.

    Args:
        model_id: The resolved model id.
        provider: An explicit provider, or None to decide by name.

    Returns:
        True for the Anthropic route, False for the OpenAI-compatible route.
    """
    if provider:
        return provider == PROVIDER_ANTHROPIC
    return "claude" in model_id.lower()


def _check_persona_vendors(overrides: dict[str, object]) -> str | None:
    """Return an error when a persona model routes elsewhere than the panel does.

    The orchestrator's backend and provider apply to the whole panel — a persona's own
    ``via:`` / ``provider:`` is not honoured — so a persona pinned to the other route is
    sent to an endpoint that does not serve its model. Unchecked, that stages a
    workspace and then fails mid-run with an error naming a model id that looks
    correct, which is hard to trace back to the profile. Refusing it costs nothing and
    names the offending key.

    Args:
        overrides: The overrides dict from :func:`_apply_model_env`.

    Returns:
        An operator-facing message, or None when every persona routes with the panel.
    """
    provider = overrides.get("provider")
    panel_anthropic = _routes_to_anthropic(
        str(overrides.get("model") or ""),
        provider if isinstance(provider, str) and provider else None,
    )
    for short_name, field in _PERSONA_FIELDS.items():
        model = overrides.get(field)
        if not isinstance(model, str) or not model:
            continue
        # A persona spec contributes only its model id, so the name alone decides.
        if _routes_to_anthropic(model, None) == panel_anthropic:
            continue
        panel, wanted = (
            ("Anthropic", "an Anthropic") if panel_anthropic
            else ("an OpenAI-compatible endpoint", "an OpenAI-compatible")
        )
        return (
            f"validate: models.validate.{short_name} is {model!r}, which routes to "
            f"{'an OpenAI-compatible endpoint' if panel_anthropic else 'Anthropic'}, "
            f"but the panel runs on {panel} (from models.validate.orchestrator). "
            f"Every persona shares the orchestrator's provider — a persona's own "
            f"via/provider is not honoured. Set {short_name} to {wanted} model, or "
            f"change models.validate.orchestrator."
        )
    return None


def _load_validated_spec(config_path: str) -> tuple[object, object] | None:
    """Load config and return (cfg, spec), or None on missing path or absent models.validate."""
    if not Path(config_path).exists():
        print(f"validate: config not found: {config_path}", file=sys.stderr)
        return None
    cfg = harness_config.load(config_path)
    spec = _validate_model_spec(cfg)
    if spec is None:
        print("validate: config defines no models.validate role", file=sys.stderr)
        return None
    return cfg, spec


def _persona_spec_resolved(spec: object) -> tuple[str, str] | None:
    """Resolve a persona model spec to ``(model_id, via)``, or None when absent/invalid."""
    if spec is None:
        return None
    try:
        model_id, via, _ = llm.resolve(spec)
    except (ValueError, AttributeError, KeyError, TypeError):
        return None  # malformed spec — fall back to inheriting models.validate
    return (model_id, via or "") if model_id else None


def _apply_model_env(config_path: str) -> tuple[int, dict[str, object]]:
    """Read the profile and return a fully-populated overrides dict for load_config().

    Returns ``(0, overrides)`` on success; ``(2, {})`` if the profile is missing or
    defines no models.validate role. All YAML-sourced values travel through the overrides
    dict — no os.environ round-trip.
    """
    loaded = _load_validated_spec(config_path)
    if loaded is None:
        return 2, {}
    cfg, spec = loaded
    model_id, via, _ = llm.resolve(spec)
    # Legacy `via: openai` is routed to DeepAgents here, before load_config, so every
    # downstream consumer (harness registry, credential probe, session launcher) sees
    # one consistent backend rather than a value only some of them accept.
    via, provider = _normalize_validate_backend(via or "", getattr(spec, "provider", None))
    overrides: dict[str, object] = _tunable_overrides(cfg)
    overrides["model"] = model_id
    overrides["via"] = via
    overrides["provider"] = provider

    # Persona model overrides — read from models.validate.{security_architect, …}
    models = getattr(cfg, "models", None)
    validate = getattr(models, "validate", None) if models is not None else None
    if validate is not None:
        for short_name, field in _PERSONA_FIELDS.items():
            resolved = _persona_spec_resolved(getattr(validate, short_name, None))
            if resolved is not None:
                overrides[field] = resolved[0]

    # validate_tools — read from step_validate.allowed_tools.
    block = getattr(cfg, "step_validate", None)
    tools = getattr(block, "allowed_tools", None) if block is not None else None
    if isinstance(tools, list) and tools:
        overrides["validate_tools"] = ",".join(str(t) for t in tools)

    return 0, overrides
