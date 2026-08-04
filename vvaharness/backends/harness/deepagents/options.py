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

"""Translate harness options into DeepAgents / LangGraph configuration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from deepagents import (
    HarnessProfile,
    create_deep_agent,
    register_provider_profile,
)
from deepagents.backends import FilesystemBackend
from deepagents.middleware.filesystem import FilesystemPermission
from deepagents.profiles.provider.provider_profiles import ProviderProfile
from langchain.agents.structured_output import ToolStrategy
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field, create_model

from vvaharness.backends.harness.deepagents.limits import RECURSION_HEADROOM
from vvaharness.backends.harness.deepagents.redaction import read_only_middleware
from vvaharness.backends.harness.genai import MODEL_TIMEOUT_SECONDS

# Environment variables OpenSSL/httpx read for a custom CA bundle.
SSL_CERT_FILE_VAR = "SSL_CERT_FILE"
SSL_CERT_DIR_VAR = "SSL_CERT_DIR"

# Parent read tools this backend can build directly (localtools-backed).
_READ_TOOLS: frozenset[str] = frozenset({"Read", "Grep", "Glob"})
# Mutating tools denied in a read-only session (allow_writes=False).
_DESTRUCTIVE_TOOLS: frozenset[str] = frozenset({"Bash", "Edit", "NotebookEdit", "Write"})
# Legacy custom dispatch tool; native subagents are used instead, so never granted.
_LEGACY_AGENT_TOOL = "Agent"

# DeepAgents' built-in OpenAI provider profile forces use_responses_api=True, which
# breaks many OpenAI-compatible endpoints (they reject store=true). Register a profile
# override once per process that disables the Responses API. This runs at import
# time before any model resolution happens.
register_provider_profile(
    "openai",
    ProviderProfile(init_kwargs={"use_responses_api": False, "timeout": MODEL_TIMEOUT_SECONDS}),
)

# Kept as the canonical read-only profile value for compatibility and tests.
# It is deliberately not registered process-wide: doing so would suppress the
# native edit tools for read-write consumers such as remediation. Read-only
# sessions are instead enforced per invocation by ``_filesystem_permissions``.
_READ_ONLY_HARNESS_PROFILE = HarnessProfile(
    excluded_tools=frozenset({"write_file", "edit_file"}),
)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

from vvaharness.backends.harness.contract.options import OneShotOptions, StreamingOptions
from vvaharness.backends.harness.contract.subagents import SubagentDefinition
from vvaharness.backends.harness.contract.tool_policy import ToolPolicy

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool


# Deny-all-writes filesystem rule for a read-only session. The matcher runs without
# DOTGLOB, so `**` never matches a component starting with `.` and unmatched paths
# fail OPEN -- `/**` alone leaves `.git/config`, `.github/workflows/*` and `.env`
# writable, which is remote code execution once the harness runs git in that tree.
# The dot patterns below cover hidden files and hidden directories at every depth.
_READ_ONLY_PERMISSIONS: list[FilesystemPermission] = [
    FilesystemPermission(
        operations=["write"],
        paths=["/**", "/.*", "/.*/**", "/**/.*", "/**/.*/**"],
        mode="deny",
    ),
]


def _anthropic_key(env: dict[str, str]) -> str | None:
    return env.get("ANTHROPIC_API_KEY") or env.get("ANTHROPIC_AUTH_TOKEN")


def _anthropic_base(env: dict[str, str]) -> str | None:
    return env.get("ANTHROPIC_BASE_URL")


def _openai_key(env: dict[str, str]) -> str | None:
    return env.get("OPENAI_API_KEY")


def _openai_base(env: dict[str, str]) -> str | None:
    return env.get("OPENAI_BASE_URL")


def _openai_ssl_context(env: dict[str, str]) -> Any:
    """Return an httpx SSL context if a CA bundle is configured via env vars.

    Custom CA bundles are read from ``SSL_CERT_FILE``, ``REQUESTS_CA_BUNDLE``,
    or ``NODE_EXTRA_CA_CERTS``; this mirrors httpx's own startup lookup so the
    client is configured even when the env vars are set after interpreter startup.
    """
    if httpx is None:
        return None
    ca_file = (
        env.get(SSL_CERT_FILE_VAR)
        or env.get("REQUESTS_CA_BUNDLE")
        or env.get("NODE_EXTRA_CA_CERTS")
        or os.environ.get(SSL_CERT_FILE_VAR)
        or os.environ.get("REQUESTS_CA_BUNDLE")
        or os.environ.get("NODE_EXTRA_CA_CERTS")
    )
    ca_dir = env.get(SSL_CERT_DIR_VAR) or os.environ.get(SSL_CERT_DIR_VAR)

    if not ca_file and not ca_dir:
        return None
    try:
        verify: str | bool = ca_file if ca_file else (ca_dir or True)
        return httpx.create_ssl_context(verify=verify, trust_env=True)
    except Exception:
        return None


def _openai_http_client(env: dict[str, str]) -> Any:
    ctx = _openai_ssl_context(env)
    if ctx is None:
        return None
    return httpx.Client(timeout=MODEL_TIMEOUT_SECONDS, verify=ctx)


def _openai_http_async_client(env: dict[str, str]) -> Any:
    ctx = _openai_ssl_context(env)
    if ctx is None:
        return None
    return httpx.AsyncClient(timeout=MODEL_TIMEOUT_SECONDS, verify=ctx)


def build_model(
    model_id: str, env: dict[str, str], provider: str | None = None
) -> BaseChatModel:
    """Resolve a model id to a chat model.

    *provider* selects the backend: "anthropic" -> ChatAnthropic, else ChatOpenAI.
    When None, infer from the name (claude-* -> Anthropic, else OpenAI-compatible).
    """
    if provider == "anthropic" or (provider is None and "claude" in model_id.lower()):
        return ChatAnthropic(
            model_name=model_id,
            api_key=_anthropic_key(env),  # type: ignore[arg-type]
            base_url=_anthropic_base(env),
            timeout=MODEL_TIMEOUT_SECONDS,
        )
    # OpenAI-compatible endpoints; Chat Completions (not Responses API).
    return ChatOpenAI(
        model=model_id,
        api_key=_openai_key(env),  # type: ignore[arg-type]
        base_url=_openai_base(env),
        timeout=MODEL_TIMEOUT_SECONDS,
        use_responses_api=False,
        http_client=_openai_http_client(env),
        http_async_client=_openai_http_async_client(env),
    )


class _ModelKey:
    """Hashable key for a resolved model that avoids keeping the env dict alive."""

    __slots__ = (
        "model_id", "provider", "openai_key", "openai_base", "anthropic_key", "anthropic_base"
    )

    def __init__(self, model_id: str, env: dict[str, str], provider: str | None) -> None:
        self.model_id = model_id
        self.provider = provider or ""
        self.openai_key = _openai_key(env) or ""
        self.openai_base = _openai_base(env) or ""
        self.anthropic_key = _anthropic_key(env) or ""
        self.anthropic_base = _anthropic_base(env) or ""

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _ModelKey):
            return NotImplemented
        return (
            self.model_id == other.model_id
            and self.provider == other.provider
            and self.openai_key == other.openai_key
            and self.openai_base == other.openai_base
            and self.anthropic_key == other.anthropic_key
            and self.anthropic_base == other.anthropic_base
        )

    def __hash__(self) -> int:
        return hash((
            self.model_id,
            self.provider,
            self.openai_key,
            self.openai_base,
            self.anthropic_key,
            self.anthropic_base,
        ))


_model_cache: dict[_ModelKey, BaseChatModel] = {}


def build_model_cached(
    model_id: str, env: dict[str, str], provider: str | None = None
) -> BaseChatModel:
    """Return a model instance, reusing a cached instance when inputs match."""
    key = _ModelKey(model_id, env, provider)
    cached = _model_cache.get(key)
    if cached is not None:
        return cached
    model = build_model(model_id, env, provider)
    _model_cache[key] = model
    return model


def _tool_policy(options: OneShotOptions | StreamingOptions) -> ToolPolicy:
    """Return the effective tool policy, falling back to an empty policy."""
    return options.tool_policy if options.tool_policy is not None else ToolPolicy()


def _build_session_tools(options: StreamingOptions, allowed_tools: tuple[str, ...]) -> list[Any]:
    """Build tools via the caller's injected ``tool_builder`` or the generic readers."""
    from vvaharness.backends.harness.deepagents.tools import build_tools

    builder = options.tool_builder or build_tools
    return builder(options, allowed_tools=allowed_tools)


def _subagent_tools(subagent: SubagentDefinition, options: StreamingOptions) -> tuple[str, ...]:
    """Return the tool allow-list for a subagent, filtered by denied tools."""
    policy = _tool_policy(options)
    allowed = subagent.tools if subagent.tools is not None else policy.allowed_tools
    denied = set(subagent.disallowed_tools or policy.disallowed_tools)
    if not options.allow_writes:
        denied |= _DESTRUCTIVE_TOOLS
    return tuple(t for t in allowed if t not in denied)


def _subagent_tool_names(subagent: SubagentDefinition, options: StreamingOptions) -> tuple[str, ...]:
    """Resolve a subagent's tool names: its allow-list plus injected fact tools.

    The legacy ``Agent`` dispatch tool is always dropped (native subagents replace
    it); mutating tools are dropped unless the caller opted into writes.
    """
    granted = tuple(dict.fromkeys([*_subagent_tools(subagent, options), *options.fact_tools]))
    excluded = {_LEGACY_AGENT_TOOL}
    if not options.allow_writes:
        excluded |= _DESTRUCTIVE_TOOLS
    return tuple(t for t in granted if t not in excluded)


def get_subagent_specs(options: StreamingOptions) -> list[dict[str, object]]:
    """Build native DeepAgents subagent specs.

    Each subagent's structured output is driven by its injected ``response_model``
    (a Pydantic class) when present; otherwise the subagent returns plain text.
    Subagent tools are compiled ``BaseTool`` instances because DeepAgents compiles
    each spec into its own graph and needs the tool objects, not string names.
    """
    specs: list[dict[str, object]] = []
    for name, subagent in options.agents.items():
        tool_names = _subagent_tool_names(subagent, options)
        tools = _build_session_tools(options, tool_names)
        # Resolve subagent models to configured Chat* instances so the
        # ``use_responses_api=False`` / CA-client settings are honored. Passing
        # bare strings would let DeepAgents apply its built-in OpenAI provider
        # profile, which forces the Responses API — incompatible with the many
        # OpenAI-compatible endpoints that require `store=false`.
        subagent_model = build_model_cached(
            subagent.model or options.model, options.env, options.model_provider
        )
        spec: dict[str, object] = {
            "name": name,
            "description": subagent.description,
            "system_prompt": subagent.prompt,
            "model": subagent_model,
            "tools": tools,
        }
        if not options.allow_writes:
            spec["middleware"] = read_only_middleware()
        if subagent.response_model is not None:
            # Same per-provider selection as the parent graph (see _strategy_for).
            spec["response_format"] = _strategy_for(
                subagent.response_model, options.model_provider
            )
        specs.append(spec)
    return specs


def _filesystem_permissions(
    options: OneShotOptions | StreamingOptions,
) -> list[FilesystemPermission]:
    """Deny all writes for a read-only session; permit them when the caller opts in."""
    if options.allow_writes:
        # DeepAgents' filesystem middleware is rooted at ``cwd``. Refuse an
        # invalid broader scope here; an empty rule list then grants writes only
        # inside that already-confined workspace.
        root = options.cwd.resolve()
        for raw in options.writable_paths:
            candidate = Path(raw).resolve()
            if candidate != root and root not in candidate.parents:
                raise ValueError(f"writable path escapes harness cwd: {raw}")
        return []
    return _READ_ONLY_PERMISSIONS


def _session_backend(
    options: OneShotOptions | StreamingOptions,
) -> FilesystemBackend | None:
    """Use a real, repo-confined filesystem only for explicit write sessions.

    DeepAgents otherwise defaults to ``StateBackend``. That is desirable for
    read-only consumers, but fix-mode remediation must apply its native
    ``write_file`` / ``edit_file`` calls to the target working tree. Virtual
    mode anchors absolute-looking tool paths under ``cwd`` and rejects ``..``
    traversal, while ``FilesystemBackend`` deliberately provides no shell
    execution capability.
    """
    # Always disk-backed: the native read_file/grep/glob are now the only read
    # path (see tools.LOGICAL_TO_NATIVE), so a read-only session on the default
    # StateBackend would see an empty filesystem. Writes are denied for read-only
    # sessions by _filesystem_permissions, which also validates writable_paths.
    _filesystem_permissions(options)
    return FilesystemBackend(root_dir=options.cwd, virtual_mode=True)


def _skill_sources(skill_root: Path | None, cwd: Path) -> list[str]:
    """Return *skill_root* as a virtual-path skill source for DeepAgents.

    Sources are listed through the backend, which is virtual-rooted at *cwd*, so
    a host absolute path re-roots to ``<cwd>/<host path>`` and fails.
    """
    if skill_root is None or not skill_root.is_dir():
        return []
    root, base = skill_root.resolve(), cwd.resolve()
    if not root.is_relative_to(base):
        msg = f"skill_root {root} must live under the session cwd {base}"
        raise ValueError(msg)
    relative = root.relative_to(base).as_posix()
    return [f"/{relative}" if relative != "." else "/"]


def _make_config(options: OneShotOptions | StreamingOptions, buffer: int) -> dict[str, object]:
    """Build a LangGraph invoke config with an optional recursion limit buffer."""
    config: dict[str, object] = {"configurable": {"thread_id": os.urandom(8).hex()}}
    if options.max_turns is not None:
        config["recursion_limit"] = options.max_turns + buffer
    return config


class _RecursionCounter:
    """Stateful counter to avoid ever-decreasing `recursion_limit` for cached configs."""

    def __init__(self) -> None:
        self._value = 0

    def next(self, base: int) -> int:
        self._value += 1
        return base + self._value


_recursion_counter = _RecursionCounter()


def _create_agent(
    model_id: str,
    env: dict[str, str],
    system_prompt: str | None,
    tools: list[Any],
    *,
    name: str,
    skills: list[str],
    permissions: list[FilesystemPermission],
    model_provider: str | None = None,
    redact_reads: bool = False,
    backend: FilesystemBackend | None = None,
    response_model: type | None = None,
    response_format: ToolStrategy | type | None = None,
    subagents: list[Any] | None = None,
) -> CompiledStateGraph:
    """Common graph builder shared by the streaming and one-shot graphs."""
    checkpointer: MemorySaver
    if response_model is None:
        checkpointer = MemorySaver()
    else:
        allowed_models = [(response_model.__module__, response_model.__name__)]
        checkpointer = MemorySaver(
            serde=JsonPlusSerializer(allowed_msgpack_modules=allowed_models)
        )
    kwargs: dict[str, Any] = {
        "model": build_model_cached(model_id, env, model_provider),
        "system_prompt": system_prompt,
        "tools": tools,
        "name": name,
        "skills": skills,
        "permissions": permissions,
        "checkpointer": checkpointer,
    }
    # Native read_file/grep have no redaction hook, so restore the localtools
    # guarantee for read-only sessions. Never in write mode: masking file content
    # breaks edit_file, which needs a byte-exact old_string from that same read.
    if redact_reads:
        kwargs["middleware"] = read_only_middleware()
    if response_format is not None:
        kwargs["response_format"] = response_format
    if subagents is not None:
        kwargs["subagents"] = subagents
    if backend is not None:
        kwargs["backend"] = backend
    return create_deep_agent(**kwargs)


def build_subagents(options: StreamingOptions) -> list[dict[str, object]]:
    """Return native DeepAgents subagent specs for the streaming parent.

    Previously this returned compiled subagent graphs wired through a custom
    ``Agent`` tool. It now returns specs passed directly to
    ``create_deep_agent(..., subagents=...)`` with per-subagent structured output.
    """
    return get_subagent_specs(options)


def _pydantic_response_format(schema: dict[str, Any]) -> type[BaseModel]:
    """Build an anonymous Pydantic model suitable for ToolStrategy."""
    type_map: dict[str, type] = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    required = set(schema.get("required", ()))
    fields: dict[str, tuple[type, Any]] = {}
    for name, prop in schema.get("properties", {}).items():
        base = type_map.get(prop.get("type"), str)
        default = Field(...) if name in required else Field(default=None)
        fields[name] = (base, default)
    return create_model("HarnessResponse", **fields)  # type: ignore[arg-type]


def _strategy_for(schema: type, provider: str | None) -> ToolStrategy | type:
    """Pick the structured-output strategy for *provider*.

    Anthropic needs an explicit override: this gateway's Messages path returns
    invalid JSON for native structured output, and a ``structured_output: False``
    profile cannot steer it away (the model-name regex fallback re-enables native).
    Everything else returns the bare schema so LangChain's auto-detection decides —
    its profile data encodes whether a model supports tools *and* structured output
    simultaneously, and forcing native on models that do not (glm, kimi) suppresses
    tool calling entirely, yielding fabricated verdicts with no work done.
    """
    if provider == "anthropic":
        return ToolStrategy(schema=schema)
    return schema


def _response_format(
    response_model: type | None, provider: str | None
) -> ToolStrategy | type | None:
    """Wrap an injected Pydantic model class as a strategy (None when unset)."""
    if response_model is None:
        return None
    return _strategy_for(response_model, provider)


def _build_streaming_graph(options: StreamingOptions) -> CompiledStateGraph:
    """Compile the parent agent graph and its declarative subagents."""
    subagent_specs = build_subagents(options)
    # The orchestrator reads context and dispatches subagents via the auto-added
    # `task()` tool; it only ever gets read tools built directly here.
    parent_tools = tuple(t for t in _tool_policy(options).allowed_tools if t in _READ_TOOLS)
    tools = _build_session_tools(options, parent_tools)
    return _create_agent(
        model_id=options.model,
        env=options.env,
        system_prompt=options.system_prompt,
        tools=tools,
        name=options.graph_name,
        skills=_skill_sources(options.skill_root, options.cwd),
        permissions=_filesystem_permissions(options),
        model_provider=options.model_provider,
        redact_reads=not options.allow_writes,
        backend=_session_backend(options),
        response_model=options.response_model,
        response_format=_response_format(options.response_model, options.model_provider),
        subagents=subagent_specs,
    )


def build_streaming_agent(
    options: StreamingOptions,
) -> tuple[CompiledStateGraph, dict[str, object]]:
    """Return a compiled parent graph and its LangGraph invoke config."""
    # options.effort is intentionally not consumed here. DeepAgents routes to any
    # OpenAI-compatible endpoint, including models with no reasoning-budget concept
    # (e.g. gpt-4o, gateway-proxied models). Injecting effort kwargs would break those.
    graph = _build_streaming_graph(options)
    # Parent recursion limit needs headroom for the initial context reads, the
    # parallel `task()` calls for all personas, and the final structured response. Each
    # parallel tool call batch counts as one recursion step, but LangGraph's
    # recursion limit also ticks per node invocation. Use a generous limit so
    # the dispatcher does not fail before subagents return.
    base_limit = (options.max_turns or 50) + RECURSION_HEADROOM
    return graph, {
        "configurable": {"thread_id": os.urandom(8).hex()},
        "recursion_limit": _recursion_counter.next(base_limit),
    }


def _oneshot_response_format(
    options: OneShotOptions,
) -> ToolStrategy | type | None:
    """Prefer an injected Pydantic model; else derive one from a JSON output schema."""
    if options.response_model is not None:
        return _strategy_for(options.response_model, options.model_provider)
    if options.output_schema is not None:
        derived = _pydantic_response_format(dict(options.output_schema))
        return _strategy_for(derived, options.model_provider)
    return None


def _build_oneshot_graph(options: OneShotOptions) -> CompiledStateGraph:
    """Compile a single-turn parser graph."""
    streaming_view = cast(StreamingOptions, options)
    policy = _tool_policy(options)
    tools = _build_session_tools(streaming_view, tuple(policy.allowed_tools))
    return _create_agent(
        model_id=options.model,
        env=options.env,
        system_prompt=options.system_prompt,
        tools=tools,
        name=f"{options.graph_name}-oneshot",
        skills=_skill_sources(options.skill_root, options.cwd),
        permissions=_filesystem_permissions(options),
        model_provider=options.model_provider,
        redact_reads=not options.allow_writes,
        backend=_session_backend(options),
        response_model=options.response_model,
        response_format=_oneshot_response_format(options),
    )


def build_oneshot_options(
    options: OneShotOptions,
) -> tuple[CompiledStateGraph, dict[str, object]]:
    """Return a compiled parser graph and invoke config for a single-turn run."""
    graph = _build_oneshot_graph(options)
    return graph, _make_config(options, buffer=5)


__all__ = ["build_model", "build_streaming_agent", "build_oneshot_options"]
