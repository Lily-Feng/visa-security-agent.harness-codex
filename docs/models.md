<!--
Copyright 2026 Visa, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Model Selection & Backends

Each model role in `config.yaml` chooses its own `{id, via}` subject to the role
matrix below. S0/S5/S9 also contain deterministic work with no model role.
Detection roles use `cli`, `sdk`, or `openai`; setup/doctor rejects
`deepagents` on S1–S9. Remediation fix mode is supported by `cli`, `sdk`, and
`deepagents` (legacy direct `openai` is report-only). Validation supports
`cli`, `sdk`, or `deepagents`; legacy `via: openai` validation is normalized to
DeepAgents with the OpenAI provider.

## Default role → backend mapping

The shipped **default profile** (`vvaharness/config/profiles/default.yaml`) is
mixed-backend: S0 is local, the S1–S9 detection roles use the `claude` CLI, and
S10 remediation and S11 validation both use DeepAgents with Anthropic. It
therefore needs Claude Code auth plus the provider
credentials for whichever enabled post-scan stages actually run; it does not
use `ANTHROPIC_SDK_API_KEY`.

| Step | Role | Default (`default.yaml`) | Switchable to |
|---|---|---|---|
| s0 rules seed | — | local AST engine | — |
| s0 LLM annotation *(only when configured)* | `graph_annotate` (legacy fallback `callgraph_creation`) | not used by default rules mode | cli ⇄ sdk ⇄ openai |
| auto-step1 | `autoexclude` | `cli` | cli ⇄ sdk ⇄ openai |
| s1 preprocess | `preprocess` | `cli` | cli ⇄ sdk ⇄ openai (agentic; Bash on `cli` only) |
| s2 threatmodel | `threatmodel` | `cli` | cli ⇄ sdk ⇄ openai |
| s3 decompose | `decompose` | `cli` | cli ⇄ sdk ⇄ openai |
| s4 deepdive | `deepdive` | `cli` | cli ⇄ sdk ⇄ openai |
| s5 prefilter | — | local | — |
| s6 verify | `verify` | `cli` | cli ⇄ sdk ⇄ openai (agentic; Bash on `cli` only) |
| s7 dedup | `dedup` | `cli` | cli ⇄ sdk ⇄ openai |
| s8 chain | `chain` | `cli` | cli ⇄ sdk ⇄ openai |
| s9 SARIF | — | local | — |
| s10 remediate (`remediate` cmd) | `remediate` | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ deepagents (`openai` is report-only) |
| s11 DTO discovery (`validate` cmd) | — | local | — |
| s11 agentic validation | `validate` (+ per-persona overrides) | `deepagents` (Anthropic) | cli ⇄ sdk ⇄ deepagents (`openai` → `deepagents`) |

> **Two post-scan commands.** `remediate` is S10: the Remediation Agent (LLM
> role `models.remediate`) proposes fixes and writes DTOs. `validate` is S11:
> it first discovers validatable DTOs deterministically (no model), then runs
> the agentic panel. The commands are separate; S10 writes the DTOs and S11
> grades them.

### s11 validation personas

The `validate` command (s11) runs an adversarial panel with **two always-on personas**
(`security-architect`, `penetration-tester`) plus **one conditional persona**
(`cross-repo-analyzer`, spawned only when the fix spans 2+ repositories). Each
persona inherits the orchestrator model when its key is unset; all four shipped
profiles instead pin each one explicitly. Each is
independently overridable via an optional per-persona key **nested under `models.validate`**
in `config.yaml`:

```yaml
models:
  validate:
    orchestrator:        {id: claude-opus-5, via: deepagents, provider: anthropic}
    security_architect:  {id: claude-sonnet-4-6}
    penetration_tester:  {id: claude-sonnet-4-6}
    cross_repo_analyzer: {id: claude-sonnet-4-6}
```

`models.validate.orchestrator` accepts `{id, via, provider}` and resolves to
`via: cli`, `via: sdk`, or `via: deepagents`; a legacy `via: openai` value is routed to
`via: deepagents` with the OpenAI provider, which is equivalent to writing
`{via: deepagents, provider: openai}`. An unset persona key inherits `models.validate`.

> **One vendor per validation panel.** The per-persona keys honour **`id` only** — a
> `via:` or `provider:` written on a persona is ignored. The whole panel runs on the
> backend and provider resolved from `models.validate.orchestrator`.
>
> So personas may differ in *model id within one vendor* (orchestrator `gpt-5.5`,
> personas `gpt-5.5-mini`), but a mixed-vendor panel is **refused at startup with exit
> code 2**, before any workspace is staged or token spent:
>
> ```yaml
> # REFUSED — gpt-5.5 cannot run on the Anthropic endpoint the panel uses
> validate:
>   orchestrator:       {id: claude-opus-4-8, via: deepagents, provider: anthropic}
>   security_architect: {id: gpt-5.5}
> ```
>
> ```
> validate: models.validate.security_architect is 'gpt-5.5', which routes to an
> OpenAI-compatible endpoint, but the panel runs on Anthropic (from
> models.validate.orchestrator). …
> ```
>
> Keep the orchestrator and every persona on the same vendor: all `claude-*` with
> `provider: anthropic` (the shipped `default.yaml`), or all `gpt-*` with
> `provider: openai`.

Other profiles ship under `vvaharness/config/profiles/`:

- **`sdk.yaml`** — every configured role is spelled `via: sdk`. Detection uses
  `ANTHROPIC_SDK_API_KEY`. In this profile specifically, S10 requests
  Edit/Write, so the read-only Anthropic SDK loop delegates that remediation
  call to the Claude Agent SDK and translates the SDK-named key. This is not
  the shipped default S10 route; `default.yaml` uses DeepAgents. S11's Agent
  SDK Harness pins external `claude` and uses
  ambient Claude login/OAuth or standard `ANTHROPIC_API_KEY` /
  `ANTHROPIC_AUTH_TOKEN`. A standard Anthropic credential alone can cover all
  stages through the sole-SDK detection fallback; the SDK-named key alone covers
  S1–S10 but does not authenticate S11. No route
  grants Bash. Its
  deepdive at `temperature: 0.4` turns on s4 majority voting (`runs: 3` /
  `vote_threshold: 2`) — which the all-`cli` `default.yaml` cannot do.
- **`full.yaml`** — an example **multi-backend** layout (a mix of `cli`, `sdk`,
  and `openai` roles) you can copy to `./config.yaml` and edit. A complete run
  needs Claude CLI auth, `ANTHROPIC_SDK_API_KEY` for SDK detection/S10,
  and `OPENAI_API_KEY` for OpenAI roles. Its SDK-spelled S11 pins external
  `claude` and can reuse the profile's Claude login/OAuth; standard Anthropic
  auth is an alternative.
- **`taint.yaml`** — S0-enabled, taint-first detection over CLI roles. Its
  `graph_annotate` and legacy `callgraph_creation` roles support optional S0 LLM
  detection, while shipped rules mode remains deterministic. S10/S11 are
  disabled in this profile.
- **DeepAgents routing** — reached per model via `via: deepagents` + a
  `provider` key on the role (no separate profile). `default.yaml` routes both
  `remediate` and `validate` (anthropic) through the shared
  DeepAgents/LangGraph harness. Two providers are supported:
  - `provider: anthropic` — uses the Anthropic Messages API (`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`); for Claude models.
  - `provider: openai` — uses the OpenAI Chat Completions API (`OPENAI_API_KEY` + optional `OPENAI_BASE_URL`); works with OpenAI models **and any OpenAI-compatible endpoint** — open-weight models served via vLLM, Together AI, Ollama, Azure OpenAI, AWS Bedrock (OpenAI-compat mode), or any other Chat Completions-compatible host. Set `OPENAI_BASE_URL` to point at your endpoint.
  When `provider` is omitted, the backend infers from the model name (`claude-*` → Anthropic, anything else → OpenAI-compatible).

## Backends

| `via:` | Transport | Tools | Honours |
|---|---|---|---|
| `cli` | Detection/S10: `claude` subprocess; S11: Claude Agent SDK Harness | Detection/S10 can expose native Read Glob Grep **Bash**; S11 is read-only | `max_budget_usd`, `effort`, and `max_turns` are each forwarded only when the installed CLI advertises the corresponding flag |
| `sdk` | Detection: Anthropic Python SDK; S10 only delegates to Claude Agent SDK when mutating tools are requested; S11: Claude Agent SDK Harness | Detection Read Glob Grep; delegated S10 repo-confined Edit/Write; S11 read-only | `temperature`, `thinking_budget`, `betas`, `max_turns` where supported |
| `openai` | OpenAI Chat Completions (any compatible endpoint) | Read Glob Grep (sandboxed `backends/localtools.py`) | `temperature`, `max_turns` |
| `deepagents` | DeepAgents / LangGraph; remediation and validation roles only | Read Glob Grep; repo-confined Edit/Write in remediation fix mode; no shell | `max_turns`, structured output |

Detection `via: sdk` / `via: openai` auto-drop and retry params the model rejects
(e.g. `temperature` on models that don't support it). `via: cli` is the only
backend with **Bash** — re-add `- Bash` to `step1.allowed_tools` if you switch
`preprocess` to `cli`. The `openai` client is bundled, so `via: openai` works
out of the box — it only needs `OPENAI_API_KEY`.

`via: cli` reads the optional `cli:` config block (`verify_ssl`, `ca_cert`, `effort`, `no_proxy`) and
propagates TLS/proxy settings into the `claude` subprocess environment: `ca_cert`
→ `NODE_EXTRA_CA_CERTS`, `verify_ssl: false` → `NODE_TLS_REJECT_UNAUTHORIZED=0`,
and `no_proxy` → `NO_PROXY`/`no_proxy`. Auth and endpoint stay delegated to the
CLI's native precedence. All of these are optional — when their env vars are
unset they inject nothing. Use absolute certificate paths — a relative value
is used as-is and resolves against the process's current working directory,
not the selected config's directory. mTLS client certs are
available only to the direct Anthropic SDK detection transport
(`ANTHROPIC_SDK_CLIENT_CERT`); Agent-SDK S10/S11 do not consume that setting,
`via: cli` cannot use it (Node exposes no env path), and neither can
`via: openai`.

A bare-string model id (e.g. `deepdive: some-model-id`) defaults to `via: cli`
for backward compatibility.

## Model Performance & Sizing

Performance varies significantly with model size and precision. The harness asks the
model to reason about multi-file codebases, reconstruct taint paths, classify CWEs,
generate adversarial security questions, and synthesise a structured verdict — all
in a single long-running agentic session. Smaller or heavily quantised models
measurably underperform on these tasks, typically losing track of dependency chains
mid-session or failing to produce schema-valid structured output.

### Recommended specification

| Dimension | Minimum | Notes |
|---|---|---|
| **Architecture** | Reasoning model | Models with explicit chain-of-thought or extended-thinking modes consistently outperform pure completion models of equal parameter count on code-analysis tasks. |
| **Parameters** | ≥ 70 B | The minimum scale where models reliably handle multi-file taint paths, CWE classification, and complex remediation reasoning. Models below this threshold tend to lose track of long dependency chains mid-session. |
| **Precision** | INT16 / FP16 / BF16 | Models quantised below INT16 — INT8, INT4, GPTQ 4-bit — show meaningful degradation in structured-output fidelity and code-level reasoning at this task complexity. FP32 is fine but rarely available at 70 B+ scale. |
| **Context window** | ≥ 32 k tokens | A typical deep-dive session over a large service can accumulate 20–30 k tokens of tool results. Models with shorter windows will truncate mid-session or refuse tool results, silently reducing coverage. |

### Example models

The following are examples of models that meet the recommended specification.
Any model satisfying the criteria above is expected to work.

| Model family | Examples | Notes |
|---|---|---|
| **Claude (Anthropic)** | Claude Opus 4, Claude Sonnet 4.x | Opus for remediation and validation; Sonnet for scan stages. |
| **GPT-5 series (OpenAI)** | gpt-5, gpt-5.6-terra | Strong structured-output reliability across all roles. |
| **Kimi** | Kimi K2.7-code | Code-focused reasoning; effective on remediation and validation. |
| **GLM (Zhipu AI)** | GLM-5.2 | OpenAI-compatible endpoint. |
| **DeepSeek** | DeepSeek-V4, DeepSeek-R1 | Strong code reasoning; R1 variant preferred for validation roles. |

### Role tiers

| Role | Recommended tier | Why |
|---|---|---|
| S1–S9 scan (`preprocess` → `chain`) | Mid-tier reasoning | High-volume; many calls per repo. Throughput and cost matter here. |
| S10 remediate | High-tier reasoning | Proposes code changes; needs deep reasoning about fix correctness. |
| S11 validate orchestrator | High-tier reasoning | Synthesises adversarial persona findings into a structured verdict. |
| S11 validate personas | Mid-to-high reasoning | Independent security review; each persona reads the full diff. |

The shipped `default.yaml` already targets appropriate tiers. The table above is
guidance for operators configuring custom deployments.

## Swapping a role

```yaml
models:
  autoexclude: {id: <model-id>, via: sdk}
  preprocess:  {id: <model-id>, via: cli}   # ← flip to get Bash in s1
  decompose:   {id: <model-id>, via: openai}
```

No code change — `backends/llm.py` `resolve()` reads `{id, via, temperature,
thinking_budget, betas}` and routes detection calls to
`backends/{claude_cli,sdk,oai}.py`; S10/S11 DeepAgents routes use the shared
Harness backend.

---

# Pydantic Data Models (`vvaharness/models.py`)

These models carry structured analysis data through the scan pipeline. All are
Pydantic `BaseModel` subclasses.

---

## Taint analysis primitives

### `TaintSymbolRef`

A reference to a single tainted symbol at a point in the dataflow graph.

| Field | Type | Description |
|---|---|---|
| `qnode` | `str` | Qualified node ID (e.g., `"pkg.mod.func.varname"`) |
| `symbol` | `str` | Short symbol name (e.g., `"user_id"`) |
| `kind` | `Literal` | One of: `param`, `local`, `return`, `arg`, `field`, `container`, `property` |

**Example use:** `src` and `dst` fields in `TaintTransferEdge` carry a
`TaintSymbolRef` that identifies the exact variable being tracked.

---

### `TaintTransferEdge`

Base class for a single taint propagation step between two symbols.

| Field | Type | Description |
|---|---|---|
| `file` | `str` | Source file where the transfer occurs |
| `line` | `int` | Line number of the transfer |
| `function_qnode` | `str` | Qualified node of the enclosing function |
| `src` | `TaintSymbolRef` | Symbol taint flows *from* |
| `dst` | `TaintSymbolRef` | Symbol taint flows *to* |
| `transfer_kind` | `Literal` | Semantics of the transfer (see [transfer_kind values](#transfer_kind-values)) |

`transfer_kind` is coerced to `"assign"` when an unrecognised value is supplied.

**Example use:** An assignment `result = request.GET["q"]` produces a
`TaintTransferEdge` with `transfer_kind="assign"`, `src` pointing to the dict
access, and `dst` pointing to `result`.

---

### `TaintEvidencePath`

A complete structured taint path from source to sink, used as evidence for a
finding.

| Field | Type | Description |
|---|---|---|
| `source_ref` | `str` | Human-readable label for the taint source |
| `sink_ref` | `str` | Human-readable label for the sink |
| `path_funcs` | `list[str]` | Ordered list of function QNames traversed |
| `edges` | `list[TaintTransferEdge]` | Ordered transfer edges along the path |
| `sink_cwe` | `list[str]` | CWE IDs associated with the sink (e.g., `["CWE-89"]`) |
| `sanitized` | `bool` | `True` if the final edge neutralises taint before the sink |

**Example use:** A SQL injection finding attaches a `TaintEvidencePath` showing
the chain from `request.GET["id"]` through one or more functions to a
`cursor.execute()` call.

---

## Control-flow graph

### `CFGNode`

A block-shaped record reserved for a control-flow graph.

| Field | Type | Description |
|---|---|---|
| `block_id` | `str` | Block identifier (e.g., `"B0"`, `"B1"`) |
| `stmts` | `list` | Statements or instruction metadata in this block |
| `successors` | `list[str]` | Block IDs this block can reach |
| `condition` | `str \| None` | Branch condition text if this block ends in a branch; `None` otherwise |

**Current engine use:** schema only. The current scanner does not populate
per-function `CFGNode` records.

---

### `CFG`

Control-flow graph container for a single function.

| Field | Type | Description |
|---|---|---|
| `blocks` | `dict[str, CFGNode]` | All basic blocks keyed by `block_id` |
| `entry` | `str` | ID of the entry block (typically `"B0"`) |
| `exit` | `str` | ID of the exit block |
| `function_name` | `str` | Function name, for reference |

**Current engine use:** schema only. The current scanner leaves the per-file
`cfgs` mapping empty, so vvaharness does not currently claim branch- or
path-sensitive CFG analysis.

---

## Condition-gated taint

### `ConditionTaintEdge` *(extends `TaintTransferEdge`)*

A schema for a taint transfer gated by a branch condition. The type is retained
for future/refined CFG data, but the current scanner does not emit these edges.

| Field | Type | Description |
|---|---|---|
| `transfer_kind` | `"condition"` | Fixed discriminator |
| `condition_text` | `str` | Text of the controlling condition (e.g., `"user.role == 'admin'"`) |
| `is_tainted_condition` | `bool` | Whether the condition expression depends on a taint source |
| `confidence` | `"high" \| "medium"` | Confidence in the taint propagation through this branch |

Inherits `file`, `line`, `function_qnode`, `src`, `dst` from `TaintTransferEdge`.

**Schema example:** a future/refined CFG for `if user_input in allowed:` could
represent the guarded transfer with `is_tainted_condition=True`.

---

## Reflection

### `ReflectionFact`

A reflective or dynamic dispatch call site discovered during analysis.

| Field | Type | Description |
|---|---|---|
| `function_qnode` | `str` | Enclosing function |
| `line` | `int` | Source line |
| `call_type` | `Literal` | One of: `getmethod`, `invoke`, `getattr`, `construct`, `delegate` |
| `target_symbols` | `list[str]` | Symbols passed to `getMethod`/`getattr`/etc. (resolved targets) |
| `receiver` | `str` | Object on which reflection is called |
| `language` | `"python" \| "java" \| "csharp"` | Source language |

**Example use:** `getattr(obj, user_input)` in Python is recorded as a
`ReflectionFact` with `call_type="getattr"` and `target_symbols=["user_input"]`.

---

### `ReflectionTaintEdge` *(extends `TaintTransferEdge`)*

A taint transfer through a dynamically resolved method or function.

| Field | Type | Description |
|---|---|---|
| `transfer_kind` | `"reflect"` | Fixed discriminator |
| `reflected_targets` | `list[str]` | QNames of the resolved reflection targets |
| `confidence` | `"low" \| "medium" \| "high"` | How well the target was resolved statically |
| `is_speculative` | `bool` | `True` when the target was inferred rather than proven |

**Example use:** When `getattr(obj, tainted_name)` cannot be fully resolved, a
`ReflectionTaintEdge` with `confidence="low"` and `is_speculative=True` is
emitted to preserve the potential flow.

---

## Framework markers and route binding

### `FrameworkMarkerFact`

A framework annotation, decorator, or implicit type-based marker that introduces
user-controlled input into a function.

| Field | Type | Description |
|---|---|---|
| `function_qnode` | `str` | Function annotated or decorated by the marker |
| `line` | `int` | Source line of the annotation |
| `marker_type` | `Literal` | One of: `spring_annotation`, `django_view`, `aspnet_annotation`, `spring_implicit`, `django_dict_access`, `aspnet_implicit` |
| `marker_name` | `str` | Annotation/attribute name (e.g., `"@RequestParam"`, `"request.GET"`) |
| `parameter_names` | `list[str]` | Parameters tainted by this marker |
| `framework` | `"spring" \| "django" \| "aspnet"` | Web framework |
| `confidence` | `"high" \| "medium"` | `high` for explicit annotations; `medium` for implicit dict access |

**Example use:** the parameter annotation in
`String find(@RequestParam("id") String id)` is recorded as a
`FrameworkMarkerFact` with `marker_type="spring_annotation"` and
`parameter_names=["id"]`.

---

### `RouteTaintFact`

A URL route with path parameters that bind to function arguments, marking those
arguments as tainted (user-controlled).

| Field | Type | Description |
|---|---|---|
| `function_qnode` | `str` | Function handling the route |
| `line` | `int` | Source line of the route declaration |
| `route_pattern` | `str` | Route pattern (e.g., `"/user/{id}"`, `"user/<int:pk>/"`) |
| `parameter_name` | `str` | Name of the tainted path parameter |
| `is_tainted` | `bool` | Defaults to `True` because URL parameters are user-controlled |
| `framework` | `"spring" \| "django" \| "aspnet"` | Web framework |

**Example use:** `@GetMapping("/item/{itemId}")` produces a `RouteTaintFact`
with `route_pattern="/item/{itemId}"` and `parameter_name="itemId"`.

---

### `ResponseDataflowFact`

A flow from an intermediate variable or return value into a framework response
sink — used to identify where tainted data reaches a response boundary.

| Field | Type | Description |
|---|---|---|
| `function_qnode` | `str` | Function containing the dataflow |
| `line` | `int` | Line of the response construction |
| `from_symbol` | `str` | Variable flowing into the response |
| `to_sink` | `str` | Response sink name (e.g., `"JsonResponse"`, `"HttpResponse"`, `"Ok"`) |
| `framework` | `"spring" \| "django" \| "aspnet"` | Web framework |
| `response_type` | `"json" \| "html" \| "text" \| "xml"` | Response content type |

**Example use:** `return JsonResponse({"data": user_input})` is recorded with
`from_symbol="user_input"`, `to_sink="JsonResponse"`, `response_type="json"`,
pointing to a potential XSS or injection reaching the HTTP response.

---

### `FrameworkTaintEdge` *(extends `TaintTransferEdge`)*

A schema for a taint transfer through framework infrastructure — request
parameter binding, route path binding, or response construction. The current
scanner emits the marker/route/response facts above but does not construct
`FrameworkTaintEdge` instances.

| Field | Type | Description |
|---|---|---|
| `transfer_kind` | `"framework"` | Fixed discriminator |
| `marker_type` | `Literal` | Same values as `FrameworkMarkerFact.marker_type` |
| `framework` | `"spring" \| "django" \| "aspnet"` | Web framework |
| `confidence` | `"high" \| "medium"` | Confidence in the framework-mediated transfer |

Inherits `file`, `line`, `function_qnode`, `src`, `dst` from `TaintTransferEdge`.

**Schema example:** A future edge for a Spring `@ModelAttribute`-bound parameter could use a
`FrameworkTaintEdge` with `transfer_kind="framework"`,
`marker_type="spring_annotation"`, connecting the HTTP request body to the
bound model object.

---

## `transfer_kind` values

| Value | Semantics |
|---|---|
| `source` | Introduces taint at a source symbol |
| `assign` | Direct variable assignment (`a = b`) |
| `arg_to_param` | Taint flows from call-site argument into callee parameter |
| `return_to_local` | Callee return value assigned to a local variable |
| `local_to_sink` | Local variable passed directly to a sink |
| `return_to_sink` | Return value used directly as a sink argument |
| `field_write` | Taint stored into an object field or attribute |
| `field_read` | Taint read from an object field or attribute |
| `container_put` | Taint added to a collection (`list.append`, `dict[k] = v`) |
| `container_get` | Taint retrieved from a collection (`dict[k]`, `list[i]`) |
| `sanitize` | Taint neutralised by a sanitiser (the final edge of a `sanitized=True` path) |
| `condition` | Taint gated by a branch condition — see `ConditionTaintEdge` |
| `reflect` | Taint via dynamic dispatch — see `ReflectionTaintEdge` |
| `framework` | Taint via framework binding/response — see `FrameworkTaintEdge` |
