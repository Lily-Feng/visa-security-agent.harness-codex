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

# Configuration Reference

All knobs live in `config.yaml`. Secrets are read from env vars via `${VAR}`
expansion — the CLI auto-loads a `.env` (searched from the working directory
upward through parent directories) — so never commit tokens into `config.yaml`.

## Setting up your config

`vvaharness` ships ready-to-run **profiles** — you do **not** author a config
from a blank file. "Setting up your config" means: **pick a shipped profile,
point the tool at it, and put your secrets in `.env`.** Customise only by
*copying* a profile and editing the knobs you care about — starting from a
shipped profile (never hand-writing one) is the supported path.

### 1. Which file the tool loads (resolution order)

The active config is resolved once, in this order:

1. **`--config <path>`** — an explicit profile/file (highest precedence).
2. **`./config.yaml`** — auto-detected if present in the directory you run from.
3. **the packaged `default.yaml`** — the built-in fallback.

Then, if a **`config.local.yaml`** sits next to the chosen file, its keys are
deep-merged on top (git-ignored — your machine-local overrides). Partial files
are fine: any step-knob you omit is filled from built-in defaults, so a config
never has to be exhaustive.

> The overlay can change security-relevant settings (model routing, `base_url`,
> TLS `ca_cert`, tool permissions), so the merge is **announced** on every
> command — the loader logs `config overlay: <path> applied (overrides: …)` with
> the top-level keys it changed, and its SHA-256 is recorded in
> `run_manifest.json`. It resolves next to your `--config` path (operator-owned),
> never the scanned target. For a reproducible run that honours **only** the
> selected config, set **`VVAHARNESS_NO_LOCAL_CONFIG`** (to any value) to skip
> the overlay.

> **Trust boundary — config/`.env` inside the scan target is refused.** The
> scanned repository is untrusted input. If the resolved `config.yaml` (or a
> `.env` discovered by the upward search) lives **at or under the `--repo`
> target**, it is ignored — the tool falls back to the packaged default and
> prints a `WARN` — so a config committed into a repo you are scanning cannot
> redirect your model endpoints, credentials, or TLS settings. Your own
> copy-then-edit `./config.yaml` in an operator-owned directory is unaffected
> (only paths *inside the target* are refused). To deliberately load config
> from inside a target you trust, set `VVAHARNESS_ALLOW_CWD_CONFIG=1`. The
> effective config path, any applied `config.local.yaml` overlay, and the
> loaded `.env` are echoed to stderr, and the SHA-256s of the config profile and
> the `config.local.yaml` overlay are recorded in `run_manifest.json` for
> auditability.

### 2. Pick a shipped profile

All four live in `vvaharness/config/profiles/`:

| Profile | Backends | Auth you need | Use when |
|---|---|---|---|
| **`default.yaml`** | S0 enabled; S1–S9 `via: cli`; S10/S11 `via: deepagents` (Anthropic) | Claude Code login for S1–S9; `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` for S10/S11 | The built-in default. Mixed backend: local static seed, detection on CLI, post-scan stages on DeepAgents. |
| **`sdk.yaml`** | S0 disabled; every model role spelled `via: sdk`. Detection uses the Anthropic Python SDK; S10 fix and S11 use Claude Agent SDK paths. No Bash. | `ANTHROPIC_SDK_API_KEY` for S1–S10; S11 pins external `claude` and uses Claude login/OAuth or standard Anthropic auth (or one standard credential can cover every stage via the sole-SDK fallback) | You want **s4 majority voting** — its deepdive role at `temperature: 0.4` activates `step4.runs`/`vote_threshold`. |
| **`full.yaml`** | S0 disabled; mixed per role (`cli` + `sdk` + `openai`) | Claude CLI auth (also usable by S11); `ANTHROPIC_SDK_API_KEY` for SDK detection/S10; `OPENAI_API_KEY`; standard Anthropic auth is an S11 alternative | You want to spread roles across backends, or template your own mix. |
| **`taint.yaml`** | S0 enabled; S1–S9 `via: cli`; **S10/S11 disabled** | Claude Code login only for model stages; supply generated source/sink rules for a rules-mode S0 seed | Taint-first source→sink scanning when S0 has usable specs. With a non-empty seed, `step1.mode: gap_fill` skips agentic S1 unless all escalation checks hold (>500 source files, web-api/web-app/service, ≥10 entry points, <5 sinks); an empty seed takes the agentic S1 path. `catchall_mode: reachable_only`; confirm/refute prompt on taint chunks. Use: `--config vvaharness/config/profiles/taint.yaml`. |

> **No shipped profile grants `Bash`.** Only the `cli` backend can shell out; to
> enable it, add `- Bash` to a `via: cli` role's `allowed_tools` (e.g. `step1`,
> `step6_verify`) in your own copy — and only for a target you trust.

Not sure which? Run **`vvaharness setup`** — it inspects the credentials you
have and recommends a profile.

### 3a. Run a profile as-is

```bash
# Use a specific profile:
vvaharness scan --repo /path/to/target --config vvaharness/config/profiles/sdk.yaml

# Or omit --config to use the packaged default.yaml:
vvaharness scan --repo /path/to/target
```

### 3b. Customise it (copy-then-edit)

```bash
cp vvaharness/config/profiles/full.yaml ./config.yaml
# edit ./config.yaml — e.g. swap model ids, change a role's `via`, tune step4.runs
vvaharness scan --repo /path/to/target        # ./config.yaml is auto-detected
```

The most common edit is the `models:` block. Detection roles use
`{id: <model>, via: cli|sdk|openai}`; `deepagents` is restricted to remediation
and validation. Validation has a nested `orchestrator` plus persona model IDs.
See [models.md](models.md) for the exact schema and role/backend matrix.

### 4. Secrets go in `.env`, never in the YAML

The profiles reference env vars with `${VAR}` (or `${VAR:-default}`); an unset
var expands to empty (or the default), so a profile with no gateway/cert vars
set just runs against the public endpoint. Copy `.env.example` to `.env` and
fill in what your chosen profile needs:

| Backend / area | Env vars |
|---|---|
| SDK (`via: sdk`) | Direct detection: `ANTHROPIC_SDK_API_KEY`, `ANTHROPIC_SDK_BASE_URL`, `ANTHROPIC_SDK_CA_CERT`, `ANTHROPIC_SDK_CLIENT_CERT`; S10 translates key/base; S11 pins external `claude` and uses ambient Claude login/OAuth or standard `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_BASE_URL` (not the SDK-named key) |
| CLI (`via: cli`) | `CLAUDE_CODE_OAUTH_TOKEN` (or run `claude` → `/login`), `CLAUDE_CLI_CA_CERT` |
| OpenAI (`via: openai`) | `OPENAI_API_KEY` (required), `OPENAI_BASE_URL`, `OPENAI_CA_CERT` |
| DeepAgents (`via: deepagents`, S10/S11 only) | Anthropic provider: `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`, optional `ANTHROPIC_BASE_URL`; OpenAI provider: `OPENAI_API_KEY`, optional `OPENAI_BASE_URL`; process trust uses `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, or `NODE_EXTRA_CA_CERTS` as supported by the provider client |
| Batch / git clone | `GITHUB_TOKEN`, `GIT_BASE_URL` |

Only credentials for the enabled routes are required. The `*_BASE_URL` /
`*_CA_CERT` / `*_CLIENT_CERT` vars are for private gateways and mutual TLS.
Certificate env values should be absolute paths: after `${VAR}` interpolation
the value is used as-is, so a relative value resolves against the process's
current working directory, not `.env` or the selected YAML config's
directory. See
[Backend transport](#backend-transport-sdk--openai--cli).

### 5. Validate before scanning

```bash
vvaharness doctor    # checks readiness + live-probes detection transports
vvaharness setup     # full readiness report + profile recommendation
```

The current doctor probe does not execute the S10/S11 Claude Agent SDK Harness;
for `sdk.yaml` / `full.yaml`, separately verify external `claude` and either
Claude login/OAuth or standard Anthropic auth for S11.

`doctor` resolves the **same** config a scan would (it honours `--config`), but
its connectivity probes validate the detection transports rather than every
post-scan launcher; apply the Agent-SDK S11 caveat above.

## Top-level sections

| Section | Purpose | See |
|---|---|---|
| `models:` | Per-role model/backend routing; nested validation orchestrator/personas | [models.md](models.md) |
| `sdk:` / `openai:` / `cli:` | Backend transport (TLS/proxy). See [Backend transport](#backend-transport-sdk--openai--cli) below. | [SETUP_GUIDE.md](SETUP_GUIDE.md) |
| `step0:` | Static AST seed enablement, rules/LLM detection mode, optional external rule files | below |
| `step1:` … `step8:` | Per-stage scan tuning (cost, depth, precision) | below |
| `step_remediate:` / `step_validate:` | Remediation Agent (s10) and validator (s11) tuning | below |
| `inject:` | Optional CVE/controls/CMDB context plus remediation policy/playbook paths | [outputs.md](outputs.md#cmdb-enrichment) |
| `rules:` | Optional external S4 CWE knowledge-base overlays | below |
| `scan_progress:` | File/chunk observability enablement and output style | below |
| `batch:` | `git_token`, `git_base_url`, `skip_repo_patterns` | [repos-csv.md](repos-csv.md) |
| `output:` | Cleanup preservation and unreachable-file appendix | [outputs.md](outputs.md) |

## Backend transport (`sdk:` / `openai:` / `cli:`)

Each backend has its own transport block holding TLS/proxy knobs. **Every key
is optional** — when its `${...}` env var is unset it expands to empty and
injects nothing, so the default profile runs with just an API key. The blocks
are only consulted by roles routed to that backend (`via: sdk`, `via: openai`,
`via: cli`).

| Key | `sdk:` | `openai:` | `cli:` |
|---|---|---|---|
| `api_key` | `${ANTHROPIC_SDK_API_KEY}` | `${OPENAI_API_KEY}` | — (CLI native auth) |
| `base_url` | `${ANTHROPIC_SDK_BASE_URL}` | `${OPENAI_BASE_URL}` | — (CLI native, `ANTHROPIC_BASE_URL`) |
| `verify_ssl` | `true` (set `false` to disable TLS verification) | `true` | `true` |
| `ca_cert` | `${ANTHROPIC_SDK_CA_CERT}` | `${OPENAI_CA_CERT}` | `${CLAUDE_CLI_CA_CERT}` |
| `client_cert` (mTLS) | `${ANTHROPIC_SDK_CLIENT_CERT}` (direct detection transport only) | not supported | not supported |
| `no_proxy` | comma-separated hosts to bypass the proxy | same | exported as `NO_PROXY`/`no_proxy` into the subprocess |

`verify_ssl` accepts a native YAML boolean or a string boolean (`"false"`,
`"true"`, `"0"`, `"1"`, `"no"`, `"yes"`, …). A string is coerced to a real
boolean, so an environment-templated value like `verify_ssl: ${VERIFY_SSL:-false}`
disables verification as intended rather than being read as a CA-bundle path.
Any other string is treated as a CA-bundle path.

`via: deepagents` does not read these three transport blocks. Its provider is
selected on `models.remediate` or `models.validate.orchestrator`:

```yaml
models:
  remediate: {id: claude-opus-4-8, via: deepagents, provider: anthropic}
  validate:
    orchestrator: {id: claude-opus-5, via: deepagents, provider: anthropic}
    security_architect: {id: claude-sonnet-4-6}
    penetration_tester: {id: claude-sonnet-4-6}
    cross_repo_analyzer: {id: claude-sonnet-4-6}
```

Use `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` for a private endpoint. DeepAgents
has no `verify_ssl` profile switch; configure certificate trust at the process
or provider-client layer. Validation is read-only for every backend: agents
return structured results, and host code writes temporary validation artifacts
and the DTO update.

The Claude Agent SDK paths selected by `via: sdk` for S10 fix mode and S11 do
not consume the `sdk:` block's CA/client-cert fields. S10 translates the
SDK-specific key and base URL to standard Anthropic names; S11 does not
translate them and pins an external `claude` executable. That process can use
ambient Claude login/`CLAUDE_CODE_OAUTH_TOKEN` or standard
`ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_BASE_URL`. The
direct SDK detection transport is the only path that uses
`ANTHROPIC_SDK_CLIENT_CERT`.

The `cli:` block tunes TLS/proxy for the `claude` **subprocess** only:

- `ca_cert` → exported as `NODE_EXTRA_CA_CERTS` into the subprocess env.
- `verify_ssl: false` → exports `NODE_TLS_REJECT_UNAUTHORIZED=0` (insecure;
  throwaway/test environments only).
- `client_cert` / mTLS is **not** available on `cli:` (Node exposes no env
  path — the backend emits a warning if one is set). The direct SDK detection
  transport is the only route exposing the configured client certificate.
- Auth and endpoint stay delegated to the CLI's own precedence: run `claude`
  then `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN`; `ANTHROPIC_BASE_URL` is
  honoured if already exported. The CLI defaults to `api.anthropic.com` when
  no base URL is set.
- `effort` (e.g. `high`) pins the reasoning effort for the `claude -p`
  subprocess so a scan never inherits the operator's interactive `/effort`
  default (some models reject `xhigh`). Accepted values are typically
  `high|low|max|medium`.

**When is a cert needed?**

- Public endpoint (`api.anthropic.com` / `api.openai.com`) + a normal API
  key → nothing TLS-related needed.
- Private gateway or a TLS-intercepting proxy whose server cert chains to an
  internal root CA not in the OS trust store → set the per-backend CA bundle
  env var (`ANTHROPIC_SDK_CA_CERT`, `OPENAI_CA_CERT`, or `CLAUDE_CLI_CA_CERT`).
- Gateway requires mutual TLS → `ANTHROPIC_SDK_CLIENT_CERT` for the direct
  Anthropic SDK detection transport only; Agent-SDK S10/S11 do not consume it.

If only the API key is set and no base URL is given, `sdk:` defaults to
`api.anthropic.com` and `openai:` to `api.openai.com` — neither fails for lack
of a URL.

## `step0:` — static AST seed

S0 is a profile-controlled pre-stage before S1. Rules mode is deterministic;
the optional annotation mode calls a model. `default.yaml` and `taint.yaml`
enable the wrapper, while `sdk.yaml` and `full.yaml` inherit the disabled
built-in default.

| Key | Effect |
|---|---|
| `enabled` | Run S0. Built-in fallback `false`; shipped default/taint profiles set `true`. |
| `callgraph_detection` | `rules` (default) or `llm`. Rules mode loads configured external YAML and has no implicit source/sink baseline. LLM mode classifies observed call fingerprints, can add observed-call heuristics when configured, and falls back to configured rule YAML when it produces no usable specs or fails. |
| `sources_yaml` / `sinks_yaml` | External Semgrep-style callgraph rule files. The shipped profiles read `VVA_STEP0_SOURCES_YAML` / `VVA_STEP0_SINKS_YAML`; no generated corpus is packaged. At least one usable file is required for rules mode to produce static matches. |
| `languages` | Optional S0 language allowlist. Omit to use every installed callgraph plugin. |
| `callgraph.llm.*` | Annotator caps and confidence thresholds: `max_tokens`, `max_candidates`, `max_batch_candidates`, `min_source_confidence`, `min_sink_confidence`, `failure_mode`, `heuristic_supplement`, `min_sources`, `min_sinks`, `max_heuristic_specs`. |

When S0 has usable external or LLM-derived specs, parser plugins exist for
Python, Java, C#, JavaScript, TypeScript, and Go. Python/Java/C# can emit typed
taint evidence; JavaScript/TypeScript/Go provide reachability-only seed paths.
Languages without a plugin receive no S0 seed, but S1–S9 still run. See
[SETUP_GUIDE.md](SETUP_GUIDE.md#optional-external-sourcesink-rule-files-s0)
for rule-pack generation.

## `step1:` — repo intake & file inventory

The deterministic repo walk that feeds s3/s4 applies, in order:

1. **symlink containment** — a symlinked file whose target resolves
   **outside the repository root** is skipped (its content would otherwise be
   off-tree host data pulled into LLM prompts). In-tree symlinks (e.g. a
   monorepo linking shared source) are still scanned. This containment check is
   **unconditional**: `step1.follow_symlinks: true` no longer re-enables
   out-of-root links — they are dropped regardless (the key is still accepted
   for back-compat, with a warning that off-root targets remain blocked).
2. **`exclude_dirs` / `exclude_exts` / `exclude_globs`** — built-in defaults
   plus `config.yaml: step1:` plus any overlay (`--step1-config` /
   `--auto-step1`). Lists **append**.
3. **`max_file_kb`** — any file larger than this (default 1024 KB) is
   skipped outright; data dumps and generated blobs never reach the LLM.

After the walk, a separate pass applies:

4. **`config_dedup`** — content-based collapse of near-duplicate per-env
   config files (below).

Everything excluded — including skipped out-of-root symlinks — is itemised in
the report's *Excluded from scan* section and in the s1 checkpoint, so each
run is fully auditable.

Overlay merge semantics: top-level `exclude_*` lists **append**; nested
dicts like `config_dedup` deep-merge with **replace** (the latest
overlay's `config_dedup.exts` wins outright).

| Key | Effect |
|---|---|
| `auto_exclude` | `true` (shipped default). After each clone, AI-survey the target to derive a per-target Step-1 exclusion overlay before s1 — same as `--auto-step1`. Flag and config OR together; `--no-auto-step1` or `auto_exclude: false` opts out, `--step1-config` overrides. |
| `auto_exclude_max_tokens` | Output cap for the auto-exclude survey call (`models.autoexclude`). Default `8000`. |
| `mode` | `full` normally. With a non-empty seed, `gap_fill` skips the S1 model call unless all four escalation checks hold: >500 source files, web-api/web-app/service classification, ≥10 entry points, and <5 sinks. An empty seed is falsey and takes the agentic S1 path; if S1 still yields no entry points or sinks, S3 restores `catchall_mode: all`. |
| `call_graph` | `regex` built-in default; `tree_sitter` in default/taint profiles for AST-backed call/definition spans. |
| `max_budget_usd` | Dollar limit forwarded only when the selected `via: cli` binary advertises `--max-budget-usd`; raw SDK/OpenAI routes ignore it. Otherwise the subprocess timeout remains the bound. Default `25.0`. |
| `max_turns` | Tool-loop cap for `via: sdk` / `via: openai`; also forwarded when an installed `via: cli` build advertises `--max-turns`. Default `40`. |
| `allowed_tools` | `[Read, Glob, Grep]` — re-add `Bash` only on `via: cli`. |
| `follow_symlinks` | `false` (default). Accepted for back-compat but no longer re-enables out-of-root symlinks: links whose target resolves outside the repo root are dropped unconditionally (host-file disclosure guard), even when this is `true`. In-tree symlinks are always followed. |
| `call_graph_validate` / `_supplement` / `_rounds` / `_max_targets` | Deterministic call-graph hardening after the agentic pass. |

### `step1.config_dedup`

Repos with per-environment configs (e.g. `service/<svc>/<env>/config.yml`,
`application-{dev,qa,prod}.yml`, `values-{env}.yaml`) often carry
thousands of structurally identical files. The dedup pass:

- shape-hashes each `.yml/.yaml/.json/.toml/.ini/.properties/.conf/.cfg/.env`
  by its **key structure only** (values stripped) and clusters identical
  shapes;
- keeps **one representative per cluster** (per top-level dir, prod
  preferred) and drops the rest;
- runs a **secret / insecure-value safety net** over every file about to
  be dropped — any file with a literal credential, private key, AWS key,
  JWT, `verify: false`, `auth: none`, `debug: true`, etc. that the
  cluster rep *doesn't* already have is promoted back into scope;
- never drops a file that is unique, unparseable, oversized, or in a
  cluster smaller than `min_cluster_size`.

```yaml
step1:
  config_dedup:
    enabled: true
    min_cluster_size: 5
    keep_per_top_dir: true
    promote_on_secret_hit: true
    promote_on_insecure_value: true
    max_file_kb: 512   # dedup-pass oversize cut (distinct from step1.max_file_kb); files larger than this are kept, never dropped
    exts: [.yml, .yaml, .json, .toml, .ini, .properties, .conf, .cfg, .env]
```

## `step2:` — threat model

`enabled`, `max_tokens`, `max_threats`, `baseline` (`auto`/`owasp`/`none`),
`max_doc_chars`, `max_manifest_chars`, evidence caps
(`max_modules`, `max_entry_points`, `max_config_reps`,
`max_api_artefacts`), graph/frontier caps (`max_graph_files`,
`max_graph_sinks`, `max_graph_edges`, `max_function_sites`), and prompt caps
(`max_prompt_modules`, `max_prompt_entry_points`, `max_notes_chars`).

## `step3:` — decompose

`taint_chunks`, `taint_max_hops`, `taint_max_chunks`,
`taint_files_per_hop`, `pack_by` (`loc`|`tokens`),
`chunk_token_budget`, `chunk_overhead_tokens`, `risk_chunk_loc`,
`catchall_enabled`, `catchall_mode` (`all`|`reachable_only`),
`catchall_reachable_min_ratio`, `catchall_reachable_min_files`,
`catchall_chunk_loc`, `catchall_max_files`,
`max_files_per_chunk`, `specialists[]`, `specialist_chunk_loc`,
`taint_chunk_slice` (`file`|`function`), `threat_surface_fallbacks`,
`threat_fallback_max_files`, prompt-size caps (`max_prompt_files`,
`max_prompt_entry_points`, `max_prompt_sinks`, `max_prompt_modules`,
`max_prompt_call_edges`, `max_prompt_notes_chars`), `timeout`, `max_tokens`.

`reachable_only` is a taint-profile optimization, not a proof of whole-repo
unreachability. Its ratio/file guards fail open to `all` when the graph is too
sparse. Function slicing reduces prompt size but may fall back to whole-file or
head excerpts when definition spans are incomplete; use `file` for guaranteed
whole-file chunk content.

## `step4:` — deep-dive

`parallel`, `runs`, `vote_threshold`, `specialist_runs`, `line_bucket`,
`max_findings_per_run`, `neighbor_context_lines`,
`neighbor_context_max`, `taint_prompt_mode` (`discover`|`confirm_refute`),
`taint_runs`, optional `taint_model`, `taint_chunk_slice` override,
`frontier_max_funcs_per_file`, `frontier_fallback_head_lines`, `timeout`,
`max_tokens`.

## `step5_prefilter:` / `step6_verify:`

`min_pre_confidence`, `require_evidence`, `ast_backfill_evidence` · `parallel`,
`min_confidence`, `max_budget_usd`, `max_turns`, `allowed_tools`.

## `step7_dedup:` / `step8:`

`line_tolerance`, `semantic`, `pre_verify_threshold` (when ≥N findings survive
s5, run a semantic dedup pass *before* s6 verify to cut cost; default 25),
`max_tokens` · `max_tokens`, `timeout`.

## `step_remediate:` — Remediation Agent (s10)

Tunes the `remediate` command and in-scan S10. The shipped `default.yaml`,
`sdk.yaml`, and `full.yaml` enable it; `taint.yaml` disables it. `--remediate`
forces it on for a scan.

| Key | Effect |
|---|---|
| `enabled` | `true` in default/sdk/full; `false` in taint. Run the Remediation Agent. |
| `top_n_findings` | Remediate only the top-N findings by CVSS: `5` in default/sdk/taint, `20` in full and the built-in fallback. `--top N` overrides; `all`/`*`/`null` remediates every finding. |
| `max_budget_usd` | Per-finding cap passed to the backend (default `10.0`). Compatible Claude CLI and Claude Agent SDK routes enforce it; raw SDK/OpenAI and DeepAgents routes ignore it. Token accounting does not enforce the cap. |
| `max_turns` | Per-finding loop cap (default `40`): forwarded to compatible Claude CLI builds and Claude Agent SDK, enforced by raw SDK/OpenAI loops, and mapped to a DeepAgents recursion limit. |
| `allowed_tools` | Fix-mode tools: `[Read, Glob, Grep, Edit, Write]` — `Edit`/`Write` apply diffs without a host shell. **Bash is omitted by design.** DeepAgents uses a repo-rooted, traversal-safe filesystem backend with no command execution; the SDK gate denies Bash even if re-added. A custom `via: cli` remediation role would grant Bash if you re-added it, so do not. |
| `enforce_policy` | `true` in default/taint; `false` in sdk/full. Deny-list/playbook gate + diff post-gate (reverts forbidden-path edits). Taint leaves S10 disabled, so its setting matters only if S10 is forced on. |
| `policy_file` | Optional remediation-policy override. Resolves relative to the active config; unset, empty, or unresolved falls back to the installed default. |
| `playbook_file` | Optional remediation-playbook override with the same resolution/fallback behavior. |

`via: deepagents` is supported only on `models.remediate` and
`models.validate`; configuration preflight rejects it for S1–S9 model roles.

The remediation model is the `models.remediate` role (see [models.md](models.md)).
Full command reference — modes, policy gate, kill-switch — in
[remediation.md](remediation.md).

## `step_validate:` — validator (s11)

Tunes the `validate` / `s11` command. It is enabled in default/sdk/full and
disabled in taint. A config that omits the key inherits the built-in `false`.

| Key | Effect |
|---|---|
| `enabled` | `true` in default/sdk/full; `false` in taint and in the built-in fallback. |
| `effort` | Reasoning effort for each panel session (default `high`); DeepAgents ignores it. |
| `max_turns` | Per-finding panel-session turn cap (default `50`); DeepAgents maps it to a recursion limit. |
| `max_budget_usd` | Per-finding panel-session cap (default `15.0`) enforced by the Claude Agent SDK Harness; DeepAgents ignores it. |
| `max_findings` | Top-N validatable findings by CVSS (default `20`); `--all` bypasses (standalone `validate` only), `--finding` ignores. |
| `allowed_tools` | Read-only repository tools: `[Read, Grep, Glob]`. Validation agents receive no `Write`, `Edit`, or `Bash`; persona dispatch is orchestrated by the session. Agents return structured output and host code alone writes temporary artifacts and the DTO update. |

Full command reference — gate weights, verdict bands, per-persona overrides,
trust model — in [validation.md](validation.md).

> **`max_findings` applies in-scan too.** The cap is enforced both by the
> standalone `vvaharness validate` command and by Step 11 running inside a
> `scan`. When `step_validate.max_findings` is unset it defaults to `20`
> (the `DEFAULT_MAX_FINDINGS` constant). All four shipped profiles set it
> explicitly to `20`, so their behavior is unchanged. Hand-written or
> copy-then-edited configs that **omit the key** previously validated every
> finding (Step 11 used to force `--all` unconditionally); they now cap at 20.
> When the cap kicks in, the scan log prints:
> `validate: capping to top 20 of N validatable findings by CVSS (use --all to validate every finding)`.
> To validate everything in a standalone run, pass `--all`; there is no
> equivalent override for the in-scan step — set `max_findings: 9999` in your
> profile if you want no cap.

## `inject:` — optional context inputs

| Key | Effect |
|---|---|
| `cve_file` | Known-CVE feed — raises threat likelihood / focuses the hunt. |
| `controls_file` | Design controls — downranks exploitability (demands bypass proof at s6). |
| `cmdb_file` | CMDB export — enables AppProfile lookup + VulContextSeverity scoring. |

CVE, controls, and CMDB inputs are optional and skipped when absent.

## `rules:` — S4 CWE knowledge overlays

`rules.kb_overlays` accepts one external `*.kb.yaml` path or a list of paths.
The entries are merged with the built-in `generic.kb.yaml` used by S4's
confirm/refute prompt. Overlay files are operator-owned and are not discovered
or packaged automatically. This is separate from S0's source/sink rule files.

## `scan_progress:` — file/chunk observability

| Key | Effect |
|---|---|
| `enabled` | Emit the observability stream. Shipped values: default `true`, taint `true`, sdk/full `false`. `VVAHARNESS_SCAN_PROGRESS_ENABLED=1` forces it on. |
| `style` | `compact`, `verbose`, or `summary_only`. Default profile uses compact; taint uses verbose. |

Stage-level events cover S0–S9. Detailed activity includes S1 discovery, S2
threat-model notes, S3 chunk queueing, and S4 scanning/results; other stages do
not manufacture per-file events.

## `output:` — cleanup and coverage appendix

`preserve_on_cleanup` lists folders retained when a batch clone is removed; all
shipped profiles preserve `security-scan` and `security-remediation`.
`emit_unreachable_appendix` controls whether S3's callgraph-unreachable files
are listed in the report (enabled by `taint.yaml`, otherwise `false`).
