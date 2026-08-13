<!--
Copyright 2026 Visa, Inc.
Modifications Copyright 2026 Lily Feng.
Modified by Lily Feng in 2026 for native Codex support.

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

# vvaharness — User Guide

Agentic SAST pipeline. It surveys a code repo, threat-models it, decomposes it
into analysis chunks, deep-dives each, adversarially verifies findings,
deduplicates, analyses exploit chains, and emits a Markdown report + SARIF
2.1.0. A separate `validate` command verifies remediations with an agentic
adversarial panel.

> **Read this first:** findings are **LLM-generated triage candidates, not
> confirmed vulnerabilities.** Human review is required. Runs are
> non-deterministic — two scans of the same repo may differ. See *Limitations*.

For full installation and credential/config setup, see
**[SETUP_GUIDE.md](SETUP_GUIDE.md)**.

---

## Quick install (per OS)

Requires Python ≥ 3.11. Any path below puts the **`vvaharness`** command on
your PATH (no need to type `python -m vvaharness …`).

**Recommended — `pipx` (isolated, no virtualenv to activate):**
```bash
pipx install .        # gives a global `vvaharness` command in its own env
```

> **Is a virtualenv required? No.** A venv just *isolates* dependencies; `pipx`
> already does that for you, and `pip install .` / `pip install --user .` work
> without one. Use a venv only if you prefer manual isolation or can't use
> pipx. Pick **one** of the paths below — don't combine them.

**Linux / macOS — venv (alternative):**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install .
```

**Windows — PowerShell**
```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install .
```

**Windows — cmd.exe**
```bat
python -m venv .venv & .\.venv\Scripts\activate.bat
pip install .
```

Prefer an isolated global tool? `pipx install .`. No venv/pipx? `pip install
--user .` (ensure the user-scripts dir is on PATH). See
[SETUP_GUIDE.md](SETUP_GUIDE.md) for all options, credentials, TLS/proxy, and
config profiles.

---

## 1. Commands

`vvaharness` exposes these subcommands (a bare invocation prints help):

| Command | Purpose |
|---|---|
| `vvaharness scan …` | Run the full pipeline against one repo or a batch. |
| `vvaharness remediate --repo <path>` | Walk a prior scan's findings and, in the default `fix` mode, apply a minimal fix per finding; `--mode report-only` only proposes. Writes DTOs under `<repo>/security-remediation/`. See [§2b](#2b-remediate--apply-or-propose-fixes). |
| `vvaharness validate --repo <path>` | Run S11: deterministically discover validatable remediation DTOs, then verify them with an agentic adversarial panel through the configured Harness backend. CLI/SDK routes use Claude Agent SDK; the default uses DeepAgents/Anthropic. (Alias: `s11`.) |
| `vvaharness setup [--install-agents] [--write-env]` | Readiness wizard; `--install-agents` drops agent instructions (AGENTS.md / CLAUDE.md + skill / copilot / GEMINI.md) for your installed AI agent; `--write-env` scaffolds `.env`. (Alias: `init`.) |
| `vvaharness doctor [--config <file>]` | Report credential/backend readiness and live-probe detection transports. The probe spends model tokens; for S10/S11 Agent-SDK routes it does not exercise the actual Harness launcher. |
| `vvaharness estimate --repo <path>` | Print a rough scope/cost preview (file count, bytes, ~input tokens). Spends nothing. |
| `vvaharness gc [--keep-runs N] [--max-age-days N] [--run <path>] [--dry-run]` | Prune old checkpoint runs from the SQLite state DB (defaults: keep 100 runs / 5 days). `--run <path>` instead fully evicts the single run for that repo path (its `run_id` is path-derived). |

A `.env` found from the current directory upward (the first match in the cwd or
any ancestor) is loaded automatically (variables you export yourself take
precedence), so no manual `source` step is required. The file actually loaded is
printed as a `[env] loaded …` line.

---

## 2. `scan` — flags

| Flag | Effect |
|---|---|
| `--repo <path>` | Scan a single local checkout. **Mutually exclusive** with `--repo-file`; one of the two is required. |
| `--repo-file <file>` | Batch mode. A `.csv` with header `AppId,RepoName[,Path]` (see [repos-csv.md](repos-csv.md)) or a `.txt` with one `application_id,repository_name,path` per line. Each entry is cloned/scanned in sequence with a fresh context. |
| `--config <file>` | Use a specific config YAML. Default: `./config.yaml` if present, else the packaged `default.yaml` profile. |
| `--repo-name <slug>` | Module / `repositoryName` tag for report filenames and SARIF `run.properties` (single-repo mode; defaults to the directory name). |
| `--application-id <id>` | Application / asset identifier — drives CMDB AppProfile lookup, VulContextSeverity environmental scoring, and SARIF `run.properties.applicationId`. |
| `--workspace <dir>` | Where remote repos are cloned in batch mode. Default `./batch-workspace`. |
| `--group-by-app` | Batch mode: clone every repo sharing an AppId under `<workspace>/<AppId>/` and run **one** scan over that directory (one report per application instead of one per repo). |
| `--keep-clones` | Don't delete cloned repos after scanning (batch mode). |
| `--resume` | Reuse on-disk checkpoints (SQLite state DB at `$VVAHARNESS_STATE_DIR/vvaharness.db`, default `~/.vvaharness/state/…`) instead of re-running completed stages. **Assumes the source is unchanged since the checkpointed run** — vvaharness does not detect code edits here. If the target changed, omit `--resume` (a fresh scan is clean) or run `vvaharness gc --run <path>` first to evict stale state. |
| `--stop-after <step>` | Stop after `clone`/`s0`/`s1`/…/`s11` (debugging). `clone` stops right after acquiring repos in batch mode and implies `--keep-clones`. `s0` stops after the static seed / callgraph stage. |
| `--remediate` | Run the Remediation Agent (s10) in fix mode after detection; successful sessions can edit target source and write DTOs under `<repo>/security-remediation/`. ORs with `step_remediate.enabled` (on by default). See [§2b](#2b-remediate--apply-or-propose-fixes). |
| `--top <N\|all\|*>` | With remediation: select only the N highest-CVSS findings (overrides `step_remediate.top_n_findings`; `all`/`*` selects every finding). |
| `--force` | Override safety refusals (currently the s10 git-SHA staleness check that guards remediating against a moved checkout). |
| `--skip-preflight` | Skip the startup credential/backend readiness probe. Does **not** bypass model/API authentication. |
| `--step1-config <file>` | Apply an explicit Step-1 overlay YAML (exclude_dirs/exts/globs, max_file_kb, config_dedup). Lists **append** to the config's `step1`. Mutually exclusive with `--auto-step1` (this wins). |
| `--auto-step1` | After clone, AI-survey each target to derive its Step-1 overlay; writes `$VVAHARNESS_STATE_DIR/checkpoints/<run_id>/step1.yaml` and applies it before s1. Ignored when `--step1-config` is given. Reused on `--resume`. **Also enabled via `step1.auto_exclude` in config — on by default in the shipped `default` profile** (flag and config OR together, like `--remediate`/`step_remediate.enabled`). To opt a run out, use a profile with `step1.auto_exclude: false`. |
| `--no-auto-step1` | Hard-disable AI auto-exclude for this run, **irrespective of `step1.auto_exclude` in the default/sdk/full profile**. Wins over `--auto-step1` and any config default (mutually exclusive with `--auto-step1`). Use this to say "no" from the command line without editing a profile. |

### Examples

> **Source-edit warning:** the shipped default continues past detection into
> S10 fix mode. If findings, credentials, and the remediation session are
> available, a plain `scan` can edit target source. Use `--stop-after s9` for
> detection only.

```bash
# Preview scope/cost (spends nothing)
vvaharness estimate --repo /path/to/target

# Detection-only scan of a local checkout
vvaharness scan --repo /path/to/target --application-id 12345 --stop-after s9

# Batch — clone + scan many repos, one report per AppId
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones
```

---

## 2a. `validate` — verify remediations

`vvaharness validate` scores remediations produced by the `remediate` command.
With the shipped `default` profile it runs **automatically as Step 11 of `scan`**;
it is also a standalone command you can run on its own. Its deterministic S11
discovery phase locates each finding's DTO under
`<repo>/security-remediation/<NN_slug>/remediate_report.json` (no model spend),
then the S11 agentic adversarial panel fills the
DTO's `validation` block and sets `status` to `validated` (fix passed),
`validation_failed` (fix did not pass; re-validatable), or `needs_review` (no
verdict produced). Re-runs are idempotent: only `validated` DTOs are skipped;
`validation_failed` and `needs_review` stay re-validatable, so a corrected patch
is re-driven on the next run with no manual DTO edit.

```bash
# vvaharness requires Python >=3.11 — no extra install needed
vvaharness validate --repo /path/to/target
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-remediation/` DTOs are validated. **Required.** |
| `--config <file>` | Config profile path; else `./config.yaml` if present, else the packaged `default.yaml`. |
| `--finding <id>` | Validate this finding id (repeatable); these exact ids only, no cap. |
| `--all` | Validate every finding in a validatable status (`awaiting_validation`, `needs_review`, or `validation_failed`), bypassing the `max_findings` cap. Terminal `validated` DTOs remain excluded. |
| `--max-findings <n>` | Cap to the top-N validatable findings by CVSS (`awaiting_validation`, `needs_review`, or `validation_failed`; overrides `step_validate.max_findings`). |
| `--workspace <path>` | Staging root for per-finding copies. **Ephemeral** — removed on completion; a non-empty path is refused. Default `<repo>/security-remediation/validation`. |
| `--resume` | Reuse a matching cached validation checkpoint for each selected validatable finding. Terminal `validated` DTOs are excluded by status whether or not this flag is present. |
| `--scan-report <file>` | Combined report (`.md`) to enrich with validation results; defaults to the newest report under `<repo>/security-remediation/`. |

The panel uses `security-architect` and `penetration-tester` personas, plus a
conditional `cross-repo-analyzer`, and scores each fix against weighted gates →
a Fixed / Partially Fixed / Not Fixed / UNVERIFIABLE verdict. It supports
`via: cli`, `via: sdk`, and `via: deepagents`; legacy `via: openai` is normalized
to DeepAgents with the OpenAI provider. Every validation route is read-only
against the repository, applies no patch, and runs no Docker.

**See [validation.md](validation.md)** for the full reference — gate weights,
verdict bands, per-persona model overrides, `step_validate` knobs, and the
trust model.

---

## 2b. `remediate` — apply or propose fixes

`vvaharness remediate` reads a prior scan's findings from
`<repo>/security-scan/` and walks them with the Remediation Agent (step 10),
running the configured `models.remediate` role per finding. For each finding it
writes a DTO under `<repo>/security-remediation/<NN_slug>/remediate_report.json`
(consumed later by `validate`). It is **on by default** for a scan
(`step_remediate.enabled: true`) and also runnable standalone.

```bash
# Standalone: remediate the findings of a completed scan
vvaharness remediate --repo /path/to/target

# Only the 10 highest-CVSS findings, interactive picker, report-only (no edits)
vvaharness remediate --repo /path/to/target --top 10 -i --mode report-only
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-scan/` findings are remediated. **Required.** |
| `--config <file>` | Config profile path; else `./config.yaml`, else packaged `default.yaml`. |
| `--mode fix\|report-only` | `fix` (default) applies minimal diffs through `via: cli`, `via: sdk`, or the repo-confined `via: deepagents` filesystem backend. Legacy direct `via: openai` has no edit tools and is report-only. `report-only` proposes without touching files. |
| `--top <N\|all\|*>` | Remediate only the N highest-CVSS findings (overrides `step_remediate.top_n_findings`; `all`/`*` does every finding). |
| `-i`, `--interactive` | Pick which findings to remediate from a menu. |
| `--resume` | Skip findings already remediated in a prior run. |
| `-v`, `--verbose` | Print the prompt + raw LLM response per finding. |

The fix-mode tool set is `Read/Glob/Grep/Edit/Write` (cwd-confined) — **Bash is
denied** so a prompt-injected agent can't reach a host shell.

**See [remediation.md](remediation.md)** for the full reference — modes, the
`step_remediate` knobs, the policy gate, and the kill-switch.

---

## 3. Pipeline stages

S0 is a configurable static seed stage controlled by `step0.enabled`. The
shipped `default.yaml` and `taint.yaml` profiles enable it; `sdk.yaml` and
`full.yaml` omit it.

| Step | Role | Output |
|---|---|---|
| s0 static seed *(profile-controlled)* | — in rules mode; `graph_annotate` in LLM mode | source/sink callgraph seed when usable specs exist; otherwise empty |
| s1 preprocess | `preprocess` (+ `autoexclude` for `--auto-step1`) | repo survey → `ContextPackage` |
| s2 threatmodel | `threatmodel` | assets, trust boundaries, ranked threats |
| s3 decompose | `decompose` | analysis chunks → `TaskManifest` |
| s4 deepdive | `deepdive` | per-chunk findings (×N runs + majority vote when enabled) |
| s5 prefilter | — (deterministic) | drops low-confidence / unproven findings |
| s6 verify | `verify` | adversarial TRUE/FALSE_POSITIVE verdict + CVSS per finding |
| s7 dedup | `dedup` | deterministic + semantic dedup → canonical findings |
| s8 chain | `chain` | exploit-chain analysis + re-ranking → `FinalReport` |
| s9 SARIF | — (deterministic) | parses the Markdown report → SARIF 2.1.0 |
| s10 remediate *(enabled in default/sdk/full)* | `remediate` | candidate fix, source edits in fix mode, remediation DTO |
| s11 validate *(enabled in default/sdk/full)* | `validate.orchestrator` + personas | read-only adversarial verdict written into the DTO |

### Taint evidence

When enabled S0 has usable external or LLM-derived specs, it can build
structured **taint evidence**—typed transfer edges that trace how tainted data
moves through source code. S1 still builds its own repository context and call
graph when S0 returns empty, but does not synthesize these S0 typed-transfer
records. S0 evidence is attached to findings so S4 and S6 can reason over
dataflow paths rather than reachability summaries. Base edge kinds
include `source`, `assign`, `arg_to_param`, `return_to_local`, `local_to_sink`,
`return_to_sink`, `field_write`, `field_read`, `container_put`, `container_get`,
`sanitize`, `reflect`, and `framework`. `condition` remains reserved in the
schema; the current scanner does not emit condition transfers or a branch CFG.

During such an S0 scan, framework sources are detected from annotations and
naming conventions already present in your source code—no vvaharness-specific
instrumentation is required:
- **Spring**: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader` on method parameters; `@GetMapping`/`@PostMapping` path variables; `ServletRequest`/`HttpServletRequest` parameter types
- **Django**: `request.GET`/`POST`/`META`/`FILES` accesses; view functions with a `request` parameter following Django naming conventions; `HttpResponse`/`JsonResponse` output sinks
- **ASP.NET**: `[FromQuery]`, `[FromRoute]`, `[FromBody]`, `[FromHeader]` on controller parameters; `[HttpGet]`/`[HttpPost]` route template variables; `Ok()`/`BadRequest()`/`Json()` response sinks

Response output sinks are identified as potential XSS risk. Paths where an explicit sanitizer neutralizes the flow are suppressed from findings — not surfaced as false positives. Languages: **Python, Java, C#**.

**Reflection APIs detected** (emits `reflect` edges with confidence scores):
- **Java:** `getMethod`, `getDeclaredMethod`, `getDeclaredField`, `getField`, `getDeclaredConstructor`, `getConstructor`, `forName`, `invoke`, `newInstance`, `MethodHandles.lookup()`
- **Python:** `getattr`, `setattr`, `__import__`, `importlib.import_module`, `vars`, `type`, `eval`, `exec`, `compile`
- **C#:** `GetMethod`, `GetMethods`, `GetConstructor`, `GetConstructors`, `GetType`, `Invoke`, `CreateDelegate`, `Activator.CreateInstance`, `Assembly.Load`, `Assembly.LoadFrom`, `Assembly.LoadFile`, `Type.InvokeMember`

Each step checkpoints to the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`;
`run_id` is derived from the absolute target path); `--resume` skips
completed steps. A scan **without** `--resume` clears that run's prior
checkpoints first, so a fresh scan never inherits stale state. `--resume`
**trusts that the source is unchanged** since the checkpointed run — it does
**not** detect code edits, so resume only after a clean/aborted run on the same
code; if the code changed, omit `--resume` or run `vvaharness gc --run <path>`
to evict the run. Run `vvaharness gc` to prune old runs. See
[architecture.md](architecture.md) for the data flow and
[models.md](models.md) for how roles map to backends.

---

## 4. Backends

Each model role picks its own `{id, via}` in `config.yaml: models`:

| `via:` | Transport | Auth | Tools |
|---|---|---|---|
| `cli` *(default profile)* | `claude` CLI subprocess | run `claude` then `/login` (or `CLAUDE_CODE_OAUTH_TOKEN` via `claude setup-token`) | Read/Glob/Grep (the only backend that *can* also run **Bash** — but no shipped profile grants it; add `- Bash` to a role's `allowed_tools` to enable) |
| `codex` | `codex exec` subprocess | `codex login` (native ChatGPT or API-key login cached by Codex) | Ephemeral read-only S0–S9 repository inspection; no Bash/Edit/Write |
| `sdk` | Anthropic Python SDK | `ANTHROPIC_SDK_API_KEY` | Read/Glob/Grep (sandboxed) — honours `temperature`, `max_turns` |
| `openai` | OpenAI-compatible API | `OPENAI_API_KEY` | Read/Glob/Grep (sandboxed) |
| `deepagents` | DeepAgents/LangGraph provider harness | Anthropic: `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`; OpenAI: `OPENAI_API_KEY` | S10/S11 only; repo-confined writes in S10 fix mode, read-only in S11; Bash denied |

The `cli`/`sdk` rows describe the detection dispatcher. In S11, both selectors
use the read-only Claude Agent SDK Harness. In S10, `via: cli` remains the
direct CLI route, while `via: sdk` fix mode delegates Edit/Write to the Claude
Agent SDK.

### Shipped profiles & how to switch (modes)

Five ready profiles live in `vvaharness/config/profiles/`. Run
`vvaharness setup`—its recommendation is a starting point based on detected
credentials, not a guarantee that every post-scan role is ready. Re-run setup
with the selected profile and resolve its warnings. Select a profile per run
with `--config`; with no flag, a `./config.yaml`
in the working dir wins, else the packaged `default.yaml`.

| Profile | Backend(s) | Use when… | Run |
|---|---|---|---|
| `default.yaml` | local S0; S1–S9 `via: cli`; S10/S11 `via: deepagents` (Anthropic) | you have Claude Code auth for S1–S9 plus `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` for S10/S11. The built-in default. | *(no flag)* |
| `codex.yaml` | S0–S9 `via: codex`; S10/S11 disabled | you have a native Codex/ChatGPT login from `codex login`; no `OPENAI_API_KEY` needed | `--config vvaharness/config/profiles/codex.yaml` |
| `sdk.yaml` | every role spelled `via: sdk`: Anthropic Python SDK for detection; Claude Agent SDK paths for S10 fix/S11; no Bash | you want s4 majority voting. `ANTHROPIC_SDK_API_KEY` covers S1–S10; S11 pins external `claude` and uses Claude login/OAuth or standard Anthropic auth. One standard credential can cover all stages via the sole-SDK fallback. | `--config vvaharness/config/profiles/sdk.yaml` |
| `full.yaml` | mixed `cli`+`sdk`+`openai` | complete run: Claude CLI auth (also usable by S11), `ANTHROPIC_SDK_API_KEY` for SDK detection/S10, and `OPENAI_API_KEY`; standard Anthropic auth is an S11 alternative | `--config vvaharness/config/profiles/full.yaml` |
| `taint.yaml` | S0 wrapper + S1–S9 `via: cli`; S10/S11 disabled | you want taint-first source→sink scanning; Claude Code login covers model stages, while shipped rules mode needs operator-supplied generated rule files for an S0 seed. | `--config vvaharness/config/profiles/taint.yaml` |

> **S0 rules note:** rules mode has no implicit source/sink baseline. It needs
> usable external source/sink rule files, such as files generated by
> `build_kb.py`, to produce a seed. No such generated files are shipped; without
> them S0 returns an empty seed and S1 continues. See
> [SETUP_GUIDE.md → Optional external source/sink rule files](SETUP_GUIDE.md#optional-external-sourcesink-rule-files-s0)
> for copy-paste build commands and
> [vvaharness/rules/README.md](../vvaharness/rules/README.md)
> for corpus/artifact workflow details.

To pin your own choice, copy a profile to `./config.yaml` and edit it:
```bash
cp vvaharness/config/profiles/sdk.yaml ./config.yaml   # then `vvaharness scan` uses it automatically
```

For the full walkthrough — config resolution order, `config.local.yaml`
overrides, secrets in `.env`, and every tunable knob — see
[configuration.md → Setting up your config](configuration.md#setting-up-your-config).

### Setting / changing the models

Edit the `models:` block of your config. Detection roles and `remediate` use a
flat `{id, via}` node. Validation is nested under `models.validate`, with an
`orchestrator` node and optional persona model overrides. **Note:** validation
runs on `via: cli`, `via: sdk`, or `via: deepagents`; a
legacy `via: openai` validate role is routed to `via: deepagents` with the OpenAI
provider, so it runs and needs `OPENAI_API_KEY`. Remediation fix mode supports
`via: cli`, `via: sdk`, and repo-confined `via: deepagents`; legacy direct
`via: openai` is limited to `--mode report-only`.
```yaml
models:
  deepdive:   {id: claude-opus-4-8,  via: sdk}     # SDK on a public Opus
  verify:     {id: claude-sonnet-4-6, via: cli}    # ← flip one role to the CLI
  threatmodel: {id: gpt-4o,          via: openai}  # ← or to OpenAI
  chain:       {id: gpt-5.6-terra,      via: codex}   # ← native Codex login
  # …autoexclude, preprocess, decompose, dedup, chain…
  validate:
    orchestrator: {id: gpt-5.5, via: deepagents, provider: openai}
```
- `id` is whatever your endpoint accepts (a public id, a dated id, or a CLI
  alias like `sonnet`/`opus`).
- After editing, run `vvaharness doctor --config <file>`. It probes the unique
  detection transports, but currently substitutes a raw-SDK probe for
  SDK-spelled S10/S11 and can false-green S11; verify external `claude` and
  either Claude login/OAuth or standard Anthropic auth separately.

### Internal gateway (if your key is a Claude-Code/JWT token)
Set the endpoint in your shell or `.env` (NOT in source). `setup` auto-detects
and prints these lines when the active profile uses a `via: sdk` role (for
shipped profiles, `sdk.yaml`/`full.yaml`). The shipped default profile has no
`via: sdk` roles (`via: cli` for S1-S9 and `via: deepagents` for S10-S11), so
set these variables explicitly when your gateway token requires them:
```bash
export ANTHROPIC_BASE_URL=https://<your-gateway>/
export NODE_EXTRA_CA_CERTS=$HOME/cacerts.pem   # only if a private CA
export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1 # if the gateway rejects beta flags (HTTP 400)
```

**TLS / private gateways.** CLI, SDK, and direct OpenAI adapters carry an
optional `verify_ssl` / `ca_cert` block in the profile—including a `cli:` block whose CA bundle
(`${CLAUDE_CLI_CA_CERT}`) is propagated into the direct adapter's `claude`
subprocess. Use absolute certificate paths; a relative value is passed through
as-is and resolves against the process's current working directory, not
`.env` or the selected config's directory. Every TLS
setting is **optional**: with only an API key set, the public official endpoint
is used and **no certificate is required**. A CA bundle is needed only behind a
private gateway or a TLS-intercepting proxy whose cert chains to an internal CA.
Mutual TLS (mTLS client certs) is supported only on the direct Anthropic SDK
detection transport, not Agent-SDK S10/S11, `via: cli`, or `via: openai`.
DeepAgents uses provider base URLs and standard process trust variables instead
of those profile blocks. See **[SETUP_GUIDE.md](SETUP_GUIDE.md)** for the full
when-is-a-cert-needed matrix and env-var names.

**Pinning the `claude` executable (shared/CI hosts).** Direct `via: cli` roles
and S11 validation configured as either `via: cli` or `via: sdk` launch the
external `claude` CLI;
by default it is resolved to an
absolute path via `PATH`. On a shared or CI host where `PATH` may include a
directory another user can write, set **`VVAHARNESS_CLAUDE_BINARY=/abs/path/to/claude`**
to pin the exact executable and bypass `PATH` resolution entirely (prevents a
planted `claude` from running under the harness with your credentials).

### Environment variables

Backend **credentials and endpoints** (`ANTHROPIC_SDK_API_KEY`,
`ANTHROPIC_SDK_BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
`OPENAI_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`,
`ANTHROPIC_BASE_URL`, `NODE_EXTRA_CA_CERTS`, …) go in `.env` — see
[`configuration.md`](configuration.md) and [`SETUP_GUIDE.md`](SETUP_GUIDE.md).
The harness-specific `VVAHARNESS_*` knobs are:

| Variable | Default | Effect |
|---|---|---|
| `VVAHARNESS_STATE_DIR` | `~/.vvaharness/state` | Root for the SQLite state DB (`vvaharness.db`), checkpoints, and the batch staging area. Reports under `<repo>/security-scan/` are unaffected. |
| `VVAHARNESS_DEBUG` | unset | On a fatal scan error, print the full Python traceback to stderr (otherwise a one-line redacted message + a pointer to `*_errors.jsonl`). Set to any value. |
| `VVAHARNESS_JSON_LOGS` | unset | Emit structured JSON stage events (`stage_start`/`stage_ok`/`stage_fail`) instead of the `▶`/`✓`/`✗` lines. Accepts `1`/`true`/`yes`. |
| `VVAHARNESS_SCAN_PROGRESS_ENABLED` | unset | Force-enable scan observability (`scan_progress.enabled=true`) even if the active profile disables it. Accepts `1`/`true`/`yes`. |
| `VVAHARNESS_CLAUDE_BINARY` | `claude` (on `PATH`) | Absolute path to the `claude` executable, bypassing `PATH` (see *Pinning the `claude` executable* above). |
| `VVAHARNESS_ALLOW_CWD_CONFIG` | unset (gate active) | Opt out of the trust gate that refuses a `--config` / `.env` located **inside the scan target** (which otherwise falls back to the packaged default / is ignored). Set only for a target you trust. |
| `VVAHARNESS_NO_LOCAL_CONFIG` | unset (overlay applied) | Skip the `config.local.yaml` overlay for a reproducible run that honours **only** the selected config. |
| `VVAHARNESS_REMEDIATE_DISABLE` | unset | Kill-switch for autonomous remediation: when truthy (`1`/`true`/`yes`/`on`), the remediation gate returns guidance-only for **every** finding (active when `step_remediate.enforce_policy: true`; a `./.vvaharness-remediate-off` file is an equivalent sentinel). See [`remediation.md`](remediation.md). |

> The `validate`/`s11` subsystem also reads a family of overrides
> (`VVAHARNESS_MODEL`, `VVAHARNESS_EFFORT`, `VVAHARNESS_VIA`, `VVAHARNESS_MAX_TURNS`,
> `VVAHARNESS_MAX_BUDGET_USD`, `VVAHARNESS_MAX_FINDINGS`, `VVAHARNESS_VALIDATE_TOOLS`,
> and the per-persona `VVAHARNESS_{SECURITY_ARCHITECT,PENETRATION_TESTER,CROSS_REPO_ANALYZER}_MODEL`).
> **Don't set these by hand** — the validation CLI exports them automatically from
> your profile's `models.validate` / `step_validate` block. Tune the profile, not
> the environment.

---

## 5. Output

Per target, under `<target>/security-scan/`:

| File | Contents |
|---|---|
| `<module>_<ts>_report.md` | findings + dropped-findings appendix |
| `<module>_<ts>_report.sarif` | SARIF 2.1.0 for tooling ingestion |
| `<module>_<ts>_errors.jsonl` | non-fatal errors; absent on a clean run |

The `validate` command writes per-DTO under
`<repo>/security-remediation/<NN_slug>/`: the `validation` block is merged back
into `remediate_report.json` (with `status` set to
`validated`/`validation_failed`/`needs_review`). When a source session log is
available and redaction/persistence succeeds, a redacted
`validation_session_<finding>.jsonl` transcript is also retained; this audit
artifact is best-effort. The agent's
`validation_report.json` and `synthesized_gates.json` are written into an
ephemeral staging workspace, consumed for host-side scoring, and removed on
completion — they are **not** persisted under the DTO folder.

Batch scans also write `<workspace>/batch_summary.md`. Every **scan** writes
`run_manifest.json` in the current working directory (tool version, detection
model roles, config/overlay hashes, target git SHA, arguments, outcome, timing)
so each scan is auditable. See [outputs.md](outputs.md) for the
full report/SARIF anatomy.

### Progress & logs
On an interactive terminal each executed stage shows a **live spinner** with
elapsed time, replaced by a green `✓` + duration when it finishes (`✗` on
failure). The current counter uses stage numbers rather than one-based slots:
a full S0–S11 run passes `n=0..11`, `total=11`, so completed lines range from
`[0/11]` through `[11/11]`. On CI / non-TTY
the tool prints plain `▶`/`✓`/`✗` lines. For
machine-readable output set **`VVAHARNESS_JSON_LOGS=1`** — each stage then emits
a structured JSON event (`stage_start` / `stage_ok` / `stage_fail` with timing)
instead, alongside the existing JSON artifacts (`run_manifest.json`,
`*_errors.jsonl`, SARIF).

### Observability
`scan_progress` is the file/chunk-level observability stream. It is enabled in
`compact` mode by `default.yaml`, `verbose` by `taint.yaml`, and disabled by
`sdk.yaml` / `full.yaml` unless overridden.

Enable it in either way:

1. Config profile:
```yaml
scan_progress:
  enabled: true
  style: verbose   # compact | verbose | summary_only
```

2. Environment override:
```bash
VVAHARNESS_SCAN_PROGRESS_ENABLED=1 vvaharness scan --repo /path/to/target
```

When observability is enabled, progress starts at the first detection stage and
prints stage events for all scan stages (`s0`–`s9`):

- `default.yaml` and `taint.yaml`: S0 runs; a resumed S0 can report `cached`.
- `sdk.yaml` and `full.yaml`: the fresh S0 wrapper completes with an empty seed;
  normal stage events then continue through S1–S9.

You will see lines such as:

```text
[progress] stage-start s0   callgraph
[progress] stage-done  s0   outcome=completed  0.9s
[progress] stage-start s1   preprocess
[progress] discovered    247 files  (repo: my-service)
[progress] queued      chunk-01 ...
[progress] scanning    chunk-01 ...
[progress] scanned     chunk-01 ... outcome=completed findings=2
```

`style: verbose` prints file-by-file lines (`discovered`, `queued`, `scanning`,
`scanned`) plus stage milestones (`stage-start`, `stage-note`, `stage-done`).

### Save verbose output to a log file

#### Linux / macOS (`bash` / `zsh`)

To save terminal output while still seeing it live, pipe both stdout and stderr
to `tee`:

```bash
mkdir -p logs
set -o pipefail
VVAHARNESS_SCAN_PROGRESS_ENABLED=1 vvaharness scan --repo /path/to/target 2>&1 \
  | tee logs/scan-$(date +%Y%m%d-%H%M%S).log
```

- `2>&1` captures stderr (where progress/stage lines are printed).
- `set -o pipefail` preserves scan failure as the shell exit code when piping.

Append to an existing log instead of creating a new one:

```bash
VVAHARNESS_SCAN_PROGRESS_ENABLED=1 vvaharness scan --repo /path/to/target 2>&1 \
  | tee -a logs/scan-latest.log
```

If you want a full terminal transcript (including TTY spinner rendering), use
`script`:

```bash
mkdir -p logs
script -q logs/scan-terminal-$(date +%Y%m%d-%H%M%S).log \
  vvaharness scan --repo /path/to/target
```

#### Windows (PowerShell)

Create a timestamped log while streaming output live:

```powershell
New-Item -ItemType Directory -Force -Path logs | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
vvaharness scan --repo C:\path\to\target 2>&1 |
  Tee-Object -FilePath "logs/scan-$ts.log"
exit $LASTEXITCODE
```

Append to a rolling log:

```powershell
vvaharness scan --repo C:\path\to\target 2>&1 |
  Tee-Object -FilePath "logs/scan-latest.log" -Append
exit $LASTEXITCODE
```

Full terminal transcript (Windows equivalent of `script`):

```powershell
New-Item -ItemType Directory -Force -Path logs | Out-Null
Start-Transcript -Path "logs/scan-terminal-$((Get-Date).ToString('yyyyMMdd-HHmmss')).log"
vvaharness scan --repo C:\path\to\target
Stop-Transcript
exit $LASTEXITCODE
```

---

## 6. Limitations (important)

- **Non-deterministic & LLM-judged.** Treat findings as leads to verify, not
  ground truth. Majority-vote false-positive filtering only engages on `via: sdk` or
  `via: openai` deep-dive models whose runs actually diverge (a model that
  accepts `temperature`); the `via: cli` backend has no temperature control and
  SDK models that reject it run single-pass, and the deterministic s5 pre-filter is the main FP defence.
- **Severity is derived from the CVSS base-score band, not judged separately.**
  Findings are labelled Critical / High / Medium / Low / Info. The four scored
  tiers come straight from the CVSS 3.1 qualitative band — Critical (9.0–10.0),
  High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9) — so the label can never
  disagree with the reported vector, while Info covers findings with no
  demonstrated exploit path. The base score (0–10) and full vector are reported
  verbatim on each finding.
- **Token-hungry.** There is no global spend cap. Compatible Claude CLI and
  Claude Agent SDK paths can enforce per-session `max_budget_usd`; raw SDK,
  OpenAI, and DeepAgents paths ignore it. Use `vvaharness estimate` before a
  scan and treat token accounting as reporting, not enforcement.
- **Validation accepts `via: openai` by routing it; remediation _fix mode_ does
  not.** A `via: openai` validate role is routed to `via: deepagents` with the
  OpenAI provider, so it runs. Remediation _fix mode_ needs the `Edit`/`Write`
  tools that only the `via: cli`, `via: sdk`, and repo-confined `via: deepagents`
  backends expose — under `via: openai` it can only run `--mode report-only`.
  Detection (S1–S9) and report-only remediation run on any backend.
- **Missing post-scan credentials are a warning, not a fatal error.** If
  `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is absent but only required by S10
  (remediate) or S11 (validate), preflight emits a `WARN` and skips that stage —
  S1–S9 detection still runs and produces findings. Missing credentials for any
  detection role (S1–S9) remain fatal and abort the scan before spending tokens.
- **`via: deepagents` is only valid for `models.remediate` and `models.validate`.**
  Configuring it for any S1–S9 detection role causes an immediate exit before
  any tokens are spent. Use `via: cli`, `via: sdk`, or `via: openai` for
  detection roles.
- **Validation is capped unless explicitly uncapped.** In-scan and standalone
  validation apply `step_validate.max_findings` by default. Standalone
  `vvaharness validate --all` bypasses the cap for every validatable DTO;
  already-`validated` DTOs remain excluded.
- **Elevated privilege; trusted targets only.** vvaharness assumes an authorized
  operator running against a repository they trust. Scanning untrusted or
  malicious code can expose host credentials, files, or other risk. If you must
  scan a less-trusted or sensitive target, apply the compensating controls in
  [`security.md` → Hardening for less-trusted or sensitive targets](security.md#hardening-for-less-trusted-or-sensitive-targets).
- **No published accuracy numbers yet.** Precision/recall figures are not yet published.
- **No rules-mode S0 corpus is bundled.** `default.yaml` and `taint.yaml` enable
  the wrapper, but rules mode returns an empty seed without operator-supplied
  generated source/sink files; later stages still run.
- **Structured S0 taint evidence, when usable specs exist, is Python, Java, and C# only.** JavaScript,
  TypeScript, and Go use reachability-only S0 paths without typed transfer
  edges, sanitizer neutralization, framework-source detection, or reflection
  tracking. Languages without an S0 plugin, including Rust, receive no static
  seed; later LLM stages still run.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `command not found: vvaharness` | use `pipx install .`, or run `python3 -m vvaharness …` |
| `ANTHROPIC_SDK_API_KEY not set` | put it in `.env` (auto-loaded) or export it; re-run `vvaharness doctor` |
| `claude` CLI not found / not logged in | install the Claude Code CLI, then run `claude` and use `/login` (or `claude setup-token`) |
| Scan too slow / costly on a huge repo | add exclusions in the config `step1` section or use `--auto-step1` |
| Re-run only later stages | `--resume` (reuses checkpoints in `$VVAHARNESS_STATE_DIR/vvaharness.db`) |

See the other guides in this folder for [configuration](configuration.md),
[models](models.md), [outputs](outputs.md), and [batch-CSV](repos-csv.md) details.
