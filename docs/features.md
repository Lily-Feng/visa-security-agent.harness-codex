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

# Features & Combinations

A single reference for **everything you can combine** when running
`vvaharness`, and **how config lets the team mix and match models per stage
without touching code**.

```
s0 static seed → s1 preprocess → s2 threatmodel → s3 decompose → s4 deepdive
              → s5 prefilter   → s6 verify     → s7 dedup → s8 chain → s9 SARIF
```

The standalone `vvaharness validate` command runs separately (s11 agentic
panel — which first discovers the DTOs awaiting validation, then runs the
panel) over the remediation DTOs written by the `remediate` command (Step 10) — see [§2](#2-pipeline-stages) and [§6](#6-commands--run-time-options).

The core idea: **every LLM stage is a config switch.** Each role picks its own
`{id, via}` in `config.yaml: models`, and the dispatcher (`backends/llm.py`)
routes on `via:`. **Swapping a role is config-only — no code change.**

---

## 1. The two axes you combine

A run is defined by combining choices on two axes:

1. **Per-role backend** (`via:`) — `cli`, `sdk`, or `openai`, chosen
   independently for each detection LLM role. S10/S11 additionally support
   `deepagents`; legacy `via: openai` validation is normalized to
   DeepAgents/OpenAI.
2. **Per-stage tuning** (`step1:`…`step4:`, `step5_prefilter:`,
   `step6_verify:`, `step7_dedup:`, `step8:`, `step_remediate:`,
   `step_validate:`, `inject:`, `batch:`, `output:`) — cost / depth / precision knobs, plus CLI flags at
   runtime.

---

## 2. Pipeline stages

| Step | Role | Backend? | Output |
|---|---|---|---|
| s0 static seed | — in rules mode; optional `graph_annotate` in LLM mode | local AST over external rules by default | source/sink callgraph seed when usable specs exist; enabled but empty without rules in default/taint |
| auto-step1 | `autoexclude` | yes | AI-derived Step-1 exclusion overlay (`--auto-step1`) |
| s1 preprocess | `preprocess` | yes (agentic) | repo survey + call graph → `ContextPackage` |
| s2 threatmodel | `threatmodel` | yes | assets, trust boundaries, ranked threats |
| s3 decompose | `decompose` | yes | risk / taint / specialist chunks → `TaskManifest` |
| s4 deepdive | `deepdive` | yes | per-chunk findings (single pass by default; ×N runs + majority vote when enabled) |
| s5 prefilter | (`dedup`) | **deterministic gates** | drops low-confidence / unproven findings; runs one optional semantic pre-dedup call (the `dedup` role) when survivors ≥ `step7_dedup.pre_verify_threshold` (default 25) and `step7_dedup.semantic` is on |
| s6 verify | `verify` | yes (agentic) | adversarial TRUE / FALSE_POSITIVE + CVSS per finding |
| s7 dedup | `dedup` | yes | deterministic + semantic dedup → canonical findings |
| s8 chain | `chain` | yes | exploit-chain analysis + re-rank → `FinalReport` |
| s9 SARIF | — | **deterministic** | parses the Markdown report → SARIF 2.1.0 |

Each `scan` stage checkpoints to the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`);
`--resume` skips completed stages. `s9` uses no model. `s5`'s gates are
deterministic, but it also fires one optional semantic pre-dedup call (the
`dedup` role) when the survivor count reaches `step7_dedup.pre_verify_threshold`.

The standalone **`vvaharness validate`** command runs two phases of the s11 stage
over the remediation DTOs the `remediate` command writes: a **discover** phase
(deterministic, no model spend — locates DTOs awaiting validation) and an **s11
panel** phase (agentic adversarial panel: two always-on personas
`security-architect` + `penetration-tester`, plus a conditional
`cross-repo-analyzer` spawned only when a fix spans 2+ repositories) that fills
each DTO's `validation` block. The default runtime is `via: deepagents`
(set in `default.yaml`); `cli` and `sdk` backends run the bundled Claude Agent
SDK instead. `models.validate` resolves to `via: cli`, `via: sdk`, or
`via: deepagents`; a legacy `via: openai` value is routed to `via: deepagents` with
the OpenAI provider before any model spend, so the spelling that detection and
report-only remediation accept also works for validation.

These same two stages also run automatically at the **end of a `scan`** —
Step 10 (remediate) then Step 11 (validate) — when `step_remediate.enabled` /
`step_validate.enabled` are set. All shipped profiles default both to `true`
except `taint.yaml`, which ships them disabled (`step_remediate.enabled: false`,
`step_validate.enabled: false`). Run the standalone command to re-validate (or
validate findings remediated out of band) on its own.

---

## 3. Backends (`via:`)

| `via:` | Transport | Auth | Tools | Honours | TLS / mTLS |
|---|---|---|---|---|---|
| `cli` *(default profile)* | `claude` CLI subprocess | run `claude` → `/login`, or `CLAUDE_CODE_OAUTH_TOKEN` | allowlisted Read · Glob · Grep; **Bash** capable only when explicitly listed | capability-gated `max_budget_usd`, `effort`, `max_turns` | `ca_cert` → `NODE_EXTRA_CA_CERTS`; **no mTLS** |
| `sdk` | Anthropic Python SDK (detection) | `ANTHROPIC_SDK_API_KEY` | Read · Glob · Grep *(sandboxed, no Bash)* | `temperature`, `thinking_budget`, `betas`, `max_turns` | direct detection only: `ca_cert` + **`client_cert` (mTLS)** |
| `openai` | OpenAI-compatible Chat Completions | `OPENAI_API_KEY` (+ `OPENAI_BASE_URL`) | Read · Glob · Grep *(sandboxed, no Bash)* | `temperature`, `max_turns` | `ca_cert`; no mTLS |
| `deepagents` *(S10/S11 only)* | DeepAgents/LangGraph provider harness | Anthropic: `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`; OpenAI: `OPENAI_API_KEY` | S10 repo-confined Read/Glob/Grep/Edit/Write; S11 read-only agents | `max_turns`, structured output | provider/process trust; no profile `verify_ssl` block |

Every **detection** role runs on `cli`, `sdk`, or `openai`; `deepagents` is
restricted to `remediate` and `validate`. Bash is CLI-exclusive and no shipped
profile grants it. For S11, `cli` and `sdk` both select the read-only Claude
Agent SDK Harness. S10 `via: sdk` delegates fix-mode Edit/Write to the Agent
SDK; S10 `via: cli` remains the direct CLI route. A bare-string model id
defaults to `via: cli`.

### Combination rules that actually matter

| Rule | Why |
|---|---|
| **Bash** is available only in agentic stages (`preprocess`, `verify`) when that role is `via: cli`. | Only the CLI backend exposes Bash; re-add `- Bash` to `allowed_tools` when you switch. |
| **s4 repeated-run voting** (`step4.runs > 1`) is supported on `via: sdk` and `via: openai`. | Runs auto-collapse to one on `via: cli` and on known temperature-rejecting **`via: sdk`** models. OpenAI is not auto-collapsed if an endpoint rejects/drops `temperature`, so N runs may provide no useful diversity; the s5 prefilter is the main FP defence when voting is ineffective. |
| **mTLS** (`client_cert`) is exposed only by the direct Anthropic SDK detection transport. | Direct CLI/OpenAI and the Agent-SDK S10/S11 paths do not consume a client cert; configure post-scan routes separately for an mTLS-gated environment. |
| **`cli` ignores** `temperature`; budget, effort, and turn flags are capability-gated. | `--max-budget-usd`, `--effort`, and `--max-turns` are each forwarded only when the installed binary advertises that flag. The subprocess timeout remains the fallback bound. |
| **`cli` agentic stages** drive the CLI with `--output-format stream-json --verbose`. | Recent Claude CLI builds reject `--print` + `stream-json` without `--verbose`; the pairing is mandatory and emitted unconditionally. Requires a `claude` build that accepts `--verbose` with stream-json (every supported 2.x does). |
| `sdk` / `openai` auto-drop and retry params the model rejects. | Lets you mix model generations without config churn. |

---

## 4. How config helps the team — recipe profiles

The `models:` block is where the team encodes its trade-offs. Six common
shapes:

### 4.1 Quick start — Claude Code login (the shipped `default.yaml`)

`default.yaml` is mixed-backend: S1–S9 run on the `claude` CLI (`via: cli`),
S10 remediation runs on `via: deepagents` with Anthropic, and S11 validation
runs on `via: deepagents` with OpenAI. In `sdk.yaml`, every configured role is
spelled `via: sdk`: detection uses the Anthropic Python SDK, S10 translates the
  SDK-named key for its Claude Agent SDK path, and S11 uses that Harness but pins
  an external `claude` executable. S11 uses ambient Claude login/OAuth or
  standard `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`; the SDK-named key alone
  is not translated. A standard credential can cover the profile through the
  sole-SDK fallback.
S4 majority voting is enabled.
The default also enables the local S0 wrapper; sdk/full omit S0, while taint
enables it. No source/sink pack is bundled, so shipped rules mode is empty
unless the operator supplies generated rule files.

For source→sink callgraph scanning, use the shipped `taint.yaml` profile and
supply generated rule files, or switch a profile copy to LLM annotation mode
(`--config vvaharness/config/profiles/taint.yaml`).

```yaml
models:
  autoexclude: {id: claude-sonnet-4-6, via: cli}
  preprocess:  {id: claude-sonnet-4-6, via: cli}
  threatmodel: {id: claude-sonnet-4-6, via: cli}
  decompose:   {id: claude-sonnet-4-6, via: cli}
  deepdive:    {id: claude-sonnet-4-6, via: cli}
  verify:      {id: claude-sonnet-4-6, via: cli}
  dedup:       {id: claude-sonnet-4-6, via: cli}
  chain:       {id: claude-sonnet-4-6, via: cli}
```

### 4.2 Multi-backend — the example `full.yaml`

Mix vendors per role: reasoning/voting on the Anthropic SDK, exploration/Bash on
the CLI, threat-model/decompose/verify on an OpenAI-compatible endpoint.
A complete run needs Claude CLI auth, `ANTHROPIC_SDK_API_KEY` for SDK
detection/S10, and `OPENAI_API_KEY` for OpenAI roles. The SDK-spelled S11 pins
external `claude` and can reuse that Claude login/OAuth; standard Anthropic
auth is an alternative.

```yaml
models:
  autoexclude: {id: claude-opus-4-8, via: cli}
  preprocess:  {id: claude-opus-4-8, via: sdk}
  threatmodel: {id: gpt-5.5,         via: openai}
  decompose:   {id: gpt-5.5,         via: openai}
  deepdive:    {id: claude-sonnet-4-6, via: sdk, temperature: 0.4}  # T0.4 → s4 voting on
  verify:      {id: gpt-5.5,         via: openai}
  dedup:       {id: claude-opus-4-8, via: sdk}
  chain:       {id: claude-opus-4-8, via: cli}
```

### 4.3 Other shapes

| Recipe | Shape | Unlocks / trade-off |
|---|---|---|
| **Max precision (voting)** | shipped on in `sdk.yaml` (deepdive `temperature: 0.4`, `step4.runs: 3`, `vote_threshold: 2`); raise toward `temperature: 1.0` / `runs: 4` / `vote_threshold: 3` for more | Majority-vote FP filtering; higher cost. Forced to single-pass on `via: cli` or a temp-rejecting Anthropic SDK model. An OpenAI-compatible endpoint that drops `temperature` still receives all configured runs, which may provide no useful diversity. |
| **Bash-powered recon** | `preprocess` + `verify` → `cli` (add `- Bash`), rest `sdk` | Shell-based repo inventory & evidence retrieval. |
| **Detection behind mTLS** | SDK detection roles with `ca_cert` + `client_cert`; stop after S9 or configure post-scan routes separately | Direct Anthropic SDK detection can reach an mTLS gateway; Agent-SDK S10/S11 do not consume those cert settings. |
| **Cost-lean detection** | detection roles on `openai`; stop after S9 or explicitly configure supported post-scan roles | Lower-cost compatible endpoint; no Bash. S4 voting still requires a temperature-capable model. |

**To use any of these:** copy the nearest shipped profile to `./config.yaml`,
edit the relevant block, then run `vvaharness doctor`. It live-probes detection
transports, but currently does not exercise the actual S10/S11 Claude Agent SDK
Harness launcher, so verify its external-CLI and standard-auth requirements too.

---

## 5. Credentials per combination

Which credentials a run needs is the **union of the backends any role uses**:

| If any role is… | You need |
|---|---|
| `via: sdk` | Detection uses `ANTHROPIC_SDK_API_KEY` (or the standard Anthropic credential fallback when SDK is the only backend); S10 translates the SDK key/base URL, while S11 pins external `claude` and uses Claude login/OAuth or standard Anthropic auth. SDK CA/mTLS vars apply only to direct detection. |
| `via: openai` | `OPENAI_API_KEY` (+ optional `OPENAI_BASE_URL`, `OPENAI_CA_CERT`) |
| `via: cli` | Claude CLI logged in — run `claude` → `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN` (+ optional `CLAUDE_CLI_CA_CERT`) |
| `via: deepagents`, Anthropic provider | `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` (+ optional `ANTHROPIC_BASE_URL`) |
| `via: deepagents`, OpenAI provider | `OPENAI_API_KEY` (+ optional `OPENAI_BASE_URL`) |

All TLS keys are optional: with just an API key the public endpoint is used and
no certificate is required. Certificate env values should be absolute paths;
a relative path is used as-is and resolves against the process's current
working directory, not the selected config's directory. See
[SETUP_GUIDE.md](SETUP_GUIDE.md) for the full when-is-a-cert-needed matrix.

---

## 6. Commands & run-time options

| Command | Purpose |
|---|---|
| `vvaharness setup` | Guided readiness check (Python/git, AI agents, keys, gateway, config); read-only unless `--write-env`, optional `--install-agents`. (Alias: `init`.) |
| `vvaharness scan …` | Run the full pipeline against one repo or a batch. |
| `vvaharness remediate --repo <path>` | Walk a prior scan's findings and propose a minimal fix per finding (Remediation Agent, s10). On by default in a scan. |
| `vvaharness validate --repo <path>` | Run S11: deterministically discover validatable remediation DTOs, then run the read-only agentic panel on the configured Harness backend. On by default in default/sdk/full. (Alias: `s11`.) |
| `vvaharness doctor [--config <file>]` | Report readiness and live-probe detection transports; it does not exercise the actual S10/S11 Agent-SDK Harness launcher. |
| `vvaharness estimate --repo <path>` | Print a rough scope/cost preview. Spends nothing. |
| `vvaharness gc […]` | Prune old checkpoint runs (`--keep-runs` / `--max-age-days` / `--dry-run`). |

| Flag | Effect |
|---|---|
| `--repo` / `--repo-file` | Single local checkout, or batch CSV/TXT (clone + scan each). One required, mutually exclusive. |
| `--config <file>` | Use a specific config YAML (default `./config.yaml`, else packaged `default.yaml`). |
| `--repo-name <name>` | Module / repository name used for report + SARIF filenames and the report title (single-repo mode only; default: target dir name). |
| `--application-id <id>` | Drives CMDB AppProfile lookup, VulContextSeverity scoring, SARIF `applicationId`. |
| `--group-by-app` | Batch: clone every repo sharing an AppId under one dir → one report per application. |
| `--resume` | Reuse on-disk checkpoints instead of re-running completed stages. |
| `--stop-after <step>` | `scan`: stop after `clone`/`s0`/`s1`…`s11`; `s0` stops after the static seed/callgraph stage. |
| `--auto-step1` / `--no-auto-step1` | Force AI auto-exclude on (survey each target to derive its Step-1 overlay) / hard-disable it for this run, overriding the profile's `step1.auto_exclude`. Mutually exclusive. |
| `--workspace <dir>` | Batch: directory to clone remote repos into (default `./batch-workspace`). |
| `--remediate` / `--top <N\|all\|*>` | Run the Remediation Agent (s10) after the scan; `--top` caps it to the N highest-CVSS findings. |
| `--step1-config <file>` | Apply an explicit Step-1 overlay (exclude dirs/exts/globs, `max_file_kb`, `config_dedup`). |
| `--keep-clones` / `--skip-preflight` | Keep cloned repos after scanning / skip the startup readiness probe. |
| `--force` | Override safety refusals (currently: the s10 git-SHA staleness check when HEAD moved since the scan). |

`validate` accepts `--repo` (required), `--config`, `--finding` (repeatable),
`--all`, `--max-findings`, `--workspace`, `--resume`, and `--scan-report`.

```bash
vvaharness estimate --repo /path/to/target                      # preview scope/cost, no spend
vvaharness scan --repo /path/to/target --application-id 12345 --stop-after s9
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones --stop-after s9
```

---

## 7. Per-stage tuning knobs

| Block | Key knobs |
|---|---|
| `step0` *(static seed)* | `enabled`, `callgraph_detection` (`rules`/`llm`), optional `sources_yaml`/`sinks_yaml`, language filter, LLM annotator caps/thresholds. |
| `step1` *(intake & inventory)* | `max_budget_usd`, `max_turns`, `allowed_tools`, `exclude_dirs/exts/globs`, `max_file_kb`, call-graph hardening (`validate`/`supplement`/`rounds`/`max_targets`), `config_dedup` (collapse per-env configs, never dropping secrets). |
| `step2` *(threat model)* | `enabled`, `max_threats`, `baseline` (`auto`/`owasp`/`none`), evidence caps (`max_modules`, `max_entry_points`, `max_config_reps`, `max_api_artefacts`). |
| `step3` *(decompose)* | `taint_chunks` + `taint_max_hops/chunks/files_per_hop`, `pack_by` (`loc`/`tokens`), `catchall_enabled`, `specialists[]` (crypto · logic-bug · access-control · batch-etl · iac), chunk LOC caps. |
| `step4` *(deep-dive)* | `parallel`, `runs` + `vote_threshold`, `specialist_runs`, `max_findings_per_run`, `neighbor_context_lines/max`, `timeout`, `max_tokens`. |
| `step5_prefilter` | `min_pre_confidence`, `require_evidence`. |
| `step6_verify` | `parallel`, `min_confidence`, `max_budget_usd`, `max_turns`, `allowed_tools`. |
| `step7_dedup` | `line_tolerance`, `semantic` (toggle LLM dedup), `max_tokens`. |
| `step8` | chain `timeout`, `max_tokens`. |
| `step_remediate` *(`remediate` cmd / `--remediate`)* | profile-specific `enabled`, `top_n_findings`, `max_budget_usd`, `max_turns`, `allowed_tools` (`Read/Glob/Grep/Edit/Write`, no Bash), `enforce_policy`, optional `policy_file` / `playbook_file`. |
| `step_validate` *(`validate` cmd)* | `enabled`, `effort`, `max_turns`, `max_budget_usd`, `max_findings`, `allowed_tools`. (The Claude binary is the `VVAHARNESS_CLAUDE_BINARY` env var, not a config field.) |
| `inject` | `cve_file`, `controls_file`, `cmdb_file`. |
| `rules` | external S4 `kb_overlays` (separate from S0 source/sink rules). |
| `scan_progress` | `enabled`, `style` (`compact`/`verbose`/`summary_only`). |
| `batch` | `git_token`, `git_base_url`, `skip_repo_patterns` (never clone UI-test/automation repos). |
| `output` | `preserve_on_cleanup`. |

See [configuration.md](configuration.md) for the full reference.

---

## 8. Capabilities that ride on top

These are cross-cutting capabilities; backend-specific constraints are noted:

- **Taint analysis** — entry→sink data-flow chunks walked across the call graph, ranked above plain risk chunks.
- **Specialist passes** — repo-wide crypto, logic-bug, access-control, batch-etl & IaC sweeps (IaC auto-gated to repos with Terraform/Docker/k8s).
- **Majority-vote FP filter** — run a chunk N× at T>0; a finding must appear in ≥ threshold runs to survive (`sdk`/`openai` + `temperature`).
- **Adversarial verification** — one verifier per finding renders TRUE / FALSE_POSITIVE with its own evidence and a CVSS 3.1 score.
- **CVSS + CMDB scoring** — CVSS 3.1 base on every finding, plus optional VulContextSeverity + OffensivePriority from a CMDB export.
- **SARIF 2.1.0 output** — machine-ingestible SARIF (`tool.driver.name = "Agentic SAST"`) alongside the Markdown report, with a `tool.driver.rules[]` catalog, a CWE taxonomy referenced via `supportedTaxonomies`, and an `invocations[]` entry that marks a degraded run (`executionSuccessful=false`).
- **Secret / PII redaction** — card numbers (Luhn+IIN), SSNs, and credential material masked at the Markdown/SARIF write boundary.
- **Batch & group-by-app** — clone + scan many repos from a CSV, one report per AppId, with a `batch_summary.md`.
- **Resume + auditable runs** — SQLite scan/per-finding checkpoints; every scan
  writes `run_manifest.json` (version, detection roles, config hashes, git SHA,
  arguments, outcome, timing).

---

## 9. Limitations (read before you trust output)

- **LLM-generated, non-deterministic.** Findings are triage candidates, not confirmed vulnerabilities — human review is required. Two runs may differ.
- **Voting needs diverse repeated samples.** The `cli` backend and known
  temp-rejecting Anthropic SDK models are forced to one run; the deterministic
  s5 prefilter is then the main FP defence. An OpenAI-compatible endpoint that
  drops `temperature` is not auto-collapsed, so all configured runs still
  execute even if they provide no useful diversity.
- **Severity is CVSS-derived.** Findings are labelled Critical / High / Medium / Low / Info, with the scored tiers taken straight from the CVSS 3.1 base-score band (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9) so the label never disagrees with the vector; Info covers findings with no demonstrated exploit path. The base score (0–10) is reported verbatim.
- **Token-hungry.** There is no global spend cap. `max_budget_usd` is
  route-specific: compatible Claude CLI / Claude Agent SDK paths enforce it,
  while raw SDK, OpenAI, and DeepAgents paths ignore it. Use
  `vvaharness estimate` before a scan and treat token accounting as reporting,
  not enforcement.
- **Validation accepts `via: openai` by routing it; remediation _fix mode_ does not.** A `via: openai` validate role is routed to `via: deepagents` with the OpenAI provider, so it runs rather than aborting. Remediation _fix mode_ still needs the `Edit`/`Write` tools that only `via: cli`, `via: sdk`, and the repo-confined `via: deepagents` backends expose, so a `via: openai` remediate role can only run `--mode report-only`. Detection (S1–S9) and report-only remediation run on any backend.
- **Missing post-scan credentials are a warning, not a fatal error.** If `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is absent but only required by S10 or S11, preflight emits a `WARN` and skips that stage — S1–S9 detection still runs. Missing credentials for detection roles remain fatal.
- **`via: deepagents` is only valid for `models.remediate` and `models.validate`.** Configuring it on any S1–S9 role causes an immediate exit before any tokens are spent.
- **Validation is capped unless explicitly uncapped.** Both standalone and
  in-scan validation apply `step_validate.max_findings`. Standalone
  `vvaharness validate --all` bypasses the cap for all validatable statuses;
  terminal `validated` DTOs remain excluded.
- **No rules-mode S0 corpus is bundled.** `default.yaml` and `taint.yaml` enable
  S0, but without operator-supplied generated source/sink rules it returns an
  empty seed and the later pipeline continues.
- **Structured S0 taint evidence, when usable specs exist, is Python, Java, and C# only.** JavaScript,
  TypeScript, and Go have reachability-only S0 support. Languages without an
  S0 plugin, including Rust, receive no static seed; later LLM stages still run.
- **Elevated privilege; trusted targets only.** vvaharness assumes an authorized operator running against a repository they trust; scanning untrusted or malicious code can expose host credentials, files, or other risk. If you must scan a less-trusted or sensitive target, apply the compensating controls in [`security.md` → Hardening for less-trusted or sensitive targets](security.md#hardening-for-less-trusted-or-sensitive-targets).
- **No published accuracy numbers yet.** Precision/recall figures are not yet published.
