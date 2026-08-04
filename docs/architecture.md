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

# Architecture

Module map and data flow for the `vvaharness` package.

## Module layout

```
vvaharness/
  cli.py              — console entry point: setup / doctor / estimate / gc /
                        scan / remediate / validate;
                        loads .env, checks the Python floor, resolves --config
  orchestrator/       — pipeline driver package:
                        entry.py (argparse + main), scan.py (single-repo driver),
                        batch.py (clone + group-by-app), preflight.py (backend
                        configure/probe), checkpoints.py, store.py (SQLite
                        state store), cleanup.py, cmdb.py,
                        enrich_findings.py, config_paths.py
  agentdoc.py         — AGENTS.md / CLAUDE.md / .github/copilot-instructions.md /
                        GEMINI.md / Claude skill text for `setup --install-agents`
  manifest.py         — run-level run_manifest.json (version, detection roles,
                        config/overlay hashes, target git SHA, arguments,
                        outcome, timing)
  models.py           — pydantic data contracts (ContextPackage, Finding, FinalReport, …)
  config/             — config loader (${ENV} expansion, local override, step1 overlays)
    profiles/         — bundled profiles: default.yaml (S1–S9 via:cli, S10/S11 via:deepagents),
                        sdk.yaml (all roles spelled via:sdk, s4 voting on), full.yaml (multi-backend), taint.yaml (taint-first)
  pipeline/stages/    — the scan analysis stages:
                        s0_seed (static callgraph seed), s1_preprocess, s1_autoexclude, s2_threatmodel, s3_decompose,
                        s4_deepdive, s5_prefilter, s6_verify, s7_dedup, s8_chain,
                        s11_validate (thin wrapper hooking the validation/ package
                        into the pipeline)
    callgraph_engine/ — tree-sitter static seed engine (parser plugins for
                        Python/Java/C#/JavaScript/TypeScript/Go; typed taint
                        facts for Python/Java/C#):
                        _scan.py    — per-file scanner; emits FileIndex containing
                                      call edges, taint facts, a reserved CFG field,
                                      reflection facts, and framework markers
                        _graph.py   — interprocedural call graph construction,
                                      reachability, and structured taint propagation
                        _annotator.py — spec derivation from observed call patterns
                        _rules.py   — rulepack loader (source/sink/sanitizer specs)
  pipeline/callgraph_consumer.py — shared read-only graph helpers used by S3 and
                        S5–S8; S2 and S4 consume ContextPackage AST views/spans
                        directly. The helpers index graph and seed facts per
                        ContextPackage
  remediation_agent/  — Step 10 (the `remediate` command / --remediate): proposes
                        and applies a minimal fix per verified finding and writes
                        per-finding DTOs under <repo>/security-remediation/
  validation/         — Step 11 (the `validate` command): DTO discovery (no
                        model spend) feeds the s11 agentic panel — two always-on
                        personas (security-architect + penetration-tester) plus a
                        conditional cross-repo-analyzer (spawned only when a fix
                        spans 2+ repos) that scores each DTO against weighted
                        fix-quality gates. Agents are read-only; host code
                        persists temporary artifacts and the DTO result
  (operator input)    — ./inputs/validator_hints.yaml (per-CWE bypass cheatsheets
                        injected into the validation session launch prompt)
  backends/           — LLM transport layer:
                        llm.py        — dispatcher; routes on `via:`
                        sdk.py        — Anthropic Python SDK
                        agent_sdk.py  — Claude Agent SDK backend for the mutating
                                        remediation `fix` role (delegated to from
                                        sdk.py under `via: sdk`); native
                                        Read/Glob/Grep/Edit/Write inside a
                                        deny-by-default (no-Bash) permission sandbox
                        oai.py        — OpenAI-compatible API
                        claude_cli.py — `claude` CLI subprocess
                        localtools.py — sandboxed Read/Glob/Grep tool-loop for sdk/openai
    harness/           — post-scan Harness abstraction: Claude Agent SDK for
                        S11 `via: cli`/`via: sdk`, plus DeepAgents/LangGraph for
                        S10/S11, with mode-specific filesystem permissions
  report/             — enrich.py (CVSS env scoring, CMDB, Markdown→SARIF),
                        cvss.py, cwe.py, redact.py (secret/PII redaction at write time)
  injectors/          — cve_feed.py, design_controls.py (optional context loaders)
  util/               — environment (setup/doctor checks), tokens, metrics, errlog,
                        prompts, json_extract, status (progress spinner)
  lang/               — language hints (EXT_TO_LANG, LANG_HINTS, SPECIALIST_HINTS)

inputs/               — context inputs: *.example.* samples plus operator-editable
                        validator_hints.yaml / remediation_policy.yaml / remediation_playbook.yaml
scripts/              — developer helper scripts (not part of the installed package)
tests/                — smoke tests
```

## Stages (data flow)

```
        repo  +  optional inputs (known_cves, design_controls, cmdb)
                              │
   s0 seed        ── Rules mode requires operator-supplied generated source/sink
                     YAML; no pack or heuristic baseline is bundled. Without
                     usable specs it returns an empty seed and later stages
                     continue. With external or LLM-derived specs, the AST
                     engine builds a callgraph and source→sink seed:
                     Python/Java/C# can emit typed taint evidence;
                     JavaScript/TypeScript/Go emit reachability-only paths;
                     unsupported languages emit no S0 seed.
                     • CFG boundary — the data model reserves CFG and
                       condition-gated transfer structures, but the current
                       scanner does not populate a branch CFG or perform
                       branch-/path-sensitive analysis
                     • Reflection detection — ReflectionFact records getMethod /
                       forName / invoke (Java), getattr / __import__ (Python),
                       GetMethod / Delegate.CreateDelegate (C#); ReflectionTaintEdge
                       propagates taint through dynamically resolved targets
                     • Framework lifecycle sources — FrameworkMarkerFact captures
                       @RequestParam / @PathVariable (Spring), request.GET/POST
                       (Django), [FromQuery] / [FromRoute] (ASP.NET); RouteTaintFact
                       models URL path-parameter bindings; ResponseDataflowFact
                       tracks flows to response sinks (JsonResponse, HttpResponse,
                       Ok, render); FrameworkTaintEdge propagates taint from
                       framework-managed entry points
                     • Transfer kinds: source / assign / arg_to_param /
                       return_to_local / local_to_sink / return_to_sink /
                       field_write / field_read / container_put / container_get /
                       sanitize / reflect / framework (`condition` remains a
                       schema type for future/refined CFG data)
                     • FileIndex fields: imports, functions, source_hits, sink_hits,
                       call_edges, assigns, returns, call_args, field_writes,
                       field_reads, container_writes, reserved cfgs,
                       reflection_facts,
                       framework_markers, route_facts, response_dataflow
   s1 preprocess  ── repo survey, call graph ─────────► ContextPackage
   s2 threatmodel ── assets, trust boundaries, threats ─► ThreatModel
   s3 decompose   ── risk/taint/catch-all/specialist chunks ► TaskManifest
   s4 deepdive    ── per-chunk findings (×N + vote) ───► Finding[]
   s5 prefilter   ── deterministic confidence/evidence gates
   s6 verify      ── adversarial TRUE/FALSE_POSITIVE + CVSS per finding
   s7 dedup       ── deterministic + semantic dedup ───► canonical Finding[]
   s8 chain       ── exploit-chain analysis + re-rank ─► FinalReport
   s9 SARIF       ── parse the Markdown report ────────► *_report.sarif
                              │
            <target>/security-scan/<module>_<ts>_report.{md,sarif}
              + <module>_<ts>_errors.jsonl only when an error was logged
```

The standalone `vvaharness validate` command runs separately, over the
remediation DTOs the `remediate` command leaves under
`<repo>/security-remediation/<NN_slug>/remediate_report.json`:

```
   remediation DTOs (validatable status, finding + evidence/diff.patch)
                              │
   discover       ── locate DTOs awaiting validation (no model spend)
   s11 panel      ── configured Harness backend — two always-on personas
                     (security-architect + penetration-tester) plus a conditional
                     cross-repo-analyzer (only when a fix spans 2+ repos) →
                     weighted gate scores → verdict
                              │
       host fills each DTO's `validation` block; status → validated |
       validation_failed | needs_review; temporary validation_report.json and
       synthesized_gates.json are consumed before the workspace is removed
```

Scan state is checkpointed in the SQLite DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`) — never
inside the scanned repo. S0–S4 have individual scan checkpoints; S5–S7 share
the S7 checkpoint; S8 and S9 are stored separately. Remediation and validation
also store per-finding resume records. `vvaharness scan --resume` reuses the
available completed work, and `vvaharness gc` prunes old runs. The whole scan
is summarised in cwd `run_manifest.json`.

## LLM transport layer

Optional S0 annotation, auto-step1, S1–S8 model calls, and non-DeepAgents S10
remediation calls go through
`backends/llm.py`, which reads the per-role `{id, via, …}` node and dispatches
to one of the detection-era transports:

| `via:` | Module | Transport |
|---|---|---|
| `sdk` | `backends/sdk.py` | Anthropic Python SDK |
| `openai` | `backends/oai.py` | OpenAI-compatible Chat Completions |
| `cli` | `backends/claude_cli.py` | `claude` CLI subprocess |

`sdk` and `openai` run their agentic Read/Glob/Grep tool-loop through
`backends/localtools.py` (sandboxed to the target repo, no Bash); `cli` uses the
CLI's native tools (Bash-capable, though no shipped profile grants it). In S10
fix mode, `via: sdk` delegates Edit/Write work to `backends/agent_sdk.py`.

The post-scan Harness is a separate route:

| Stages | Selector | Implementation |
|---|---|---|
| S10/S11 | `via: deepagents` | DeepAgents/LangGraph; repo-confined writes for S10 fix mode and read-only agents for S11 |
| S11 | `via: cli` or `via: sdk` | Both select the Claude Agent SDK Harness; validation remains read-only |
| S11 | legacy `via: openai` | Normalized to DeepAgents with `provider: openai` before launch |

See [models.md](models.md) for the complete role/backend matrix.

## Cross-cutting concerns

- **Config** (`config/`): `${ENV:-default}` expansion, optional
  `config.local.yaml` deep-merge, and per-scan `step1` overlays.
- **Redaction** (`report/redact.py`): card/PII/credential material is masked at
  the Markdown and SARIF write boundary so it does not land in those final
  artifacts. Card numbers are Luhn+IIN gated and SSNs area/group/serial gated
  for precision; values
  following a strong credential keyword (`password`, `api_key`, `access_key`,
  `client_secret`, `auth_token`) are always masked, while a short lowercase word
  after a prose-ambiguous keyword (`secret`, `token`, `credential`) is left as ordinary text.
- **Token & cost accounting** (`util/tokens.py`, `util/metrics.py`): phase
  buckets record usage by phase; they do not enforce spend caps. Budget caps
  are route-specific parameters enforced only by compatible CLI/Claude Agent
  SDK paths and ignored by raw SDK, OpenAI, and DeepAgents paths. The report's embedded `ScanMetrics` and
  terminal `Tokens:` summary are built immediately before S8, so they omit
  S8–S11 activity; `run_manifest.json.per_stage_cost` is currently `null`.
- **Error log** (`util/errlog.py`): non-fatal errors are appended to the
  per-scan `*_errors.jsonl`.
