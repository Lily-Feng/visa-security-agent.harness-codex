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

# vvaharness — Features & Capabilities (one-page)

**Agentic SAST** — an S0 static pre-stage plus a 9-stage detection pipeline ·
4 backends (`cli`, `sdk`, `openai`, `deepagents`) · 42 language lenses ·
**config-driven**.
Surveys a repo → threat-models → decomposes → deep-dives → verifies → dedups → chains exploits → emits enriched **Markdown + SARIF 2.1.0**. A `remediate` command proposes fixes and an agentic `validate` command verifies them — both also run **in-scan by default** (see below). Model-backed roles and stage knobs are config-driven; supported role backends can be swapped with **no code change**.

> Full reference: **[features.md](features.md)** · shipped profiles: **`vvaharness/config/profiles/`** (`default.yaml`, `sdk.yaml`, `full.yaml`, `taint.yaml`)

---

## S0 pre-stage + 9-stage detection pipeline  (checkpointed · `--resume`)

```
s0 static seed → s1 preprocess → s2 threatmodel → s3 decompose → s4 deepdive
              → s5 prefilter   → s6 verify     → s7 dedup → s8 chain → s9 SARIF
```

| Stage | Role | Model tier (best blend) | Output |
|---|---|---|---|
| s0 | static seed | local AST engine over external rules *(optional LLM annotation mode)* | source/sink callgraph seed when usable specs exist; enabled but empty without rules in default/taint |
| s1 | preprocess | high-volume | repo survey + call graph → ContextPackage |
| s2 | threatmodel | reasoning | assets, trust boundaries, ranked threats |
| s3 | decompose | reasoning | risk / taint / specialist chunks |
| s4 | deepdive | high-volume · T0.4 | per-chunk findings, single pass (majority vote opt-in) |
| s5 | prefilter | *(deterministic)* | confidence + evidence gates |
| s6 | verify | reasoning | adversarial TRUE / FALSE_POSITIVE + CVSS |
| s7 | dedup | high-volume | deterministic + semantic dedup |
| s8 | chain | reasoning | exploit-chain analysis + re-rank → report |
| s9 | SARIF | *(deterministic)* | parse report.md → SARIF 2.1.0 |

*(exact model IDs are pinned per role in the active profile, not hard-coded here. The auto-step1 `autoexclude` role is a cheap one-shot exclusion survey; in the shipped profiles it runs on the high-volume tier in `default`/`sdk` and the reasoning tier in `full`.)*

> **The shipped `default` profile runs past s9.** Because `step_remediate.enabled`
> and `step_validate.enabled` are both true, a plain `vvaharness scan` continues
> into **s10 remediate** (fix mode can edit source when findings, credentials,
> and the remediation session succeed) and **s11 validate** (the panel below).
> That is an S0 pre-stage plus S1–S11. Pass `--stop-after s9`
> for detection only, or set those flags false in your profile.

### Standalone `validate` command  (agentic remediation verification)

Run separately over the remediation DTOs the `remediate` command writes. The
default runtime is the DeepAgents backend (`via: deepagents`); `cli` and `sdk`
backends use the bundled Claude Agent SDK (Python ≥3.11). Permitted backends:
`via: cli`, `via: sdk`, `via: deepagents`; a legacy `via: openai` value is routed
to `via: deepagents` with the OpenAI provider.

| Stage | Role | Model | Output |
|---|---|---|---|
| s11 discovery phase | *(deterministic)* | *(no model spend)* | locate DTOs awaiting validation |
| s11 agentic phase | validate | default profile: `claude-opus-5` orchestrator with `claude-sonnet-4-6` personas via DeepAgents/Anthropic; sdk/full/taint define same-vendor persona model mixes (taint leaves S11 disabled) | agentic panel → weighted gate scores → Fixed / Partially Fixed / Not Fixed / UNVERIFIABLE |

> The "best blend" column is a **recommendation**, not the shipped default. The
> packaged `default.yaml` runs every **detection** role (s1–s8 + autoexclude) on
> the high-volume tier `via: cli`, with `remediate` on the reasoning tier
> `via: deepagents` (Anthropic) and the s11 `validate` panel `via: deepagents`
> (Anthropic). `sdk.yaml` runs the same detection roles via the Anthropic SDK with
> s4 voting on; mix models/backends per role in `config.yaml` to taste.

---

## 4 backends  (`via:`)

| via: | Transport | Tools | Honours | Auth |
|---|---|---|---|---|
| `cli` *(S1–S9 default)* | `claude` subprocess | allowlisted Read · Glob · Grep; **Bash** only when explicitly listed | capability-gated `max_budget_usd`, `effort`, `max_turns` | `claude /login` / `CLAUDE_CODE_OAUTH_TOKEN` |
| `sdk` | Anthropic Python SDK | Read · Glob · Grep | `temperature`, `thinking_budget`, `betas`, direct-transport **mTLS** | `ANTHROPIC_SDK_API_KEY` |
| `openai` | OpenAI-compatible | Read · Glob · Grep | `temperature` | `OPENAI_API_KEY` |
| `deepagents` *(S10/S11 default)* | DeepAgents / LangGraph runtime | repo-confined Edit/Write in S10 fix mode; read-only agents in S11, with host-written artifacts | structured output, `max_turns` | `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` (`provider: anthropic`); `OPENAI_API_KEY` (`provider: openai`, including compatible endpoints via `OPENAI_BASE_URL`) |

The `cli`/`sdk` rows describe detection. S11 maps both to the read-only Claude
Agent SDK Harness; S10 `via: sdk` fix mode delegates Edit/Write to the Agent
SDK, while S10 `via: cli` remains the direct CLI route. SDK-spelled S11 pins an
external `claude` and uses ambient Claude login/OAuth or standard Anthropic
auth rather than the SDK-named key.

**Best generic-Claude blend (2M LOC):** the reasoning tier for low-volume reasoning roles (threatmodel, decompose, verify, chain) · the high-volume tier for high-throughput roles + voting (preprocess, deepdive, dedup) and the auto-step1 survey.
**Voting note:** effective s4 voting needs diverse repeated samples.
`via: cli` and known temp-rejecting Anthropic SDK models are forced to one run.
An OpenAI-compatible endpoint that drops `temperature` still receives all
configured runs, which may provide no useful diversity.

---

## Inputs → Outputs

| Inputs | Effect | Outputs |
|---|---|---|
| target repo / batch CSV | code under scan | `<module>_<timestamp>_report.md` |
| `known_cves.json` | **raises** threat likelihood / focuses the hunt | `<module>_<timestamp>_report.sarif` (2.1.0) |
| `design_controls.yaml` | **downranks** exploitability (demands bypass proof at s6) | `<module>_<timestamp>_errors.jsonl` *(only when recoverable errors occur)* |
| `cmdb.csv` | environmental VulContextSeverity scoring | cwd `run_manifest.json` · batch-only `batch_summary.md` |
| remediation DTOs *(`validate`)* | agentic panel fills each DTO's `validation` block | `remediate_report.json` updated (status → `validated`, `validation_failed`, or `needs_review`) |

---

## Cross-cutting specialists  (auto-gated — skip when no matching surface)

Six specialist lenses are defined; **five are active by default**
(`step3.specialists: crypto, logic-bug, access-control, batch-etl, iac`).
`deserialization` is defined and available but **opt-in** — add it to
`step3.specialists` to enable it.

| Specialist | Default | Focuses on |
|---|---|---|
| `crypto` | ✅ | weak/abusable crypto, key handling, JWT alg-confusion, IV reuse, non-CSPRNG |
| `logic-bug` | ✅ | TOCTOU races, state-machine flaws, sentinel/overflow |
| `access-control` | ✅ | IDOR/BOLA, missing authz, priv-esc, mass assignment, tenant leakage |
| `batch-etl` | ✅ | pipeline path traversal, COMP-3/EBCDIC parsing, CSV formula injection |
| `iac` | ✅ | Terraform, Dockerfile, Kubernetes/Helm, GitHub Actions, and Ansible misconfiguration |
| `deserialization` | opt-in | unsafe deserialization and object injection |

---

## Core capabilities

**Taint analysis** — entry→sink data-flow chunks across the call graph, ranked
first. The engine implements interprocedural and structural taint tracking for
Python, Java, and C#:

| Capability | Detail |
|---|---|
| **Interprocedural taint** | Taint tracks across function call boundaries via argument-to-parameter, return-value, and local-alias propagation |
| **Field & container flow** | Taint flows through object field writes/reads and container element writes (lists, dicts, arrays) |
| **Sanitizer detection** | 18+ recognized sanitizer names (escape, quote, encode, validate, …); tainted flows through them are neutralized |
| **CFG schema only** | The data model reserves CFG nodes and condition-gated transfer types, but the current scanner does not populate a branch CFG or claim branch-/path-sensitive flow |
| **Reflection & dynamic dispatch** | Detects common reflection APIs in each language (see below); emits speculative taint evidence with confidence scores. **Java:** `getMethod`, `getDeclaredMethod`, `getDeclaredField`, `getField`, `getDeclaredConstructor`, `getConstructor`, `forName`, `invoke`, `newInstance`, `MethodHandles.lookup()`. **Python:** `getattr`, `setattr`, `__import__`, `importlib.import_module`, `vars`, `type`, `eval`, `exec`, `compile`. **C#:** `GetMethod`, `GetMethods`, `GetConstructor`, `GetConstructors`, `GetType`, `Invoke`, `CreateDelegate`, `Activator.CreateInstance`, `Assembly.Load`, `Assembly.LoadFrom`, `Assembly.LoadFile`, `Type.InvokeMember`. |
| **Framework lifecycle sources** | Spring (`@RequestParam`, `@PathVariable`, `@RequestBody`), Django (`request.GET/POST/META`), ASP.NET (`[FromQuery]`, `[FromRoute]`, `[FromBody]`) treated as taint sources |
| **Route parameter taint** | URL path parameters (`/user/{id}`) automatically tainted and mapped to function arguments |
| **Response dataflow** | Tracks tainted data into response objects (`JsonResponse`, `ResponseEntity`, `Ok`/`BadRequest`), flagging XSS risk |

- **Majority-vote FP filter** — N runs at T>0; a finding must appear in ≥ threshold runs.
- **Adversarial verification** — one verifier per finding → TRUE / FALSE_POSITIVE + CVSS.
- **CVSS 3.1 + CMDB scoring** — base CVSS + VulContextSeverity + OffensivePriority.
- **CWE taxonomy** — per-finding CWE → MITRE name + URL (77 ids mapped); SARIF taxa.
- **SARIF 2.1.0** — machine-ingestible; `tool.driver.name = "Agentic SAST"`, with a `tool.driver.rules[]` catalog, CWE `supportedTaxonomies`, and a degraded-run `invocations[].executionSuccessful` flag.
- **Secret / PII redaction** — cards (Luhn+IIN), SSNs, credentials masked at write time.
- **Batch & group-by-app** — clone+scan many repos from CSV, one report per AppId.
- **Resume + audit manifest** — SQLite scan/per-finding checkpoints;
  `run_manifest.json` (version, detection roles, config hashes, git SHA,
  arguments, outcome, timing).

---

## 42 language lenses  (per-language researcher hints, auto-selected by file type)

| Family | Languages |
|---|---|
| **Systems** | C/C++ · Rust · Go · Zig · Nim · Crystal · Assembly |
| **JVM / .NET** | Java · Kotlin · Scala · Groovy · C# · VB.NET · F# |
| **Scripting** | Python · JavaScript · TypeScript · PHP · Ruby · Perl · Lua · R · Shell · PowerShell · Batch |
| **Functional** | Haskell · OCaml · Clojure · Elixir · Erlang |
| **Mobile** | Swift · Objective-C · Dart |
| **Enterprise / Mainframe** | COBOL · JCL · ABAP · SQL/PL-SQL/T-SQL |
| **Web / IaC / Cloud** | Web-templates · Terraform/HCL · Ansible · Solidity · Julia |

---

> **Limitations:** findings are LLM-generated **triage candidates** — human
> review required. Runs are non-deterministic. Severity is labelled Critical /
> High / Medium / Low / Info per the CVSS 3.1 bands; the base score (0–10) is
> reported verbatim. No rules-mode S0 source/sink corpus is bundled; without
> operator-supplied generated rules, the enabled default/taint wrappers return
> an empty seed and later stages continue. **Structured taint evidence, when S0
> has usable specs, is available for Python, Java, and C#.** JavaScript,
> TypeScript, and Go have reachability-only S0 support.
> Languages without an S0 plugin, such as Rust, receive no static seed; later
> LLM stages still run.

*© 2026 Visa, Inc. · Apache-2.0*
