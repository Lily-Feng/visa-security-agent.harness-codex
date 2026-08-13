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

# Changelog

## [1.2.0] — 2026-08-04

This release ships four headline improvements across the full pipeline. **AST
callgraph** — a tree-sitter-backed static seed stage (S0) can build
source→sink call graphs before the agentic explorer runs from operator-supplied
generated rule files or optional LLM-derived specs. No source/sink rule pack is
bundled, so shipped rules mode returns an empty seed when those files are
absent. **DeepAgents backend** —
remediation (S10) and validation (S11) were refactored onto a shared harness
backend layer with first-class DeepAgents/provider routing, structured-output
strategies, and read-only enforcement. **Multi-model support** — a new
`taint.yaml` profile adds model role slots for callgraph annotation (`graph_annotate`,
`callgraph_creation`) alongside upgraded Opus-tier deepdive/verify roles;
`default.yaml` also gains S0 callgraph with `step1.call_graph: tree_sitter`.
**Observability** — `scan_progress` is enabled in compact mode by the default
profile and verbose mode by the taint profile (disabled in `sdk.yaml` and
`full.yaml`). Stage events span S0–S9; detailed file/threat/chunk events come
from S1, S2, S3, and S4.

### Added
- **Step 0 static seed stage (`s0_seed`).** Tree-sitter-backed source→sink
  callgraph seeding runs before the agentic explorer with no external binary
  required. Rules mode loads operator-supplied generated source/sink YAML; no
  generated corpus or implicit heuristic baseline is bundled. With no usable
  rule files it returns an empty seed and later stages continue. The S0 wrapper
  is enabled in both `default.yaml` and `taint.yaml`.
- **Callgraph engine package** under
  `vvaharness/pipeline/stages/callgraph_engine/` — rule translation, graph
  construction, AST scanning, and an optional LLM annotator mode
  (`callgraph_detection: llm`) that falls back to configured rule YAML.
- **Rule corpus tooling** under `vvaharness/rules/` — `generic_pack.py`
  generates the first-party `generic.kb.yaml` CWE knowledge pack, while
  `build_kb.py` can compile Semgrep, FindSecBugs, and CodeQL inputs into that KB
  format and optional external source/sink callgraph rule packs. TypeScript
  graph support was added in `vvaharness/lang/ts_graph.py`.
- **Shared harness backend** (`vvaharness/backends/harness/`) — a single
  abstraction layer for the DeepAgents provider including client, options, tool
  translation, redaction, and read-only session enforcement, consumed by both
  S10 remediation and S11 validation.
- **New taint-first profile (`taint.yaml`)** with `step0.enabled: true`,
  `step1.mode: gap_fill`, `step3.catchall_mode: reachable_only`, and dedicated
  model roles `graph_annotate` / `callgraph_creation` plus upgraded Opus-tier
  `deepdive` and `verify`. Its shipped rules mode needs operator-supplied rule
  files for an S0 seed; an empty seed follows the normal agentic S1 path.
- **Profile-controlled `scan_progress`.** `default.yaml` ships enabled/compact
  and `taint.yaml` enabled/verbose; `sdk.yaml` and `full.yaml` ship disabled.
  Stage-start/done/note events cover S0–S9, with file/threat/chunk detail in
  S1/S2/S3/S4.
- **Remediation path/rules helpers** (`remediation_agent/rule_paths.py`) and
  bundled validation scoring resources (not staged as a DeepAgents skill).
- **Expanded test suites** covering S0 seed, callgraph engine, reachable-only
  chunking, taint-path handling, KB compilation, DeepAgents backend routing,
  read-only enforcement, structured-output handling, and validation consensus.

### Changed
- **Python support floor raised to 3.11.** DeepAgents cannot install on Python
  3.10, and the shipped default routes S10/S11 through DeepAgents, so package
  metadata and tooling now require Python 3.11 or newer.
- **`default.yaml` gains S0 callgraph.** `step0.enabled: true` and
  `step1.call_graph: tree_sitter` are now set in the default profile. Because no
  source/sink pack is bundled, the rules-mode S0 wrapper returns an empty seed
  unless the operator supplies generated rule files; S1 still runs normally.
- **Pipeline wiring across S1–S8** updated to consume S0/callgraph artifacts
  directly, improving the reachability context fed into decompose, deep-dive,
  and verify.
- **Validation backend abstractions hoisted** into `vvaharness/backends/harness`;
  the previous `vvaharness/validation/backends/` subtree was refactored and moved.
- **S11 validation routing hardened** — single-vendor panel enforcement,
  rejection of invalid startup routes, normalization of legacy `via: openai`
  validation roles to DeepAgents with the OpenAI provider, and per-backend
  structured-output strategy selection.
- **S11 runtime and scoring reorganized** — session, synthesis, tooling, and
  scoring modules restructured; dead/contradictory scoring CLI paths removed.
- **S10 remediation updated for DeepAgents** — plugin-runner/policy plumbing,
  virtual-path handling, and packaged policy/rule delivery revised.
- **Checkpoint/store/config plumbing** extended for S0/callgraph artifacts and
  taint-profile runtime behavior.
- **Default/full/sdk profiles, remediation and validation docs** updated for the
  revised S10/S11 backend behavior and new credential requirements.

### Fixed
- **Callgraph and AST robustness** — parser-driven edge extraction fallback
  handling and reachability/taint-path correctness across decomposition,
  prefiltering, verification, and dedup.
- **Validation verdict integrity** — failed S11 sessions can no longer produce
  a terminal `validated` outcome; scoring paths that could inflate a failed fix
  were closed.
- **In-scan validation scope** — Step 11 now correctly honors
  `step_validate.max_findings` during `scan` execution.
- **Remediation setup and policy delivery** — missing inputs discovered earlier;
  policy/rule resources delivered correctly via the updated DeepAgents backend.
- **Stage-level progress events wired for all stages S0–S9** in the scan
  orchestrator, with completed/cached/skipped/error outcomes for both taint and
  non-taint profiles. The current stage wrapper passes S0–S11 as `n=0..11`
  with `total=11`; it does not display one-based `[1/12]..[12/12]` slots.

## [1.1.0] — 2026-06-30

This release extends vvaharness past detection into a full remediate-and-validate
workflow, hardens how scan state is stored, and reorganises the shipped profiles.
The nine-stage detection pipeline (S1–S9) is unchanged apart from default tuning
and a redaction fix; everything new is layered on top of it.

### Added
- **`remediate` — a new command that proposes per-finding fixes (pipeline stage
  S10).** It reads the
  findings a prior `scan` wrote under `<repo>/security-scan/` and walks them one at
  a time on a dedicated `models.remediate` role, writing a per-finding DTO and
  evidence (`diff.patch`, summary, triage) under
  `<repo>/security-remediation/<NN_slug>/`. `--mode fix` (default) applies a minimal
  diff to the working tree; `--mode report-only` proposes without editing. Other
  flags: `--top N` (or `all`/`*`) to cap by CVSS, `-i/--interactive` to pick
  findings from a menu, `--resume`, and `-v/--verbose` (live agent trace).
- **`validate` — a new command (pipeline stage S11, alias `s11`) that grades
  remediation fixes.** A
  Claude Agent SDK adversarial panel — a security architect and a penetration
  tester, plus a cross-repo reviewer when a fix spans more than one repository —
  scores each fix against four weighted gates (`root_cause`, `instance_coverage`,
  `no_new_vulnerabilities`, `security_best_practices`) and labels it **Fixed**,
  **Partially Fixed**, **Not Fixed**, or **UNVERIFIABLE**, writing the verdict back
  into the fix report. Per-CWE adversarial bypass hints can be supplied via
  `./inputs/validator_hints.yaml`. Re-runs are idempotent.
- **`gc` — a new command that prunes old run state** from the SQLite database
  (`--keep-runs` / `--max-age-days` / `--run <path>` / `--dry-run`). Reports and
  SARIF under `<repo>/security-scan/` are never touched.
- **Remediation and validation run by default at the end of `scan`.** The shipped
  default profile sets `step_remediate.enabled` and `step_validate.enabled`, so a
  plain `scan` continues past S9 into **S10 — Remediate** (fix mode can edit
  source files when findings, credentials, and a successful session are present)
  and **S11 — Validate**. New scan flags `--remediate`
  (force it on) and `--top N`; pass `--stop-after s9` for detection only.
- **New configuration surface.** `step_remediate` / `step_validate` profile blocks
  (enabled flags, budgets, turn caps, `allowed_tools`, finding caps), new
  `models.remediate` / `models.validate` roles with per-persona overrides, and a new
  `step1.auto_exclude` key — on by default in the shipped profiles, disable with
  `--no-auto-step1`.
- **Optional remediation policy gate with an emergency kill-switch.** With
  `enforce_policy: true`, every fix passes through a gate driven by
  `inputs/remediation_policy.yaml` and `inputs/remediation_playbook.yaml`
  (deny/allow CWE maps, forbidden-path globs, a diff post-gate that reverts edits to
  forbidden paths). A kill-switch forces guidance-only output when
  `VVAHARNESS_REMEDIATE_DISABLE` is truthy or a `./.vvaharness-remediate-off` file is
  present.
- **Claude Agent SDK backend.** A new `via: sdk` backend supports file-mutating
  roles (remediation fix mode) through a sandboxed Read/Glob/Grep/Edit/Write
  tool-loop. `claude-agent-sdk` is now a core runtime dependency and ships with
  vvaharness (Python ≥ 3.10); `pydantic-settings` and `typing_extensions` were added
  as well.
- **Remediation results enrich the scan report** — fixes are reflected back into the
  Markdown report and SARIF output.

### Changed
- **Profiles reorganised.** The all-CLI `cli.yaml` profile was renamed to
  **`sdk.yaml`** and repurposed as a true all-SDK layout (every role `via: sdk`, with
  S4 majority voting on). No shipped profile grants Bash. `vvaharness setup`/`doctor`
  now recommends `sdk` when only an SDK key is present. In the default profile, scan
  roles use a high-volume tier and the post-scan remediate/validate roles use a
  higher reasoning tier.
- **The default profile now runs single-pass.** S4 majority voting is off by
  default (matching the CLI backend, which has no temperature control); the verifier
  confidence floor and neighbour-context budget were trimmed. The `full` profile
  enables S4 voting and repoints its model roles.
- **Scan resume state moved to a single SQLite store** under `~/.vvaharness/state`,
  serialised as JSON. State is validated on load and is never read from the scanned
  repo.
- **`security-remediation/` is preserved on cleanup** alongside the existing scan
  outputs.
- **Reports derive a CWE from the vulnerability class** when a finding carries none.

### Removed
- **The all-CLI `cli.yaml` profile.** Use `sdk.yaml` (all-SDK) or the `default`
  profile instead, and update any `cp …/cli.yaml config.yaml` step.
- **Reading of legacy pickle (`.pkl`) checkpoints.** Pre-upgrade resume state is not
  migrated, so `--resume` on a run started before this release begins again from S1.

### Fixed
- **Source redaction no longer over-masks ordinary numbers.** Card-number masking is
  now gated on card-likeness (a Luhn check, or a card keyword such as `card`/`acct`
  nearby), so timestamps, database IDs, and version numbers in the code the model
  sees are left intact. Real and clearly-labelled test card numbers are still masked
  before any source leaves for the model.
- **Batch mode no longer skips repositories whose names share a common tail**, and
  ambiguous agent-emitted file paths are dropped instead of being misattributed to
  the wrong finding.
- **`--max-budget-usd` is forwarded to the Claude CLI only when the installed build
  supports it**, and CLI permission-mode capability detection no longer false-matches
  help text.

### Security
- **Eliminated a code-execution risk (CWE-502).** Scan state is now stored as JSON
  in a SQLite database, never as Python pickle — validated on load and never
  deserialised from the scanned repo.
- **No agentic stage gets host-shell access.** No shipped profile grants Bash, the
  CLI backend no longer force-adds it, and on `via: sdk` the agent gate denies Bash
  even if re-added; the CLI permission mode defaults to `acceptEdits` rather than a
  blanket bypass.
- **The validation panel runs strictly read-only** — it never applies a patch or
  runs Docker — and its verdicts are computed fail-closed, so missing or hedged
  gates cannot inflate a result.
- **Remediation and diff writes are confined to the repository**, with symlinks
  rejected and UNC/network input paths refused (preventing NTLM credential leakage
  over SMB; CWE-22 path containment on the remediation-applied check).
- **Agent narrative, tool output, and persisted session logs are redacted** before
  they are stored or sent upstream.
- **Operator/CMDB and batch-summary fields are escaped** in reports to block
  Markdown/table injection, and a loud warning is emitted when TLS verification is
  disabled on the SDK/OpenAI backends.

## [1.0.0] — 2026-06-09

Initial open-source release.

### What's included
- 9-stage agentic SAST pipeline: repository survey → threat model →
  decompose → deep-dive → pre-filter → adversarial verify → dedup →
  chain → SARIF 2.1.0
- Multi-model: works with the Claude CLI, Anthropic SDK, or any
  OpenAI-compatible endpoint; mix backends per role
- Precision controls: call-graph validation, taint-flow analysis,
  multi-agent voting, CVSS 3.1 scoring
- Batch mode: clone and scan multiple repositories from a CSV manifest
- Three shipped configuration profiles: CLI-first default, Bash-enabled
  CLI, and multi-backend
