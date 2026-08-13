<!--
Copyright 2026 Visa, Inc.
Modifications Copyright 2026 Lily Feng.
Modified by Lily Feng in 2026 for independent Codex maintenance.

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

# Codex Vulnerability Agentic Harness — Agentic SAST Pipeline

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Python](https://img.shields.io/badge/python-%E2%89%A5%203.11-blue.svg)
![Version](https://img.shields.io/badge/version-1.2.0-informational.svg)
![Output](https://img.shields.io/badge/output-Markdown%20%2B%20SARIF%202.1.0-green.svg)

Codex Vulnerability Agentic Harness is an independently maintained, Codex-first
derivative of Visa's open-source
[Visa Vulnerability Agentic Harness](https://github.com/visa/visa-vulnerability-agentic-harness).
It preserves the upstream Git history and the `vvaharness` Python module and
CLI names for compatibility while adding native `codex login` authentication
and a read-only Codex detection profile.

> **Independent project.** This project is maintained by Lily Feng and is not
> affiliated with or endorsed by Visa Inc. or OpenAI. Visa and Codex are used
> only to identify the upstream project and the supported integration.

VVAH runs as a four-phase, eleven-stage pipeline from code ingest to validated
fix (with an optional Stage 0 static seed used by the taint-first profile):

- **Phase 1 — Discovery & Modeling (S1–S3)**: map the attack surface and build a
  threat-aware plan.
- **Phase 2 — Deep Dive & Verification (S4–S6)**: run multi-lens analysis and
  adversarial verification to confirm exploitability.
- **Phase 3 — Synthesis & Reporting (S7–S9)**: deduplicate, chain, and emit
  structured findings (Markdown + SARIF).
- **Phase 4 — Remediation & Validation (S10–S11)**: propose candidate fixes and
  adversarially validate them before adoption.

Three design choices drive finding quality: threat modeling before analysis
focuses the attack surface; multi-agent deterministic voting reduces false
positives; and structured triage artifacts compress the lifecycle from
AI-discovered weakness to actionable finding. The bottleneck in AI-assisted
vulnerability management is triage speed, not discovery. VVAH is designed
around that constraint. The primary effectiveness metric is **Mean Time to
Adapt (MTTA)**: elapsed time from AI-discovered exploitability to a validated
fix in production.

Multi-model by design, VVAH supports Anthropic Claude and OpenAI-compatible
models across the detection pipeline (S1–S9), and extends remediation (S10)
and validation (S11) to OpenAI-compatible and open-weight models served via
Chat Completions-compatible endpoints. These stages can be wired to different
providers via a vendor-neutral abstraction layer. No single provider is a hard
dependency. See [docs/models.md](docs/models.md) for the full model/backend
matrix.

For setup, see [`docs/SETUP_GUIDE.md`](docs/SETUP_GUIDE.md). Contributions are
welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md). For upstream provenance and
the synchronization policy, see [`UPSTREAM.md`](UPSTREAM.md).

> **Authorized use only.** Run scans only against code you own or have explicit
> permission to test. Findings and fixes are LLM-generated triage candidates
> that require human review — see [Limitations](#limitations-read-before-you-trust-output).
>
> **Data egress warning.** Any role routed to `via: sdk`, `via: openai`, or
> `via: deepagents` sends prompt data to that model provider endpoint
> (Anthropic/OpenAI or your configured gateway). Use only approved endpoints
> and scan targets you are authorized to process.

**Docs:** [SETUP_GUIDE.md](docs/SETUP_GUIDE.md) — install & configuration ·
[USER_GUIDE.md](docs/USER_GUIDE.md) — commands & options ·
[models.md](docs/models.md) — model/backend selection ·
[remediation.md](docs/remediation.md) · [validation.md](docs/validation.md) ·
[Project Glasswing white paper](https://corporate.visa.com/content/dam/VCOM/corporate/visa-perspectives/security-and-trust/documents/project-glasswing.pdf) — technical background.

**Project companion guides:**
[Enterprise Security Companion](enterprise-security/README.md) — host, runtime,
cloud, identity, supply-chain, detection, response, and post-scan assurance ·
[Codex-Only Direction](codex/README.md) — native Codex backend plan,
authentication boundary, implementation milestones, efficiency, and safety.

---

## Features

- **S0–S11 pipeline** — optional static AST/callgraph seed, then threat-modeled
  discovery, multi-lens deep-dive, adversarial verification, dedup, exploit-chain
  synthesis, remediation, and adversarial fix validation.
- **AST/call-graph seeding (S0/S1)** — tree-sitter-backed static analysis builds
  a source→sink callgraph seed (S0) and an AST-exact call graph (S1), focusing
  later-stage analysis on reachable code paths rather than the whole repo.
- **4 backends** (`via: cli` / `sdk` / `openai` / `deepagents`) — mix per role,
  swap without code changes.
- **DeepAgents runtime** — the shared, model-agnostic backend for S10
  remediation and S11 validation; the same harness routes to either the
  Anthropic or OpenAI provider per role.
- **Majority-vote FP filtering** — N runs at T>0 on the `sdk`/`openai` backends;
  a finding must survive ≥ threshold runs to be kept.
- **Taint analysis** — interprocedural, field/container, and reflection-aware
  data-flow tracking for Python, Java, and C#.
- **6 cross-cutting specialist lenses** (crypto, logic-bug, access-control,
  batch/ETL, IaC, deserialization) — auto-gated to matching attack surface.
- **Structured output** — Markdown report + SARIF 2.1.0, CVSS 3.1 + CMDB-aware
  scoring, and CWE taxonomy mapping.
- **Automated remediation + validation** — `remediate` proposes (and in fix
  mode applies) a fix per finding; `validate` runs an agentic adversarial panel
  to grade those fixes.
- **Batch scanning** — clone and scan many repos from a CSV, one report per
  AppId; resumable via a SQLite checkpoint DB.
- **Harness observability** — `scan_progress` is an optional real-time
  file/chunk-level `[progress]` view streamed to stderr across S0–S9 (compact,
  verbose, or summary-only); it has no impact on scan results or data
  handling. See [docs/USER_GUIDE.md → Observability](docs/USER_GUIDE.md#observability).

See [docs/capabilities.md](docs/capabilities.md) (one-page reference) and
[docs/features.md](docs/features.md) (full detail) for more.

---

## Quick start

```bash
pip install .                                          # venv / pipx options under Install
vvaharness doctor                                      # check credentials & backends
vvaharness estimate --repo /path/to/target             # rough scope/cost — spends nothing
vvaharness scan --repo /path/to/target --stop-after s9 # detection only — no code changes
```

> ⚠️ **A plain `scan` edits your code.** The shipped default profile continues past
> detection into Phase 4 remediation (S10) in fix mode, which **edits source
> files in the target repo**. Add `--stop-after s9` for detection only (no code
> changes).

New here? Follow [Install](#install) → [Configure](#configure) → [Run](#run).

---

## Pipeline

VVAH implements an eleven-stage pipeline across four phases.

### Detection pipeline (`scan`, S0–S9)

S0 is an **optional** static seed stage (`step0`) used by the shipped
`taint.yaml` profile. The packaged `default.yaml` starts at S1.

Nine detection stages combine deterministic controls with frontier-model
reasoning to produce structured, exploit-validated findings.

| Stage group | Stages | Purpose |
|---|---|---|
| Static seed (optional) | S0 | Source/sink callgraph seed for taint-first scanning |
| Discovery & Modeling | S1–S3 | Attack surface mapping, threat modeling, hunting plan |
| Deep Dive & Verification | S4–S6 | Multi-lens research, policy gates, adversarial verification |
| Synthesis, Chaining & Reporting | S7–S9 | Deduplication, chain construction, SARIF emission |

### Remediation & validation (`remediate` and `validate`, S10–S11)

After detection, the shipped `default.yaml` runs two more steps. The three core
commands map cleanly to the workflow:

- **`scan`** — finds issues (S1–S9 detection pipeline above).
- **`remediate`** (S10) — proposes, and in fix mode applies, a minimal fix per
  finding.
- **`validate`** (S11) — checks those fixes with an agentic adversarial panel
  before they are treated as validated.

(The CLI also ships `setup`, `doctor`, `estimate`, and `gc` — run
`vvaharness --help`.)

> ⚠️ Because remediation and validation are on by default, a plain
> `vvaharness scan` runs all 11 stages and **edits source files in the target
> repo** (S10 fix mode). For detection only, pass `--stop-after s9`.

Standardized inputs (batch repositories, GitHub Enterprise metadata, CMDB
records, CVE and control feeds) flow in; structured reports, SARIF artifacts,
remediation DTOs, and validation reports flow out. See
[`docs/architecture.md`](docs/architecture.md) for stage-by-stage detail.

---

## Skills

Each LLM-driven pipeline stage is implemented as a composable, reusable skill.
Two stages have no dedicated skill of their own: **S9** (SARIF emission) is
fully deterministic, and **S5** (pre-filter) runs deterministic gates plus one
*optional* semantic-dedup call that reuses the S7 `dedup` role — fired only when
the survivor count reaches `step7_dedup.pre_verify_threshold` (default 25) and
`step7_dedup.semantic` is on (default true). Skills can be independently tuned,
versioned, and replaced without rewiring the pipeline.

| Stage | Skill |
|---|---|
| S1 — Explore the attack surface | Attack surface mapper (code, CMDB, CVE, controls) |
| S2 — Model threats in business context | AppSec threat modeler (STRIDE, OWASP, trust boundaries) |
| S3 — Strategize and prioritize | Vulnerability research strategist (taint, API boundaries, authorization controls) |
| S4 — Research by specialized lens | Language, Crypto, Logic-bug, Access-control, Batch/ETL, IaC (Deserialization defined but not default-enabled — see `docs/SKILLS.md`) |
| S6 — Adversarial verification | Adversarial reviewer (exploit chain, trust boundary tracing) |
| S7 — Deduplicate findings | Finding deduplicator (semantic collapse of overlapping findings, atop a deterministic pass) |
| S8 — Chain construction and reporting | Exploit strategist (CWE, attack paths, remediation) |
| S10 — Remediation agent | Remediation playbooks per CWE–language–framework triple, generating candidate patches and remediation DTOs |
| S11 — Validation panel | Agentic adversarial panel (`security-architect`, `penetration-tester`, optional `cross-repo-analyzer`) scoring fixes against weighted gates |

The standalone `validate` command uses the S11 validation panel (Claude Agent
SDK) to grade each remediation DTO against fix-quality gates and emit verdicts
such as `validated`, `validation_failed`, and `needs_review`.

See [`docs/SKILLS.md`](docs/SKILLS.md) for configuration and extension guidance
and [`docs/remediation.md`](docs/remediation.md) /
[`docs/validation.md`](docs/validation.md) for S10/S11 behavior.

---

## Requirements

- **Python ≥ 3.11**
- LLM credentials for the profile you run. For `default.yaml`: Claude Code
  login for S1–S9, and `ANTHROPIC_API_KEY` for S10 and S11. For `codex.yaml`:
  a native `codex login` (including ChatGPT authentication), with no API key.
  For `sdk.yaml`: `ANTHROPIC_SDK_API_KEY`. For mixed/custom routing, provide
  credentials for each backend in use; see [Configure](#configure).
- The `claude` CLI — required for S1–S9 in the default profile (`via: cli`);
  optional for all-SDK profiles.

---

## Install

Recommended — install into a virtual environment (keeps the install isolated).

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
```

Or install it as an isolated global command (no venv needed) on any OS:

```bash
pipx install .
```

Either way this installs one command: `vvaharness`. Direct adapters for
Anthropic SDK, Claude CLI, Codex CLI, and OpenAI-compatible endpoints ship out
of the box; the DeepAgents harness powers supported post-scan roles. The
Anthropic SDK and OpenAI backends need only an API key, but the **Claude CLI
backend used by the default profile also requires the external `claude` CLI to
be installed separately** (see [Requirements](#requirements)).

The tree-sitter parsers used by taint seeding (`tree-sitter` + `tree-sitter-language-pack`) are included in the default install — no extra flag needed.

---

## Configure

**macOS / Linux:**

```bash
cp .env.example .env          # then edit .env to add your credential (see below)
```

**Windows (PowerShell):**

```powershell
Copy-Item .env.example .env   # then edit .env
```

`vvaharness` loads a `.env` automatically — it is searched for starting in the
working directory and walking up the parent directories — so no manual `source`
step is needed. (Variables you export yourself still take precedence.)

Which credential you need depends on the backend each role uses:

- **`via: cli`** (the default profile) — use a Claude Code session instead of an
  API key: run `claude` then `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN` (from
  `claude setup-token`).
- **`via: codex`** — run `codex login`, then select `codex.yaml`. This reuses
  native Codex/ChatGPT authentication through `codex exec`; no
  `OPENAI_API_KEY` is required. Calls are ephemeral and read-only.
- **`via: sdk`** — set `ANTHROPIC_SDK_API_KEY`. Behind a private gateway, also
  set `ANTHROPIC_SDK_BASE_URL` (plus `ANTHROPIC_SDK_CA_CERT` /
  `ANTHROPIC_SDK_CLIENT_CERT` for mTLS).
- **`via: openai`** — set `OPENAI_API_KEY` (and `OPENAI_BASE_URL` for an
  OpenAI-compatible endpoint).

The default profile (`vvaharness/config/profiles/default.yaml`) is a mixed-backend
layout:

| Stages | Backend | Credential needed |
|---|---|---|
| S1–S9 (detection) | `via: cli` | Claude Code login (`claude` then `/login`, or `CLAUDE_CODE_OAUTH_TOKEN`) |
| S10 remediate | `via: deepagents`, `provider: anthropic` | `ANTHROPIC_API_KEY` |
| S11 validate | `via: deepagents`, `provider: anthropic` | `ANTHROPIC_API_KEY` |

No shipped profile runs the full S1–S11 pipeline on a Claude Code login alone.
`sdk.yaml` covers S1–S11 with a single `ANTHROPIC_SDK_API_KEY` (all roles
`via: sdk`; also enables S4 majority voting). `taint.yaml` is login-only but
ships with S10/S11 disabled. To use the multi-backend layout (Claude CLI +
Anthropic SDK + OpenAI roles), copy `vvaharness/config/profiles/full.yaml` to
`./config.yaml` and edit it.

For source→sink callgraph scanning, use the shipped `taint.yaml` profile:
`vvaharness/config/profiles/taint.yaml`.

For a native Codex detection run:

```bash
codex login
vvaharness scan --repo /path/to/target \
  --config vvaharness/config/profiles/codex.yaml
```

This runs S0–S9 with the standard Markdown, SARIF, error-log, checkpoint, and
manifest artifact types. The profile disables S10 remediation and S11
validation because the Codex transport is deliberately read-only.

For a step-by-step walkthrough — picking a profile, config resolution order,
secrets in `.env`, and copy-then-edit customization — see
**[docs/configuration.md → Setting up your config](docs/configuration.md#setting-up-your-config)**.

---

## Run

```bash
vvaharness scan --repo /path/to/target --application-id 12345   # full 11-stage run — ⚠ edits source (S10 fix mode)
vvaharness scan --repo /path/to/target --stop-after s9          # detection only — no code changes
```

Batch (clone + scan, one report per AppId):

```bash
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones
```

A `scan` run writes `run_manifest.json` (tool version, model roles, config hash,
target git SHA, timing) into the working directory. (`doctor` and `estimate` do
no scan and write no manifest.) Remember the default profile **edits source in
the target** — see the [Quick start](#quick-start) warning.

---

## Validation

`vvaharness validate` checks the fixes that `remediate` produced. It discovers
the per-finding reports under
`<repo>/security-remediation/<NN_slug>/remediate_report.json`, then runs an
agentic adversarial panel (Claude Agent SDK) that scores each fix and records a
verdict (`validated`, `validation_failed`, or `needs_review`). The panel is
**read-only** — it reads the repo and writes only its own validation artifacts,
never applies a patch, and runs no Docker. Re-runs are idempotent.

```bash
vvaharness validate --repo /path/to/target
```

Validation runs on a Harness backend (`via: cli`, `via: sdk`, or `via: deepagents`);
a legacy `via: openai` role is routed to `via: deepagents` with the OpenAI provider,
so it works without a profile change. For the panel personas, weighted gates, and verdict
thresholds, see [`docs/validation.md`](docs/validation.md) and
[`docs/remediation.md`](docs/remediation.md).

---

## Use with an AI agent (Codex / Claude / Copilot / Gemini)

```bash
vvaharness setup --install-agents
```

This detects your installed agent(s) and drops the operating instructions where
each one reads them — `AGENTS.md` (cross-tool), `.github/copilot-instructions.md`
(Copilot), `CLAUDE.md` + a Claude skill in `~/.claude/skills/` (Claude Code),
`GEMINI.md` (Gemini CLI). Existing files are left untouched. See
[AGENTS.md](AGENTS.md) for the operating rules and [docs/SKILLS.md](docs/SKILLS.md)
for the analysis capabilities.

---

## Output

Per target, under `<target>/security-scan/`:

- `<module>_<ts>_report.md` — findings + dropped-findings appendix
- `<module>_<ts>_report.sarif` — SARIF 2.1.0
- `<module>_<ts>_errors.jsonl` — non-fatal errors

With the default profile, a scan also writes
`<target>/security-remediation/<NN_slug>/remediate_report.json` and **edits
source files in the target repo** (S10 fix mode — see the
[Quick start](#quick-start) warning); pass `--stop-after s9` to skip.
`run_manifest.json` is written to the working directory.

Pipeline checkpoints and resume state are kept **outside** the scanned repo, in
a SQLite state DB at `$VVAHARNESS_STATE_DIR/vvaharness.db` (default
`~/.vvaharness/state/`); prune old runs with `vvaharness gc`.

---

## Limitations (read before you trust output)

- **LLM-generated, non-deterministic.** Findings and fixes are triage candidates,
  not confirmed vulnerabilities or production-ready patches — human review is
  required. Two runs may differ. Majority-vote FP filtering runs on the `sdk`
  and `openai` backends; the `cli` backend (no temperature control) always runs
  single-pass, as do SDK/OpenAI models that reject `temperature`.
- **Token-hungry.** Caps are per-stage / per-finding, not global. Use
  `vvaharness estimate` and the `step*.max_budget_usd` knobs.
- **No published accuracy numbers yet.** Precision/recall figures are not yet
  published.
- **Elevated privilege.** This tool runs with elevated privilege and must only be
  used against trusted repositories by authorized operators. Running VVAH
  against untrusted or malicious input may expose host credentials, API keys,
  and sensitive files. If you must scan a less-trusted target, see
  [`docs/security.md` → Hardening for less-trusted or sensitive targets](docs/security.md#hardening-for-less-trusted-or-sensitive-targets).
- **Validation (S11) needs a Harness backend.** The panel runs on `via: cli`,
  `via: sdk`, or `via: deepagents`; a legacy `via: openai` validate role is routed
  to `via: deepagents` with the OpenAI provider rather than refused.
- **Remediation fix mode is effectively.** Applying a fix needs
  the agent's file-mutation tools (`Edit`/`Write`), which only the `via: cli`
  and `via: sdk` backends expose; the OpenAI-compatible backend is sandboxed to
  Read/Glob/Grep and **cannot edit files**. A `via: openai` `models.remediate`
  role therefore can only run `--mode report-only`.
- **Missing post-scan credentials are a warning, not a fatal error.** If
  `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is absent but only required by S10
  (remediate) or S11 (validate), preflight emits a `WARN` and skips that stage —
  S1–S9 detection still runs. Missing credentials for detection roles remain fatal.
- **`via: deepagents` is only valid for `models.remediate` and `models.validate`.**
  Configuring it for any S1–S9 detection role causes an immediate exit before
  any tokens are spent.
- **In-scan S11 validation is budget-capped; standalone `validate` is not.**
  In-scan S11 applies `step_validate.max_findings` (top-N by CVSS score);
  `vvaharness validate --all` bypasses this cap and re-validates all findings.
- **Structured taint evidence is Python, Java, and C# only.** For all other
  languages the callgraph engine falls back to reachability-based seed paths
  with no typed transfer edges, no sanitizer neutralization, no framework-source
  detection, and no reflection tracking. LLM stages still run; taint evidence
  just won't be present in the prompt context.
- **Review remediation fixes before you rely on them.** The remediation agent
  proposes — and in fix mode applies — code changes, but VVAH does **not**
  compile, build, or run tests against the patched tree. Always review the
  generated fixes and build/test them yourself before merging.

See `docs/` for configuration, models, pipeline, and output details.

---

## Security

Report vulnerabilities responsibly — see [SECURITY.md](SECURITY.md). Please do
not open security issues in a public tracker.

---

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Original work copyright 2026 Visa, Inc.; independent
modifications copyright 2026 Lily Feng.

Third-party dependencies are installed from PyPI at install time (not bundled
in this repository); their licenses are inventoried in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

See [CHANGELOG.md](CHANGELOG.md) for release history.
