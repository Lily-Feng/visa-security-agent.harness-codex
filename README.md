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

# Visa Vulnerability Agentic Harness — Agentic SAST Pipeline

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Python](https://img.shields.io/badge/python-%E2%89%A5%203.10-blue.svg)
![Version](https://img.shields.io/badge/version-1.1.0-informational.svg)
![Output](https://img.shields.io/badge/output-Markdown%20%2B%20SARIF%202.1.0-green.svg)

VVAH is Visa's open-source harness for autonomous vulnerability discovery,
remediation, and validation using frontier AI models, built on learnings from
[Project Glasswing](https://www.anthropic.com/glasswing) (Anthropic's
initiative for AI-assisted vulnerability research).

VVAH runs as a four-phase, eleven-stage pipeline from code ingest to validated
fix:

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

Multi-model by design, VVAH works with Anthropic Claude, OpenAI-compatible
models, or a combination via a vendor-neutral abstraction layer. No single
provider is a hard dependency, although current remediation and validation
capabilities require Anthropic models for full functionality.

For setup, see [`docs/SETUP_GUIDE.md`](docs/SETUP_GUIDE.md). This repository is
not currently accepting external code contributions; see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

> **Authorized use only.** Run scans only against code you own or have explicit
> permission to test. Findings and fixes are LLM-generated triage candidates
> that require human review — see [Limitations](#limitations-read-before-you-trust-output).

**Docs:** [SETUP_GUIDE.md](docs/SETUP_GUIDE.md) — install & configuration ·
[USER_GUIDE.md](docs/USER_GUIDE.md) — commands & options ·
[remediation.md](docs/remediation.md) · [validation.md](docs/validation.md) ·
[Project Glasswing white paper](https://corporate.visa.com/content/dam/VCOM/corporate/visa-perspectives/security-and-trust/documents/project-glasswing.pdf) — technical background.

**Fork companion guides:**
[Enterprise Security Companion](enterprise-security/README.md) — host, runtime,
cloud, identity, supply-chain, detection, response, and post-scan assurance ·
[Codex-Only Direction](codex/README.md) — native Codex backend plan,
authentication boundary, implementation milestones, efficiency, and safety.

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

### Detection pipeline (`scan`, S1–S9)

Nine detection stages combine deterministic controls with frontier-model
reasoning to produce structured, exploit-validated findings.

| Stage group | Stages | Purpose |
|---|---|---|
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

- **Python ≥ 3.10**
- An LLM credential — a Claude Code login (run `claude` then `/login`) for the
  default profile, **or** an Anthropic API key (`ANTHROPIC_SDK_API_KEY`) /
  `OPENAI_API_KEY` if you switch roles to `via: sdk` / `via: openai`; see
  [Configure](#configure).
- The `claude` CLI — required for the default profile (every role `via: cli`);
  optional otherwise.

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

Either way this installs one command: `vvaharness`. All three backend adapters
(Anthropic SDK, Claude CLI, OpenAI-compatible) ship out of the box. The
Anthropic SDK and OpenAI backends need only an API key, but the **Claude CLI
backend used by the default profile also requires the external `claude` CLI to
be installed separately** (see [Requirements](#requirements)).

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
- **`via: sdk`** — set `ANTHROPIC_SDK_API_KEY`. Behind a private gateway, also
  set `ANTHROPIC_SDK_BASE_URL` (plus `ANTHROPIC_SDK_CA_CERT` /
  `ANTHROPIC_SDK_CLIENT_CERT` for mTLS).
- **`via: openai`** — set `OPENAI_API_KEY` (and `OPENAI_BASE_URL` for an
  OpenAI-compatible endpoint).

The default profile (`vvaharness/config/profiles/default.yaml`) runs detection
stages (S1–S8) through the `claude` CLI, with the remediation (S10) and
validation (S11) roles pinned to a higher-tier model — all `via: cli`, so your
Claude Code login is enough, no SDK key required. (`sdk.yaml` runs the same
roles via the Anthropic SDK instead — set `ANTHROPIC_SDK_API_KEY` — and turns
on S4 majority voting.) To use the multi-backend layout (Claude CLI +
Anthropic SDK + OpenAI roles), copy `vvaharness/config/profiles/full.yaml` to
`./config.yaml` and edit it.

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

Validation is **Anthropic-only** (`models.validate` must run `via: cli` or
`via: sdk`); a `via: openai` validate role is refused (the validate step aborts
with exit code 2). For the panel personas, weighted gates, and verdict
thresholds, see [`docs/validation.md`](docs/validation.md) and
[`docs/remediation.md`](docs/remediation.md).

---

## Use with an AI agent (Claude / Copilot / Gemini)

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
- **Validation (S11) is Anthropic-only.** The validation panel runs only on
  Anthropic models (`via: cli` or `via: sdk`); a `via: openai` validate role is
  refused.
- **Remediation fix mode is effectively Anthropic-only.** Applying a fix needs
  the agent's file-mutation tools (`Edit`/`Write`), which only the `via: cli`
  and `via: sdk` backends expose; the OpenAI-compatible backend is sandboxed to
  Read/Glob/Grep and **cannot edit files**. A `via: openai` `models.remediate`
  role therefore can only run `--mode report-only`.
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
[NOTICE](NOTICE). Copyright 2026 Visa, Inc.

Third-party dependencies are installed from PyPI at install time (not bundled
in this repository); their licenses are inventoried in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

See [CHANGELOG.md](CHANGELOG.md) for release history.
