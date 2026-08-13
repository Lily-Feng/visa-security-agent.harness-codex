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
# AGENTS.md — How to operate vvaharness (for AI coding agents)

You are running **vvaharness**, a *released* command-line security-scanning
product. Your job is to **operate it**, not to develop or repair it.

This file is the operating manual for AI agents (Claude Code, GitHub Copilot,
Cursor, Codex, etc.). Read it fully before doing anything in this repo.

---

## 🔴 The three rules (most important)

1. **Do NOT modify the product's source to make a scan run.** Files under
   `vvaharness/` are the shipped tool. If a scan won't start, that is an
   environment problem to fix (below) or a bug to report — never a reason to
   edit `claude_cli.py`, a stage, or any package file. Hand-edited source =
   non-reproducible, unsupported results.
2. **Do NOT hand-write config files.** Everything needed is in the shipped
   profiles (`vvaharness/config/profiles/*.yaml`). Pick a profile with
   `--config`; never create a bespoke `config-*.yaml` to work around an error.
3. **When anything fails, run `vvaharness setup` (or `doctor`) and fix the
   environment it points to** — then re-run the same command. Do not improvise.

If the tool genuinely misbehaves after `setup` is green, report it as a bug
(stack trace via `VVAHARNESS_DEBUG=1`). Don't patch around it.

---

## What this tool does
An S0–S9 detection pipeline plus remediation/validation. S0 is a configurable
static seed stage (`step0`) enabled by the shipped `default` and `taint`
profiles. Their rules-mode configuration needs operator-supplied generated
source/sink YAML to produce a seed; no such rule pack is bundled. Without it,
S0 returns an empty seed and S1 and the later stages continue. The core
detection flow is survey → threat-model →
decompose → deep-dive → pre-filter → adversarial-verify → dedup → chain →
SARIF. It emits a Markdown report + SARIF 2.1.0.

> ⚠️ **The default profile does more than scan — it also remediates and
> validates.** With the shipped `default.yaml` (`step_remediate.enabled: true`
> and `step_validate.enabled: true`), `vvaharness scan` continues past s9 into
> **Step 10 — Remediate** and **Step 11 — Validate** (S0 plus S1–S11). When
> findings, credentials, and a successful fix session are available, Step 10 runs the Remediation Agent in
> **fix mode: it edits source files in the target repo** and writes
> `<repo>/security-remediation/`. Step 11 then runs the
> agentic validation panel over those fixes. If you only want detection (no
> changes to the target), pass `--stop-after s9`, or use a profile with
> `step_remediate.enabled: false` / `step_validate.enabled: false`.

`remediate` and `validate` are also standalone commands: `vvaharness remediate`
proposes/applies fixes over a prior scan's findings, and `vvaharness validate`
runs the agentic adversarial panel over the remediation DTOs (s11 panel —
which first discovers the DTOs awaiting validation, then runs the panel). See `docs/SKILLS.md` for the analysis capabilities and
`docs/USER_GUIDE.md` for the full command/flag reference.

## First run — always start here
```bash
pipx install .            # or: pip install .   (one command on PATH: vvaharness)
vvaharness setup         # checks Python, agents, keys, gateway, config
```
`setup` reports the normal readiness checks and remedies. Do what it says, then
re-run it until green, while also applying the SDK-profile S11 caveat below:
the current probe does not exercise that Agent-SDK launcher.

## Choosing a profile (`setup` recommends a starting point)
| You have… | Use | How |
|---|---|---|
| Claude Code auth + an Anthropic provider key | `default` | default — no flag |
| Anthropic SDK/API credential(s) | `sdk` | `--config vvaharness/config/profiles/sdk.yaml` |
| Multi-provider (Claude auth + Anthropic SDK + OpenAI) | `full` | `--config vvaharness/config/profiles/full.yaml` |
| Claude Code auth, detection only; external rules for an S0 seed | `taint` | `--config vvaharness/config/profiles/taint.yaml` |

The recommendation is a starting point, not proof that every enabled post-scan
stage is ready. Re-run `setup` with the chosen profile and resolve its warnings.

No shipped profile enables `Bash`. To let a `via: cli` role shell out, add
`- Bash` to its `allowed_tools` in your own copy (trusted targets only).

`sdk.yaml` has a post-scan credential split that `setup`/`doctor` can currently
false-green: `ANTHROPIC_SDK_API_KEY` authenticates S1–S10, but its S11 Claude
Agent SDK launcher does not translate that SDK-named key. S11 pins external
`claude` and can reuse an ambient Claude login / `CLAUDE_CODE_OAUTH_TOKEN`, or
use `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`. A standard Anthropic
credential alone can cover all stages because sole-SDK detection accepts it as
a fallback; otherwise pair the SDK-named key with working Claude auth for S11.
For `full.yaml`, the Claude auth already required by its CLI roles can also
serve S11, so standard Anthropic auth is an alternative, not a fourth mandatory
credential.

### Internal gateway note (common cause of 401)
If `ANTHROPIC_API_KEY` is a JWT (`eyJ…`) you are using a gateway/Claude-Code
token. It will **401 against the public API** unless you set the gateway:
```bash
export ANTHROPIC_BASE_URL=https://<your-gateway>/
export NODE_EXTRA_CA_CERTS=$HOME/cacerts.pem   # if it needs a private CA
export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1 # if the gateway returns "400 invalid beta flag"
```
`vvaharness setup` auto-detects this and prints the exact lines **when the active profile uses a `via: sdk` role** (e.g. `sdk`/`full`). The shipped default profile has no `via: sdk` roles (`via: cli` for S1-S9 and `via: deepagents` for S10-S11), so `setup` will not auto-print these — set them yourself if your gateway token needs them. Set them in
your shell or `.env` — **do not** edit the package to work around it.

## Running a scan
```bash
vvaharness estimate --repo /path/to/target          # scope/cost preview, no spend
vvaharness scan --repo /path/to/target --application-id <id> [--config <profile>]
```
- Progress prints per stage (`▶ … / ✓ … (Ns)`). The default runs S0, S1–S9,
  then enabled S10 remediation and S11 validation.
- Output: `<target>/security-scan/*_report.md` and `*.sarif`; an
  `*_errors.jsonl` file is created only when a recoverable error is logged.
- With the default profile, a successful S10 fix session with findings and
  credentials writes `<target>/security-remediation/` and can **edit source
  files in the target repo**, then S11 validates those fixes. Use
  `--stop-after s9` for detection only.
- A `run_manifest.json` (written in the current working directory, not under `security-scan/`) records models/config/timing for the run.
- Findings are **triage candidates, not confirmed vulnerabilities** — say so
  when you summarize them.

## When a scan fails
1. Read the one-line `✗ scan failed: …` message.
2. Run `vvaharness doctor` — fix any ✗ it reports (usually a credential or the
   gateway base-URL).
3. Re-run the same scan command. For a full stack trace: `VVAHARNESS_DEBUG=1`.
4. Still failing with a green `doctor`? **Report a bug. Do not edit source.**

## Cost & safety
- Scans spend real model tokens; large repos are expensive. Use `estimate`
  first and scope with `--repo <subdir>` or `--stop-after s3`.
- Scan only code you are authorized to scan.
- The tool never prints credential values; keep it that way.
- **Validation runs in-scan by default, and is also a standalone command.**
  With the default profile it executes as Step 11 of `scan` (see the warning
  under *What this tool does*); run on its own, `vvaharness validate --repo <path>`
  discovers remediation DTOs written by the model-backed `remediate` command
  (S10). That S11 discovery phase has no model spend; S11 then runs an agentic
  adversarial panel to fill each DTO's
  `validation` block. The default runtime is the DeepAgents backend
  (`via: deepagents`, as shipped in `default.yaml`); `cli` and `sdk` backends run
  the bundled Claude Agent SDK instead. Permitted backends: `via: cli`, `via: sdk`,
  `via: deepagents`; a legacy `via: openai` validate model is routed to
  `via: deepagents` with the OpenAI provider, so the same profile spelling that
  detection and report-only remediation accept also works here. The panel reads
  the repo and writes only its
  own validation artifacts — there is no Docker, and nothing is applied to the
  scanned repo. Re-runs are idempotent (already-`validated` DTOs are skipped;
  `validation_failed` / `needs_review` stay re-validatable).

## Do / Don't (quick reference)
| ✅ Do | ❌ Don't |
|---|---|
| `vvaharness setup` / `doctor` on any error | edit files under `vvaharness/` |
| pick a shipped `--config` profile | hand-write a config-*.yaml |
| set env vars / `.env` for creds & gateway | paste keys into config or source |
| report bugs with `VVAHARNESS_DEBUG=1` | "fix" the tool to force a run |
| invoke from outside the target with explicit `--config` | `cd` into the scanned repo then run |
| use `via: sdk` or `via: openai` for untrusted targets | use `via: cli` against repos you didn't author |
| re-run a failed scan clean | pass `--resume` against an untrusted repo |
