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

# Operational Security

> What the agent can and cannot do, how cloned repos are isolated, what gets
> redacted, and what you should never scan with this tool.

> **Reporting a vulnerability in the harness itself?** See
> [`SECURITY.md`](../SECURITY.md) at the repo root.

## Execution boundary

vvaharness is a **static** analyzer: it reads source, it does not build, compile,
or run the target's code. The analysis stages reason over file *contents* and a
textual call graph.

The one place shell execution is possible is the **`cli` backend with `Bash`
enabled** — no shipped profile does this; it requires a `via: cli` role that
adds `- Bash` to its `allowed_tools`. There the `claude` subprocess can run shell commands inside
the target directory for repo inventory and evidence retrieval. The `sdk` and
`openai` backends have **no Bash** — they use only the sandboxed Read/Glob/Grep
tool loop (below). DeepAgents has no shell backend: S10 fix mode can use a
repo-confined filesystem, while S11 agents are read-only. If you are scanning untrusted code and want to avoid any shell
execution against it, use a profile whose agentic roles are `via: sdk` /
`via: openai`, or keep `Bash` out of `allowed_tools`.

## Repo isolation / sandboxing

For the `sdk` and `openai` backends, the agentic Read/Glob/Grep tools are
implemented in `vvaharness/backends/localtools.py` and **confined to the scanned
repo root**. `_jail()` resolves every requested path against the root and rejects
anything that escapes it — `..` traversal, absolute paths that resolve outside
the root, and symlinks pointing outside all return an error string instead of
file content. This matters because
the s6 verifier reads attacker-influenced finding text; a prompt-injected path
must not be able to exfiltrate files outside the repo. The tools also cap output
(≈200 KB per read, 200 grep matches, 500 glob hits) so a single call can't dump
an unbounded amount of data.

Batch mode clones each repo under the `--workspace` directory and (unless
`--keep-clones`) deletes the clone after scanning, preserving only the folders in
`output.preserve_on_cleanup` (the shipped profiles keep
`[security-scan, security-remediation]`; the built-in fallback when the key is
omitted is `[security-scan]`). Pipeline checkpoints
are stored outside the clone in the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`).
Payloads are **JSON bytes, never pickle** — loaded via pydantic
`validate_json` so there is no constructor/REDUCE opcode and therefore no
code-execution path (CWE-502). A hostile target repo cannot plant a
checkpoint that `--resume` would execute; at worst a tampered payload fails
schema validation and the stage is re-run.

## Validation (`validate` command) trust model

`vvaharness validate` runs an agentic adversarial panel over the remediation
DTOs the `remediate` command produced. It reads the repo to judge each fix but
**never** modifies the scanned checkout, so its guard rails centre on the
agent's permission sandbox. (For the command reference — flags, gates,
verdicts — see [validation.md](validation.md); this section covers the trust
model only.)

- **Read-only sessions.** Parent and persona agents can inspect the staged repo
  with Read/Grep/Glob and dispatch personas, but receive no Write/Edit/Bash.
  DeepAgents also exposes deterministic read-only diff, changed-line, impact,
  pattern-scan, and test-inventory helpers. Agents return structured output;
  host code alone writes temporary `validation_report.json` /
  `synthesized_gates.json`, updates the DTO, and removes the workspace. No
  target build or test is executed.
- **Know which endpoint receives finding data.** `models.validate` resolves to
  `via: cli`, `via: sdk`, or `via: deepagents`, and a legacy `via: openai` value is
  routed to `via: deepagents` with the OpenAI provider when the step starts. The
  panel's egress target is therefore the *provider*, not the `via:` spelling: a
  `deepagents` role with `provider: openai` sends finding data to an
  OpenAI-compatible endpoint. **The shipped `default.yaml` stays on Anthropic**
  (`{id: claude-opus-5, via: deepagents, provider: anthropic}`), so validation
  data does not leave an Anthropic endpoint by default. To keep it that way,
  leave the validate role on `via: cli` / `via: sdk`, or on `via: deepagents`
  with `provider: anthropic`; repointing it at an OpenAI provider route changes
  the egress target. If your policy permits an approved OpenAI-compatible gateway,
  pin it with `OPENAI_BASE_URL`. `vvaharness doctor` prints the resolved backend
  and discloses routing (`via:openai routed to deepagents`).
- **Adversarial panel.** Two always-on personas — a `security-architect` and a
  `penetration-tester` — review each fix independently, plus a conditional
  `cross-repo-analyzer` spawned only when a fix spans 2+ repositories; the
  panel's shared launch prompt is primed with per-CWE bypass cheatsheets from
  `./inputs/validator_hints.yaml` (the penetration-tester is their primary
  consumer) so weak or partial fixes are scored down rather than rubber-stamped.
- **Closed results are not silently re-graded.** A DTO whose host verdict was
  FIXED is written back with the terminal `validated` status, which is *not* in
  the validatable set — a repeated `validate` skips it. A non-passing verdict is
  written back as `validation_failed`, which **stays re-validatable** on the next
  run (so a corrected patch re-drives with no manual DTO edit). `--resume` may
  reuse a matching checkpoint only for a DTO that is still in a validatable
  status; terminal `validated` DTOs are filtered out before checkpoint lookup.
- **Read-only against the repo.** Nothing the panel produces is auto-applied;
  the verdict and weighted gate scores are written back into each DTO's
  `validation` block for human review.

## Redaction (`vvaharness/report/redact.py`)

Card data, PII, and credential material are masked at two boundaries:

- **Write boundary** — the Markdown report and the SARIF JSON are passed through
  `redact()` / `redact_tree()` before they land on disk, so every rendered field
  (description, code snippet, exploit scenario, verifier reasoning, …) is covered.
- **Outbound tool content** — `localtools` runs `Read`/`Grep` results through
  `redact_counts()` before handing them back to the model, so quoted source that
  the agent retrieves is scrubbed before it leaves the process.

Detectors are tuned for **high precision** (few false positives):

- **Card / PAN** — 13–19 digit runs gated by both the Luhn checksum *and* an
  IIN/BIN network check (Visa, Mastercard, Amex, Discover, JCB, UnionPay, Diners,
  Maestro, RuPay), so random Luhn-passing ids aren't masked. Also `CVV`/`CVC` and
  magnetic `TRACK` data.
- **PII** — SSN/ITIN, both separated (`NNN-NN-NNNN`) and keyword-gated bare
  9-digit, validated by area/group/serial rules.
- **Cloud / SaaS keys** — AWS (`AKIA…`), GitHub (`ghp_…`, `github_pat_…`), Slack,
  Stripe, Google API, Azure SAS, Twilio.
- **Tokens & keys** — JWTs, `Bearer`/`Basic` credentials, and PEM private-key
  blocks.
- **URL credentials** — the password component of a `scheme://user:secret@host`
  URL (the scheme and username are preserved, only the secret is masked).
- **Generic secrets** — values assigned after a credential keyword
  (`password`, `api_key`, `access_key`, `client_secret`, `auth_token`, …). Strong
  keywords always mask; values after prose-ambiguous keywords (`secret`, `token`)
  are left alone when they look like ordinary words or code expressions, and
  obvious placeholders (`${VAR}`, `changeme`, `xxxx`, `<redacted>`, …) are never
  masked.

Redaction is a defense-in-depth measure for the written artifacts and outbound
tool reads — it is **not** a guarantee that no sensitive token ever reaches the
model (see below).

## Data sent to the LLM provider

To analyze a repo, the pipeline necessarily sends the **source code under scan**
to whichever provider each role is routed to: the Anthropic API (`via: sdk`),
an OpenAI-compatible endpoint (`via: openai`), or the Anthropic backend the
`claude` CLI is logged into (`via: cli`). DeepAgents sends S10/S11 context to
the provider selected on that role (`anthropic` or `openai`). Use a backend/endpoint your
organization permits for the code in question — e.g. a private Anthropic gateway
(`ANTHROPIC_SDK_BASE_URL` / `ANTHROPIC_BASE_URL`) rather than the public API —
and for sensitive code prefer one with a no-/zero-retention data policy.

The tool never prints credential *values* in `setup`/`doctor` output (only
set/unset presence), and the redaction pass scrubs quoted source before it is
written to disk or returned through the sandboxed tools.

## Hardening for less-trusted or sensitive targets

The boundaries above (tool jail, redaction, approved endpoint) assume the
implicit threat model: an **authorized operator**, running with **elevated
privilege**, against a repository they **trust**. The further a target is from
that — third-party code, an unreviewed fork, a dependency, anything an outside
party can influence — the more these compensating controls matter. They build on,
rather than repeat, the sections above; layer them.

- **Add host-level isolation around the in-process jail.** *Repo isolation* above
  confines the agent's file *reads* to the repo; it does not bound host CPU,
  memory, or disk. Run scans in a disposable container or VM with resource and
  file-count/inode quotas, as a least-privileged user whose write access is
  confined to the workspace — so a pathological repository (e.g. a huge file
  inventory) can't exhaust the host, and any unexpected write or deletion lands on
  throwaway storage rather than a sensitive host path.
- **Scan a copy, not a live working tree.** Point the tool at a fresh checkout or
  snapshot, and don't run a fix-mode scan while other processes are modifying the
  same files. Review applied fixes as a diff before merging — vvaharness does not
  build or test the patched tree.
- **Enforce the endpoint and git-host choice at the perimeter.** *Data sent to the
  LLM provider* covers picking an approved endpoint in config; for a less-trusted
  target also restrict the scanner host at an egress proxy or firewall to only
  that endpoint and the git host(s) you intend to clone from, and use short-lived,
  minimally-scoped clone tokens — so a crafted repository reference or batch
  manifest can't redirect a credentialed clone, or finding data, to an
  attacker-chosen host.
- **Treat manifests and injected context as trusted configuration.** The
  `--repo-file` / repos CSV and any injected files (CMDB, CVE, controls) decide
  what gets cloned and where credentials are sent. Never run ones supplied by an
  untrusted party; review them before a batch run.
- **Verify scan coverage.** Confirm the run analyzed the trees you care about by
  reviewing the excluded/skipped paths it reports. For sensitive or less-trusted
  repositories, disable AI auto-exclusion (`--no-auto-step1`) and set scope
  explicitly, so repository content can't quietly narrow what gets scanned and
  drop a vulnerable tree.
- **Remember findings can be steered both ways.** Beyond being triage candidates
  to verify (see below), results can be influenced by prompt injection in the
  repo — to *suppress* real issues or *fabricate* false ones. Independently
  confirm expected high-risk components were covered, and don't feed raw output
  into automated gating, ticketing, or merge decisions without human review.

## What not to scan

- Code you are **not authorized** to test, or that you may not share with the
  configured LLM provider/endpoint.
- Data you must not egress — secrets, customer data, PII/PHI, financial data, or
  trade secrets. Redaction reduces but does not eliminate exposure, so do not
  point the tool at a repository whose contents may not leave your environment
  under the backend you've configured. This applies to **realistic test
  fixtures** too: synthetic or sample card numbers, keys, and tokens can still
  reach the model, because the detectors deliberately favour precision over
  masking clearly-fake values — scrub or synthesize them out before scanning.

> Findings are LLM-generated **triage candidates, not confirmed vulnerabilities**
> — human review is required.
