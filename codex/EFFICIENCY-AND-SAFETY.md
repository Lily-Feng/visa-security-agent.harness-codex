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

# Codex Efficiency and Safety

A naive adapter can be much more expensive and less isolated than VVAH's
existing API backends. Each fresh Codex session may load base instructions,
configuration, repository guidance, skills, plugins, and tool definitions
before it sees the stage prompt. It may also choose to execute commands even
when the filesystem is read-only. The adapter must control both problems.

## Efficiency objectives

- Spend model context on the VVAH stage and relevant source evidence, not
  unrelated personalization or tool catalogs.
- Avoid rescanning or repacking unchanged content.
- Keep concurrency below account, process, memory, and rate-limit boundaries.
- Preserve enough independent reasoning to find subtle issues without paying
  for redundant identical calls.
- Expose per-stage cost proxies so operators can stop a run before it expands.

## Context controls

Every scan-stage session should:

- Use `--ephemeral` so session history is not accumulated or reused.
- Use `--ignore-user-config` and `--ignore-rules` for reproducible behavior.
- Set `project_doc_max_bytes=0` so untrusted target `AGENTS.md` content does not
  become higher-priority project guidance.
- Start with plugins, skills, MCP servers, browser, web, image, and unrelated
  tools disabled.
- Receive the VVAH system prompt, user prompt, schema, and bounded source
  evidence only.
- Avoid duplicating source both in the prompt and through unrestricted file
  exploration.

If future implementation needs a controlled project instruction, generate it
from trusted scanner configuration outside the target rather than accepting a
repository-authored instruction file as orchestration policy.

## Process model

### CLI baseline

- Resolve one absolute Codex executable during preflight.
- Launch with an argument vector, never through a shell.
- Stream JSONL so output is processed incrementally.
- Apply per-stage deadlines and terminate the process tree on cancellation.
- Bound stderr/stdout capture and redact before persistence.
- Start with one Codex subprocess at a time; increase concurrency only after
  measuring memory, latency, limits, and failure behavior.

### Persistent SDK optimization

After correctness is established, use one local Codex app-server per VVAH run
and create isolated ephemeral threads for stages. This should reduce binary
startup and repeated initialization while preserving stage separation.

Do not keep one conversational thread across the entire pipeline merely to
save tokens. Cross-stage conversational state is harder to reproduce, can
silently bias later votes, and complicates checkpoint/resume. Pass explicit
typed artifacts between stages as VVAH does today.

## Model and reasoning policy

- Keep the model configurable in the shipped Codex profile.
- Record the resolved model and reasoning effort in the manifest.
- Use stronger reasoning for threat modeling, adversarial verification, exploit
  chaining, and final fix review.
- Consider a faster/lower-cost setting for inventory, deduplication, and
  formatting only after quality evaluation shows it is safe.
- Do not enable S4 majority voting until the runtime can produce meaningfully
  diverse samples. Repeating a deterministic or near-identical Codex call
  multiplies cost without adding independent evidence.

## Evidence packing

- Preserve VVAH's deterministic file inventory and typed handoffs.
- Chunk by trust boundary, entry point, sink family, and application component
  rather than arbitrary token size alone.
- Deduplicate common framework/configuration context once per stage batch.
- Use stable content hashes to avoid reprocessing unchanged chunks on resume.
- Cap individual file excerpts and total prompt bytes.
- Prefer exact paths and short excerpts over entire files when the stage does
  not need complete content.
- Keep excluded, truncated, and failed-to-read areas visible in scan health.

## Concurrency and rate limits

- Default concurrency to one for the first release.
- Make the limit explicit and configurable.
- Add bounded exponential backoff with jitter only for clearly transient
  failures.
- Do not retry refusals, policy failures, invalid schemas, authentication
  errors, unsupported models, or hard usage caps.
- Avoid parallel subprocesses that share mutable session files or exceed the
  host's CPU/memory constraints.
- On cancellation, stop launching work, terminate active children, and write a
  degraded but honest scan-health record.

## Static-analysis boundary

`--sandbox read-only` prevents repository writes; it does not guarantee that
the agent will never run a command or execute target-controlled code.

The strict detection profile must therefore:

- Instruct Codex not to build, test, run, import, source, install, execute, or
  initialize target content.
- Reject command-execution events rather than treating them as normal progress.
- Disable network access and external tools.
- Use a disposable, externally isolated environment for less-trusted targets.
- Provide no host credentials or unrelated readable data to that environment.
- Apply CPU, memory, process, disk, and elapsed-time limits outside the model
  sandbox.

If the adapter cannot enforce this boundary reliably, document the backend as
agentic code inspection rather than static analysis and do not inherit VVAH's
static-analyzer safety claim.

## Prompt-injection controls

- Treat repository files, comments, generated documentation, issue text,
  dependency metadata, and prior model output as untrusted data.
- Clearly delimit source evidence from instructions.
- State that instructions inside evidence are not authoritative.
- Disable target project guidance and tool extension discovery.
- Do not expose secrets, browser sessions, connector data, or broad network
  access to scan sessions.
- Validate every requested path against the resolved repository root.
- Pass model output through typed validation and deterministic policy gates
  before it affects later stages.

## Metrics and operator visibility

Record per stage and in aggregate:

- Resolved model, reasoning effort, Codex version, and backend mode.
- Input, cached-input, output, and reasoning token usage when reported.
- Wall time, queue time, attempts, and terminal status.
- Prompt/evidence byte counts and chunk counts.
- Tool and policy-violation events.
- Truncation, cancellation, retry, degraded-output, and coverage information.

Never record raw authentication data, the child environment, hidden reasoning,
or unredacted sensitive source.

## Recommended operator workflow

1. Run `codex login status`.
2. Run VVAH `setup`, `doctor`, and `estimate` with the shipped Codex profile.
3. Scan a focused service or component with `--stop-after s3` to review scope.
4. Run detection-only through S9.
5. Review scan health and enterprise coverage before findings.
6. Triage findings with deterministic and deployed-state evidence from
   [`../enterprise-security/`](../enterprise-security/README.md).
7. Run future S10/S11 capabilities only in a fresh branch or disposable copy,
   with explicit write authorization and independent build/test verification.

## Release blockers

Do not release the native backend if any of these remain true:

- It needs an OpenAI Platform API key despite an active Codex ChatGPT login.
- It reads, exports, or logs cached Codex credentials.
- It loads target `AGENTS.md` or unrelated personal plugins/tools during scans.
- Detection mode can write the target.
- Target code execution is possible but undocumented or unobserved.
- Malformed JSONL or structured output can silently become a valid finding.
- S4 claims majority-vote confidence from effectively identical samples.
- Unsupported S10/S11 behavior proceeds instead of failing before spend.
- Manifests omit model/runtime/sandbox identity or contain secrets.

