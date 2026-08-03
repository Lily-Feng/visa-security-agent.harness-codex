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

# Native Codex Backend Implementation Plan

## Goal

Add a `via: codex` transport that preserves VVAH's stage contracts while using
the authenticated local Codex runtime. The fork should be able to complete
S1–S9 without an Anthropic dependency or an OpenAI Platform API key when the
operator is already signed in to Codex with ChatGPT.

## Non-goals for the first milestone

- Do not emulate the OpenAI Chat Completions API with cached Codex credentials.
- Do not read or manipulate Codex credential files.
- Do not enable S10 source edits.
- Do not claim S11 support.
- Do not run target builds, tests, lifecycle scripts, containers, or services.
- Do not load arbitrary plugins, MCP servers, skills, personal instructions,
  or target-controlled agent instructions into scan-stage sessions.
- Do not remove or redesign upstream backends in the first implementation PR;
  isolate the Codex addition so upstream changes remain mergeable.

## Backend contract

Create `vvaharness/backends/codex_cli.py` with the public surface expected by
`vvaharness/backends/llm.py`:

```python
def prompt(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    max_tokens: int | None = None,
    json_schema: dict | None = None,
    output_format: str = "text",
    cwd: str | None = None,
    timeout: int | None = None,
    tag: str | None = None,
    **ignored: object,
) -> str: ...


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_turns: int | None = None,
    timeout: int | None = None,
    tag: str | None = None,
    **ignored: object,
) -> str: ...
```

The backend combines VVAH's system and user prompts with a clear boundary,
requests structured output when a schema is supplied, returns only the final
agent message, and records usage from Codex events in VVAH's shared token
metrics.

## Runtime choice

### Initial implementation: `codex exec`

Use the installed Codex CLI as a subprocess because it is easy to test against
the current user-visible runtime and naturally reuses `codex login`.

Conceptual invocation:

```bash
codex exec \
  --ephemeral \
  --ignore-user-config \
  --ignore-rules \
  --sandbox read-only \
  -c project_doc_max_bytes=0 \
  --cd /absolute/path/to/repo \
  --model configured-model \
  --json \
  "bounded VVAH stage prompt"
```

When VVAH supplies a JSON Schema, write it to a scanner-controlled temporary
location outside the target and add `--output-schema <path>`. Delete the
temporary schema after the subprocess exits. Never place orchestration files
inside the repository being scanned.

Parse JSONL incrementally. Capture:

- `thread.started` for diagnostics only.
- `item.completed` with `type: agent_message` as the candidate final response.
- `turn.completed` usage for token metrics.
- `turn.failed` and `error` as structured failures.
- Command, file, MCP, or web events as policy violations when that capability
  was not authorized for the stage.

Bound stdout/stderr retained in memory and redact before logging.

### Follow-up optimization: Codex Python SDK

Evaluate `openai-codex` after the CLI backend is correct. A long-lived local
app-server can avoid cold-starting Codex for every stage and can make
concurrency, cancellation, event handling, and future S11 sessions cleaner.
Keep the VVAH-facing backend contract unchanged so this is an internal runtime
swap rather than a pipeline rewrite.

## Required repository changes

### Dispatcher and configuration

1. Import the new backend and add `"codex": codex_cli` to `_BACKENDS` in
   `vvaharness/backends/llm.py`.
2. Treat Codex as a CLI-style backend for unsupported sampling parameters.
3. Add an optional `codex:` configuration block for executable path, sandbox,
   timeout, reasoning effort, extra environment policy, and bounded parallelism.
4. Add `vvaharness/config/profiles/codex.yaml` with every S1–S9 model role set
   to `via: codex` and S10/S11 disabled.
5. Make `codex.yaml` a shipped profile; users should not need to invent a
   configuration to obtain the safe defaults.

### Preflight, setup, and doctor

1. Resolve the Codex executable to an absolute path; do not rely on a mutable
   `PATH` after preflight.
2. Run `codex login status` and report the authentication mode without reading
   credential content.
3. Run one minimal structured preflight request with the exact model and
   restrictions the scan will use.
4. Verify JSONL and JSON Schema capabilities.
5. Reject unsupported combinations before model spend, including S10 fix or
   S11 on the first-milestone profile.
6. Update setup guidance so Codex login is sufficient for `via: codex`; do not
   ask for `OPENAI_API_KEY` on that route.

### Pipeline compatibility

1. Keep S4 single-pass initially. Codex CLI does not expose VVAH's temperature
   sampling contract, so majority-vote claims would be misleading.
2. Remove hard-coded checks that equate only `via: cli` with all CLI behavior;
   branch on explicit capabilities instead.
3. Preserve existing Pydantic/schema validation and repair behavior after the
   backend returns.
4. Include Codex CLI version, configured model, auth mode category, backend
   settings hash, and sandbox mode in the run manifest. Never record tokens or
   secrets.
5. Ensure checkpoint/resume does not persist Codex session credentials or
   reusable thread state.

### Documentation

Update the main setup, configuration, model, security, and limitation docs to
distinguish:

- `via: openai`: OpenAI-compatible API and `OPENAI_API_KEY`.
- `via: codex`: authenticated local Codex runtime.
- S1–S9 support versus future S10/S11 work.
- Codex sandbox boundaries versus VVAH's existing Read/Glob/Grep jail.

## Security design

### Credential handling

- Let Codex own authentication and refresh.
- Invoke only `codex login status`; never inspect `auth.json`, a credential
  store, browser state, or token environment values.
- Pass a minimal environment to the child process. Do not forward unrelated
  secrets from the scanner host.
- Never print the full child environment or raw authentication errors.

### Repository isolation

- Resolve and validate `cwd` before process launch.
- Use a fresh checkout or snapshot and default to read-only.
- Disable project instruction ingestion for scan stages.
- Disable user configuration, rules, plugins, skills, MCP servers, browser,
  web search, and network-dependent behavior unless a later, separately
  reviewed capability explicitly needs one.
- Treat command-execution events as violations in the strict static profile.
  Read-only filesystem sandboxing alone does not prevent a command from
  executing target code.
- For strong enforcement, run Codex/VVAH inside an externally hardened
  disposable container or VM with no target secrets, constrained resources,
  and restricted egress.

### Output handling

- Enforce schema validation on every structured stage.
- Bound event and final-response sizes.
- Redact VVAH reports, errors, traces, and manifests through existing redaction
  paths.
- Treat model output as untrusted data when used in later prompts.

## Test plan

### Offline unit tests

- Command construction with spaces and platform-specific paths.
- No shell interpolation; subprocess argument vectors only.
- System/user prompt boundary construction.
- JSONL parsing for success, multiple messages, missing final message, partial
  lines, malformed events, model refusal, turn failure, and process failure.
- JSON Schema temporary-file creation, permissions, cleanup, and target-path
  exclusion.
- Timeout, cancellation, process-tree termination, and retry classification.
- Token usage normalization.
- Secret and error redaction.
- Preflight handling for missing binary, signed-out CLI, unsupported version,
  unavailable model, and policy violation.
- Dispatcher and profile resolution for `via: codex`.

### Integration tests

- A tiny fixture repository completes each S1–S9 contract with a stub Codex
  executable that emits recorded JSONL.
- An opt-in live test uses an authenticated Codex CLI, spends a bounded amount,
  and verifies the same fixture end-to-end.
- A hostile fixture containing `AGENTS.md`, prompt injection, symlinks,
  lifecycle scripts, large files, and secret-shaped values cannot broaden the
  session or leak host data.
- Detection-only scans leave the target byte-for-byte unchanged.
- Markdown, SARIF, error, checkpoint, and manifest outputs remain compatible
  with upstream consumers.

## Milestone acceptance criteria

S1–S9 is complete only when:

- `vvaharness doctor --config .../codex.yaml` succeeds with ChatGPT-authenticated
  Codex and no API-key environment variables.
- The same scan works with Codex API-key auth without backend code changes.
- A detection-only scan completes on a representative authorized repository.
- The target working tree is unchanged.
- No Anthropic dependency, credential, subprocess, or model call is used.
- Unsupported S10/S11 requests fail before model spend with a clear message.
- Token and elapsed-time metrics are present and secrets are absent.
- Offline tests pass on supported platforms, and the opt-in live test is
  documented separately from the default unit suite.

## Future S10 and S11 work

S10 report-only can reuse the read-only backend after output confinement is
implemented. S10 fix mode requires a separate write-enabled policy, minimal
diff enforcement, changed-path validation, and human review before adoption.

S11 requires replacing or generalizing the Claude-specific validation launcher,
persona configuration, backend constants, and refusal checks. Preserve the
security-architect and penetration-tester separation, but do not claim
independence when both personas use the same model/runtime. Record that
limitation in validation output and require deterministic tests alongside the
model verdict.

