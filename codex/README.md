<!--
Copyright 2026 Visa, Inc.
Modifications Copyright 2026 Lily Feng.
Modified by Lily Feng in 2026 for native Codex support.

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

# Native Codex Direction

This independently maintained project's Codex direction runs VVAH with Codex
as the model and agent runtime. The upstream `via: openai` backend is not that
integration: it
calls an OpenAI-compatible API and requires `OPENAI_API_KEY`. A native Codex
backend should instead use the locally authenticated Codex runtime and support
both ChatGPT subscription authentication and Codex API-key authentication as
provided by Codex itself.

The first milestone is implemented: the shipped `codex.yaml` profile runs
read-only S0-S9 detection through `codex exec`. Report-only remediation, fix
mode, and Codex-native validation remain future milestones.

## Desired user experience

```bash
codex login status
vvaharness setup --config vvaharness/config/profiles/codex.yaml
vvaharness doctor --config vvaharness/config/profiles/codex.yaml
vvaharness estimate --repo /path/to/target
vvaharness scan \
  --repo /path/to/target \
  --config vvaharness/config/profiles/codex.yaml \
  --stop-after s9
```

The first supported milestone is detection-only S1–S9. It must:

- Reuse Codex's active login instead of reading or copying cached credentials.
- Require no Anthropic installation, login, key, SDK, or model.
- Require no OpenAI Platform API key when Codex is signed in with ChatGPT.
- Preserve VVAH's Markdown, SARIF, error-log, checkpoint, and manifest formats.
- Run against a trusted copy of an authorized repository.
- Default to read-only filesystem access and no target execution.
- Keep model selection configurable rather than hard-coding a transient model
  identifier into the backend.

## Important authentication distinction

Codex supports ChatGPT subscription login and API-key login. `codex exec` and
the Codex SDK reuse the active Codex authentication. The cached ChatGPT login
is not an `OPENAI_API_KEY` and must never be extracted, printed, copied into a
VVAH `.env`, or sent directly to an OpenAI-compatible endpoint.

Official references:

- [Codex authentication](https://learn.chatgpt.com/docs/auth)
- [Codex non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode)
- [Codex SDK](https://learn.chatgpt.com/docs/codex-sdk)

## Scope by milestone

| Milestone | VVAH stages | Codex permissions | Result |
|---|---|---|---|
| 1 — Detection | S1–S9 | Read-only | Markdown, SARIF, errors, manifest |
| 2 — Report-only remediation | S10 report-only | Read-only, artifact write confined to output | Candidate fixes and remediation DTOs, no source edit |
| 3 — Fix mode | S10 fix | Workspace write, strict repository jail | Minimal reviewed source changes and remediation DTOs |
| 4 — Validation | S11 | Read-only plus validation-artifact output | Codex-native adversarial fix verdicts |

Do not collapse these milestones. In particular, a working S1–S9 dispatcher
does not make the current S11 implementation Codex-compatible: upstream S11 is
coupled to the Claude Agent SDK and must be replaced or generalized separately.

## Design documents

- [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md) defines the backend,
  configuration, migration, tests, and acceptance criteria.
- [EFFICIENCY-AND-SAFETY.md](EFFICIENCY-AND-SAFETY.md) defines context, token,
  process, concurrency, sandbox, prompt-injection, and observability controls.
