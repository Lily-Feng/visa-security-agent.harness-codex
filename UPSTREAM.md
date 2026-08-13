<!--
Copyright 2026 Lily Feng.

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

# Upstream provenance

Codex Vulnerability Agentic Harness is an independently maintained derivative
of [Visa Vulnerability Agentic Harness][upstream]. The original Git history,
authors, copyright notices, Apache-2.0 license, and `NOTICE` attribution are
preserved.

This repository is not affiliated with or endorsed by Visa Inc. or OpenAI.
References to Visa identify the upstream project; references to Codex identify
the supported integration.

## Repository remotes

The intended local remote layout is:

```text
origin    https://github.com/Lily-Feng/codex-vulnerability-agentic-harness.git
upstream  https://github.com/visa/visa-vulnerability-agentic-harness.git
```

`origin/main` is the independently maintained default branch. The `upstream`
remote is read-only project history and a source for selectively reviewing
future Apache-2.0 changes. Its push URL is deliberately set to `DISABLED` to
prevent accidental pushes to Visa's repository.

## Reviewing upstream changes

```bash
git fetch upstream
git log --oneline --left-right main...upstream/main
git diff main...upstream/main
```

Merge or cherry-pick upstream changes only after reviewing compatibility with
the native Codex backend and the project's security boundaries. Preserve the
original author metadata and applicable copyright notices. Add a prominent
modification notice whenever this project changes a derived file.

## Independent changes

Independent Codex work begins with the design and security guidance commit
`fcf38ccfaaec216de238a6855652736c75edc7bb`; the native Codex integration lands
in `b73a2ce01b466fc09b857033e9c6e7efb5a790b8`. Future work belongs on this
repository's `main` branch or short-lived branches merged into `main`.

[upstream]: https://github.com/visa/visa-vulnerability-agentic-harness
