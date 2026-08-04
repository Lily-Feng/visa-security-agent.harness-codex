# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Packaged AI-agent operating instructions.

`vvaharness setup --install-agents` writes these into the files each agent
reads (AGENTS.md, CLAUDE.md, .github/copilot-instructions.md, GEMINI.md, and a
Claude skill) so an agent driving the tool RUNS it rather than editing it.
Kept in the package (not just the repo AGENTS.md) so pip-installed users have it
too."""
from __future__ import annotations

# Canonical operating manual (cross-tool: AGENTS.md, Cursor, Codex, …).
# Leads with the Apache header so generated files carry it like the rest of the tree.
AGENT_DOC = """\
<!--
Copyright 2026 Visa, Inc.
Licensed under the Apache License, Version 2.0; see http://www.apache.org/licenses/LICENSE-2.0
-->
# Operating vvaharness (for AI coding agents)

`vvaharness` is a **released** CLI security-scanning product. **Operate it,
do not develop or repair it.**

## The three rules
1. **Never edit the `vvaharness` package source** to make a scan run. If it
   won't run, that's an environment problem (below) or a bug to report.
2. **Never hand-write config files.** Use a shipped profile via `--config`.
3. **On any failure, run `vvaharness doctor` (or `setup`), fix the environment
   it points to, and re-run.** Report bugs; don't patch around them.

## Run it
```
pipx install vvaharness            # or: pip install vvaharness
vvaharness setup                   # checks Python, agents, keys, gateway, config
vvaharness scan --repo <path> --application-id <id> --stop-after s9
```
- The shipped default is mixed: local S0, Claude CLI for S1-S9,
  DeepAgents/Anthropic for S10, and DeepAgents/OpenAI for S11. A complete run
  needs credentials for each enabled backend. `setup` reports missing pieces.
- A plain default-profile `scan` continues into S10 fix mode and can edit target
  source. Keep `--stop-after s9` for detection only.
- `sdk.yaml` spells every role `via: sdk`; its detection and S10 paths use
  `ANTHROPIC_SDK_API_KEY`, while S11 pins external `claude` and uses ambient
  Claude login / `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` /
  `ANTHROPIC_AUTH_TOKEN`. The SDK-named key alone does not authenticate S11. A
  standard Anthropic credential can cover all stages through the sole-SDK
  detection fallback.
- For an enterprise gateway, use the endpoint/trust variables for the selected
  backend (`ANTHROPIC_SDK_BASE_URL` for direct SDK detection;
  `ANTHROPIC_BASE_URL` for Claude/DeepAgents paths). Run `setup` for exact
  environment guidance.

## On failure
Read the one-line `✗ scan failed: …`, run `vvaharness doctor`, fix what it
flags (usually a credential or `ANTHROPIC_BASE_URL`), re-run. Full trace:
`VVAHARNESS_DEBUG=1`. Findings are triage candidates, not confirmed vulns.
"""

# Claude Code skill: same content, with the required frontmatter so Claude Code
# auto-discovers it from ~/.claude/skills/vvaharness/SKILL.md.
CLAUDE_SKILL = (
    "---\n"
    "name: vvaharness\n"
    "description: Operate the vvaharness SAST CLI (install, setup, doctor, "
    "scan). Use when asked to scan a repo for vulnerabilities with vvaharness. "
    "Operate the tool; never edit its source or hand-write its config.\n"
    "---\n\n"
) + AGENT_DOC


def gemini_doc() -> str:
    return AGENT_DOC.replace("(for AI coding agents)", "(for the Gemini CLI)")
