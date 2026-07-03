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
pipx install .            # or: pip install .
vvaharness setup                   # checks Python, agents, keys, gateway, config
vvaharness scan --repo <path> --application-id <id>
```
- Public/subscription users: an Anthropic API key (`ANTHROPIC_SDK_API_KEY`) or
  `claude login` is enough — nothing else.
- Enterprise gateway: also `export ANTHROPIC_BASE_URL=<gateway>` (and
  `NODE_EXTRA_CA_CERTS`, `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` if needed).
  `setup` auto-detects this and prints the exact lines.

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
