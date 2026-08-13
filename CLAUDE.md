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
# CLAUDE.md

**Read `AGENTS.md` in full before doing anything in this repo.** It is the
operating manual for running vvaharness.

vvaharness is a *released* CLI security-scanning product — operate it, don't
develop or repair it.

Critical rules (full details in AGENTS.md):
1. Never edit files under `vvaharness/` to make a scan run.
2. Never hand-write config — use a shipped profile via `--config`.
3. On any failure run `vvaharness setup` / `vvaharness doctor`, fix the
   environment it points to, and re-run. Report bugs; don't patch around them.

Detection-only quick start: `pipx install .` → `vvaharness setup` →
`vvaharness scan --repo <path> --stop-after s9`.

A plain `scan` may edit target source through default S10 fix-mode remediation.
