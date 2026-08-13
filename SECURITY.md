<!--
Copyright 2026 Visa, Inc.
Modifications Copyright 2026 Lily Feng.
Modified by Lily Feng in 2026 for independent project governance.

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

# Security Policies and Procedures

This document outlines security procedures and general policies for the
independently maintained Codex Vulnerability Agentic Harness project. It is not
affiliated with or endorsed by Visa Inc. or OpenAI.

- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Disclosure Policy](#disclosure-policy)
- [Security considerations](#security-considerations)

---

## Reporting a Vulnerability

Thank you for improving the security of our software. We appreciate your
efforts and responsible disclosure and will make every effort to acknowledge
your report.

Use GitHub's private vulnerability reporting for this repository:

- **https://github.com/Lily-Feng/codex-vulnerability-agentic-harness/security/advisories/new**

If private vulnerability reporting is temporarily unavailable, contact the
maintainer through the contact methods on the
[Lily-Feng GitHub profile](https://github.com/Lily-Feng) before sharing
sensitive details.

Please do **not** report security vulnerabilities through public GitHub issues.

The maintainer will acknowledge the report and coordinate triage, remediation,
and disclosure. Additional information or validation may be requested.

When reporting, please include as much of the following as you can to help us
triage quickly:

- The version (or commit) of `vvaharness` affected.
- The profile/backend in use (`via: cli`, `via: sdk`, `via: openai`, or
  `via: deepagents` plus its provider) and OS.
- A description of the issue and its security impact.
- Step-by-step instructions to reproduce.
- Proof-of-concept or exploit code, if available.
- Any known mitigations or workarounds.

Report security vulnerabilities in **third-party dependencies** to the party
that maintains the affected component.

---

## Disclosure Policy

When the project receives a vulnerability report, the maintainer coordinates
the fix and release process, involving the following steps:

- Confirm the problem and determine the affected versions.
- Audit code to find any potential similar problems.
- Prepare fixes for all releases still under maintenance. These fixes are
  released as quickly as possible.

Public disclosure is coordinated with the reporter; please give us reasonable
time to remediate before any public discussion of the issue.

---

## Security considerations

**TL;DR:** `vvaharness` reads repository content and forwards excerpts to the
configured model endpoint. SDK/OpenAI tool results and read-only
DeepAgents tool results are scrubbed, but redaction is not a universal
pre-egress guarantee for every prompt or backend. On-disk reports are redacted
on every backend. Keep scan credentials and config outside
the repositories you scan, restrict tool access in CI/CD, and scope batch jobs
to repositories your team is authorized to scan.

### How the tool handles your data

File reads through the sandboxed tool loop and the s1 inventory are confined
to the repository root — symlinks and path traversals that point outside it
are rejected. Redaction — masking of credentials, private keys, and payment
card data — is applied at the report write boundary (Markdown and SARIF, on
every backend). Sandboxed `via: sdk` / `via: openai` tool results are scrubbed
before returning to the model, as are filesystem reads in read-only
DeepAgents sessions such as validation. DeepAgents fix-mode remediation permits
writes and does not promise that same read-result redaction. The default
`via: cli` detection route drives the `claude` CLI's own filesystem tools, so
quoted source on that path is masked only at the report boundary, not before it
reaches the model. API keys and git tokens are kept in environment variables
and sent as request credentials; they should not appear in prompts. For full detail see
[`docs/security.md`](docs/security.md).

Batch mode clones each repository into an isolated workspace directory and
scans it. Unless you pass `--keep-clones`, the clone is removed when the scan
completes, preserving only folders listed in `output.preserve_on_cleanup`.
All shipped profiles currently preserve both `security-scan` and
`security-remediation`. See
[`docs/security.md`](docs/security.md) for details.

For a full description of redaction patterns, backend TLS settings, and
credential handling, see [`docs/security.md`](docs/security.md).

### Deployment recommendations

- **Only scan repositories you trust.** The scanned repository is an input to
  the pipeline; treat it with the same caution as any other untrusted input
  to a privileged process.
- **Keep scan infrastructure separate from scan targets.** Store config and
  credentials in directories outside the repositories you scan. Run scans from
  a working directory that is **not** inside the target repository.
- **Restrict tool access in CI/CD.** Review and restrict tool access, and
  ensure sandboxing to reduce risk.
- **Keep batch manifests under security-team control** and restrict the git
  host to your internal domain.

### Input handling

As with any analysis tool, `vvaharness` processes repository content as part
of its normal operation. Findings and artifacts are produced for human review.
With remediation enabled, a plain default-profile scan can also edit target
source when S10 has findings, credentials, and a successful fix-mode session;
use `--stop-after s9` for detection-only operation. Apply the same judgement to
SARIF and generated patches that you would to any automated tool result.

### What not to scan

- Repositories your team is not authorized to scan.
- **Repositories whose committers you do not fully trust.**
- Large monorepos without first scoping the scan using `vvaharness estimate`,
  `--stop-after`, or `--auto-step1`.
- Directories containing only binaries, generated code, or vendored
  dependencies — exclude these via `exclude_dirs` in your config to keep
  results focused.
