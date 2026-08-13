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

# Output Formats

## On-disk layout

Per target, under `<target>/security-scan/`:

- `<module>_<ts>_report.md`
- `<module>_<ts>_report.sarif`
- `<module>_<ts>_errors.jsonl` (only written if a recoverable error was logged; absent on a clean run)

Every scan also writes `run_manifest.json` in the **current working directory**
(not under `security-scan/`). It records the tool version, detection roles,
config/overlay hashes, target git SHA, arguments, outcome, and timing. Batch
mode additionally writes `<workspace>/batch_summary.md`.

Remediation artifacts live separately, under
`<repo>/security-remediation/<NN_slug>/` (written by the `remediate` command).
The `validate` command updates each finding's DTO in place:

- `remediate_report.json` — the persistent per-finding DTO at `<NN_slug>/`;
  `validate` fills its `validation` block and advances `status` to one of
  `validated` (fix passed), `validation_failed` (fix did not pass;
  re-validatable), or `needs_review` (session could not produce a verdict)
- `validation_report.json` — the agentic panel's per-DTO findings
- `synthesized_gates.json` — qualitative consensus gate outcomes; host code
  applies the configured weights to compute the score and verdict

`validation_report.json` and `synthesized_gates.json` are *ephemeral*: agents
return structured output and host code writes these files to the per-finding
staging workspace under
`<repo>/security-remediation/validation/<finding_id>/`, folded into the DTO's
`validation` block, and then the workspace is deleted after each finding. Only
`remediate_report.json` survives under `<NN_slug>/`. When a source session log
is available and redaction/persistence succeeds, a redacted
`validation_session_*.jsonl` transcript is also retained beside it; transcript
persistence is best-effort.

Checkpoints in the SQLite state DB at `$VVAHARNESS_STATE_DIR/vvaharness.db`
(default `~/.vvaharness/state/vvaharness.db`; run `vvaharness gc` or delete
the file to force a fresh run). Payloads are JSON bytes, schema-validated
via pydantic on load (no pickle / no code-execution path), and are never
read from the scanned repo. The auto-derived `step1.yaml` (`--auto-step1`)
is still a plain file under `$VVAHARNESS_STATE_DIR/checkpoints/<run_id>/`.
Batch mode also writes `<workspace>/batch_summary.md`.

> Only resume from checkpoints you produced yourself; do not `--resume` a
> scan of an untrusted repository.

`output.preserve_on_cleanup` in `config.yaml` controls which folders inside
the clone survive when cloned source is deleted. The shipped profiles preserve
`[security-scan, security-remediation]`; if the key is omitted entirely the
built-in fallback keeps `[security-scan]` only. Checkpoints live outside the
clone, so `--resume` works regardless of cleanup.

## Markdown report — finding block

Each verified finding follows this block order (metadata fields on
consecutive lines — one field per line, no blank lines between, so the
SARIF parser reads each by regex):

```
### N. [SEVERITY] Title
**Class:** <CWE-NNN: name, or the vuln-class when no CWE resolves>
**CWE:** CWE-NNN: name - https://cwe.mitre.org/...   (if a CWE resolved)
**File:** `path:start-end`
**CVSS 3.1:** score (rating) — `vector`
**VulContextSeverity:** `env-vector` - score (rating)   (if CMDB enrichment ran)
**OffensivePriority:** Pn - label | reason
**Confidence:** 0.NN (N runs agreed)
**Also at:** `file:line`, …   (if s7 dedup collapsed other call sites)

#### Description
#### Impact
#### Exploit scenario
#### Preconditions
``` code snippet ```
#### How to fix
**Exploitability:** notes
#### Adversarial verification
```

## SARIF 2.1.0 mapping

`vvaharness/report/enrich.py: md_to_sarif()` parses the markdown back and
emits SARIF. Per finding:

| Markdown | SARIF |
|---|---|
| `[SEVERITY]` | `level`, `properties.severity` |
| Title + CVSS | `message.text` |
| `**Class:**` | `ruleId`, `properties.category` |
| `**CWE:**` (parsed token, else VulnClass fallback) | `properties.{cwe,cweId,cweName}`, result `taxa[]` (resolves against the CWE taxonomy) |
| `**File:**` line | `locations[0].physicalLocation.{artifactLocation.uri, region.startLine}` |
| `**CVSS 3.1:**` | `rank` (CVSS 0–10 scaled to SARIF's 0–100), `properties.{cvssVector,cvssScore,cvssRating,security-severity}` |
| `**VulContextSeverity:**` | `properties.{vulContextSeverityVector,vulContextSeverityScore,vulContextSeverityRating}` |
| `**OffensivePriority:**` | `properties.{offensivePriority,offensivePriorityLabel,offensivePriorityReason}` |
| `**Confidence:**` | `properties.confidence` (and `properties.votes` only when the line carries an explicit `N of M runs` count — the pipeline's `(N runs agreed)` form does not, so `votes` is normally absent) |
| `**Also at:**` line | `relatedLocations[]`, `properties.dedupRelatedLocationCount` |
| Description → Verification | `properties.description` (markdown body, ≤4000 chars) |

Run-level `properties` always carries `applicationId`; `applicationName` and
`cmdbSource` are added only when a CMDB AppInfo was resolved for that
application (i.e. CMDB enrichment ran). The SARIF `tool.driver.name` is
`"Agentic SAST"`. `tool.driver.rules[]` catalogs every emitted `ruleId`, and
`tool.driver.supportedTaxonomies` references the CWE taxonomy (by a stable guid)
so each result's `taxa[]` resolves. The run carries one `invocations[]` entry.
If exploit-chain analysis falls back to an unranked report,
`executionSuccessful=false`; deep-dive chunk failures and other recoverable
stage errors instead add `toolExecutionNotifications` while leaving that flag
true. A clean run reports `executionSuccessful=true` with no notifications.

### Scan Health (markdown)

When a run loses coverage — deep-dive chunks that failed or timed out, a
chain pass that could not be computed, or any stage that logged a recoverable
error — the report adds a `## Scan Health`
section listing chunks attempted/failed, per-stage error counts, and a pointer
to the per-run `*_errors.jsonl`. A fully clean run (no failed chunks, no chain
fallback, no logged errors) omits the section entirely. Note: a
run that simply found no exploit chains is **not** degraded — that is a normal
outcome and is stated as "No exploit chains were identified".

## CMDB enrichment

Set `inject.cmdb_file` in `config.yaml` to a single CMDB export CSV
(default `./inputs/cmdb.csv`) to enable AppProfile lookup and
VulContextSeverity environmental scoring. When unset or missing, base
CVSS and OffensivePriority are still computed; only the
VulContextSeverity adjustment is skipped.
