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

"""Augment the combined SARIF + MD report with validation results.

After a validation run, copy the scan's pristine ``security-scan/*_report.{sarif,md}``
into ``security-remediation/`` (once) and add, per validated finding, a ``validation``
block to the matching SARIF result and a ``### Validation`` section (status, weighted
score, gate breakdown) to the matching MD finding. Best-effort: a failure here never
fails the validation run.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from vvaharness.validation.constants.artifacts import (
    REMEDIATION_DIRNAME,
    SCAN_REPORT_GLOB,
)

if TYPE_CHECKING:
    from vvaharness.validation.models import RemediationReport, ValidationResult

log = logging.getLogger(__name__)

# A validated (source DTO, host result) pair for one finding.
Pair = tuple["RemediationReport", "ValidationResult"]

# Finding heading in the markdown report, e.g. ``### 1. [HIGH] Some title``.
_FINDING_RE = re.compile(r"(?m)^### \d+\. \[[^\]]*\]\s*(.+?)\s*$")
# A previously-appended ``### Validation`` block, anchored to the end of a finding segment.
_EXISTING_VALIDATION_RE = re.compile(r"(?s)\n+### Validation\n.*\Z")
# A report-level ``## `` (H2) heading. Per-finding ``### Validation`` blocks must stay
# above any such section that s10 appended after the last finding (e.g. its EOF
# ``## Remediation Summary``); finding bodies use ``###``/``####`` only, so the first
# ``## `` at or after the last finding marks the report-level tail.
_TRAILING_SECTION_RE = re.compile(r"(?m)^## ")


def augment_reports(repo: Path, pairs: list[Pair], report_md: Path | None = None) -> None:
    """Add validation results to the combined report under ``security-remediation/``.

    Best-effort: any failure is logged and swallowed so reporting never breaks a run.
    """
    try:
        _augment(repo, pairs, report_md)
    except Exception as e:  # report augmentation must never fail the validation run
        log.warning(
            "report augmentation skipped (results not written to combined report): %s: %s",
            type(e).__name__, e,
        )


def _augment(repo: Path, pairs: list[Pair], report_md: Path | None) -> None:
    """Resolve the combined report in ``security-remediation/`` and augment SARIF + MD in place."""
    located = _locate_combined_report(repo, report_md)
    if located is None:
        log.warning("no combined report under %s/%s — skipping report augmentation",
                    repo, REMEDIATION_DIRNAME)
        return
    sarif_dst, md_dst = located
    _augment_sarif(sarif_dst, pairs)
    _augment_md(md_dst, pairs)
    log.info("validation results written to combined report under %s", sarif_dst.parent)


def _locate_combined_report(repo: Path, report_md: Path | None = None) -> tuple[Path, Path] | None:
    """Pick the ``(*_report.sarif, *_report.md)`` pair under ``security-remediation/`` to enrich.

    Explicit *report_md* (in-pipeline) wins; the basename is rebased onto ``security-remediation/``
    so this function never returns a ``security-scan/`` path. Else the newest ``*_report`` (latest
    cycle). None when the report or its sibling is absent.
    """
    if report_md is not None:
        md = repo / REMEDIATION_DIRNAME / Path(report_md).with_suffix(".md").name
        sarif = md.with_suffix(".sarif")
        return (sarif, md) if (md.exists() and sarif.exists()) else None
    sarifs = sorted((repo / REMEDIATION_DIRNAME).glob(SCAN_REPORT_GLOB))
    if not sarifs:
        return None
    sarif = sarifs[-1]
    md = sarif.with_suffix(".md")
    return (sarif, md) if md.exists() else None


# ---------------------------------------------------------------------------
# value helpers
# ---------------------------------------------------------------------------


def _status_label(result: ValidationResult) -> str:
    """Map the tri-state result to the report's ``validationStatus`` enum."""
    if result.fixed == "Yes":
        return "fixed"
    if result.partially_fixed == "Yes":
        return "partially_fixed"
    return "not_fixed"


def _status_word(result: ValidationResult) -> str:
    """Human-readable status for the markdown section."""
    return {"fixed": "Fixed", "partially_fixed": "Partially Fixed",
            "not_fixed": "Not Fixed"}[_status_label(result)]


def _parse_gates(raw: str) -> dict:
    """Parse the gate-scores JSON blob, returning {} on absence/error."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _validation_block(result: ValidationResult) -> dict:
    """Build the SARIF per-result ``validation`` object."""
    reason = (result.reason_for_decision or result.justification or "").strip()
    return {
        "validationStatus": _status_label(result),
        "validationReason": reason[:2000],
        "weightedScore": result.fix_confidence,
        "mergeReadiness": result.pr_merge_readiness,
        "gateScores": _parse_gates(result.gate_results_json),
    }


# ---------------------------------------------------------------------------
# SARIF augmentation
# ---------------------------------------------------------------------------


def _norm_path(p: str) -> str:
    """Fold Windows separators to POSIX so a separator mismatch can't defeat location matching."""
    return p.replace("\\", "/")


def _result_loc(sarif_result: dict) -> tuple[str, int]:
    """Return (uri, startLine) for a SARIF result, or ("", -1) when unavailable."""
    try:
        pl = sarif_result["locations"][0]["physicalLocation"]
        return _norm_path(pl["artifactLocation"]["uri"]), int(pl["region"]["startLine"])
    except (KeyError, IndexError, TypeError, ValueError):
        return "", -1


def _match_by_loc(results: list[dict], file: str, line: int) -> dict | None:
    """Return the result whose physical location is exactly (file, line)."""
    target = (_norm_path(file), line)
    for r in results:
        if _result_loc(r) == target:
            return r
    return None


def _match_by_title(results: list[dict], title: str) -> dict | None:
    """Return the result whose message text starts with *title* — only when exactly one does."""
    hits = [r for r in results if str(r.get("message", {}).get("text", "")).startswith(title)]
    return hits[0] if len(hits) == 1 else None


def _match_sarif(results: list[dict], report: RemediationReport) -> dict | None:
    """Match a SARIF result to a finding by (file, startLine), else by title prefix."""
    finding = report.finding
    by_loc = _match_by_loc(results, finding.file, finding.line_start) if finding.file else None
    if by_loc is not None:
        return by_loc
    title = (finding.title or "").strip()
    return _match_by_title(results, title) if title else None


def _augment_sarif(path: Path, pairs: list[Pair]) -> None:
    """Add a ``validation`` block to each SARIF result matching a validated finding."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    runs = doc.get("runs") or [{}]
    results = runs[0].get("results", []) if runs else []
    for report, result in pairs:
        match = _match_sarif(results, report)
        if match is not None:
            match["validation"] = _validation_block(result)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Markdown augmentation
# ---------------------------------------------------------------------------


_MD_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Inline Markdown / HTML metacharacters that could forge emphasis/links/code spans,
# inject HTML (active content in a permissive renderer), or break out of a table cell.
# Applied as a single per-character pass, so a backslash already present in the
# untrusted text is itself escaped and cannot consume the escape added for the
# character that follows it. Mirrors the audited map in
# remediation_agent/report_augment/mdsafe.py.
_MD_ESCAPE: dict[str, str] = {
    "\\": "\\\\", "`": "\\`", "*": "\\*", "_": "\\_",
    "[": "\\[", "]": "\\]", "|": "\\|", "#": "\\#",
    "<": "&lt;", ">": "&gt;", "&": "&amp;",
}


def _trim_dangling_escape(text: str) -> str:
    """Drop a trailing lone backslash left behind by truncation.

    Escaping doubles every backslash, so a complete sequence always ends in an even-length
    run. An odd run means the length limit cut one in half, and the surviving backslash
    would escape whatever follows it -- e.g. the ``|`` delimiter opening the next cell.
    """
    if (len(text) - len(text.rstrip("\\"))) % 2:
        return text[:-1]
    return text


def _md_escape(text: object, limit: int = 2000) -> str:
    """Neutralize agent-authored text for inline Markdown.

    Strips control chars, defangs HTML and link/code/table syntax, collapses newlines, and
    bounds length so the text renders inertly. Truncation happens after escaping so the
    returned length is the real bound callers rely on.
    """
    s = _MD_CTRL_RE.sub("", str(text))
    s = s.replace("\r", " ").replace("\n", " ")
    s = "".join(_MD_ESCAPE.get(ch, ch) for ch in s)
    return _trim_dangling_escape(s[:limit])


def _md_cell(text: object) -> str:
    """Escape a value for a Markdown table cell (``|`` is part of the escape map)."""
    return _md_escape(text, limit=200)


def _gate_rows(gates: dict) -> list[str]:
    """Render gate-score rows as markdown table lines (best-effort over the blob shape)."""
    rows: list[str] = []
    for name, val in gates.items():
        if isinstance(val, dict):
            status = val.get("status", "")
            weight = val.get("weight", "")
            weighted = val.get("weighted_score", val.get("weighted", ""))
            cells = " | ".join(_md_cell(v) for v in (name, status, weight, weighted))
            rows.append(f"  | {cells} |")
        else:
            rows.append(f"  | {_md_cell(name)} | {_md_cell(val)} | | |")
    return rows


def _md_validation_section(result: ValidationResult) -> str:
    """Render the ``### Validation`` markdown section for one finding."""
    lines = [
        "### Validation",
        f"- **Status:** {_status_word(result)}",
        f"- **Weighted score:** {result.fix_confidence}"
        f"  (merge readiness: {result.pr_merge_readiness or 'n/a'})",
    ]
    summary = (result.justification or result.reason_for_decision or "").strip()
    if summary:
        lines.append(f"- **Summary:** {_md_escape(summary)}")
    gates = _parse_gates(result.gate_results_json)
    rows = _gate_rows(gates)
    if rows:
        lines += ["- **Gate scores:**", "", "  | gate | status | weight | weighted |",
                  "  |---|---|---|---|", *rows]
    return "\n".join(lines) + "\n"


def _ftitle(pair: Pair) -> str:
    report, result = pair
    return (report.finding.title or result.finding_title or "").strip().lower()


def _only(pairs: list[Pair]) -> ValidationResult | None:
    """The single result when *pairs* is unambiguous, else None (fail closed on 0 or >1)."""
    return pairs[0][1] if len(pairs) == 1 else None


def _best_md_match(title: str, pairs: list[Pair]) -> ValidationResult | None:
    """Match an MD heading title to a result, failing closed on ambiguity (CWE-345).

    Unique exact title wins; else a unique substring (either direction) wins; duplicates or
    multiple substring candidates → None (the section is left unattributed, never mis-attached).
    """
    norm = title.strip().lower()
    if not norm:
        return None
    exact = [p for p in pairs if _ftitle(p) == norm]
    if exact:
        return _only(exact)
    return _only([p for p in pairs if (ft := _ftitle(p)) and (ft in norm or norm in ft)])


def _augment_md(path: Path, pairs: list[Pair]) -> None:
    """Insert/replace a ``### Validation`` section at the end of each matched finding.

    The per-finding region is bounded at the first report-level ``## `` heading after
    the last finding (e.g. the ``## Remediation Summary`` s10 appends at EOF), and that
    tail is re-appended verbatim so every finding's ``### Validation`` stays above it.
    With no trailing ``## `` section, ``end == len(text)`` and the behavior is identical
    to bounding at the end of the document.
    """
    text = path.read_text(encoding="utf-8")
    matches = list(_FINDING_RE.finditer(text))
    if not matches:
        return
    tail = _TRAILING_SECTION_RE.search(text, matches[-1].start())
    end = tail.start() if tail else len(text)
    bounds = [m.start() for m in matches] + [end]
    rebuilt = [text[: bounds[0]]]
    for i, m in enumerate(matches):
        segment = text[bounds[i]: bounds[i + 1]]
        result = _best_md_match(m.group(1), pairs)
        rebuilt.append(_augment_segment(segment, result))
    rebuilt.append(text[end:])  # report-level ``## `` sections stay below every finding
    path.write_text("".join(rebuilt), encoding="utf-8")


def _augment_segment(segment: str, result: ValidationResult | None) -> str:
    """Replace any prior ``### Validation`` block in *segment* and append the current one."""
    if result is None:
        return segment
    stripped = _EXISTING_VALIDATION_RE.sub("", segment)
    return stripped.rstrip() + "\n\n" + _md_validation_section(result) + "\n"
