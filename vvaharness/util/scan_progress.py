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

"""
vvaharness.util.scan_progress — per-file scan observability.

Controlled by ``scan_progress.enabled`` in the active config profile (the
built-in scalar default is false; shipped profiles choose explicitly). When
enabled, the pipeline emits structured ``[progress]`` lines to stderr for
stage milestones across S0-S9 plus these detailed events:

  1. ``discovered``  — after s1 walks the repo and builds the file inventory
  2. ``queued``      — after s3 assigns files to chunks (which files will be
                       deep-dived and which chunk they belong to)
  3. ``scanning``    — when s4 starts a chunk (files now actively under LLM review)
  4. ``scanned``     — when s4 finishes a chunk (files now complete, with outcome)

S2 also emits threat-model evidence/request notes, and S4 emits a final summary
block after its chunks finish.

The output is both human-readable and machine-parseable:

  [progress] discovered  247 files  (repo: my-service)
  [progress] queued      chunk-01 (rank=1, lens=java+spring, 2 files)
             →  src/api/AuthController.java
             →  src/service/TokenService.java
  [progress] scanning    chunk-01  [2 files]  (2 / 18 chunks)
  [progress] scanned     chunk-01  [2 files]  outcome=completed  findings=3
             ✓  src/api/AuthController.java
             ✓  src/service/TokenService.java
  [progress] summary     18 / 18 chunks done  |  scanned=32 files
             outcomes:  completed=16  error=1  guardrail=1

Design notes:
- Thread-safe: s4 runs chunks in a ThreadPoolExecutor; all emit calls are
  guarded by a threading.Lock so lines don't interleave.
- No separate process / socket / poll loop: all output goes to stderr for the
  invoking terminal or job-log capture.
- One stateful tracker is instantiated per repo scan and shared with stages via
  the config object. Each stage calls the tracker's API; stages do not format
  these progress lines themselves.
- ``scan_progress.style`` controls verbosity:
    ``compact`` (default) — chunk lifecycle lines; file lists appear only when
                            a chunk has findings or a non-clean outcome.
    ``verbose``           — every file listed on its own line for all events.
    ``summary_only``      — only the final S4 summary block is emitted.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Literal


# ── public API ────────────────────────────────────────────────────────────────

Style = Literal["compact", "verbose", "summary_only"]


@dataclass
class ChunkProgress:
    chunk_id: str
    files: list[str]
    rank: int
    lens: str
    hypothesis: str
    state: Literal["queued", "scanning", "scanned"] = "queued"
    outcome: str | None = None       # "completed" | "error" | "guardrail"
    findings: int = 0
    started_at: float = field(default_factory=time.monotonic)
    elapsed: float = 0.0


class ScanProgress:
    """
    Thread-safe scan progress tracker.  One instance per repo scan.

    Typical call sequence (orchestrator / stage side):

        tracker = ScanProgress.from_cfg(cfg, repo_name="my-service")

        # after s1 builds the file inventory:
        tracker.discovered(all_files)

        # after s3 assigns files to chunks:
        for chunk in manifest.chunks:
            tracker.queued(chunk)

        # s4 — before and after each chunk:
        tracker.scanning(chunk)
        ... run deep-dive ...
        tracker.scanned(chunk, outcome="completed", n_findings=3)

        # end of scan:
        tracker.print_summary()
    """

    def __init__(self, *, enabled: bool = False,
                 style: Style = "compact",
                 repo_name: str = ""):
        self.enabled = enabled
        self.style = style
        self.repo_name = repo_name
        self._lock = threading.Lock()
        self._total_files: int = 0
        self._chunks: dict[str, ChunkProgress] = {}  # chunk_id -> ChunkProgress
        self._stages: dict[str, dict[str, float | str]] = {}
        self._n_scanning: int = 0
        self._n_scanned: int = 0
        self._start: float = time.monotonic()

    # ── factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_cfg(cls, cfg, repo_name: str = "") -> "ScanProgress":
        """Build a tracker from the active config.  Always safe to call — when
        ``scan_progress.enabled`` is False (the default), all emit methods
        become no-ops without any code change in the calling stage."""
        sp = getattr(cfg, "scan_progress", None)
        enabled = bool(getattr(sp, "enabled", False)) if sp else False
        env_enabled = os.environ.get("VVAHARNESS_SCAN_PROGRESS_ENABLED", "").lower()
        if env_enabled in ("1", "true", "yes"):
            enabled = True
        style: Style = str(getattr(sp, "style", "compact")) if sp else "compact"
        if style not in ("compact", "verbose", "summary_only"):
            style = "compact"
        return cls(enabled=enabled, style=style, repo_name=repo_name)

    # ── stage hooks ───────────────────────────────────────────────────────────

    def stage_started(self, stage_id: str, label: str = "") -> None:
        """Emit stage-level start progress (S0-S9)."""
        if not self.enabled:
            return
        with self._lock:
            self._stages[stage_id] = {"state": "started", "start": time.monotonic()}
            if self.style == "summary_only":
                return
            extra = f"  {label}" if label else ""
            self._emit(f"[progress] stage-start {stage_id:<4}{extra}")

    def stage_done(self, stage_id: str, *, outcome: str = "completed",
                   detail: str = "") -> None:
        """Emit stage-level completion progress (S0-S9)."""
        if not self.enabled:
            return
        with self._lock:
            rec = self._stages.get(stage_id, {"start": time.monotonic()})
            elapsed = max(0.0, time.monotonic() - float(rec.get("start", time.monotonic())))
            rec["state"] = outcome
            rec["elapsed"] = elapsed
            self._stages[stage_id] = rec
            if self.style == "summary_only":
                return
            msg = f"[progress] stage-done  {stage_id:<4} outcome={outcome}  {elapsed:.1f}s"
            if detail:
                msg += f"  {detail}"
            self._emit(msg)

    def stage_note(self, stage_id: str, detail: str) -> None:
        """Emit an in-stage progress note (non-terminal milestone)."""
        if not self.enabled or not detail:
            return
        with self._lock:
            if self.style == "summary_only":
                return
            self._emit(f"[progress] stage-note  {stage_id:<4} {detail}")

    def discovered(self, all_files: list[str]) -> None:
        """Call after s1 completes the file inventory walk."""
        if not self.enabled:
            return
        with self._lock:
            self._total_files = len(all_files)
            if self.style == "summary_only":
                return
            label = f"  (repo: {self.repo_name})" if self.repo_name else ""
            self._emit(
                f"[progress] discovered  {len(all_files):>5} files{label}"
            )

    def queued(self, chunk) -> None:
        """Call for each chunk after s3 decompose assigns files to chunks.

        ``chunk`` is a ``vvaharness.models.Chunk`` instance.
        """
        if not self.enabled:
            return
        lens = getattr(chunk, "specialist", None) or "+".join(
            (getattr(chunk, "languages", None) or [])[:3]
        ) or "generic"
        cp = ChunkProgress(
            chunk_id=chunk.id,
            files=list(getattr(chunk, "files", []) or []),
            rank=getattr(chunk, "risk_rank", 0),
            lens=lens,
            hypothesis=(getattr(chunk, "hypothesis", "") or "")[:80],
        )
        with self._lock:
            self._chunks[chunk.id] = cp
            if self.style == "summary_only":
                return
            file_count = len(cp.files)
            self._emit(
                f"[progress] queued      {chunk.id:<16} "
                f"(rank={cp.rank}, lens={lens}, {file_count} file{'s' if file_count != 1 else ''})"
            )
            if self.style == "verbose":
                for f in cp.files:
                    self._emit(f"           →  {f}")

    def scanning(self, chunk) -> None:
        """Call immediately before s4 starts processing a chunk."""
        if not self.enabled:
            return
        with self._lock:
            cp = self._chunks.get(chunk.id)
            if cp:
                cp.state = "scanning"
                cp.started_at = time.monotonic()
            self._n_scanning += 1
            n_total = len(self._chunks)
            n_done = self._n_scanned
            if self.style == "summary_only":
                return
            file_count = len(getattr(chunk, "files", []) or [])
            self._emit(
                f"[progress] scanning    {chunk.id:<16}  "
                f"[{file_count} file{'s' if file_count != 1 else ''}]  "
                f"({n_done + self._n_scanning} / {n_total} chunks)"
            )
            if self.style == "verbose":
                for f in (getattr(chunk, "files", []) or []):
                    self._emit(f"           ▶  {f}")

    def scanned(self, chunk, *, outcome: str, n_findings: int = 0) -> None:
        """Call after s4 finishes a chunk (success, error, or guardrail)."""
        if not self.enabled:
            return
        with self._lock:
            cp = self._chunks.get(chunk.id)
            if cp:
                cp.state = "scanned"
                cp.outcome = outcome
                cp.findings = n_findings
                cp.elapsed = time.monotonic() - cp.started_at
            self._n_scanning = max(0, self._n_scanning - 1)
            self._n_scanned += 1
            if self.style == "summary_only":
                return
            elapsed_s = f"{cp.elapsed:.1f}s" if cp else "?"
            icon = {"completed": "✓", "error": "✗", "guardrail": "⊘"}.get(outcome, "?")
            finding_note = (f"  findings={n_findings}" if n_findings else "")
            self._emit(
                f"[progress] scanned     {chunk.id:<16}  "
                f"outcome={outcome}  {elapsed_s}{finding_note}  {icon}"
            )
            files = getattr(chunk, "files", []) or []
            # verbose: always list files; compact: list files only when there
            # is something notable (findings or non-clean outcome)
            show_files = self.style == "verbose" or (
                self.style == "compact" and (n_findings > 0 or outcome != "completed")
            )
            if show_files:
                for f in files:
                    self._emit(f"           {icon}  {f}")

    def print_summary(self) -> None:
        """Call once after all s4 chunks complete.  Always emits when enabled,
        regardless of style, so the operator always gets a final count."""
        if not self.enabled:
            return
        with self._lock:
            total = len(self._chunks)
            outcomes: dict[str, int] = {}
            total_files = 0
            for cp in self._chunks.values():
                o = cp.outcome or "pending"
                outcomes[o] = outcomes.get(o, 0) + 1
                if cp.state == "scanned":
                    total_files += len(cp.files)
            remaining = total - self._n_scanned
            elapsed = time.monotonic() - self._start
            outcome_str = "  ".join(
                f"{k}={v}" for k, v in sorted(outcomes.items())
            )
            self._emit(
                f"[progress] summary     {self._n_scanned} / {total} chunks done  |"
                f"  scanned={total_files} files  elapsed={elapsed:.1f}s"
            )
            if outcome_str:
                self._emit(f"           outcomes:  {outcome_str}")
            if remaining > 0:
                self._emit(
                    f"           WARNING: {remaining} chunk(s) not scanned "
                    f"(see error log)"
                )

    # ── internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _emit(line: str) -> None:
        print(line, file=sys.stderr, flush=True)
