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


from __future__ import annotations

"""orchestrator.checkpoints — see package docstring.

SECURITY: checkpoint payloads are JSON, never pickle. The previous
pickle-based implementation was vulnerable to CWE-502 (RCE on ``--resume``
via a hostile checkpoint, irrespective of allow-listing — pickle's
REDUCE/BUILD opcodes are an arbitrary-callable VM by design). JSON has no
constructor opcodes: parsing yields only dict / list / str / int / float /
bool / None, and every object is then re-hydrated through pydantic
``model_validate``, so a tampered payload produces at worst a
``ValidationError`` → the step is re-run. There is deliberately NO
``import pickle`` in this module. Payloads now live as BLOB rows in the
SQLite state store (orchestrator.store) instead of loose ``*.json`` files,
but the bytes on disk are the same ``TypeAdapter.dump_json()`` output and
the same validate-on-load gate applies.
"""
import hashlib
import json
import sys
from pathlib import Path

from pydantic import TypeAdapter, ValidationError
from typing_extensions import TypedDict

from vvaharness.models import (ContextPackage, ThreatModel, TaskManifest,
                               Finding, DroppedFinding, FinalReport)
from vvaharness.orchestrator import store


# ── Per-step schema ──────────────────────────────────────────────────────────
# Each pipeline step checkpoints exactly one shape. The TypeAdapter both
# serialises (dump_json — pydantic-aware, handles Enum/datetime/nested
# BaseModel) and validates on load (validate_json — every field passes its
# pydantic validator, so a tampered value is rejected with a field path
# rather than smuggled into the pipeline). Adding a step = add one row here.
class _S4Ckpt(TypedDict):
    findings: list[Finding]
    outcomes: dict[str, str]


_S7Ckpt = tuple[list[DroppedFinding],   # pre_dropped
                list[Finding],          # verified
                list[DroppedFinding],   # dropped
                list[Finding],          # canonical
                list[DroppedFinding]]   # dup_dropped


from vvaharness.pipeline.stages.s0_seed import SeedPackage

_STEP_SCHEMA: dict[str, TypeAdapter] = {
    # s0 is a plain @dataclass; TypeAdapter serialises it (incl. the Path field)
    # to JSON and rebuilds it on load — same no-pickle guarantee as the rest.
    "s0": TypeAdapter(SeedPackage),
    "s1": TypeAdapter(ContextPackage),
    "s2": TypeAdapter(ThreatModel),
    "s3": TypeAdapter(TaskManifest),
    "s4": TypeAdapter(_S4Ckpt),
    "s7": TypeAdapter(_S7Ckpt),
    "s8": TypeAdapter(FinalReport),
    "s9": TypeAdapter(str),
}

# Step 10 — the Remediation Agent checkpoints one small JSON-serialisable
# dict per finding under a dynamic ``remediate_<index>`` step key (both the
# standalone ``vvaharness remediate`` command and the in-pipeline
# ``--remediate`` run use this), so it can't live in the fixed table above.
# These steps share a permissive dict adapter; the per-finding record is inert
# data (no nested BaseModel), so validate-on-load still rejects non-JSON /
# oversized payloads.
_REMEDIATE_STEP_SCHEMA: TypeAdapter = TypeAdapter(dict)

# s11 validation's dynamic ``validate_<finding_id>`` steps store a ValidationResult.
# Built lazily on first use: ``ValidationResult`` lives in ``vvaharness.validation``,
# which already imports from this package — a module-level import here would create a
# cycle. The adapter is cached after the first resolve.
_VALIDATE_STEP_SCHEMA: TypeAdapter | None = None


def _validate_schema() -> TypeAdapter:
    """Lazily build and cache the TypeAdapter for ``validate_<id>`` checkpoint steps."""
    global _VALIDATE_STEP_SCHEMA  # cached adapter — intentional module-level state
    if _VALIDATE_STEP_SCHEMA is None:
        from vvaharness.validation.models import ValidationResult
        _VALIDATE_STEP_SCHEMA = TypeAdapter(ValidationResult)
    return _VALIDATE_STEP_SCHEMA


def _schema_for(step: str) -> TypeAdapter:
    """Resolve the TypeAdapter for a checkpoint step. Fixed pipeline steps come
    from ``_STEP_SCHEMA``; the Remediation Agent's dynamic ``remediate_<N>`` steps
    and the validator's ``validate_<id>`` steps use their dynamic adapters."""
    if step in _STEP_SCHEMA:
        return _STEP_SCHEMA[step]
    if step.startswith("remediate_"):
        return _REMEDIATE_STEP_SCHEMA
    if step.startswith("validate_"):
        return _validate_schema()
    return _STEP_SCHEMA[step]   # unknown step → KeyError (caller bug, fail loud)


# No legitimate checkpoint produced by this pipeline approaches this size; an
# oversized payload is either corruption or a deliberate resource-exhaustion
# attempt. Enforced at save time (refuse to persist) AND by a CHECK constraint
# on checkpoints.size, so a hostile direct INSERT is also rejected.
_CKPT_MAX_BYTES = 100 * 1024 * 1024


def save_ckpt(ckpt_dir: Path, run_id: str, step: str, obj) -> None:
    """Persist ``obj`` for ``(run_id, step)`` to the SQLite state store.

    ``ckpt_dir`` is retained for call-site compatibility (scan.py passes it
    at every stage) and ignored — the DB path comes from
    ``$VVAHARNESS_STATE_DIR`` via :func:`store.db_path`."""
    del ckpt_dir
    blob = _schema_for(step).dump_json(obj)
    if len(blob) > _CKPT_MAX_BYTES:
        print(f"  [ckpt] WARN: {step} payload {len(blob)} bytes exceeds "
              f"{_CKPT_MAX_BYTES}; not persisted", file=sys.stderr)
        return
    con = store.connect()
    try:
        with con:   # one transaction == atomic; replaces .tmp + os.replace()
            # Ensure a parent runs row exists so the FK + ON DELETE CASCADE
            # hold even when scan.py's register_run() was skipped (tests,
            # ad-hoc callers).
            con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) "
                        "VALUES (?, '')", (run_id,))
            con.execute("UPDATE runs SET updated_at = datetime('now') "
                        "WHERE run_id = ?", (run_id,))
            con.execute(
                "INSERT OR REPLACE INTO checkpoints"
                "(run_id, step, payload, size) VALUES (?, ?, ?, ?)",
                (run_id, step, blob, len(blob)),
            )
    finally:
        con.close()
    print(f"  [ckpt] saved {step}", file=sys.stderr)


def load_ckpt(ckpt_dir: Path, run_id: str, step: str):
    """Return the rehydrated checkpoint for ``(run_id, step)`` or ``None``.

    ``None`` means: not present, schema-invalid, oversized, or otherwise
    untrusted — in every case the caller re-runs the step. ``ckpt_dir`` is
    ignored (kept for call-site compatibility)."""
    del ckpt_dir
    con = store.connect()
    try:
        row = con.execute(
            "SELECT payload, size FROM checkpoints WHERE run_id=? AND step=?",
            (run_id, step),
        ).fetchone()
    finally:
        con.close()
    if row is None:
        if step == "s1":
            print(f"  [ckpt] no checkpoints for {run_id[:12]}… in "
                  f"{store.db_path()} — if you expected resume, check "
                  f"$VVAHARNESS_STATE_DIR", file=sys.stderr)
        return None
    payload, size = row
    if size > _CKPT_MAX_BYTES:   # belt-and-braces; CHECK already enforces
        print(f"  [ckpt] WARN: {step} exceeds {_CKPT_MAX_BYTES} bytes; "
              f"ignoring and re-running", file=sys.stderr)
        return None
    try:
        obj = _schema_for(step).validate_json(payload)
    except (ValidationError, ValueError) as e:
        # Both branches degrade the same safe way — re-run the step instead of
        # crashing or trusting a bad payload — but the diagnostics differ, and
        # the only distinction the bytes actually support is "is this valid
        # JSON at all?". Payloads carry no schema-version field and no
        # signature, so a version bump cannot be told apart from a value-level
        # tamper once the JSON parses; claiming otherwise would be fiction.
        try:
            json.loads(payload)
        except (ValueError, TypeError):
            # Not even well-formed JSON: truncated, corrupt, or a substituted
            # non-checkpoint blob — i.e. genuinely unreadable and untrusted.
            print(f"  [ckpt] WARN: {step} unreadable — payload is not valid "
                  f"JSON (corrupt or untrusted) ({e}); ignoring and "
                  f"re-running", file=sys.stderr)
        else:
            # Well-formed JSON that fails the pydantic schema: almost always a
            # checkpoint written by a different tool version whose model
            # fields moved/renamed (a value-level tamper is indistinguishable
            # here and equally inert). Not a tampering signal on its own.
            print(f"  [ckpt] WARN: {step} schema mismatch — likely written by "
                  f"an incompatible tool version ({e}); discarding and "
                  f"re-running", file=sys.stderr)
        return None
    print(f"  [ckpt] resumed {step} from db", file=sys.stderr)
    return obj


def run_id_for(repo: str | Path) -> str:
    """Stable, non-reversible run id per repo path. SHA-256 so the on-disk
    checkpoint filename leaks nothing about the host's directory layout and
    cannot be trivially predicted by a hostile target repo. Accepts ``str``
    or ``Path`` — callers pass ``ContextPackage.repo_root`` (str) as well as
    the orchestrator's ``Path`` repo handle."""
    return hashlib.sha256(str(Path(repo).resolve()).encode()).hexdigest()[:32]


# ── gc ──────────────────────────────────────────────────────────────────────
def prune_checkpoints(*, keep_runs: int = 100, max_age_days: int = 5,
                      dry_run: bool = False) -> dict:
    """Delete ``runs`` rows (and their checkpoints, via ON DELETE CASCADE)
    older than ``max_age_days`` OR beyond the ``keep_runs`` most-recent by
    ``updated_at``. ``dry_run`` reports without touching the DB. Only the
    state store under ``$VVAHARNESS_STATE_DIR`` is touched — reports under
    ``<repo>/security-scan/`` are never affected. Returns
    ``{'root', 'kept', 'deleted': [run_id, …]}``."""
    con = store.connect()
    try:
        total = con.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        victims = [r[0] for r in con.execute(
            """SELECT run_id FROM runs
               WHERE updated_at < datetime('now', ?)
                  OR run_id NOT IN (
                       SELECT run_id FROM runs
                       ORDER BY updated_at DESC LIMIT ?)
               ORDER BY updated_at""",
            (f"-{max_age_days} days", keep_runs),
        )]
        if not dry_run and victims:
            with con:
                con.executemany("DELETE FROM runs WHERE run_id = ?",
                                [(v,) for v in victims])
            # Reclaim freed pages from the main DB file, then truncate the
            # -wal file back to zero — without the second step the WAL can
            # sit at the high-water-mark of the largest deleted blob.
            con.execute("PRAGMA incremental_vacuum")
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        con.close()
    return {"root": str(store.db_path()),
            "kept": total - len(victims), "deleted": victims}
