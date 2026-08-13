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

"""
Agentic SAST — profile-controlled S0 static seeding plus an S1-S11 workflow.

Usage (via the `vvaharness` console script):
  vvaharness scan --repo /path/to/target [--config config.yaml]
                   [--resume] [--repo-name acme/payments] [--application-id ID]
                   [--remediate] [--top N]

The shipped default runs S1-S9 through the Claude CLI (`via: cli`) on
claude-sonnet-4-6, S10 through DeepAgents/Anthropic, and S11 through
DeepAgents/OpenAI. The post-scan stages are enabled in that profile but are
skipped with a warning when their provider credential is unavailable; use
`--stop-after s9` for detection only. Other profiles can route detection roles
to the Anthropic SDK (`via: sdk`) or an OpenAI-compatible endpoint
(`via: openai`).

Steps:
  0. Static AST/callgraph seed (profile-controlled) → SeedPackage
  1. Pre-process (agentic exploration)      → ContextPackage
  2. Threat-model (consumes ctx)            → ThreatModel
  3. Decompose (1 run)                      → TaskManifest
  4. Deep-dive (×N + majority vote)         → Finding[]
  5. Pre-filter (deterministic + pre-dedup) → Finding[]
  6. Adversarial verify                     → (verified[], dropped[])
  7. Dedup + VulContextSeverity/Offensive   → (canonical[], dup_dropped[])
  8. Chain                                  → FinalReport (+ ScanMetrics)
  9. MD → SARIF                             → *_report.sarif
 10. Remediate (profile-controlled) — Remediation Agent → <repo>/security-remediation/<NN_slug>/remediate_report.json
 11. Validate  (profile-controlled) — s11 agentic panel → fills each DTO's validation block;
                                               when source-log capture and persistence
                                               succeed, a redacted transcript is retained
                                               beside the DTO as validation_session_<finding>.jsonl

The `vvaharness validate --repo <path> --all` command (or `s11`) runs after remediation.
Both security-scan/ and security-remediation/ are preserved after workspace cleanup.

Each step checkpoints to the SQLite state DB at
~/.vvaharness/state/vvaharness.db (or $VVAHARNESS_STATE_DIR/vvaharness.db).
--resume skips completed steps.
Final report is written to {repo}/security-scan/{module}_{timestamp}_report.{md,sarif}.
"""
import shutil as shutil  # re-exported: patched by tests via orchestrator.shutil
from vvaharness.orchestrator.config_paths import (
    _app_root as _app_root,
    _default_config as _default_config,
    _resolve_against as _resolve_against,
    _iter_model_roles as _iter_model_roles,
    _MODEL_ROLES as _MODEL_ROLES,
)
from vvaharness.orchestrator.checkpoints import (
    save_ckpt as save_ckpt,
    load_ckpt as load_ckpt,
    run_id_for as run_id_for,
)
from vvaharness.orchestrator.cleanup import (
    _rmtree_rw as _rmtree_rw,
    _preserve_set as _preserve_set,
    _purge_clone as _purge_clone,
)
from vvaharness.orchestrator.cmdb import (
    _cmdb_path as _cmdb_path,
    _set_cmdb_path as _set_cmdb_path,
    _load_app_profile as _load_app_profile,
)
from vvaharness.orchestrator.enrich_findings import _enrich_findings as _enrich_findings
from vvaharness.orchestrator.preflight import (
    _mask as _mask,
    _reachable_despite_token_cap as _reachable_despite_token_cap,
    configure_backends as configure_backends,
    check_backends as check_backends,
    probe_backends as probe_backends,
)
from vvaharness.orchestrator.scan import scan_repo as scan_repo
from vvaharness.orchestrator.batch import run_batch as run_batch
from vvaharness.orchestrator.entry import main as main
