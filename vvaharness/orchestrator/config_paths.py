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

"""orchestrator.config_paths — see package docstring."""
from pathlib import Path

from vvaharness.config import is_network_path





def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _default_config() -> Path:
    cwd_cfg = Path.cwd() / "config.yaml"
    if cwd_cfg.exists():
        return cwd_cfg
    return _packaged_default()


def _packaged_default() -> Path:
    """The bundled default profile — the trusted fallback used when a config
    sourced from inside the scan target is refused."""
    return _app_root() / "config" / "profiles" / "default.yaml"


def _path_within(candidate, root) -> bool:
    """True if `candidate` resolves at or under `root` (both fully resolved).
    Used to refuse a config/.env that lives INSIDE the scanned (untrusted)
    repository, which an attacker who controls the checkout could plant."""
    try:
        Path(candidate).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def _resolve_against(base: Path, p: str) -> str:
    # Refuse UNC/network input paths before they reach any loader's
    # is_file()/read — on Windows that touch leaks the user's NTLM hash over
    # SMB. Covers every injected input that funnels through here: inject.*
    # (cve/controls/cmdb), step_remediate policy/playbook (via _resolve_input),
    # and TLS ca_cert/client_cert. Check the raw value and the base-joined
    # result (a UNC base would taint an otherwise-relative path).
    if is_network_path(p):
        raise ValueError(
            f"refusing network/UNC input path {p!r} "
            f"(reading it could leak credentials over SMB)")
    pp = Path(p)
    resolved = pp if pp.is_absolute() else (base / pp)
    if is_network_path(resolved):
        raise ValueError(
            f"refusing network/UNC input path {str(resolved)!r} "
            f"(reading it could leak credentials over SMB)")
    return str(resolved)


_MODEL_ROLES = ("autoexclude", "preprocess", "threatmodel", "decompose",
                "deepdive", "verify", "dedup", "chain", "remediate", "validate")


def _iter_model_roles(cfg):
    for r in _MODEL_ROLES:
        m = getattr(cfg.models, r, None)
        if m is None:
            continue
        if r == "validate":
            m = getattr(m, "orchestrator", None)
            if m is None:
                continue
        yield r, m
