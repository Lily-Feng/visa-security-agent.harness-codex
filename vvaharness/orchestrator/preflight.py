# Copyright 2026 Visa, Inc.
# Modifications Copyright 2026 Lily Feng.
# Modified by Lily Feng in 2026 for native Codex support.
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

import asyncio

"""orchestrator.preflight — see package docstring."""
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path

from vvaharness.backends import claude_cli as cli
from vvaharness.backends import codex_cli as codex
from vvaharness.backends import oai, sdk
from vvaharness.backends.llm import (
    DEEPAGENTS_ROLES,
    POST_SCAN_ROLES,
    resolve as resolve_model,
)
from vvaharness.orchestrator.config_paths import _iter_model_roles, _resolve_against





def _mask(v: str | None) -> str:
    """Credential PRESENCE only — never emit key material, a prefix, or the
    length. Even a masked prefix/length leaks the token type and size into
    terminals, CI logs, and screen-shares; for a security tool we report binary
    presence and nothing more."""
    return "set ✓" if v else "<unset>"


def configure_backends(cfg, cfg_dir: Path) -> None:
    """Apply cfg.sdk / cfg.openai / cfg.cli (api_key, base_url, TLS/proxy) to the
    backend clients. Called by main() before scanning AND by `vvaharness doctor`
    so the live preflight probe in check_backends() hits the same
    gateway/credentials the real scan will use."""
    # Whether via:sdk is the SOLE backend across all roles — gates the SDK's
    # ANTHROPIC_API_KEY/AUTH_TOKEN fallback so it only kicks in when sdk isn't
    # sharing the run with via:cli (which uses those same vars for the `claude`
    # subprocess). Mirrors the same condition in check_backends().
    vias = {resolve_model(m)[1] for _, m in _iter_model_roles(cfg)}
    sdk_sole = vias == {"sdk"}
    sdk_cfg = getattr(cfg, "sdk", None)
    if sdk_cfg is not None:
        ca_cert = getattr(sdk_cfg, "ca_cert", None) or None
        client_cert = getattr(sdk_cfg, "client_cert", None) or None
        sdk.configure(
            api_key=getattr(sdk_cfg, "api_key", None),
            base_url=getattr(sdk_cfg, "base_url", None),
            verify_ssl=getattr(sdk_cfg, "verify_ssl", True),
            ca_cert=_resolve_against(cfg_dir, ca_cert) if ca_cert else None,
            client_cert=_resolve_against(cfg_dir, client_cert)
                        if isinstance(client_cert, str) else client_cert,
            no_proxy=getattr(sdk_cfg, "no_proxy", None) or None,
            allow_api_key_fallback=sdk_sole,
        )
    oai_cfg = getattr(cfg, "openai", None)
    if oai_cfg is not None:
        ca_cert = getattr(oai_cfg, "ca_cert", None) or None
        oai.configure(
            api_key=getattr(oai_cfg, "api_key", None),
            base_url=getattr(oai_cfg, "base_url", None),
            verify_ssl=getattr(oai_cfg, "verify_ssl", True),
            ca_cert=_resolve_against(cfg_dir, ca_cert) if ca_cert else None,
            organization=getattr(oai_cfg, "organization", None) or None,
            no_proxy=getattr(oai_cfg, "no_proxy", None) or None,
        )
    # via:cli roles shell out to the `claude` binary; push the same gateway
    # TLS/proxy settings into the subprocess env (auth/endpoint stay delegated
    # to the CLI). No-op when there is no cli: block.
    cli_cfg = getattr(cfg, "cli", None)
    if cli_cfg is not None:
        ca_cert = getattr(cli_cfg, "ca_cert", None) or None
        client_cert = getattr(cli_cfg, "client_cert", None) or None
        cli.configure(
            verify_ssl=getattr(cli_cfg, "verify_ssl", True),
            ca_cert=_resolve_against(cfg_dir, ca_cert) if ca_cert else None,
            client_cert=_resolve_against(cfg_dir, client_cert)
                        if isinstance(client_cert, str) else client_cert,
            no_proxy=getattr(cli_cfg, "no_proxy", None) or None,
            effort=getattr(cli_cfg, "effort", None) or None,
        )
    codex_cfg = getattr(cfg, "codex", None)
    if codex_cfg is not None:
        codex.configure(effort=getattr(codex_cfg, "effort", None) or None)


def _reachable_despite_token_cap(err_msg: str) -> bool:
    """True when a probe error actually proves the model is reachable.

    A via:cli model that responded but whose reply exceeded the tiny preflight
    max_tokens cap surfaces as an error ("...response exceeded the N output
    token maximum..."), yet it demonstrably reached the model — so the probe
    should pass. (The sdk/openai backends truncate silently and never produce
    this; real scans use a large max_tokens and an over-long output there is a
    genuine result worth surfacing, which is why this is scoped to the probe.)"""
    low = (err_msg or "").lower()
    return "exceeded" in low and "output token" in low


def _post_scan_only(roles: Iterable[str]) -> bool:
    """True when every role in *roles* runs after detection (S10/S11).

    Empty is False: an unattributed gap is never assumed harmless.
    """
    return bool(roles) and set(roles) <= POST_SCAN_ROLES


def _report_credential_gap(message: str, roles: Iterable[str], *remedies: str) -> bool:
    """Print a credential gap; return True when it must abort the run.

    A gap that only affects post-scan roles is a WARN: S1-S9 detection needs nothing
    from that credential, and the S10/S11 gates in orchestrator.scan disable the
    affected stage on their own. A credential shared with ANY detection role stays
    fatal exactly as before - a scan that cannot detect must not start.
    """
    if _post_scan_only(roles):
        print(f"  WARN: {message}", file=sys.stderr)
        print(f"    required only by {', '.join(sorted(roles))} — that stage "
              f"will be skipped", file=sys.stderr)
        return False
    print(f"ERROR: {message}", file=sys.stderr)
    for line in remedies:
        print(f"  {line}", file=sys.stderr)
    return True


def check_backends(cfg) -> bool:
    """
    Verify whichever backend(s) the config actually uses:
      - any role with via:cli  → `claude` must be on PATH
      - any role with via:codex → `codex` on PATH with a valid native login
      - any role with via:sdk   → ANTHROPIC_SDK_API_KEY (or cfg.sdk.api_key) must be set
    """
    model_roles = list(_iter_model_roles(cfg))
    vias = {resolve_model(m)[1] for _, m in model_roles}
    # Which roles depend on each backend — decides whether a gap is fatal (any
    # detection role) or a skip-this-stage WARN (post-scan roles only).
    roles_by_via: dict[str, set[str]] = {}
    for _role, _model in model_roles:
        roles_by_via.setdefault(resolve_model(_model)[1], set()).add(_role)

    print(f"  [auth] active backends: {', '.join(sorted(vias)) or '(none)'}",
          file=sys.stderr)

    # CLI auth is validated by the live probe, not env-var presence: Claude Code
    # can authenticate from its normal login/keychain state.
    if "cli" in vias:
        print("  [auth] cli: delegated to configured CLI; live probe verifies login",
              file=sys.stderr)
        if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            print("    NOTE: ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN is set and is "
                  "passed through to the `claude` CLI — it will use that "
                  "credential per its native precedence (API key → auth token "
                  "→ OAuth on disk).", file=sys.stderr)
        if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
            print("    CLAUDE_CODE_OAUTH_TOKEN present for unattended CLI auth ✓",
                  file=sys.stderr)

    if "codex" in vias:
        print("  [auth] codex: delegated to `codex login`; live probe verifies access",
              file=sys.stderr)

    # Presence dump only for credentials required by active API backends.
    # via:sdk uses the Anthropic Python SDK and requires SDK/API credentials.
    if "sdk" in vias:
        sdk_cfg = getattr(cfg, "sdk", None)
        print("  [auth] sdk credential sources (presence only — secrets never printed):",
              file=sys.stderr)
        for label, val in (
            ("env  ANTHROPIC_SDK_API_KEY    ", os.environ.get("ANTHROPIC_SDK_API_KEY")),
            ("cfg  sdk.api_key              ", getattr(sdk_cfg, "api_key", None)),
            ("cfg  sdk.base_url             ", getattr(sdk_cfg, "base_url", None)),
        ):
            shown = (val or "<unset>") if "base_url" in label else _mask(val)
            print(f"    {label}= {shown}", file=sys.stderr)

    if "openai" in vias:
        openai_cfg = getattr(cfg, "openai", None)
        print("  [auth] openai credential sources (presence only — secrets never printed):",
              file=sys.stderr)
        for label, val in (
            ("env  OPENAI_API_KEY           ", os.environ.get("OPENAI_API_KEY")),
            ("cfg  openai.api_key           ", getattr(openai_cfg, "api_key", None)),
            ("cfg  openai.base_url          ", getattr(openai_cfg, "base_url", None)),
        ):
            shown = (val or "<unset>") if "base_url" in label else _mask(val)
            print(f"    {label}= {shown}", file=sys.stderr)

    ok = True
    invalid_deepagents = sorted(
        role for role, model in model_roles
        if resolve_model(model)[1] == "deepagents" and role not in DEEPAGENTS_ROLES
    )
    if invalid_deepagents:
        print(
            "ERROR: via:deepagents is supported only for models.remediate and "
            f"models.validate; invalid role(s): {', '.join(invalid_deepagents)}",
            file=sys.stderr,
        )
        ok = False
    if "cli" in vias:
        if not (shutil.which("claude") or shutil.which("claude.cmd")):
            if _report_credential_gap(
                    "`claude` CLI not found on PATH (required by via:cli roles).",
                    roles_by_via["cli"],
                    "Install: https://docs.anthropic.com/en/docs/claude-code"):
                ok = False
        else:
            print("  [cli] claude found on PATH ✓", file=sys.stderr)

    if "codex" in vias:
        if not (shutil.which("codex") or shutil.which("codex.exe")):
            print("ERROR: `codex` CLI not found on PATH (required by via:codex roles).",
                  file=sys.stderr)
            print("  Install: https://developers.openai.com/codex/cli/",
                  file=sys.stderr)
            ok = False
        elif not codex.login_status():
            print("ERROR: Codex CLI is installed but not logged in.", file=sys.stderr)
            print("  Run: codex login", file=sys.stderr)
            ok = False
        else:
            print("  [codex] CLI found and login ready ✓", file=sys.stderr)

    if "sdk" in vias:
        key = getattr(getattr(cfg, "sdk", None), "api_key", None) \
              or os.environ.get("ANTHROPIC_SDK_API_KEY")
        # Sole-sdk profile: accept the shared ANTHROPIC_API_KEY/AUTH_TOKEN as a
        # fallback (matches sdk._get_client()). When sdk coexists with via:cli
        # we do NOT fall back, so each backend keeps its own credential and the
        # SDK never borrows the CLI's gateway token.
        sdk_sole = vias == {"sdk"}
        used_fallback = False
        if not key and sdk_sole:
            key = os.environ.get("ANTHROPIC_API_KEY") \
                  or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            used_fallback = bool(key)
        if not key:
            remedies = ["export ANTHROPIC_SDK_API_KEY=sk-ant-..."]
            if sdk_sole:
                remedies.append("(or set ANTHROPIC_API_KEY — accepted as a fallback "
                                "because sdk is the only backend)")
            if _report_credential_gap(
                    "ANTHROPIC_SDK_API_KEY not set (required by via:sdk roles).",
                    roles_by_via["sdk"], *remedies):
                ok = False
        elif used_fallback:
            print("  [sdk] ANTHROPIC_SDK_API_KEY unset — using "
                  "ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN fallback "
                  "(sdk is the only backend) ✓", file=sys.stderr)
        else:
            print("  [sdk] ANTHROPIC_SDK_API_KEY present ✓", file=sys.stderr)

    if "openai" in vias:
        key = getattr(getattr(cfg, "openai", None), "api_key", None) \
              or os.environ.get("OPENAI_API_KEY")
        if not key:
            if _report_credential_gap(
                    "OPENAI_API_KEY not set (required by via:openai roles).",
                    roles_by_via["openai"], "export OPENAI_API_KEY=sk-..."):
                ok = False
        else:
            print("  [openai] OPENAI_API_KEY present ✓", file=sys.stderr)

    if "deepagents" in vias:
        from vvaharness.util.environment import _backend_credential_ok

        # Credentials are per (model_id, provider) target, not per via, so the
        # fatal/WARN decision needs the roles behind each individual target.
        deep_specs: dict[tuple[str, str | None], set[str]] = {}
        for role, model in model_roles:
            if resolve_model(model)[1] != "deepagents":
                continue
            spec = (resolve_model(model)[0], getattr(model, "provider", None))
            deep_specs.setdefault(spec, set()).add(role)
        # Sort on a total order: provider is None for name-inferred targets, which
        # would make a bare tuple comparison against a str provider raise.
        for (model_id, provider), roles in sorted(
                deep_specs.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
            ready, detail = _backend_credential_ok("deepagents", model_id, provider)
            if ready:
                print(f"  [deepagents] {model_id}: {detail} ✓", file=sys.stderr)
            elif _report_credential_gap(f"DeepAgents {model_id}: {detail}", roles):
                ok = False

    # ── Live connectivity probe ─────────────────────────────────────────
    # Skipped when credential checks already failed (nothing to probe).
    if not ok:
        print("  [probe] skipped — fix credential errors above first",
              file=sys.stderr)
        return ok
    # Catch the gateway gap (JWT-shaped ANTHROPIC_API_KEY with no
    # ANTHROPIC_BASE_URL) BEFORE the live probe — otherwise the request goes to
    # the public endpoint and (behind a corporate proxy) hangs to a 60s+ timeout
    # instead of giving the actionable fix. Fail fast with the exact remedy.
    if vias & {"cli", "sdk"}:
        from vvaharness.util.environment import _gateway_check, FAIL as _FAIL
        gw = _gateway_check()
        if gw.status == _FAIL:
            print(f"ERROR: {gw.detail}", file=sys.stderr)
            return False
    return probe_backends(cfg)


# The only two roles that drive the agentic() backend path (every other role
# uses prompt()): s1_preprocess.py and s6_verify.py. Kept here so the smoke
# probe exercises exactly the roles a real scan would.
_AGENTIC_ROLES = ("preprocess", "verify")


def _agentic_role_tools(cfg, role: str) -> list[str]:
    """The allowed_tools each agentic role passes to llm.agentic(), mirroring
    s1_preprocess.py and s6_verify.py exactly so the probe sends the same tool
    set the real scan will — the tool set is what makes a via:sdk/openai role
    raise NotImplementedError (those backends reject Bash/custom tools), so it
    is part of the probe's identity."""
    if role == "preprocess":
        at = getattr(getattr(cfg, "step1", None), "allowed_tools", None)
        return list(at) if isinstance(at, list) else ["Read", "Glob", "Grep", "Bash"]
    if role == "verify":
        at = getattr(getattr(cfg, "step6_verify", None), "allowed_tools", None)
        return list(at) if at else ["Read", "Glob", "Grep"]
    return []


def _probe_agentic_roles(cfg) -> bool:
    """Smoke-probe the agentic() backend path for the preprocess + verify roles.

    The prompt-based probe in probe_backends() only exercises prompt(); it
    never touches agentic(). That blind spot let two whole classes of failure
    reach mid-scan silently: (1) a via:cli stream-json argv regression
    (e.g. missing --verbose) that exits rc=1 before any output, and (2) a role
    moved to via:sdk/openai whose allowed_tools contain a tool those backends
    reject (NotImplementedError). A bounded 1-turn agentic call per unique
    (model, via, tool-set) surfaces both here instead.

    Failure is signalled ONLY by a raised exception: a 1-turn agent may
    legitimately end on a tool_use with no final text, so _parse_envelope
    returns "" — an empty reply is NOT a failure. Bounded by max_turns=1 and a
    tiny prompt; note that no wall-clock timeout is plumbed through
    llm.agentic (the cli backend caps itself at its own subprocess timeout)."""
    from vvaharness.backends.llm import agentic as _probe_agentic
    # (model_id, via, frozenset(tools)) -> (model_cfg_node, tools, [roles]).
    targets: dict[tuple, tuple] = {}
    for role, m in _iter_model_roles(cfg):
        if role not in _AGENTIC_ROLES:
            continue
        mid, via, _ = resolve_model(m)
        tools = _agentic_role_tools(cfg, role)
        _node, _t, roles = targets.setdefault(
            (mid, via, frozenset(tools)), (m, tools, []))
        roles.append(role)

    if not targets:
        return True

    print(f"  [probe] agentic backend path ({len(targets)} agentic "
          f"role/backend pair(s)):", file=sys.stderr)
    ok = True
    for (mid, via, _tk), (mcfg, tools, roles) in targets.items():
        role_list = ",".join(roles)
        t0 = time.time()
        workdir = tempfile.mkdtemp(prefix="vva-preflight-")
        try:
            _probe_agentic("reply with the single word ok",
                           model=mcfg, system_prompt=None,
                           allowed_tools=list(tools), cwd=workdir,
                           max_turns=1, tag="preflight-agentic")
            print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                  f"agentic roles: {role_list}", file=sys.stderr)
        except Exception as e:
            if _reachable_despite_token_cap(str(e)):
                print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                      f"agentic roles: {role_list}  (reachable; reply exceeded "
                      f"preflight token cap)", file=sys.stderr)
                continue
            lines = str(e).splitlines()
            msg = (lines[0][:160] if lines else "") or "(no message)"
            print(f"    ✗ [{via:<6}] {mid:<32} FAILED (agentic)  "
                  f"roles: {role_list}", file=sys.stderr)
            print(f"      {type(e).__name__}: {msg}", file=sys.stderr)
            ok = False
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    return ok


def probe_backends(cfg) -> bool:
    """Live connectivity probe: one minimal request per unique (model_id, via)
    so bad credentials, an unreachable base_url, TLS/proxy misconfig, or an
    unknown model id fail HERE instead of mid-scan after tokens are spent
    (~4 output tokens each). Shared by check_backends() and `vvaharness doctor`
    so both exercise the same path the real scan will use. The prompt ping is
    followed by a bounded agentic smoke probe for the agentic-only roles."""
    from vvaharness.backends.llm import prompt as _probe
    invalid_deepagents = sorted(
        role for role, model in _iter_model_roles(cfg)
        if resolve_model(model)[1] == "deepagents" and role not in DEEPAGENTS_ROLES
    )
    if invalid_deepagents:
        print(
            "ERROR: refusing DeepAgents probe for unsupported role(s): "
            + ", ".join(invalid_deepagents),
            file=sys.stderr,
        )
        return False
    # (model_id, via) -> (model_cfg_node, [roles]) — keep the original cfg
    # node so llm.resolve() (which reads .id/.via via getattr) works.
    targets: dict[tuple[str, str], tuple[object, list[str]]] = {}
    for role, m in _iter_model_roles(cfg):
        mid, via, _ = resolve_model(m)
        node, roles = targets.setdefault((mid, via), (m, []))
        roles.append(role)

    print(f"  [probe] live model connectivity ({len(targets)} unique "
          f"model/backend pair(s)):", file=sys.stderr)
    ok = True
    # Post-scan roles whose model is unreachable. Tracked so the closing summary
    # cannot claim "all reachable" right after WARNing that one was not.
    skipped: set[str] = set()
    for (mid, via), (mcfg, roles) in targets.items():
        role_list = ",".join(roles)
        t0 = time.time()
        try:
            if via == "deepagents":
                from vvaharness.backends.harness import OneShotOptions, get_harness

                with tempfile.TemporaryDirectory(
                        prefix="vva-preflight-deepagents-") as workdir:
                    result = asyncio.run(get_harness(via).run_oneshot(
                        "reply with the single word ok",
                        OneShotOptions(
                            model=mid,
                            cwd=Path(workdir),
                            env=dict(os.environ),
                            max_turns=2,
                        ),
                    ))
                if result.is_error:
                    raise RuntimeError(
                        f"DeepAgents preflight failed: {result.subtype or 'unknown error'}")
            else:
                _probe("ping", model=mcfg,
                       max_tokens=4, timeout=120, tag="preflight")
            print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                  f"roles: {role_list}", file=sys.stderr)
        except Exception as e:
            if _reachable_despite_token_cap(str(e)):
                print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                      f"roles: {role_list}  (reachable; reply exceeded preflight "
                      f"token cap)", file=sys.stderr)
                continue
            # str(e) can be empty (some socket/timeout/SDK connection errors
            # carry no message) — splitlines() then yields [], so guard the
            # index to avoid an IndexError masking the real probe failure.
            lines = str(e).splitlines()
            msg = (lines[0][:160] if lines else "") or "(no message)"
            # A model only S10/S11 use being unreachable degrades that stage, not the
            # scan: detection never touches it and the S10/S11 gates skip it.
            if _post_scan_only(roles):
                print(f"    WARN [{via:<6}] {mid:<32} unreachable  roles: "
                      f"{role_list} — that stage will be skipped", file=sys.stderr)
                print(f"      {type(e).__name__}: {msg}", file=sys.stderr)
                skipped.update(roles)
                continue
            print(f"    ✗ [{via:<6}] {mid:<32} FAILED  roles: {role_list}",
                  file=sys.stderr)
            print(f"      {type(e).__name__}: {msg}", file=sys.stderr)
            ok = False

    # Exercise the agentic() path too (preprocess/verify only). Listed first so
    # it always runs even when a prompt probe already failed — more complete
    # diagnostics in one pass.
    ok = _probe_agentic_roles(cfg) and ok

    if ok and skipped:
        print(f"  [probe] detection backends reachable ✓ — "
              f"{', '.join(sorted(skipped))} unreachable, so that stage is "
              f"skipped (see WARN above)", file=sys.stderr)
    elif ok:
        print("  [probe] all model backends reachable ✓", file=sys.stderr)
    else:
        print("ERROR: one or more model backends unreachable — fix before "
              "scanning, or pass --skip-preflight to bypass.", file=sys.stderr)
    return ok
