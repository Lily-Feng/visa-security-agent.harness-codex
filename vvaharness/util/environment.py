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

"""Environment readiness engine shared by ``vvaharness setup`` and
``vvaharness doctor``.

Pure, side-effect-free detection: each check returns a :class:`Check` with a
status and a human detail. NEVER prints or returns credential material — only
presence (set / unset). The CLI layer renders these; this module never touches
stdout, so it stays unit-testable and reusable.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from vvaharness.backends.llm import DEEPAGENTS_ROLES
from vvaharness.validation.cli._model import _validate_model_spec

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass(frozen=True)
class Check:
    name: str
    status: str            # OK | WARN | FAIL
    detail: str
    required: bool = False  # a FAIL on a required check blocks scanning


# ── helpers ──────────────────────────────────────────────────────────────────
def _is_set(env: str) -> bool:
    return bool(os.environ.get(env))


def _looks_like_jwt(v: str | None) -> bool:
    """Claude Code / gateway session tokens are JWTs ('eyJ…'); a real Anthropic
    API key is 'sk-ant-…'. We only inspect the PREFIX shape, never log the
    value."""
    if not v:
        return False
    if v.startswith("eyJ"):
        return True
    # Some gateways issue opaque JWT-like session tokens that don't begin with
    # eyJ but still follow the three-segment shape.
    parts = v.split(".")
    if len(parts) == 3 and v.startswith("ey"):
        return all(bool(p) for p in parts)
    return False


# ── individual checks ──────────────────────────────────────────────────────────
def python_check() -> Check:
    """Interpreter floor, read from package metadata (never hardcoded)."""
    floor = (3, 10)
    try:
        from importlib.metadata import metadata
        import re
        req = (
            metadata("codex-vulnerability-agentic-harness").get("Requires-Python")
            or ""
        )
        m = re.search(r">=\s*(\d+)\.(\d+)", req)
        if m:
            floor = (int(m.group(1)), int(m.group(2)))
    except Exception:
        pass
    cur = ".".join(str(v) for v in sys.version_info[:3])
    if sys.version_info[:2] >= floor:
        return Check("Python", OK, f"{cur} (≥ {floor[0]}.{floor[1]})")
    return Check("Python", FAIL,
                 f"{cur} — requires ≥ {floor[0]}.{floor[1]}", required=True)


def tool_check(cmd: str, why: str, *, required: bool = False) -> Check:
    path = shutil.which(cmd)
    if path:
        return Check(cmd, OK, path)
    return Check(cmd, FAIL if required else WARN, f"not on PATH ({why})",
                 required=required)


# AI coding agents the harness can drive (or that indicate available creds).
# (display, command, the env key that powers it, backend it maps to)
_AGENTS = [
    ("Claude Code", "claude", ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                               "CLAUDE_CODE_OAUTH_TOKEN"), "via:cli"),
    ("OpenAI Codex", "codex", (), "via:codex"),
    ("Gemini CLI", "gemini", ("GEMINI_API_KEY", "GOOGLE_API_KEY"), "—"),
    ("Cursor Agent", "cursor-agent", (), "—"),
    ("GitHub Copilot CLI", "copilot", (), "via:cli"),
]


def _claude_code_login_present() -> bool:
    if (Path.home() / ".claude" / ".credentials.json").exists():
        return True
    state = Path.home() / ".claude.json"
    if not state.exists():
        return False
    try:
        import json
        data = json.loads(state.read_text(encoding="utf-8"))
    except Exception:
        return False
    return bool(data.get("oauthAccount"))


def _codex_login_present() -> bool:
    """Ask the CLI itself; Codex auth may live in a keychain or auth.json."""
    from vvaharness.backends.codex_cli import login_status
    return login_status()


def agent_checks() -> list[Check]:
    """Detect installed AI agents and whether they are ready to use.
    Presence only — never the key value."""
    out: list[Check] = []
    oauth = _claude_code_login_present()
    for display, cmd, keys, backend in _AGENTS:
        path = shutil.which(cmd)
        if not path:
            out.append(Check(f"agent: {display}", WARN, "not installed"))
            continue
        if cmd == "codex":
            has_auth = _codex_login_present()
        else:
            has_auth = ((not keys) or any(_is_set(k) for k in keys)
                        or (cmd == "claude" and oauth))
        if not keys and cmd != "codex":
            keyinfo = "installed"
        else:
            keyinfo = "installed and logged in" if has_auth else "installed; login not detected"
        status = OK if has_auth else WARN
        out.append(Check(f"agent: {display}", status,
                         f"{cmd} ✓ ({backend}) — {keyinfo}"))
    return out


# (module import name, required for baseline runtime)
_DEPS = [
    ("pydantic", True),
    ("yaml", True),
    ("anthropic", True),
    ("tree_sitter", False),
    ("tree_sitter_language_pack", False),
    ("openai", False),
]


def dep_checks() -> list[Check]:
    out: list[Check] = []
    for mod, required in _DEPS:
        present = importlib.util.find_spec(mod) is not None
        label = {
            "yaml": "PyYAML",
            "tree_sitter": "tree-sitter",
            "tree_sitter_language_pack": "tree-sitter-language-pack",
        }.get(mod, mod)
        if present:
            out.append(Check(f"dep: {label}", OK, "importable"))
        elif required:
            out.append(Check(f"dep: {label}", FAIL, "missing", required=True))
        elif mod == "tree_sitter":
            out.append(Check(
                f"dep: {label}",
                WARN,
                "NOT INSTALLED — call graph falls back to regex (degraded taint coverage)",
            ))
        elif mod == "tree_sitter_language_pack":
            out.append(Check(
                f"dep: {label}",
                WARN,
                "NOT INSTALLED — tree-sitter AST plugins unavailable; call graph degrades",
            ))
        else:
            out.append(Check(f"dep: {label}", WARN,
                             "missing (optional — needed only for via:openai)"))
    return out


# Credential env vars we report presence for (NEVER the value).
_CRED_ENVS = [
    "ANTHROPIC_SDK_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY", "GEMINI_API_KEY",
    "GITHUB_TOKEN",
]


def credential_checks() -> list[Check]:
    out: list[Check] = []
    for env in _CRED_ENVS:
        out.append(Check(f"cred: {env}", OK if _is_set(env) else WARN,
                         "set" if _is_set(env) else "unset"))
    return out


def _gateway_check() -> Check:
    """The exact trap we hit: a JWT-shaped ANTHROPIC_API_KEY with no
    ANTHROPIC_BASE_URL → it is a gateway/Claude-Code token that will 401
    against the public Anthropic API. Flag it loudly with the remedy."""
    base = os.environ.get("ANTHROPIC_BASE_URL")
    key = os.environ.get("ANTHROPIC_API_KEY")
    if base:
        # Strip any query string before echoing — a token embedded as a query
        # parameter must not be printed by doctor/setup.
        return Check("via:sdk endpoint", OK,
                     f"ANTHROPIC_BASE_URL={base.split('?', 1)[0]}")
    if _looks_like_jwt(key):
        return Check("via:sdk endpoint", FAIL,
                     "ANTHROPIC_API_KEY looks like a gateway/Claude-Code token "
                     "(eyJ…) but ANTHROPIC_BASE_URL is unset — it will 401 "
                     "against the public API. Set ANTHROPIC_BASE_URL to your "
                     "gateway (and NODE_EXTRA_CA_CERTS if it needs a private CA).",
                     required=True)
    return Check("via:sdk endpoint", OK, "public api.anthropic.com (default)")


# ── actionable discovery (for setup's guidance / --write-env) ────────────────
_RC_FILES = (".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile")
_BASE_URL_RX = None  # compiled lazily


def detect_gateway() -> tuple[str | None, str | None]:
    """Find a usable ANTHROPIC_BASE_URL even if the user hasn't exported it.
    Order: live env → a (possibly commented-out) export in the shell rc files.
    Returns (url, source) or (None, None). Reads only; never writes."""
    import re
    live = os.environ.get("ANTHROPIC_BASE_URL")
    if live:
        return live, "environment"
    rx = re.compile(r'ANTHROPIC_BASE_URL\s*=\s*["\']?(https?://[^"\'\s]+)')
    for name in _RC_FILES:
        p = Path.home() / name
        if not p.is_file():
            continue
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                m = rx.search(line)
                if m:
                    return m.group(1), f"~/{name}"
                    # (commented lines match too — that's the point: surface it)
        except OSError:
            continue
    return None, None


def detect_ca_cert() -> str | None:
    """A private-CA bundle the gateway may need (NODE_EXTRA_CA_CERTS), or the
    conventional ~/cacerts.pem if present."""
    env_cert = os.environ.get("NODE_EXTRA_CA_CERTS")
    if env_cert and Path(env_cert).is_file():
        return env_cert
    default = Path.home() / "cacerts.pem"
    return str(default) if default.is_file() else None


def recommend_profile() -> tuple[str | None, str]:
    """Suggest the shipped profile that matches the credentials actually
    available. This is a starting-profile recommendation, not a claim that
    every enabled post-scan stage is ready; ``config_check`` reports those
    provider credentials separately.
    Returns (profile_name, reason)."""
    # A native Codex login needs no API key and maps to the all-Codex profile.
    if shutil.which("codex") and _codex_login_present():
        return "codex", ("Codex CLI login detected — codex.yaml runs detection "
                         "roles via `codex exec` using that login")
    # Prefer the default when Claude Code auth is available because its S1-S9
    # detection flow uses the CLI. S10/S11 have separate advisory readiness
    # checks and are skipped when their provider credentials are unavailable.
    cli_auth = shutil.which("claude") and (
        _looks_like_jwt(os.environ.get("ANTHROPIC_API_KEY"))
        or _is_set("ANTHROPIC_AUTH_TOKEN")
        or _is_set("CLAUDE_CODE_OAUTH_TOKEN")
        or _claude_code_login_present())
    if cli_auth:
        return "default", ("Claude Code auth detected — default-profile "
                           "detection uses the claude CLI; setup checks S10/S11 "
                           "provider credentials separately")
    # Without CLI auth, suggest the profile associated with an available API
    # key. Later checks still report any other credentials that profile needs.
    if _is_set("ANTHROPIC_SDK_API_KEY"):
        return "sdk", ("ANTHROPIC_SDK_API_KEY is set — sdk.yaml routes model "
                       "roles via sdk; setup checks the S11 credential separately")
    if _is_set("OPENAI_API_KEY"):
        return "full", ("OPENAI_API_KEY is set — full.yaml includes OpenAI "
                        "roles; setup checks its other backends separately")
    return None, "no usable credential detected yet"


def dotenv_check() -> Check:
    """Report the .env file that startup auto-loads, if present.

    Missing .env is OK for CLI login/keychain users, so this is
    informational rather than a warning or blocker.
    """
    for d in (Path.cwd(), *Path.cwd().parents):
        p = d / ".env"
        if p.is_file():
            detail = ".env found" if d == Path.cwd() else f"{p} found"
            return Check(".env", OK, detail)
    return Check(".env", OK, "not found (optional; use setup --write-env)")


def config_check(cfg_path: str | Path) -> list[Check]:
    """Confirm the active profile loads and report which backends it uses and
    whether the credential each backend needs is present."""
    p = Path(cfg_path)
    if not p.exists():
        return [Check("config", FAIL, f"not found: {p}", required=True)]
    try:
        from vvaharness import config as config_mod
        cfg = config_mod.load(p)
    except Exception as e:  # noqa: BLE001
        return [Check("config", FAIL, f"failed to load {p}: {e}", required=True)]
    cwd_cfg = Path.cwd() / "config.yaml"
    if p.resolve() == cwd_cfg.resolve():
        detail = "config.yaml loads"
    elif not cwd_cfg.exists():
        detail = (f"{p.name} loads — create ./config.yaml for local defaults "
                  f"(config.yml is not auto-loaded)")
    else:
        detail = f"{p.name} loads"
    out = [Check("config", OK, detail)]
    roles = ("autoexclude", "preprocess", "threatmodel", "decompose",
             "deepdive", "verify", "dedup", "chain", "remediate", "validate")
    vias = set()
    for r in roles:
        node = getattr(getattr(cfg, "models", None), r, None)
        if node is not None:
            vias.add(getattr(node, "via", "cli"))
    out.append(Check("active backends", OK, ", ".join(sorted(vias)) or "(none)"))
    invalid_deepagents = sorted(
        r for r in roles
        if (node := getattr(getattr(cfg, "models", None), r, None)) is not None
        and getattr(node, "via", "cli") == "deepagents"
        and r not in DEEPAGENTS_ROLES
    )
    if invalid_deepagents:
        out.append(Check(
            "via:deepagents roles",
            FAIL,
            "supported only for models.remediate and models.validate; invalid "
            f"role(s): {', '.join(invalid_deepagents)}",
            required=True,
        ))
    if "sdk" in vias:
        out.append(_gateway_check())
        sdk_cfg = getattr(cfg, "sdk", None)
        has_sdk_key = (_is_set("ANTHROPIC_SDK_API_KEY")
                       or bool(getattr(sdk_cfg, "api_key", None)))
        # Sole-sdk profile: accept the shared ANTHROPIC_API_KEY/AUTH_TOKEN as a
        # fallback (matches preflight.check_backends() and sdk._get_client()).
        # When sdk coexists with via:cli we require the SDK's own key so the two
        # backends keep distinct credentials.
        sdk_sole = vias == {"sdk"}
        fallback = sdk_sole and (_is_set("ANTHROPIC_API_KEY")
                                 or _is_set("ANTHROPIC_AUTH_TOKEN"))
        if has_sdk_key:
            pass  # SDK-specific key present — nothing to flag
        elif fallback:
            out.append(Check("via:sdk credential", OK,
                             "ANTHROPIC_SDK_API_KEY unset — using "
                             "ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN fallback "
                             "(sdk is the only backend)"))
        else:
            detail = "ANTHROPIC_SDK_API_KEY not set (required by this profile)"
            if sdk_sole:
                detail += " — or set ANTHROPIC_API_KEY (accepted as a fallback)"
            out.append(Check("via:sdk credential", FAIL, detail, required=True))
        # The profile also reads three OPTIONAL SDK knobs via ${ENV}. Unset is
        # valid (public api.anthropic.com, system trust store, no mTLS) — so
        # these are never blocking — but surface presence so an enterprise /
        # gateway user knows the levers exist and which env var sets each.
        for env_name, attr, note in (
            ("ANTHROPIC_SDK_BASE_URL", "base_url",
             "gateway endpoint — defaults to public api.anthropic.com"),
            ("ANTHROPIC_SDK_CA_CERT", "ca_cert",
             "gateway CA bundle — only for a private-CA gateway"),
            ("ANTHROPIC_SDK_CLIENT_CERT", "client_cert",
             "client cert for mTLS — off when unset"),
        ):
            present = _is_set(env_name) or bool(getattr(sdk_cfg, attr, None))
            out.append(Check(f"via:sdk {env_name}", OK if present else WARN,
                             "set" if present else f"unset (optional: {note})"))
    if "openai" in vias and not _is_set("OPENAI_API_KEY"):
        out.append(Check("via:openai credential", FAIL,
                         "OPENAI_API_KEY not set (required by this profile)",
                         required=True))
    if "codex" in vias:
        if not shutil.which("codex"):
            out.append(Check("via:codex backend", FAIL,
                             "`codex` CLI not on PATH (required by this profile)",
                             required=True))
        elif not _codex_login_present():
            out.append(Check("via:codex credential", FAIL,
                             "Codex login not detected — run `codex login`",
                             required=True))
        else:
            out.append(Check("via:codex credential", OK,
                             "Codex CLI login ready (credential value not read)"))
    if "cli" in vias and not shutil.which("claude"):
        out.append(Check("via:cli backend", FAIL,
                         "`claude` CLI not on PATH (required by this profile)",
                         required=True))
    # Profile-controlled post-scan steps (s10 remediate / s11 validate) never block
    # the core scan — when misconfigured the orchestrator disables the step and
    # continues — so their checks are advisory (WARN), but surfacing them here
    # tells an operator who enabled the flags whether the step will actually run.
    out += _remediate_checks(cfg)
    out += _validate_checks(cfg)
    return out


def remediation_inputs_check() -> Check:
    """Ensure fail-closed remediation defaults are available."""
    from vvaharness.remediation_agent import rule_paths
    missing = rule_paths.missing_rules(rule_paths.__file__)
    configured = rule_paths.configured_inputs_dir()
    if not missing:
        detail = (f"using {configured}" if configured else
                  "bundled policy and playbook available")
        return Check("remediation inputs", OK, detail)
    return Check(
        "remediation inputs", FAIL,
        f"missing {', '.join(missing)}; run interactive `vvaharness setup` "
        "to select the inputs directory", required=True)


def _backend_credential_ok(
    via: str, model_id: str = "", provider: str | None = None
) -> tuple[bool, str]:
    """(ready, detail) for a model role's backend. Presence only — never the value."""
    if via == "cli":
        if shutil.which("claude"):
            return True, "`claude` CLI on PATH"
        return False, "`claude` CLI not on PATH"
    if via == "sdk":
        if (_is_set("ANTHROPIC_SDK_API_KEY") or _is_set("ANTHROPIC_API_KEY")
                or _is_set("ANTHROPIC_AUTH_TOKEN")):
            return True, "Anthropic SDK credential present"
        return False, ("ANTHROPIC_SDK_API_KEY not set "
                       "(or ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN)")
    if via == "openai":
        if _is_set("OPENAI_API_KEY"):
            return True, "OPENAI_API_KEY set"
        return False, "OPENAI_API_KEY not set"
    if via == "codex":
        if not shutil.which("codex"):
            return False, "`codex` CLI not on PATH"
        if not _codex_login_present():
            return False, "Codex CLI not logged in"
        return True, "Codex CLI login ready"
    if via == "deepagents":
        # Use explicit provider; fall back to name-based inference only when absent.
        is_openai = (provider == "openai") if provider else ("claude" not in model_id.lower())
        if is_openai:
            if _is_set("OPENAI_API_KEY"):
                return True, "OpenAI-compatible DeepAgents credential present"
            return False, "OPENAI_API_KEY not set (set OPENAI_BASE_URL for a custom endpoint)"
        if (_is_set("ANTHROPIC_API_KEY") or _is_set("ANTHROPIC_AUTH_TOKEN")):
            return True, "Anthropic-compatible DeepAgents credential present"
        return False, "ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN not set"
    return True, f"via:{via}"


def _remediate_checks(cfg) -> list[Check]:
    """Step-10 readiness — empty unless ``step_remediate.enabled``. Mirrors
    ``orchestrator.scan._remediate_preflight``: needs a configured
    ``models.remediate`` role whose backend credential is present."""
    if not getattr(getattr(cfg, "step_remediate", None), "enabled", False):
        return []
    rem = getattr(getattr(cfg, "models", None), "remediate", None)
    if rem is None:
        return [Check("step10: remediate", WARN,
                      "step_remediate.enabled but models.remediate is unset "
                      "— remediation will be skipped")]
    via = getattr(rem, "via", "cli")
    ready, detail = _backend_credential_ok(via, getattr(rem, "id", ""), getattr(rem, "provider", None))
    return [Check("step10: remediate", OK if ready else WARN,
                  f"via:{via} — {detail}"
                  + ("" if ready else " — remediation will be skipped"))]


def _validate_checks(cfg) -> list[Check]:
    """Step-11 readiness — empty unless ``step_validate.enabled``. Mirrors the
    s11 preflight: the legacy via:openai backend is routed to DeepAgents (so the
    credential reported is the one s11 will actually use), and the bundled
    ``claude_agent_sdk`` must be importable. The hoisted via:deepagents route is
    supported."""
    if not getattr(getattr(cfg, "step_validate", None), "enabled", False):
        return []
    out: list[Check] = []
    val = _validate_model_spec(cfg)
    if val is None:
        out.append(Check("step11: validate", WARN,
                         "step_validate.enabled but models.validate.orchestrator is unset "
                         "— validation will be skipped"))
    else:
        from vvaharness.validation.cli._model import _normalize_validate_backend
        raw_via = getattr(val, "via", "cli")
        via, provider = _normalize_validate_backend(raw_via, getattr(val, "provider", None))
        ready, detail = _backend_credential_ok(via, getattr(val, "id", ""), provider)
        routed = f" (via:{raw_via} routed to {via})" if via != raw_via else ""
        out.append(Check("step11: validate", OK if ready else WARN,
                         f"via:{via} — {detail}{routed}"
                         + ("" if ready else " — validation will be skipped")))
    if importlib.util.find_spec("claude_agent_sdk") is not None:
        out.append(Check("step11: claude_agent_sdk", OK,
                         "claude_agent_sdk importable"))
    else:
        out.append(Check("step11: claude_agent_sdk", WARN,
                         "claude_agent_sdk missing — reinstall vvaharness (pip install .)"))
    return out


def tls_check() -> Check:
    """Definitively determine whether a private CA bundle is needed: do a real
    TLS handshake to the active Anthropic endpoint using the system trust store
    (plus NODE_EXTRA_CA_CERTS if set). This is how setup tells a *public* user
    ("no CA needed") apart from an *enterprise gateway* user whose endpoint
    chains to a corporate root CA. No tokens spent — just a TLS handshake.

    - verifies cleanly        → OK   (public/trusted CA, or the configured bundle works)
    - certificate not trusted → FAIL (needs the org CA bundle; auto-suggests one)
    - network/DNS/timeout     → WARN (can't determine here; the live probe will)"""
    base = os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com"
    u = urlparse(base if "://" in base else f"https://{base}")
    host, port = u.hostname or "api.anthropic.com", u.port or 443
    cafile = os.environ.get("NODE_EXTRA_CA_CERTS")
    use_bundle = bool(cafile and Path(cafile).is_file())
    try:
        ctx = ssl.create_default_context(cafile=cafile if use_bundle else None)
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass
        src = " via NODE_EXTRA_CA_CERTS" if use_bundle else " (system trust store)"
        return Check("TLS / CA cert", OK,
                     f"{host}:{port} verified{src} — no extra CA bundle needed"
                     if not use_bundle else f"{host}:{port} verified{src}")
    except ssl.SSLCertVerificationError:
        ca = detect_ca_cert()
        hint = (f" A bundle was detected — run: export NODE_EXTRA_CA_CERTS={ca}"
                if ca else " Point NODE_EXTRA_CA_CERTS at your org's CA bundle.")
        return Check("TLS / CA cert", FAIL,
                     f"{host} presents a certificate the system trust store does "
                     f"not accept — this machine reaches it through a private CA "
                     f"(an internal gateway or a TLS-intercepting corporate "
                     f"proxy), so you need your org's CA bundle.{hint}")
    except Exception as e:  # noqa: BLE001 — DNS/timeout/proxy: can't decide here
        return Check("TLS / CA cert", WARN,
                     f"could not verify {host}:{port} ({type(e).__name__}) — "
                     f"skipping CA determination; the live probe will confirm")


def run_checks(cfg_path: str | Path) -> list[Check]:
    """The full readiness report, in display order."""
    checks: list[Check] = [python_check(),
                           tool_check("git", "batch --repo-file cloning"),
                           tool_check("pip3", "installing optional extras")]
    checks += agent_checks()
    checks += credential_checks()
    checks += dep_checks()
    # Anthropic endpoint TLS is irrelevant to a Codex-only/OpenAI-only profile.
    # Keep the check for configs that actually launch Claude or the Anthropic
    # SDK, and conservatively retain it when the config cannot be loaded.
    needs_anthropic_tls = True
    try:
        from vvaharness import config as config_mod
        from vvaharness.orchestrator.config_paths import _iter_model_roles
        active = config_mod.load(cfg_path)
        vias = {getattr(m, "via", "cli")
                for _, m in _iter_model_roles(active)}
        needs_anthropic_tls = bool(vias & {"cli", "sdk"})
    except Exception:
        pass
    if needs_anthropic_tls:
        checks.append(tls_check())
    checks.append(remediation_inputs_check())
    cfg_checks = config_check(cfg_path)
    if cfg_checks:
        checks.append(cfg_checks[0])
        checks.append(dotenv_check())
        checks += cfg_checks[1:]
    return checks


def summarize(checks: list[Check]) -> tuple[int, int, int]:
    """(#ok, #warn, #fail-required) — required fails are what block a scan."""
    n_ok = sum(1 for c in checks if c.status == OK)
    n_warn = sum(1 for c in checks if c.status == WARN)
    n_blocking = sum(1 for c in checks if c.status == FAIL and c.required)
    return n_ok, n_warn, n_blocking
