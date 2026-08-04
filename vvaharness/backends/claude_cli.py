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
Wrapper around the `claude` CLI. All model calls go through here.

Two modes:
  1. agentic(...)  — Claude gets tools, explores the repo, returns structured output
  2. prompt(...)   — Single-shot prompt, no tools, returns text/JSON

Auth is handled by the CLI itself: run `claude` then `/login`, or
`claude setup-token` for an unattended CLAUDE_CODE_OAUTH_TOKEN. No API key needed.

Windows note: The npm `claude.cmd` shim hits "Access is denied" when called
via subprocess. We bypass it by calling Node + cli.js directly.
"""
from __future__ import annotations
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path


# Token accounting is shared with the SDK backend so ScanMetrics sees one
# unified total. The counter lives in util/tokens.py; re-exported here for
# any legacy `from backends.claude_cli import TOKENS` import.
from vvaharness.util.tokens import TOKENS
from vvaharness.backends._tls import coerce_verify
from vvaharness.report.redact import redact


# ─────────────────────────────────────────────────────────────────────────────
# Cooperative cancellation
#
# KeyboardInterrupt only fires in the main thread. Worker threads inside the
# s4/s6 ThreadPoolExecutors keep dequeuing tasks and spawning fresh `claude`
# subprocesses, and ThreadPoolExecutor.__exit__ → shutdown(wait=True) blocks
# until the entire queue drains. The pool callers therefore call abort() on
# Ctrl-C, which (a) sets a flag every worker checks before launching, and
# (b) hard-kills any in-flight `claude` process tree so the running futures
# return immediately.
# ─────────────────────────────────────────────────────────────────────────────

_ABORT = threading.Event()
_LIVE_LOCK = threading.Lock()
_LIVE: set[subprocess.Popen] = set()


def aborted() -> bool:
    return _ABORT.is_set()


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=10)
        else:
            proc.kill()
    except Exception:
        pass


def abort() -> int:
    """Set the stop flag and kill every in-flight `claude` subprocess.
    Returns the number of processes signalled."""
    _ABORT.set()
    with _LIVE_LOCK:
        procs = list(_LIVE)
    for p in procs:
        _kill_tree(p)
    return len(procs)


def reset_abort() -> None:
    """Clear the global stop flag.

    `_ABORT` is process-global, so a programmatic abort() (e.g. a guardrail
    block) leaves it set and poisons every subsequent repo in a batch run with
    a spurious "aborted by user (Ctrl-C)". The orchestrator calls this between
    repos to reset cooperative-cancellation state for the next unit of work."""
    _ABORT.clear()


class GuardrailBlocked(RuntimeError):
    """Raised when the Anthropic org content-guardrail substitutes a canned
    refusal for the model response."""


# Known canned-refusal strings the server-side input classifier returns in
# `result` with is_error:false / stop_reason:end_turn. Exact match only — we
# do NOT fuzzy-match here because a legitimately short model reply must not
# be mistaken for a block.
_GUARDRAIL_REFUSALS = frozenset({
    "Your request was not allowed",
})


def _check_guardrail(env: dict) -> None:
    text = env.get("result")
    if (isinstance(text, str)
            and text.strip() in _GUARDRAIL_REFUSALS
            and (env.get("num_turns") or 1) <= 1
            and not env.get("is_error")):
        out_tok = ((env.get("usage") or {}).get("output_tokens"))
        raise GuardrailBlocked(
            "org content-guardrail blocked this prompt "
            f"(result={text!r}, num_turns={env.get('num_turns')}, "
            f"out_tok={out_tok}). The classifier on api.anthropic.com is "
            "rejecting the prompt content — this is NOT a pipeline bug. ")


def _parse_envelope(stdout: str) -> tuple[str, dict | None]:
    """
    Parse `claude -p --output-format json` envelope → (result_text, usage_dict).

    Handles both CLI output shapes:
      - dict:  {"result": "...", "usage": {...}, ...}
      - list:  [{"type":"system",...}, {"type":"assistant","message":{...}},
                ..., {"type":"result","result":"...","usage":{...}}]
    Falls back to raw stdout only when the envelope isn't JSON at all (older
    CLI / error path). When the envelope IS valid JSON but carries no model
    text (truncated stream, turn ended on a tool_use block, budget/turn cap),
    returns "" so the caller's extract_json() raises and the stage degrades
    loudly — never echoing the transport envelope back as if it were model
    output.

    Raises GuardrailBlocked if the envelope carries the org content-guardrail
    refusal, so callers fail loudly instead of treating it as model text.
    """
    try:
        env = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        objs: list = []
        for ln in stdout.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                objs.append(json.loads(ln))
            except (json.JSONDecodeError, TypeError):
                continue
        if not objs:
            return stdout.strip(), None
        env = objs

    if isinstance(env, list):
        result_evt = next((e for e in reversed(env)
                           if isinstance(e, dict) and e.get("type") == "result"),
                          None)
        if result_evt:
            _check_guardrail(result_evt)
        usage = (result_evt or {}).get("usage")
        text = (result_evt or {}).get("result")
        if not isinstance(text, str) or not text.strip():
            last_asst = next(
                (e for e in reversed(env)
                 if isinstance(e, dict) and e.get("type") == "assistant"),
                None,
            )
            parts = [
                blk.get("text", "")
                for blk in ((last_asst or {}).get("message", {}) or {}).get("content", []) or []
                if isinstance(blk, dict) and blk.get("type") == "text"
            ]
            # No assistant text blocks either: the envelope parsed but carries
            # no model output. Return "" (not the raw stdout envelope) so the
            # caller degrades on an empty/unparseable response.
            text = "".join(parts)
        return text.strip(), usage if isinstance(usage, dict) else None

    if not isinstance(env, dict):
        return stdout.strip(), None
    _check_guardrail(env)
    result = env.get("result")
    if not isinstance(result, str):
        # Valid JSON envelope but no string result → empty, not the raw envelope.
        result = ""
    return result.strip(), env.get("usage")


def _find_claude_cmd() -> list[str]:
    """
    Resolve the claude CLI to a subprocess-safe command list, pinned to an
    ABSOLUTE path where possible (avoid bare-name PATH resolution at exec time
    — CWE-426/427).

    Resolution order (both platforms):
      1. ``$VVAHARNESS_CLAUDE_BINARY`` if it points at an existing file — an
         explicit operator pin that bypasses PATH entirely (the only thing that
         defeats an already-poisoned PATH; recommended on shared/CI hosts).
      2. ``shutil.which("claude")`` — the absolute path PATH resolves to,
         pinned once at import so later model calls don't re-resolve a freshly
         planted binary.
      3. bare ``["claude"]`` as a last resort, with a warning, so the harness
         still runs where neither is available.

    On Windows the npm .cmd shim fails with "Access is denied" under subprocess,
    so we drill to the underlying native binary / cli.js as before.
    """
    override = os.environ.get("VVAHARNESS_CLAUDE_BINARY")
    if override:
        if Path(override).is_file():
            print(f"  [cli] using VVAHARNESS_CLAUDE_BINARY={override}",
                  file=sys.stderr)
            return [override]
        print(f"  [cli] WARN: VVAHARNESS_CLAUDE_BINARY={override} not found; "
              f"falling back to PATH resolution", file=sys.stderr)
    if os.name == "nt":
        cmd_path = shutil.which("claude") or shutil.which("claude.cmd") or shutil.which("claude.CMD")
        if cmd_path:
            pkg = Path(cmd_path).parent / "node_modules" / "@anthropic-ai" / "claude-code"
            # ≥2.1.x ships a native binary — call it directly, no Node needed.
            native = pkg / "bin" / "claude.exe"
            if native.exists():
                return [str(native)]
            # ≤2.0.x: Node + cli.js
            cli_js = pkg / "cli.js"
            if cli_js.exists():
                node = shutil.which("node") or "node"
                return [node, str(cli_js)]
            # Last resort: the resolved .cmd shim (full path so CreateProcess
            # finds it). Bare "claude" fails with WinError 2 on Windows.
            return [cmd_path]
        print("  [cli] WARN: 'claude' not found on PATH; using bare name",
              file=sys.stderr)
        return ["claude"]
    # Unix: pin to the absolute path PATH resolves to, instead of a bare name.
    resolved = shutil.which("claude")
    if resolved:
        return [resolved]
    print("  [cli] WARN: 'claude' not found on PATH; using bare name",
          file=sys.stderr)
    return ["claude"]


# Resolve once at import time
_CLAUDE_CMD = _find_claude_cmd()

# Permission-mode values we prefer for non-interactive scanning, in order.
# acceptEdits auto-approves Read/Glob/Grep/Edit/Write (everything the shipped
# profiles list) without granting blanket bypass — Bash is NOT auto-approved,
# so a prompt-injected agent in a hostile target repo cannot escalate to a
# host shell. bypassPermissions is deliberately last (a fallback only for CLI
# builds that lack acceptEdits) and never the default.
_PERMISSION_FALLBACKS = ("acceptEdits", "default", "bypassPermissions")

_caps_cache: dict | None = None


def _cli_capabilities() -> dict:
    """Probe `claude --help` ONCE and memoise which flags/values this installed
    CLI accepts. Claude CLI 2.0.x dropped `--effort` and the `auto`
    permission-mode; rather than hardcode a version table we read the help text
    so the harness adapts to whatever CLI is on PATH and never passes an
    argument the CLI will reject (the old failure that made users hand-edit
    source). Best-effort: on any probe failure we assume the modern surface
    (no --effort, choose a safe permission-mode from the fallback list)."""
    global _caps_cache
    if _caps_cache is not None:
        return _caps_cache
    help_text = ""
    try:
        r = subprocess.run([*_CLAUDE_CMD, "--help"], capture_output=True,
                           text=True, timeout=20)
        help_text = (r.stdout or "") + (r.stderr or "")
    except Exception:
        help_text = ""
    # Parse permission modes ONLY from the --permission-mode option's own
    # "(choices: ...)" list — never the whole help blob. A blanket scan
    # false-matches stray words like "auto" in "auto-updater" / "automatic
    # fallback", which made us believe an invalid `auto` mode was supported and
    # pass it straight to a CLI that rejects it (choices are acceptEdits,
    # bypassPermissions, default, plan). The CLI prints the option as:
    #   --permission-mode <mode>  ... (choices: "acceptEdits", "default", ...)
    modes: set[str] = set()
    m = re.search(r"--permission-mode\b.*?\(choices:\s*([^)]*)\)",
                  help_text, re.DOTALL)
    if m:
        modes = set(re.findall(r'"([^"]+)"', m.group(1)))
    _caps_cache = {
        "effort": "--effort" in help_text,
        "max_turns": "--max-turns" in help_text,
        "max_budget": "--max-budget-usd" in help_text,
        "permission_modes": modes,
        "probed": bool(help_text),
    }

    return _caps_cache


def _safe_permission_mode(requested: str) -> str:
    """Map a requested --permission-mode to one this CLI actually accepts.
    Honour the request if supported; otherwise pick the first non-interactive
    fallback the CLI lists; if the probe yielded nothing, trust the request."""
    caps = _cli_capabilities()
    modes = caps["permission_modes"]
    if not modes:                      # couldn't read help — don't second-guess
        return requested
    if requested in modes:
        return requested
    for m in _PERMISSION_FALLBACKS:
        if m in modes:
            return m
    return next(iter(modes))


def _tail(text: str | None, n: int = 1200) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= n:
        return text
    return "...\n" + text[-n:]


def _short_cmd(cmd: list[str]) -> str:
    """Render argv with long args (system prompts) elided so error lines stay readable."""
    out = []
    for a in cmd:
        if len(a) > 80:
            head = a[:60].replace("\n", " ")
            out.append(f"{head}...<{len(a)} chars>")
        else:
            out.append(a)
    return " ".join(out)


def _extract_envelope_error(stdout: str | None) -> str | None:
    """If stdout is a claude --output-format json envelope carrying an error,
    return a one-line summary like '401 Invalid API key · Fix external API key'."""
    if not stdout:
        return None
    s = stdout.strip()
    # The CLI emits two envelope shapes (see _parse_envelope): a dict, or a
    # list of streamed events ending in a {"type":"result",...} object. Anchor
    # on whichever bracket comes first so the list shape isn't truncated to its
    # first inner '{' (which json.loads would reject or mis-parse).
    candidates = [p for p in (s.find("{"), s.find("[")) if p >= 0]
    if not candidates:
        return None
    try:
        env = json.loads(s[min(candidates):])
    except Exception:
        return None

    if isinstance(env, list):
        # Pull the terminal result event (or any error-bearing event).
        evt = next((e for e in reversed(env)
                    if isinstance(e, dict)
                    and (e.get("type") == "result"
                         or e.get("is_error")
                         or e.get("subtype") in ("error", "error_during_execution"))),
                   None)
        env = evt
    if not isinstance(env, dict):
        return None
    if not (env.get("is_error") or env.get("subtype") in ("error", "error_during_execution")):
        return None
    status = env.get("api_error_status")
    msg = env.get("result") or env.get("error") or env.get("message") or "unknown error"
    return f"{status} {msg}" if status else str(msg)


def _format_cli_error(prefix: str, cmd: list[str], result: subprocess.CompletedProcess) -> str:
    env_err = _extract_envelope_error(result.stdout)
    if env_err:
        return f"{prefix}: {env_err} (rc={result.returncode})"

    # stdout/stderr tails carry raw subprocess + model output, which can include
    # tokens echoed from the gateway or quoted source — scrub before surfacing.
    err_tail = redact(_tail(result.stderr))
    out_tail = redact(_tail(result.stdout))
    parts = [
        f"{prefix} (rc={result.returncode})",
        f"cmd: {_short_cmd(cmd)}",
    ]
    if err_tail:
        parts.append(f"stderr tail:\n{err_tail}")
    if out_tail:
        parts.append(f"stdout tail:\n{out_tail}")
    if not err_tail and not out_tail:
        parts.append("no stdout/stderr captured")
    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# TLS / proxy configuration for the `claude` subprocess
#
# The sdk/openai backends build an httpx client and pass verify=/cert= to it.
# The CLI backend instead shells out to the Node `claude` binary, so the same
# gateway settings have to reach it as environment variables:
#   ca_cert        -> NODE_EXTRA_CA_CERTS              (trust a private root CA)
#   verify_ssl=False -> NODE_TLS_REJECT_UNAUTHORIZED=0 (skip verification)
#   no_proxy       -> NO_PROXY / no_proxy
# Auth and endpoint stay delegated to the CLI's own precedence (run `claude`
# then `/login`, or CLAUDE_CODE_OAUTH_TOKEN; ANTHROPIC_BASE_URL if already set).
# mTLS client certs are NOT supported here: Node exposes no environment path to
# present a client certificate, so an mTLS-gated gateway must use a via:sdk role.
# ─────────────────────────────────────────────────────────────────────────────

_cfg: dict = {"verify_ssl": True, "ca_cert": None,
              "client_cert": None, "no_proxy": None, "effort": "high"}
_tls_extra: dict = {}


def _build_tls_env() -> dict:
    """Translate the stored TLS/proxy config into subprocess env vars."""
    out: dict = {}
    ca = _cfg["ca_cert"]
    verify = _cfg["verify_ssl"]
    # A CA bundle may arrive either as ca_cert or as a string-valued verify_ssl
    # — mirrors the `verify = ca or verify_ssl` precedence in backends/sdk.py.
    bundle = ca or (verify if isinstance(verify, str) else None)
    if bundle:
        if os.path.exists(bundle):
            out["NODE_EXTRA_CA_CERTS"] = bundle
        else:
            print(f"WARN [cli]: ca_cert '{bundle}' not found — not setting "
                  f"NODE_EXTRA_CA_CERTS for the claude subprocess",
                  file=sys.stderr)
    if verify is False:
        out["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        print("WARN [cli]: TLS verification disabled (verify_ssl=false) for the "
              "claude subprocess", file=sys.stderr)
    np = _cfg["no_proxy"]
    if np:
        out["NO_PROXY"] = np
        out["no_proxy"] = np
    if _cfg["client_cert"]:
        print("WARN [cli]: client_cert/mTLS is configured but the `claude` CLI "
              "backend cannot present a client certificate (Node exposes no "
              "env-var path for it). Use a `via: sdk` role for mTLS gateways.",
              file=sys.stderr)
    return out


def configure(*, verify_ssl: bool | str | None = None,
              ca_cert: str | None = None,
              client_cert: str | tuple | None = None,
              no_proxy: str | None = None,
              effort: str | None = None) -> None:
    """Push gateway TLS/proxy settings into the `claude` subprocess environment.

    Optional — when never called the subprocess inherits the ambient process
    environment unchanged (the historical behaviour). Auth and base_url remain
    delegated to the CLI's native precedence; only TLS/proxy env vars are
    injected here. mTLS client certs are unsupported on this backend (a warning
    is emitted); use a via:sdk role instead.

    `effort` pins the reasoning effort passed to `claude -p --effort` so the
    scan never inherits the operator's interactive `/effort` default
    (settings.json effortLevel / CLAUDE_EFFORT) — some models reject levels
    such as 'xhigh'. Defaults to 'high' (the one level every model supports);
    set cli.effort in config to raise it (e.g. 'max' for Opus-tier models)."""
    global _tls_extra
    if verify_ssl is not None:
        _cfg["verify_ssl"] = coerce_verify(verify_ssl)
    if ca_cert:
        _cfg["ca_cert"] = ca_cert
    if client_cert:
        _cfg["client_cert"] = client_cert
    if no_proxy:
        _cfg["no_proxy"] = no_proxy
    if effort:
        _cfg["effort"] = effort
    _tls_extra = _build_tls_env()


def _run(cmd: list[str], *, input: str | None = None,
         cwd: str | None = None, timeout: int = 600,
         env: dict | None = None,
         heartbeat_label: str | None = None,
         heartbeat_interval: int = 300,
         stream_cb=None) -> subprocess.CompletedProcess:
    """Central subprocess runner with optional periodic progress heartbeat.

    The full process env (including ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN /
    ANTHROPIC_BASE_URL) is passed through to the `claude` CLI so it follows
    its native auth precedence (API key → auth token → OAuth on disk). Any
    TLS/proxy env vars registered via configure() (NODE_EXTRA_CA_CERTS,
    NODE_TLS_REJECT_UNAUTHORIZED, NO_PROXY) are layered on top of the ambient
    env, and the per-call `env` argument wins over both.

    When ``stream_cb`` is provided, stdout is read line-by-line and each line is
    passed to the callback AS IT ARRIVES (used by `--verbose` to surface the
    live agent trace: tool calls, intermediate text). The full stdout is still
    captured and returned, so all downstream parsing is unchanged."""
    proc_env = {**os.environ, **_tls_extra, **(env or {})}

    if stream_cb is not None:
        return _run_streaming(cmd, input=input, cwd=cwd, timeout=timeout,
                              proc_env=proc_env, stream_cb=stream_cb)

    if not heartbeat_label:
        return subprocess.run(
            cmd,
            input=input,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            env=proc_env,
            timeout=timeout,
        )

    start = time.monotonic()
    deadline = start + timeout
    pending_input = input

    with subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        env=proc_env,
    ) as proc:
        with _LIVE_LOCK:
            _LIVE.add(proc)
        try:
            while True:
                if _ABORT.is_set():
                    _kill_tree(proc)
                    out, err = proc.communicate()
                    raise RuntimeError("aborted by user (Ctrl-C)")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    out, err = proc.communicate()
                    raise subprocess.TimeoutExpired(cmd, timeout, output=out, stderr=err)

                try:
                    out, err = proc.communicate(
                        input=pending_input,
                        timeout=min(float(heartbeat_interval), remaining),
                    )
                    break
                except subprocess.TimeoutExpired:
                    elapsed = int(time.monotonic() - start)
                    print(f"    [cli] {heartbeat_label} still running... {elapsed}s elapsed", file=sys.stderr)
                    pending_input = None
        except KeyboardInterrupt:
            _ABORT.set()
            _kill_tree(proc)
            try:
                proc.communicate(timeout=2)
            except Exception:
                pass
            raise
        finally:
            with _LIVE_LOCK:
                _LIVE.discard(proc)

        return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def _run_streaming(cmd: list[str], *, input: str | None, cwd: str | None,
                   timeout: int, proc_env: dict,
                   stream_cb) -> subprocess.CompletedProcess:
    """Run the CLI, forwarding each stdout line to *stream_cb* as it arrives,
    while still capturing full stdout/stderr for the normal return contract.

    Used for the `--verbose` live agent trace. A reader thread drains stdout so
    a slow consumer never deadlocks the pipe; stderr is captured at the end."""
    chunks: list[str] = []

    def _reader(pipe):
        for line in iter(pipe.readline, ""):
            chunks.append(line)
            try:
                stream_cb(line)
            except Exception:  # noqa: BLE001 — tracing must never break the run
                pass
        pipe.close()

    with subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        env=proc_env,
        bufsize=1,  # line-buffered
    ) as proc:
        with _LIVE_LOCK:
            _LIVE.add(proc)
        reader = threading.Thread(target=_reader, args=(proc.stdout,), daemon=True)
        reader.start()
        try:
            if input is not None:
                try:
                    proc.stdin.write(input)
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                reader.join(timeout=2)
                err = proc.stderr.read() if proc.stderr else ""
                raise subprocess.TimeoutExpired(
                    cmd, timeout, output="".join(chunks), stderr=err)
        except KeyboardInterrupt:
            _ABORT.set()
            _kill_tree(proc)
            raise
        finally:
            with _LIVE_LOCK:
                _LIVE.discard(proc)
        reader.join(timeout=5)
        err = proc.stderr.read() if proc.stderr else ""
    return subprocess.CompletedProcess(cmd, proc.returncode, "".join(chunks), err)


def stream_trace(line: str, *, out=None) -> None:
    """Render one ``stream-json`` event line as a concise human trace for
    `--verbose`: tool calls (name + key args), assistant text, and the final
    result. Unknown / noisy event types are skipped. Best-effort and redacted —
    never raises."""
    out = out or sys.stderr
    line = (line or "").strip()
    if not line:
        return
    try:
        evt = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return
    etype = evt.get("type")
    if etype == "assistant":
        for blk in (evt.get("message", {}) or {}).get("content", []) or []:
            if not isinstance(blk, dict):
                continue
            if blk.get("type") == "text" and blk.get("text", "").strip():
                print(f"    [agent] 💬 {redact(blk['text'].strip())[:400]}",
                      file=out, flush=True)
            elif blk.get("type") == "tool_use":
                name = blk.get("name", "?")
                args = blk.get("input", {}) or {}
                summ = ", ".join(f"{k}={v!r}" for k, v in args.items())
                summ = redact(summ)
                if len(summ) > 160:
                    summ = summ[:157] + "..."
                print(f"    [agent] 🔧 {name}({summ})", file=out, flush=True)
    elif etype == "user":
        # tool_result coming back to the model — show a short confirmation.
        for blk in (evt.get("message", {}) or {}).get("content", []) or []:
            if isinstance(blk, dict) and blk.get("type") == "tool_result":
                content = blk.get("content")
                if isinstance(content, list):
                    content = " ".join(
                        c.get("text", "") for c in content
                        if isinstance(c, dict))
                n = len(str(content or ""))
                print(f"    [agent] ↩ tool result ({n} chars)", file=out, flush=True)
    elif etype == "result":
        if evt.get("is_error"):
            print(f"    [agent] ✗ {redact(str(evt.get('result') or evt.get('error') or ''))[:200]}",
                  file=out, flush=True)


# ── transient-failure retry ──────────────────────────────────────────────────
_RETRYABLE_STATUSES = frozenset({429, 502, 503, 529})
_RL_TRANSIENT = re.compile(
    r"\b429\b|rate.?limit|too many requests|overloaded|temporarily unavailable",
    re.IGNORECASE,
)
# Connection-level transients: a dropped/closed socket aborts a single call but
# is retryable (the prompt is single-shot idempotent). These surface with no
# HTTP status, so they must be matched on text regardless of api_error_status.
_CONN_TRANSIENT = re.compile(
    r"socket connection was closed|connection (?:reset|closed|aborted)"
    r"|ECONNRESET|EPIPE|broken pipe|incomplete(?:ly)? read"
    r"|premature(?:ly)? closed|EOF occurred",
    re.IGNORECASE,
)
# Hard usage-cap reset ("resets May 31, 7pm") — backoff won't help.
_RL_HARD_CAP = re.compile(r"hit your (usage )?limit.*resets", re.IGNORECASE)
_RL_MAX_RETRIES = 4
_RL_BACKOFF = (30, 60, 120, 240)
# A subprocess timeout is retried at most this many times (the call may have
# been a genuine transient hang); bounded to cap the added wall-clock.
_TIMEOUT_MAX_RETRIES = 1

# Claude Code may return a placeholder while background sub-agents are still
# executing. Treat these as incomplete output and retry boundedly rather than
# letting callers parse partial/non-JSON text as an empty map.
_PENDING_RESULT_RX = re.compile(
    r"__PENDING__"
    r"|still executing"
    r"|(?:task\s+is\s+)?still\s+pending"
    r"|waiting\s+for\s+(?:background\s+)?sub-?agent"
    r"|background\s+sub-?agent",
    re.IGNORECASE,
)
_PENDING_MAX_RETRIES = 3
_PENDING_BACKOFF = (5, 15, 30)


def _is_pending_result(text: str | None) -> bool:
    if not isinstance(text, str):
        return False
    return bool(_PENDING_RESULT_RX.search(text))


def _terminal_result_fields(stdout: str | None
                            ) -> tuple[int | None, str | None, bool]:
    """Return (api_error_status, result_text, envelope_found) from the CLI's
    terminal result event.

    Both envelope shapes are handled: a single dict, or a streamed list whose
    last ``type == "result"`` event is authoritative. Interior telemetry events
    (``rate_limit_event``, ``api_retry``, ``system``) are deliberately ignored —
    they are routine quota/retry reporting, not the verdict for this call. When
    stdout carries no parseable JSON envelope, envelope_found is False and the
    caller falls back to text matching."""
    if not stdout:
        return None, None, False
    s = stdout.strip()
    candidates = [p for p in (s.find("{"), s.find("[")) if p >= 0]
    if not candidates:
        return None, None, False
    try:
        env = json.loads(s[min(candidates):])
    except (json.JSONDecodeError, ValueError, TypeError):
        return None, None, False
    if isinstance(env, list):
        env = next((e for e in reversed(env)
                    if isinstance(e, dict) and e.get("type") == "result"), None)
        if env is None:
            return None, None, False      # truncated stream: no terminal event
    if not isinstance(env, dict):
        return None, None, False
    status = env.get("api_error_status")
    text = env.get("result") or env.get("error") or env.get("message")
    return (status if isinstance(status, int) else None,
            text if isinstance(text, str) else None,
            True)


def _is_transient_failure(result: subprocess.CompletedProcess) -> bool:
    """Classify a non-zero CLI exit: True only for a genuine transient worth
    retrying.

    Structural: reads api_error_status off the terminal result event, so routine
    `rate_limit_event` telemetry, stray "429" digits, and the null-status
    "exceeded output token maximum" pseudo-error are never mistaken for a rate
    limit. A tightened text scan runs ONLY when no JSON envelope is present."""
    status, text, found = _terminal_result_fields(result.stdout)
    if found:
        if status in _RETRYABLE_STATUSES:
            return True
        # A null status with a transient phrase in the result TEXT (e.g. an
        # "Overloaded" the CLI surfaced without an HTTP status, or a dropped
        # socket) still retries; telemetry lives in separate events, never in
        # the result text.
        if status is None and text and (_RL_TRANSIENT.search(text)
                                        or _CONN_TRANSIENT.search(text)):
            return True
        return False
    # No parseable envelope: best-effort transient detection on the raw text
    # (genuinely not JSON here, so no rate_limit_event telemetry to false-match).
    blob = f"{result.stdout or ''}\n{result.stderr or ''}"
    return bool(_RL_TRANSIENT.search(blob) or _CONN_TRANSIENT.search(blob))


def _run_with_retry(cmd: list[str], *, label: str, **kw
                    ) -> subprocess.CompletedProcess:
    """_run() + exponential backoff on GENUINE transient failures only.

    Transience is classified structurally from the CLI result envelope (see
    _is_transient_failure); terminal errors (4xx, null-status pseudo-errors such
    as the output-token cap, and the usage hard-cap) surface immediately instead
    of burning 30/60/120/240s of pointless backoff. Returns the final
    CompletedProcess (success or terminal failure); caller still owns the
    rc!=0 → raise."""
    attempt = 0
    timeout_attempt = 0
    while True:
        try:
            result = _run(cmd, **kw)
        except subprocess.TimeoutExpired:
            # A timeout is not a CompletedProcess, so the structural classifier
            # can never see it; retry once (bounded, abort-aware) before letting
            # it propagate so a single transient hang doesn't lose the unit.
            if _ABORT.is_set() or timeout_attempt >= _TIMEOUT_MAX_RETRIES:
                raise
            timeout_attempt += 1
            print(f"    [cli] {label}: timed out — retrying once "
                  f"({timeout_attempt}/{_TIMEOUT_MAX_RETRIES})", file=sys.stderr)
            continue
        if result.returncode == 0:
            return result
        _, text, _ = _terminal_result_fields(result.stdout)
        err_text = text or f"{result.stdout or ''}\n{result.stderr or ''}"
        if _RL_HARD_CAP.search(err_text):
            print(f"    [cli] {label}: hard usage cap reached — not retrying",
                  file=sys.stderr)
            return result
        if attempt >= _RL_MAX_RETRIES or not _is_transient_failure(result):
            return result
        wait = _RL_BACKOFF[min(attempt, len(_RL_BACKOFF) - 1)]
        print(f"    [cli] {label}: transient upstream error (attempt "
              f"{attempt + 1}/{_RL_MAX_RETRIES}); retrying in {wait}s",
              file=sys.stderr)
        slept = 0
        while slept < wait:
            if _ABORT.is_set():
                raise RuntimeError("aborted by user (Ctrl-C)")
            time.sleep(min(5, wait - slept))
            slept += 5
        attempt += 1


def prompt(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    json_schema: dict | None = None,
    output_format: str = "text",
    cwd: str | None = None,
    max_budget_usd: float | None = None,
    max_tokens: int | None = None,
    timeout: int = 1800,
    tag: str | None = None,
) -> str:
    """
    Single-shot prompt. No tools. Returns the model's text response.
    Use for steps 2, 3, 4 where we pipe in a big prompt and get analysis back.
    """
    if _ABORT.is_set():
        raise RuntimeError("aborted by user (Ctrl-C)")
    cmd = [*_CLAUDE_CMD, "-p", "--model", model]
    if _cfg.get("effort") and _cli_capabilities()["effort"]:
        cmd += ["--effort", _cfg["effort"]]

    if system_prompt:
        cmd += ["--system-prompt", system_prompt]
    # Always request the JSON envelope so we can read .usage for token
    # accounting; the model's text is unwrapped from .result before returning.
    cmd += ["--output-format", "json"]
    if json_schema:
        cmd += ["--json-schema", json.dumps(json_schema)]
    # Forward the spend cap only when the installed CLI advertises the flag.
    # Older/newer CLIs that lack --max-budget-usd reject the unknown flag with
    # rc=1; the timeout is the bound there. (Probe-gated like --effort / --max-turns.)
    if max_budget_usd and _cli_capabilities().get("max_budget"):
        cmd += ["--max-budget-usd", str(max_budget_usd)]

    # Disable all tools — pure reasoning

    cmd += ["--tools", ""]

    # claude CLI reads max output tokens from env, not a flag.
    env = {"CLAUDE_CODE_MAX_OUTPUT_TOKENS": str(max_tokens)} if max_tokens else None

    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [cli] prompt mode -> {model}{tag_sfx} ({len(user_prompt)} chars"
          f"{f', max_tokens={max_tokens}' if max_tokens else ''})",
          file=sys.stderr)

    result = _run_with_retry(
        cmd,
        label=f"prompt({model}){tag_sfx}",
        input=user_prompt,
        cwd=cwd,
        timeout=timeout,
        env=env,
        heartbeat_label=f"prompt mode ({model}){tag_sfx}",
    )

    if result.returncode != 0:
        raise RuntimeError(_format_cli_error("claude CLI failed", cmd, result))

    text, usage = _parse_envelope(result.stdout)
    TOKENS.add(usage)
    if usage:
        _in = (int(usage.get('input_tokens', 0) or 0)
               + int(usage.get('cache_creation_input_tokens', 0) or 0)
               + int(usage.get('cache_read_input_tokens', 0) or 0))
        _cache_r = int(usage.get('cache_read_input_tokens', 0) or 0)
        _cache_w = int(usage.get('cache_creation_input_tokens', 0) or 0)
        _out = int(usage.get('output_tokens', 0) or 0)
        cache_info = f" (cache_read={_cache_r}, cache_write={_cache_w})" if (_cache_r or _cache_w) else ""
        print(f"    [cli] usage: in={_in}{cache_info} out={_out}", file=sys.stderr)
    return text


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,
    permission_mode: str = "auto",
    max_turns: int | None = None,  # forwarded as --max-turns only when the
                                   # installed CLI advertises the flag (probe-
                                   # gated); otherwise the CLI owns its loop and
                                   # --max-budget-usd / the timeout are the bounds.
    tag: str | None = None,
    stream_cb=None,                # optional: called with each raw stream-json
                                   # line as it arrives (live --verbose trace).
) -> str:
    """
    Agentic mode — Claude gets tools and explores the repo.
    Used for Step 1 where Opus needs to read files, grep, etc.
    Returns the final text output.

    When ``stream_cb`` is supplied the CLI's ``stream-json`` events are streamed
    to it live (see :func:`stream_trace`); otherwise output is buffered as
    before. Streaming bypasses the periodic heartbeat (the live trace already
    shows progress).
    """
    if _ABORT.is_set():
        raise RuntimeError("aborted by user (Ctrl-C)")
    cmd = [*_CLAUDE_CMD, "-p", "--model", model]
    if _cfg.get("effort") and _cli_capabilities()["effort"]:
        cmd += ["--effort", _cfg["effort"]]

    if system_prompt:
        cmd += ["--system-prompt", system_prompt]
    if allowed_tools:
        # Honour the caller's allowlist as-given. Bash is NEVER force-added:
        # a hostile target repo can prompt-inject the agent via files it
        # Reads/Greps, and an auto-granted shell would turn that into RCE on
        # the scanning host. Operators who need Bash must list it explicitly
        # in step*.allowed_tools (and accept that risk).
        cmd += ["--allowedTools"] + list(allowed_tools)
    # Forward the spend cap only when the installed CLI advertises the flag —
    # builds that lack --max-budget-usd reject the unknown flag with rc=1
    # (the timeout / --max-turns bound the run there). Probe-gated like --effort.
    if max_budget_usd and _cli_capabilities().get("max_budget"):
        cmd += ["--max-budget-usd", str(max_budget_usd)]
    # Cap the tool loop only when the installed CLI actually accepts the flag —

    # appending it unconditionally is a silent no-op on builds that lack it and
    # an error on builds that reject unknown flags.
    if max_turns and _cli_capabilities().get("max_turns"):
        cmd += ["--max-turns", str(int(max_turns))]

    cmd += ["--permission-mode", _safe_permission_mode(permission_mode)]
    cmd += ["--output-format", "stream-json", "--verbose"]

    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [cli] agentic mode -> {model}{tag_sfx}, cwd={cwd}", file=sys.stderr)

    # When streaming the live trace, the per-line callback already shows
    # progress, so the periodic heartbeat is suppressed (the streaming runner
    # ignores it anyway).
    pending_attempt = 0
    while True:
        result = _run_with_retry(
            cmd,
            label=f"agentic({model}){tag_sfx}",
            input=user_prompt,
            cwd=cwd,
            timeout=3600,
            heartbeat_label=(None if stream_cb
                             else f"agentic mode ({model}){tag_sfx}"),
            stream_cb=stream_cb,
        )

        if result.returncode != 0:
            raise RuntimeError(_format_cli_error("claude CLI agentic failed", cmd, result))

        text, usage = _parse_envelope(result.stdout)
        TOKENS.add(usage)
        if usage:
            _in = (int(usage.get('input_tokens', 0) or 0)
                   + int(usage.get('cache_creation_input_tokens', 0) or 0)
                   + int(usage.get('cache_read_input_tokens', 0) or 0))
            _cache_r = int(usage.get('cache_read_input_tokens', 0) or 0)
            _cache_w = int(usage.get('cache_creation_input_tokens', 0) or 0)
            _out = int(usage.get('output_tokens', 0) or 0)
            cache_info = f" (cache_read={_cache_r}, cache_write={_cache_w})" if (_cache_r or _cache_w) else ""
            print(f"    [cli] usage: in={_in}{cache_info} out={_out}", file=sys.stderr)

        if not _is_pending_result(text):
            return text

        pending_attempt += 1
        snippet = redact((text or "").strip().replace("\n", " "))[:200]
        if pending_attempt > _PENDING_MAX_RETRIES:
            raise RuntimeError(
                "claude CLI agentic returned an unfinished background-subagent "
                f"state after {_PENDING_MAX_RETRIES} retries; refusing to "
                f"continue with partial output. last_result={snippet!r}"
            )
        wait = _PENDING_BACKOFF[min(pending_attempt - 1,
                                    len(_PENDING_BACKOFF) - 1)]
        print(
            f"    [cli] agentic returned pending output; retrying in {wait}s "
            f"({pending_attempt}/{_PENDING_MAX_RETRIES})",
            file=sys.stderr,
        )
        slept = 0
        while slept < wait:
            if _ABORT.is_set():
                raise RuntimeError("aborted by user (Ctrl-C)")
            step = min(5, wait - slept)
            time.sleep(step)
            slept += step


def parse_json_response(text: str) -> dict | list:
    """
    When output_format=json, the CLI wraps the response.
    Extract the actual JSON content.
    """
    try:
        envelope = json.loads(text)
        if isinstance(envelope, dict) and "result" in envelope:
            content = envelope["result"]
            if isinstance(content, str):
                return json.loads(content)
            return content
        return envelope
    except (json.JSONDecodeError, TypeError):
        pass

    from vvaharness.util.json_extract import extract_json
    return extract_json(text)
