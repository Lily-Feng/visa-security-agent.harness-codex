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

"""The environment readiness engine behind `vvaharness setup` / `doctor`."""
from __future__ import annotations

import pytest

from vvaharness import cli
from vvaharness.remediation_agent import rule_paths
from vvaharness.util import environment as env
from vvaharness.util.environment import FAIL, OK, WARN


def _clear_anthropic(monkeypatch):
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(v, raising=False)


# ── the gateway trap (the bug that bit us) ───────────────────────────────────
def test_gateway_jwt_without_base_url_is_blocking(monkeypatch):
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJhbGciOiJI.fake.jwt")  # JWT shape
    c = env._gateway_check()
    assert c.status == FAIL
    assert c.required is True
    assert "ANTHROPIC_BASE_URL" in c.detail


def test_gateway_ok_when_base_url_set(monkeypatch):
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJhbGciOiJI.fake.jwt")  # JWT shape
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.example/")
    c = env._gateway_check()
    assert c.status == OK
    assert "api.example" in c.detail


def test_gateway_ok_with_real_key_no_base_url(monkeypatch):
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-realkey")
    assert env._gateway_check().status == OK


# ── credential checks never leak the value ───────────────────────────────────
def test_credential_checks_presence_only(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-value-123")
    checks = env.credential_checks()
    openai = next(c for c in checks if c.name == "cred: OPENAI_API_KEY")
    assert openai.status == OK
    assert openai.detail == "set"               # never the value
    assert "secret" not in openai.detail


# ── deps + python ────────────────────────────────────────────────────────────
def test_required_deps_present():
    deps = {c.name: c for c in env.dep_checks()}
    assert deps["dep: pydantic"].status == OK
    assert deps["dep: anthropic"].status == OK


def test_dep_checks_warn_when_tree_sitter_missing(monkeypatch):
    real_find_spec = env.importlib.util.find_spec

    def fake_find_spec(name):
        if name in {"tree_sitter", "tree_sitter_language_pack"}:
            return None
        return real_find_spec(name)

    monkeypatch.setattr(env.importlib.util, "find_spec", fake_find_spec)
    deps = {c.name: c for c in env.dep_checks()}

    ts = deps["dep: tree-sitter"]
    assert ts.status == WARN
    assert "degraded taint coverage" in ts.detail

    tsp = deps["dep: tree-sitter-language-pack"]
    assert tsp.status == WARN
    assert "AST plugins unavailable" in tsp.detail


def test_python_check_ok_on_current_interpreter():
    assert env.python_check().status == OK


# ── config-driven backend credential checks ──────────────────────────────────
def test_sdk_profile_flags_missing_key(monkeypatch, tmp_path):
    # Clear ALL Anthropic creds, not just the SDK key — the sole-sdk profile
    # accepts ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN as a fallback, so leaving
    # those set (as a dev/CI shell often does) would mask the missing-key path.
    _clear_anthropic(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_SDK_API_KEY", raising=False)
    cfg = tmp_path / "p.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: sdk}\n", encoding="utf-8")
    checks = env.config_check(cfg)
    blocking = [c for c in checks if c.status == FAIL and c.required]
    assert any("ANTHROPIC_SDK_API_KEY" in c.detail for c in blocking)


def test_missing_config_is_blocking(tmp_path):
    checks = env.config_check(tmp_path / "nope.yaml")
    assert checks[0].status == FAIL and checks[0].required


def test_summarize_counts():
    checks = [env.Check("a", OK, ""), env.Check("b", WARN, ""),
              env.Check("c", FAIL, "", required=True),
              env.Check("d", FAIL, "", required=False)]
    n_ok, n_warn, n_block = env.summarize(checks)
    assert (n_ok, n_warn, n_block) == (1, 1, 1)


def test_remediation_inputs_missing_is_blocking(monkeypatch, tmp_path):
    monkeypatch.setattr(rule_paths, "candidate_inputs_dirs",
                        lambda _package_file: (tmp_path,))
    check = env.remediation_inputs_check()
    assert check.status == FAIL
    assert check.required is True
    assert "interactive `vvaharness setup`" in check.detail


def test_setup_prompt_persists_valid_inputs_dir(monkeypatch, tmp_path, capsys):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for name in rule_paths.RULE_FILES:
        (inputs / name).write_text("schema_version: '1.0'\n", encoding="utf-8")
    settings = tmp_path / "settings.json"
    missing_dir = tmp_path / "missing"
    monkeypatch.setenv("VVAHARNESS_SETTINGS_FILE", str(settings))

    def candidates(_package_file):
        configured = rule_paths.configured_inputs_dir()
        return (missing_dir,) + ((configured,) if configured else ())
    monkeypatch.setattr(rule_paths, "candidate_inputs_dirs", candidates)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: str(inputs))

    cli._prompt_for_remediation_inputs()

    assert rule_paths.configured_inputs_dir() == inputs.resolve()
    assert "saved remediation inputs directory" in capsys.readouterr().out


# ── setup command end-to-end (rendering + exit code) ─────────────────────────
def test_setup_command_blocks_on_gateway_gap(monkeypatch, tmp_path, capsys):
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJhbGciOiJI.fake.jwt")  # JWT shape
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "sdk.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: sdk}\n", encoding="utf-8")
    rc = cli.main(["setup", "--config", str(cfg)])
    out = capsys.readouterr().out
    assert "setup" in out
    assert "via:sdk endpoint" in out
    # gateway gap is blocking → non-zero, "Not ready"
    assert rc == 1
    assert "Not ready" in out


@pytest.mark.parametrize("alias", ["setup", "init"])
def test_setup_and_init_are_aliases(alias, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "p.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: cli}\n", encoding="utf-8")
    # both must dispatch to the wizard (don't assert exit code — env-dependent)
    rc = cli.main([alias, "--config", str(cfg)])
    assert rc in (0, 1)


# ── actionable discovery (gateway + profile recommendation) ──────────────────
def test_detect_gateway_from_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gw.example/")
    url, src = env.detect_gateway()
    assert url == "https://gw.example/" and src == "environment"


def test_detect_gateway_from_rc_file(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    monkeypatch.setattr(env.Path, "home", lambda: tmp_path)
    (tmp_path / ".zshrc").write_text(
        '#export ANTHROPIC_BASE_URL="https://ai.example/"\n', encoding="utf-8")
    url, src = env.detect_gateway()
    assert url == "https://ai.example/" and src == "~/.zshrc"


def test_recommend_default_when_jwt_and_claude(monkeypatch):
    # JWT gateway token + the claude CLI present = Claude Code auth → the
    # CLI-first default profile (every role via: cli).
    monkeypatch.delenv("ANTHROPIC_SDK_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJbc.def.ghi")
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude" if c == "claude" else None)
    prof, _ = env.recommend_profile()
    assert prof == "default"


def test_recommend_sdk_when_only_sdk_key(monkeypatch, tmp_path):
    # An SDK key but NO Claude Code auth: sdk.yaml is the drop-in all-SDK
    # profile (every role via: sdk), so it is the right recommendation.
    monkeypatch.setattr(env.Path, "home", lambda: tmp_path)   # no on-disk CLI login
    monkeypatch.setattr(env.shutil, "which", lambda c: None)  # no claude on PATH
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-x")
    assert env.recommend_profile()[0] == "sdk"


def test_recommend_codex_when_native_login_ready(monkeypatch):
    monkeypatch.setattr(
        env.shutil, "which", lambda c: "/usr/bin/codex" if c == "codex" else None)
    monkeypatch.setattr(env, "_codex_login_present", lambda: True)
    prof, reason = env.recommend_profile()
    assert prof == "codex"
    assert "Codex CLI login" in reason


def test_codex_profile_accepts_native_login_without_openai_key(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(
        env.shutil, "which", lambda c: "/usr/bin/codex" if c == "codex" else None)
    monkeypatch.setattr(env, "_codex_login_present", lambda: True)
    cfg = tmp_path / "codex.yaml"
    cfg.write_text("models:\n  deepdive: {id: gpt-test, via: codex}\n",
                   encoding="utf-8")
    checks = env.config_check(cfg)
    cred = next(c for c in checks if c.name == "via:codex credential")
    assert cred.status == OK
    assert not any(c.name == "via:openai credential" for c in checks)


def test_claude_agent_uses_claude_json_login(monkeypatch, tmp_path):
    monkeypatch.setattr(env.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude" if c == "claude" else None)
    (tmp_path / ".claude.json").write_text('{"oauthAccount":{"emailAddress":"u@example.test"}}', encoding="utf-8")

    checks = env.agent_checks()
    claude = next(c for c in checks if c.name == "agent: Claude Code")
    assert claude.status == OK
    assert "installed and logged in" in claude.detail


def test_copilot_replaces_aider_in_agent_checks(monkeypatch):
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/copilot" if c == "copilot" else None)
    checks = env.agent_checks()
    names = [c.name for c in checks]
    assert "agent: GitHub Copilot CLI" in names
    assert "agent: Aider" not in names
    copilot = next(c for c in checks if c.name == "agent: GitHub Copilot CLI")
    assert copilot.status == OK
    assert copilot.detail == "copilot ✓ (via:cli) — installed"


def test_dotenv_check_detects_current_dir(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("X=1\n", encoding="utf-8")
    check = env.dotenv_check()
    assert check.status == OK
    assert check.name == ".env"
    assert check.detail == ".env found"


def test_run_checks_places_dotenv_after_config(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: cli}\n", encoding="utf-8")
    names = [c.name for c in env.run_checks(cfg)]
    assert names[names.index("config") + 1] == ".env"


# ── opt-in step 10 (remediate) / step 11 (validate) readiness ────────────────
def _has(checks, name):
    return any(c.name == name for c in checks)


def test_remediate_validate_absent_when_flags_off(tmp_path):
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  remediate: {id: x, via: cli}\n"
        "  validate:\n    orchestrator: {id: x, via: cli}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    assert not _has(checks, "step10: remediate")
    assert not _has(checks, "step11: validate")


def test_remediate_flag_on_with_cli_backend_ok(monkeypatch, tmp_path):
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  remediate: {id: x, via: cli}\n"
        "step_remediate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step10: remediate")
    assert c.status == OK


def test_remediate_flag_on_missing_cli_warns_not_blocking(monkeypatch, tmp_path):
    monkeypatch.setattr(env.shutil, "which", lambda c: None)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: sdk}\n"
        "  remediate: {id: x, via: cli}\n"
        "step_remediate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step10: remediate")
    assert c.status == WARN and c.required is False


def test_deepagents_remediation_requires_provider_credential(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  remediate: {id: gpt-5.5, via: deepagents, provider: openai}\n"
        "step_remediate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step10: remediate")
    assert c.status == WARN
    assert "OPENAI_API_KEY" in c.detail


def test_deepagents_remediation_accepts_openai_credential(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  remediate: {id: gpt-5.5, via: deepagents}\n"
        "step_remediate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step10: remediate")
    assert c.status == OK
    active = next(c for c in checks if c.name == "active backends")
    assert "deepagents" in active.detail


def test_deepagents_scan_role_is_invalid(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: gpt-5.5, via: deepagents}\n",
        encoding="utf-8",
    )
    checks = env.config_check(cfg)
    invalid = next(c for c in checks if c.name == "via:deepagents roles")
    assert invalid.status == FAIL
    assert invalid.required is True
    assert "deepdive" in invalid.detail


def test_validate_flag_on_rejects_openai_backend(monkeypatch, tmp_path):
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  validate:\n    orchestrator: {id: x, via: openai}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step11: validate")
    assert c.status == WARN
    assert "openai" in c.detail


def test_validate_flag_warns_when_sdk_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    monkeypatch.setattr(env.importlib.util, "find_spec", lambda m: None)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  validate:\n    orchestrator: {id: x, via: cli}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    sdk = next(c for c in checks if c.name == "step11: claude_agent_sdk")
    assert sdk.status == WARN and "claude_agent_sdk" in sdk.detail


def test_optin_step_issues_never_block_scan(monkeypatch, tmp_path):
    # Even with both opt-in steps misconfigured, summarize() must report zero
    # blocking issues — the core scan is unaffected, so doctor's live probe runs.
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    monkeypatch.setattr(env.importlib.util, "find_spec", lambda m: None)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  validate:\n    orchestrator: {id: x, via: openai}\n"
        "step_remediate:\n  enabled: true\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    _ok, _warn, n_blocking = env.summarize(checks)
    assert n_blocking == 0
