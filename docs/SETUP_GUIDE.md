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

# vvaharness — Setup Guide

Detailed install and configuration. For day-to-day usage and the full flag
reference, see **[USER_GUIDE.md](USER_GUIDE.md)**.

---

## 1. Prerequisites

| Need | Why |
|---|---|
| **Python ≥ 3.11** | required by package metadata. Installers reject older interpreters before any backend is selected. |
| **git** on `PATH` | only for batch clone mode (`--repo-file`). |
| **External Claude Code CLI** | required for S1–S9 in `default.yaml` (logged in, or with `CLAUDE_CODE_OAUTH_TOKEN`) and by the current S11 launcher when validation is spelled `via: cli` or `via: sdk`. SDK detection/S10 can use the Agent SDK's bundled executable. |
| **An Anthropic API key** | required by the shipped `default.yaml` for S10/S11 (`via: deepagents`: `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` for both remediate and validate). An OpenAI key is also required for `sdk.yaml` / `full.yaml` where roles use `via: sdk` / `via: openai`. |

---

## 2. Install

`vvaharness` is distributed as a source tree with a `pyproject.toml` — it is
**not** published to PyPI, so you install it **from this folder** rather than by
name. Installing it (any option below) builds the package into your environment
and puts the **`vvaharness`** command on your PATH, so you don't have to type
`python -m vvaharness …` each time. Run the commands from the project root
(where `pyproject.toml` lives). Pick the option that fits your platform.

### Option A — pipx (recommended; fully isolated)

```bash
pipx install .
```

### Option B — virtual environment (recommended when pipx isn't available)

A venv keeps the install isolated; `vvaharness` is on your PATH whenever the
venv is active.

**Linux / macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip3 install .
vvaharness --help
```

**Windows — PowerShell**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
vvaharness --help
```

**Windows — cmd.exe**
```bat
python -m venv .venv
.\.venv\Scripts\activate.bat
pip install .
vvaharness --help
```

### Development install

```bash
pip install -e .     # editable — code changes take effect without reinstalling
```

All installs expose one command, **`vvaharness`**, and bundle the three
detection adapters (Anthropic SDK, Claude CLI, OpenAI-compatible) plus the
DeepAgents/LangGraph harness used by post-scan roles—you only need credentials
for the routes your config actually uses. Base dependencies
(`pydantic`, `pydantic-settings`, `PyYAML`, `anthropic`, `openai`, `httpx`,
`urllib3`, `python-dotenv`, `typing_extensions`, `claude-agent-sdk`,
`tree-sitter`, `tree-sitter-language-pack`, `deepagents`, `langchain`,
`langchain-anthropic`, `langchain-openai`, `langgraph`) are declared in `pyproject.toml`
and resolved by pip — there is no separate requirements file and no extra flags
needed. The tree-sitter parsers for taint analysis are included in the standard
install.

> **`vvaharness: command not found`?** The script directory isn't on your PATH.
> Use a venv (Option B), or fall
> back to `python3 -m vvaharness …` (works from any install, any OS).

---

## 3. Credentials & `.env`

```bash
cp .env.example .env
$EDITOR .env          # fill in the keys for the backends you use
```

`vvaharness` **auto-loads** a `.env` found from the current directory upward at
startup, so you do **not** need to `source` it. Variables you export in your
shell take precedence over `.env` (handy for CI). One safety exception: if the
discovered `.env` resolves *inside* the `--repo` scan target (an
attacker-influenced checkout), it is ignored with a warning — set
`VVAHARNESS_ALLOW_CWD_CONFIG=1` to override. The `.env.example` template lists
the common credential and endpoint variables:

| Variable | Backend / use |
|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | `via: cli` — the default profile (alternative to interactive `claude` → `/login`) |
| `ANTHROPIC_SDK_API_KEY` | direct `via: sdk` detection roles and `sdk.yaml` S10; it is not translated for S11, which uses external-Claude login/OAuth or standard Anthropic auth |
| `ANTHROPIC_SDK_BASE_URL` | optional gateway/region override for `via: sdk` |
| `ANTHROPIC_SDK_CA_CERT` / `ANTHROPIC_SDK_CLIENT_CERT` | optional absolute paths for the direct Anthropic SDK detection transport; not consumed by Agent-SDK S10/S11 |
| `CLAUDE_CLI_CA_CERT` | optional absolute CA-bundle path for the direct `via: cli` adapter (→ `NODE_EXTRA_CA_CERTS` on its `claude` subprocess) |
| `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_BASE_URL` | DeepAgents with the Anthropic provider (default S10), and one authentication option for Agent-SDK S11 |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_CA_CERT` | key/base URL serve direct `via: openai` and DeepAgents/OpenAI; the CA var serves only the direct adapter and must be an absolute path |
| `SSL_CERT_FILE` / `SSL_CERT_DIR` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` | generic CA trust overrides honored by the DeepAgents OpenAI-compatible client |
| `GITHUB_TOKEN` / `GIT_BASE_URL` | batch clone (`--repo-file`) of private repos / URL derivation |

Start with the guided, no-spend readiness check:

```bash
vvaharness setup
```

After setup is green, optionally verify live connectivity. `doctor` sends a
small request to configured model backends and therefore spends model tokens:

```bash
vvaharness doctor
```

`doctor` honours `--config`, so `vvaharness doctor --config ./my.yaml` checks
the exact profile that scan will use.

### Claude Code CLI auth (the default profile, and any `via: cli` role)

Install the Claude Code CLI, then authenticate one of two ways:

- **Interactive:** run `claude`, then type `/login` inside the REPL.
- **Unattended / CI:** generate a token with `claude setup-token` and set
  `CLAUDE_CODE_OAUTH_TOKEN`.

### Endpoints & TLS — base URLs and certificates

> **Public / subscription users: you can skip this whole section.** With just an
> Anthropic API key (`ANTHROPIC_SDK_API_KEY=sk-ant-…`) or `claude login`, the
> public endpoints are used automatically — **no base URL, no CA certificate,
> no extra flags.** This section is only for users behind a **private corporate
> AI gateway** (e.g. an internal endpoint with its own
> root CA). If that's not you, jump to *§4 Configuration profiles*.
>
> **Enterprise gateway, in short:** export `ANTHROPIC_BASE_URL=https://<gateway>/`,
> add `NODE_EXTRA_CA_CERTS=$HOME/cacerts.pem` if it uses a private CA, and
> `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` if it returns `400 invalid beta flag`.
> `vvaharness setup` prints these exact lines when the active profile uses a `via: sdk`
> role (for shipped profiles, `sdk.yaml`/`full.yaml`). The shipped default profile has
> no `via: sdk` roles (`via: cli` for S1-S9 and `via: deepagents` for S10-S11), so
> set these variables explicitly when your gateway token requires them.

**Base URLs are optional.** If you set only the API key(s) and leave the
`*_BASE_URL` variables unset, vvaharness uses the official public endpoints
automatically — it does **not** fail:

- Anthropic (`via: sdk`) → `https://api.anthropic.com`
- OpenAI (`via: openai`) → `https://api.openai.com/v1`

Set a base URL only to point at an internal gateway, a specific region, or any
OpenAI-compatible endpoint.

**A certificate is _never_ required for public endpoints.** TLS settings—the `ca_cert` /
`client_cert` config keys, `verify_ssl`, and every `*_CA_CERT` /
`*_CLIENT_CERT` env var—are optional for the direct CLI/SDK/OpenAI routes. Use
absolute paths for certificate env values: after `${VAR}` interpolation the
value is passed through as-is (a bare string) to `os.path.exists()`/the TLS
client, so a relative path resolves against the process's current working
directory, not the selected YAML profile's directory or `.env`. DeepAgents uses
provider base URLs and normal process trust variables. When
their env vars are unset they expand to empty and inject **nothing**: no custom
HTTP client on the SDK/OpenAI side, no environment change on the `claude`
subprocess. A detection-only default run uses your Claude Code login; enabled
S10/S11 additionally use provider keys. You add a cert only when
something in front of the endpoint demands it.

**When is a certificate needed?** Only behind a private gateway or a
TLS-intercepting corporate proxy whose server certificate chains to an
**internal root CA that isn't in your OS trust store**. For the public official
APIs (`api.anthropic.com`, `api.openai.com`) you need **no certificate and no CA
bundle at all** — the system trust store validates them.

| Situation | What to set | Applies to |
|---|---|---|
| Public endpoint (`api.anthropic.com` / `api.openai.com`) + a normal API key | **nothing** TLS-related | all backends |
| Private gateway / intercepting proxy whose server cert chains to an **internal root CA** | the per-backend or generic CA bundle env var (see table below) | sdk, openai, cli, deepagents |
| Gateway requires **mutual TLS (mTLS)** | `ANTHROPIC_SDK_CLIENT_CERT` | direct Anthropic SDK detection transport only; not Agent-SDK S10/S11 |
| Throwaway/test env where you must skip verification (**insecure**) | `verify_ssl: false` in the backend's config block | sdk, openai, cli |

Per-backend env vars / config keys:

| Backend (`via:`) | CA bundle (private/internal root CA) | mTLS client cert | Disable verification (insecure) |
|---|---|---|---|
| `sdk` (Anthropic) | `ANTHROPIC_SDK_CA_CERT` | `ANTHROPIC_SDK_CLIENT_CERT` | `verify_ssl: false` in the `sdk:` block |
| `openai` | `OPENAI_CA_CERT` | **not supported** | `verify_ssl: false` in the `openai:` block |
| `cli` (`claude` subprocess) | `CLAUDE_CLI_CA_CERT` → `NODE_EXTRA_CA_CERTS` | **not supported** (Node exposes no env path) | `verify_ssl: false` → `NODE_TLS_REJECT_UNAUTHORIZED=0` on the subprocess |
| `deepagents` | process trust (`SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, or `NODE_EXTRA_CA_CERTS` for OpenAI-compatible clients) | **not exposed by vvaharness** | no `verify_ssl` profile block; configure trust at the provider/process layer |

Notes:
- **mTLS is exposed only by the direct Anthropic SDK transport.** Neither the
  OpenAI backend nor the direct `claude` CLI backend exposes a client-certificate
  path. The Claude Agent SDK paths used by `sdk.yaml` S10/S11 also do not consume
  `ANTHROPIC_SDK_CLIENT_CERT`; a gateway that requires it cannot serve those
  post-scan routes through this setting.
- The `via: cli` backend injects TLS settings into the `claude` **subprocess**
  environment: `CLAUDE_CLI_CA_CERT` becomes `NODE_EXTRA_CA_CERTS`, and
  `verify_ssl: false` becomes `NODE_TLS_REJECT_UNAUTHORIZED=0`. Auth and
  endpoint are left to the CLI's own precedence (run `claude` then `/login`, or
  `CLAUDE_CODE_OAUTH_TOKEN`; `ANTHROPIC_BASE_URL` if already exported).
- A CA-cert path takes precedence over `verify_ssl`. If the path is set but the
  file is missing, vvaharness **warns and falls back** to normal verification
  rather than failing.
- `verify_ssl` accepts a native YAML boolean (`true` / `false`) **or** a string
  boolean (`"false"`, `"true"`, `"0"`, `"1"`, `"no"`, `"yes"`, …). This matters
  when the value is supplied via an environment template such as
  `verify_ssl: ${VERIFY_SSL:-false}` (which expands to a string): the string is
  coerced to a real boolean, so `"false"` disables verification rather than
  being mistaken for a CA-bundle path. Any other string is still treated as a
  CA-bundle path.
- When a custom CA, verify-off, or mTLS is configured, the `sdk` / `openai`
  backends build their HTTP client via the SDK's own `DefaultHttpxClient`, so
  the tuned timeouts (~600 s) and the larger connection pool are preserved
  (robustness detail; no user-facing config).

---

## 4. Configuration profiles

`vvaharness` ships four profiles under `vvaharness/config/profiles/`:

- **`default.yaml`** — mixed-backend layout. S1–S9 (detection) run `via: cli`
  (the `claude` CLI subprocess) using your Claude Code login. S10 remediate and
  S11 validate both run `via: deepagents` with `ANTHROPIC_API_KEY`. No shipped
  profile runs the full S1–S11 pipeline on a
  Claude Code login alone. Used automatically when no `./config.yaml` is
  present. The `cli` backend gives the model native Read/Glob/Grep tools inside
  the target directory; Bash is off unless you add `- Bash` to a role's
  `allowed_tools` — for untrusted targets prefer `via: sdk` / `via: openai`
  (sandboxed Read/Glob/Grep, no shell); see [`security.md`](security.md).
- **`sdk.yaml`** — every configured role is spelled `via: sdk`. Detection uses
  the Anthropic Python SDK, S10 translates `ANTHROPIC_SDK_API_KEY` into its
  Claude Agent SDK environment, and S11 uses the same Harness but pins an
  external `claude` executable. S11 can reuse Claude login/
  `CLAUDE_CODE_OAUTH_TOKEN`, or standard `ANTHROPIC_API_KEY` /
  `ANTHROPIC_AUTH_TOKEN`; the SDK-named key alone is not translated on that
  path. A standard Anthropic credential alone can cover the profile because
  sole-SDK detection accepts it as fallback. No route grants Bash. Its
  deepdive at `temperature: 0.4` enables s4 majority voting (`step4.runs: 3` /
  `vote_threshold: 2`).
- **`full.yaml`** — an example multi-backend layout you can copy and edit. A
  complete run needs Claude CLI auth, `ANTHROPIC_SDK_API_KEY` for SDK
  detection/S10, and `OPENAI_API_KEY` for OpenAI detection roles. Its
  SDK-spelled S11 pins external `claude` and can reuse the same Claude login or
  OAuth token already needed by the profile; standard Anthropic auth is an
  alternative:

  ```bash
  cp vvaharness/config/profiles/full.yaml ./config.yaml
  $EDITOR ./config.yaml
  ```

- **`taint.yaml`** — taint-first source→sink scanning with the callgraph engine.
  Both `default.yaml` and `taint.yaml` enable the tree-sitter S0 callgraph in
  rules mode. With a non-empty seed, Taint's `step1.mode: gap_fill` skips
  agentic S1 except when all four escalation checks hold: more than 500 source
  files, a web-api/web-app/service classification, at least 10 entry points,
  and fewer than 5 sinks. An empty seed is falsey and takes the agentic S1
  path. `catchall_mode: reachable_only` limits catch-all chunks to reachable files;
  confirm/refute prompt on taint chunks in S4 (single-run, Opus — `claude-opus-4-8`); S9 appendix
  lists files skipped as unreachable. **S10 and S11 are disabled** in this
  profile (`step_remediate.enabled: false`, `step_validate.enabled: false`) —
  only a Claude Code login is needed. The profile's header comment
  (`vvaharness/config/profiles/taint.yaml:16–31`) is the canonical reference
  until full engine documentation exists. Use:
  `--config vvaharness/config/profiles/taint.yaml`.

S0 is profile-controlled via `step0.enabled`; `default.yaml` and `taint.yaml`
enable it, while `sdk.yaml` and `full.yaml` disable it by omission.

### Optional external source/sink rule files (S0)

S0 rules mode requires at least one usable generated source/sink rule file to
produce static matches. No generated source/sink corpus or implicit heuristic
baseline is bundled. With neither file, S0 returns an empty seed and the later
pipeline continues. In `taint.yaml`, that empty `SeedPackage` is falsey, so
`step1.mode: gap_fill` takes the agentic S1 path; the four-part gap-fill
escalation predicate is evaluated only for a non-empty seed.

To produce a rules-mode seed, generate external Semgrep-style source/sink files
from licensed local corpus clones and supply them through:

- `step0.sources_yaml` / `VVA_STEP0_SOURCES_YAML`
- `step0.sinks_yaml` / `VVA_STEP0_SINKS_YAML`

Those generated files are deliberately **not packaged** with vvaharness: their
third-party provenance and licences must remain explicit. `generic.kb.yaml` is
a different artifact used by S4's CWE confirm/refute prompt; it is not an S0
source/sink rule pack.

Build both files into an operator-owned directory. Do not write generated
artifacts into an installed `vvaharness/` package:

```bash
mkdir -p ./vvaharness-generated-rules
python -m vvaharness.rules.build_kb \
  --semgrep /path/to/semgrep-rules \
  --codeql /path/to/codeql \
  --sources-out ./vvaharness-generated-rules/sources.generated.yaml \
  --sinks-out ./vvaharness-generated-rules/sinks.generated.yaml
export VVA_STEP0_SOURCES_YAML="$PWD/vvaharness-generated-rules/sources.generated.yaml"
export VVA_STEP0_SINKS_YAML="$PWD/vvaharness-generated-rules/sinks.generated.yaml"
```

Build just one file (if you only have one corpus):

```bash
python -m vvaharness.rules.build_kb \
  --semgrep /path/to/semgrep-rules \
  --sources-out ./vvaharness-generated-rules/sources.generated.yaml
```

```bash
python -m vvaharness.rules.build_kb \
  --codeql /path/to/codeql \
  --sinks-out ./vvaharness-generated-rules/sinks.generated.yaml
```

Verify the files exist:

```bash
ls -lh ./vvaharness-generated-rules/sources.generated.yaml \
  ./vvaharness-generated-rules/sinks.generated.yaml
```

If you do not have corpus clones, the shipped profiles still run, but their
rules-mode S0 result is empty and S1 continues agentically. The alternative
spec-discovery path is `step0.callgraph_detection: llm` in your own profile
copy; if annotation fails or yields no usable specs, it falls back to the same
configured external YAML. See
[vvaharness/rules/README.md](../vvaharness/rules/README.md) for the artifact
schemas, provenance requirements, and maintainer build workflow.

`vvaharness` automatically picks up a `./config.yaml` in the working directory
(it overrides the packaged default); `--config <file>` selects an explicit one.
A git-ignored `config.local.yaml` next to your config is deep-merged on top, for
machine-specific overrides you don't commit.

Key sections (full reference in [configuration.md](configuration.md)):

- `models` — the `{id, via}` per role (see §5).
- `step0` — deterministic seed enablement, mode, and external rule paths.
- `step1` … `step8` — per-stage budgets, exclusions, and tuning knobs.
- `step_remediate` / `step_validate` — the remediation (stage 10) and
  validation (stage 11) stages: `enabled`, budgets, and tool allowlists. They are
  enabled in `default.yaml`, `sdk.yaml`, and `full.yaml`, and disabled in
  `taint.yaml`.
- `inject` — paths to optional context inputs (see §6).
- `batch` — clone token / base URL / skip patterns for `--repo-file` mode.
- `output.preserve_on_cleanup` — folders kept when a clone is purged.

> **Backend limits when repointing `models.remediate` / `models.validate`.**
> By default, `models.remediate` and `models.validate` both use `via: deepagents`
> with `ANTHROPIC_API_KEY`. If you
> override them: a `via: openai` validate role is routed to `via: deepagents` with
> the OpenAI provider, so it still needs `OPENAI_API_KEY` (plus `OPENAI_BASE_URL`
> for a custom endpoint). Remediation **fix mode** requires `via: cli`, `via: sdk`, or the
> repo-confined `via: deepagents` filesystem backend; a `via: openai` remediate
> role can only run `--mode report-only` (proposes fixes, applies none).
> Detection (S1–S9) and report-only remediation run on any backend. See
> [models.md](models.md) and [remediation.md](remediation.md).

> **Scanning a less-trusted or sensitive target?** vvaharness assumes an
> authorized operator running against a trusted repository. For third-party code,
> forks, or anything an outside party can influence, apply the compensating
> controls in [`security.md` → Hardening for less-trusted or sensitive targets](security.md#hardening-for-less-trusted-or-sensitive-targets).

---

## 5. Backends & swapping roles

| `via:` | Transport | Auth | Notes |
|---|---|---|---|
| `cli` | `claude` CLI subprocess | run `claude` then `/login`, or `CLAUDE_CODE_OAUTH_TOKEN` | the default profile; only backend capable of **Bash**, which still must be allowlisted |
| `sdk` | Anthropic Python SDK for detection; Claude Agent SDK for S10 fix/S11 | SDK key for detection/S10; S11 pins external `claude` and uses Claude login/OAuth or standard Anthropic auth (SDK key alone is insufficient) | detection honours `temperature`, `max_turns`; sandboxed Read/Glob/Grep; direct detection transport alone exposes **mTLS** |
| `openai` | OpenAI-compatible API | `OPENAI_API_KEY` | any compatible endpoint via `OPENAI_BASE_URL`; sandboxed Read/Glob/Grep |
| `deepagents` | DeepAgents/LangGraph provider harness | `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` or `OPENAI_API_KEY` | S10/S11 only; S10 fix mode has repo-confined writes, S11 is read-only; Bash denied |

The `cli`/`sdk` rows describe detection. S11 maps both selectors to the
read-only Claude Agent SDK Harness; S10 remains direct CLI for `via: cli` and
delegates fix-mode Edit/Write to the Agent SDK for `via: sdk`.

Swapping is config-only — no code change:

```yaml
models:
  deepdive: {id: <model-id>, via: openai}
  verify:   {id: <model-id>, via: sdk}
```

See [models.md](models.md) for the role→backend matrix.

---

## 6. Optional context inputs

The `inject` block points at optional files that enrich findings. Only the
`*.example.*` templates ship; copy them to the real names referenced by the
config (or point `inject.*` at your own paths):

```bash
cp inputs/cmdb.example.csv          inputs/cmdb.csv
cp inputs/known_cves.example.json   inputs/known_cves.json
cp inputs/design_controls.example.yaml inputs/design_controls.yaml
```

If a file is absent the pipeline still runs — the corresponding enrichment is
simply skipped (e.g. without a CMDB export, base CVSS + OffensivePriority are
still computed; only VulContextSeverity environmental scoring is skipped). The
real-data filenames (`inputs/cmdb.csv`, `inputs/repos.csv`,
`inputs/design_controls.yaml`, `inputs/known_cves.json`) are git-ignored, so
they aren't committed by an ordinary `git add` — only the shipped
`*.example.*` templates are tracked. (A `git add -f` can still force one in,
so don't override the ignore for a file holding real internal data.)

For batch scanning, see [repos-csv.md](repos-csv.md) and the worked
example at `inputs/repos.example.csv`.

---

## 7. Verifying the install

```bash
vvaharness --help
vvaharness doctor
vvaharness estimate --repo /path/to/some/repo
```

If `doctor` reports all configured backends present and reachable, you're ready
to `vvaharness scan` (see [USER_GUIDE.md](USER_GUIDE.md)).
