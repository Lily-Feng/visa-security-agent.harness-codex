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

"""Typed configuration tree; all VVAHARNESS_* env access funnelled through _EnvScalars."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from vvaharness.validation.constants.artifacts import (
    DEFAULT_CLAUDE_BINARY,
    DEFAULT_EFFORT,
    DEFAULT_MAX_BUDGET_USD,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_MAX_TURNS,
    DEFAULT_MODEL,
    DEFAULT_VIA,
    ENV_CLAUDE_BINARY,
    ENV_CROSS_REPO_ANALYZER_MODEL,
    ENV_EFFORT,
    ENV_GHE_ARCHIVED_TOKEN,
    ENV_GHE_TOKEN,
    ENV_MAX_BUDGET_USD,
    ENV_MAX_FINDINGS,
    ENV_MAX_RETRIES,
    ENV_MAX_TURNS,
    ENV_MODEL,
    ENV_MODEL_PROVIDER,
    ENV_PENETRATION_TESTER_MODEL,
    ENV_SECURITY_ARCHITECT_MODEL,
    ENV_VALIDATE_TOOLS,
    ENV_VIA,
    OUTPUTS_DIRNAME,
    PROMPTS_DIRNAME,
    TARGETS_DIRNAME,
)
from vvaharness.validation.enums import EffortLevel

_ASSETS_ROOT = Path(__file__).resolve().parent.parent


class PathsConfig(BaseModel):
    """Filesystem layout for a run."""

    model_config = ConfigDict(extra="forbid")

    project_root: Path
    targets_dir: Path
    outputs_dir: Path
    prompts_dir: Path


class AgentConfig(BaseModel):
    """Agent runtime knobs: model selection, backend, execution limits."""

    model_config = ConfigDict(extra="forbid")

    binary: str = DEFAULT_CLAUDE_BINARY
    model: str = DEFAULT_MODEL
    max_turns: int = DEFAULT_MAX_TURNS
    max_budget_usd: float | None = DEFAULT_MAX_BUDGET_USD
    effort: EffortLevel = DEFAULT_EFFORT
    max_retries: int = DEFAULT_MAX_RETRIES
    via: str = DEFAULT_VIA
    provider: str | None = None  # deepagents backend: openai|anthropic; None → infer
    # Optional per-persona model overrides for the s11 validator; None → inherit ``model``.
    security_architect_model: str | None = None
    penetration_tester_model: str | None = None
    cross_repo_analyzer_model: str | None = None
    # Tool allow-list for the reviewer personas (step_validate.allowed_tools); None → .md default.
    validate_tools: tuple[str, ...] | None = None


class GheConfig(BaseModel):
    """GitHub Enterprise tokens passed through to the agent for ``gh api``."""

    model_config = ConfigDict(extra="forbid")

    token: str = ""
    archived_token: str = ""


class Config(BaseModel):
    """The composed configuration tree consumed across the package."""

    model_config = ConfigDict(extra="forbid")

    paths: PathsConfig
    agent: AgentConfig = Field(default_factory=AgentConfig)
    ghe: GheConfig = Field(default_factory=GheConfig)
    max_findings: int | None = DEFAULT_MAX_FINDINGS
    live: bool = False
    verbose: bool = False
    dry_run: bool = False


class _EnvScalars(BaseSettings):
    """The flat ``VVAHARNESS_*`` environment surface (sole env reader)."""

    model_config = SettingsConfigDict(extra="ignore", populate_by_name=True)

    model: str = Field(default=DEFAULT_MODEL, alias=ENV_MODEL)
    effort: EffortLevel = Field(default=DEFAULT_EFFORT, alias=ENV_EFFORT)
    max_turns: int = Field(default=DEFAULT_MAX_TURNS, alias=ENV_MAX_TURNS)
    max_budget_usd: float | None = Field(default=DEFAULT_MAX_BUDGET_USD, alias=ENV_MAX_BUDGET_USD)
    max_findings: int | None = Field(default=DEFAULT_MAX_FINDINGS, alias=ENV_MAX_FINDINGS)
    max_retries: int = Field(default=DEFAULT_MAX_RETRIES, alias=ENV_MAX_RETRIES)
    binary: str = Field(default=DEFAULT_CLAUDE_BINARY, alias=ENV_CLAUDE_BINARY)
    via: str = Field(default=DEFAULT_VIA, alias=ENV_VIA)
    provider: str | None = Field(default=None, alias=ENV_MODEL_PROVIDER)
    ghe_token: str = Field(default="", alias=ENV_GHE_TOKEN)
    ghe_archived_token: str = Field(default="", alias=ENV_GHE_ARCHIVED_TOKEN)
    security_architect_model: str | None = Field(default=None, alias=ENV_SECURITY_ARCHITECT_MODEL)
    penetration_tester_model: str | None = Field(default=None, alias=ENV_PENETRATION_TESTER_MODEL)
    cross_repo_analyzer_model: str | None = Field(default=None, alias=ENV_CROSS_REPO_ANALYZER_MODEL)
    validate_tools: str = Field(default="", alias=ENV_VALIDATE_TOOLS)


def _parse_tools(raw: str) -> tuple[str, ...] | None:
    """Parse a comma-separated tool list into a tuple; empty/blank → None (inherit .md default)."""
    tools = tuple(t.strip() for t in raw.split(",") if t.strip())
    return tools or None


def _build_paths(project_root: Path) -> PathsConfig:
    """Build PathsConfig for *project_root*, resolving asset dirs from the package."""
    return PathsConfig(
        project_root=project_root,
        targets_dir=project_root / TARGETS_DIRNAME,
        outputs_dir=project_root / OUTPUTS_DIRNAME,
        prompts_dir=_ASSETS_ROOT / PROMPTS_DIRNAME,
    )


def load_config(
    project_root: Path | None = None,
    *,
    live: bool = False,
    overrides: dict[str, object] | None = None,
) -> Config:
    """Build the configuration tree from the environment and a project root.

    *overrides* seeds the settings layer directly (by field name, typed — no string
    round-trip through ``os.environ``); supplied keys take precedence over the
    ``VVAHARNESS_*`` environment, which remains the fallback for everything unset.
    """
    seeded: dict[str, object] = _EnvScalars().model_dump()
    seeded.update(overrides or {})
    env = _EnvScalars.model_validate(seeded)
    root = project_root if project_root is not None else Path.cwd()
    cfg = Config(
        paths=_build_paths(root),
        agent=AgentConfig(
            binary=env.binary,
            model=env.model,
            max_turns=env.max_turns,
            max_budget_usd=env.max_budget_usd,
            effort=env.effort,
            max_retries=env.max_retries,
            via=env.via,
            provider=env.provider,
            security_architect_model=env.security_architect_model,
            penetration_tester_model=env.penetration_tester_model,
            cross_repo_analyzer_model=env.cross_repo_analyzer_model,
            validate_tools=_parse_tools(env.validate_tools),
        ),
        ghe=GheConfig(token=env.ghe_token, archived_token=env.ghe_archived_token),
        max_findings=env.max_findings,
        live=live,
    )
    cfg.paths.targets_dir.mkdir(parents=True, exist_ok=True)
    cfg.paths.outputs_dir.mkdir(parents=True, exist_ok=True)
    return cfg
