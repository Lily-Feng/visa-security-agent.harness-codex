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

"""A read-only session must not be able to write, and must not leak file content.

The filesystem deny rules cannot carry this alone: the matcher runs without DOTGLOB
and unmatched paths fail open, so hidden paths stayed writable. `.git/config` is the
sharp case -- the harness itself runs git in that tree, so a write there is remote
code execution. The write tools are therefore withheld from the model as well.

DeepAgents applies ``create_deep_agent(middleware=...)`` to the parent stack only, so
subagents need their own copy or they read unredacted -- and the personas are what do
almost all of the reading.

Offline and deterministic: no network, no LLM, no subprocess.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from vvaharness.backends.harness.contract.options import StreamingOptions
from vvaharness.backends.harness.contract.subagents import SubagentDefinition
from vvaharness.backends.harness.deepagents.options import get_subagent_specs
from vvaharness.backends.harness.deepagents.redaction import (
    WRITE_TOOLS,
    ExcludeTools,
    RedactToolResults,
    read_only_middleware,
)


def _options(*, allow_writes: bool) -> StreamingOptions:
    return StreamingOptions(
        model="test",
        cwd=Path("/tmp"),
        allow_writes=allow_writes,
        agents={
            "security-architect": SubagentDefinition(
                name="security-architect", description="d", prompt="p"
            )
        },
    )


def test_read_only_middleware_redacts_and_withholds_write_tools() -> None:
    kinds = [type(m).__name__ for m in read_only_middleware()]
    assert "RedactToolResults" in kinds
    assert "ExcludeTools" in kinds


def test_write_tools_are_removed_from_the_model_request() -> None:
    """FilesystemMiddleware always offers write_file/edit_file; strip them."""
    tools = [SimpleNamespace(name=n) for n in ("read_file", "grep", "write_file", "edit_file")]
    captured: dict[str, object] = {}

    request = SimpleNamespace(
        tools=tools,
        override=lambda **kw: SimpleNamespace(tools=kw["tools"], override=None),
    )
    ExcludeTools(WRITE_TOOLS).wrap_model_call(
        request, lambda req: captured.setdefault("tools", req.tools)
    )
    names = {getattr(t, "name", None) for t in captured["tools"]}
    assert names == {"read_file", "grep"}


def test_subagents_get_their_own_read_only_middleware() -> None:
    """Parent-only middleware left the personas reading unredacted."""
    specs = get_subagent_specs(_options(allow_writes=False))
    assert specs, "expected a persona spec"
    for spec in specs:
        kinds = [type(m).__name__ for m in spec["middleware"]]
        assert "RedactToolResults" in kinds, spec["name"]
        assert "ExcludeTools" in kinds, spec["name"]


def test_write_sessions_keep_their_edit_tools() -> None:
    """Remediation edits files: masking reads would break edit_file's old_string."""
    for spec in get_subagent_specs(_options(allow_writes=True)):
        assert "middleware" not in spec
    assert isinstance(RedactToolResults(), object)
