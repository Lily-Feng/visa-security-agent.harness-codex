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

"""DeepAgents implementation of the validation Harness contract."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import cast
from uuid import uuid4

from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph

from vvaharness.backends.harness.base import Harness
from vvaharness.backends.harness.contract.errors import HarnessError, HarnessProcessError
from vvaharness.backends.harness.contract.messages import (
    HarnessMessage,
    HarnessSessionInit,
    OneShotResult,
)
from vvaharness.backends.harness.contract.options import OneShotOptions, StreamingOptions
from vvaharness.backends.harness.deepagents.options import (
    build_oneshot_options,
    build_streaming_agent,
)
from vvaharness.backends.harness.deepagents.translate import (
    make_terminal_result,
    translate_final_state,
    translate_stream_events,
)


async def _safe_get_snapshot(
    graph: CompiledStateGraph, config: RunnableConfig
) -> object:
    """Return graph snapshot, or None if the graph has no initialised state."""
    try:
        return await graph.aget_state(config)
    except ValueError:
        return None


class DeepAgentHarness(Harness):
    """Validation harness backed by the DeepAgents / LangGraph runtime."""

    async def run_oneshot(
        self, prompt: str, options: OneShotOptions
    ) -> OneShotResult:
        """Run a single-turn parser-only invocation and return the result."""
        graph, config = build_oneshot_options(options)
        state = await graph.ainvoke(
            {"messages": [HumanMessage(content=prompt)]},
            config=cast(RunnableConfig, config),
        )
        return translate_final_state(state, oneshot=True)

    def run_streaming(
        self, prompt: str, options: StreamingOptions
    ) -> AsyncIterator[HarnessMessage]:
        """Return an async iterator of typed messages for a streaming session."""
        graph, config = build_streaming_agent(options)
        runnable_config = cast(RunnableConfig, config)

        async def _gen() -> AsyncIterator[HarnessMessage]:
            session_id = uuid4().hex
            seen_tool_ids: set[str] = set()
            # Subgraph namespace -> persona name, so subagent steps are tagged.
            ns_to_agent: dict[tuple, str] = {}
            try:
                yield HarnessSessionInit(session_id=session_id)
                # subgraphs=True surfaces each persona's internal steps; events
                # become (namespace, payload) tuples.
                async for event in graph.astream(
                    {"messages": [HumanMessage(content=prompt)]},
                    config=runnable_config,
                    stream_mode="updates",
                    subgraphs=True,
                ):
                    async for msg in translate_stream_events(event, seen_tool_ids, ns_to_agent):
                        yield msg
                snapshot = await _safe_get_snapshot(graph, runnable_config)
                state = getattr(snapshot, "values", None) if snapshot is not None else None
                yield make_terminal_result(
                    state if state is not None else {},
                    session_id=session_id,
                )
            except HarnessError:
                raise
            except Exception as exc:
                # On recursion-limit errors the graph has partial state in the
                # checkpointer. Snapshot it and yield a terminal so consumers
                # can attempt post-hoc extraction before the error propagates.
                if "GraphRecursionError" in type(exc).__name__:
                    snapshot = await _safe_get_snapshot(graph, runnable_config)
                    state = getattr(snapshot, "values", None) if snapshot is not None else None
                    yield make_terminal_result(state if state is not None else {}, session_id=session_id)
                raise HarnessProcessError(
                    f"DeepAgents stream failed: {type(exc).__name__}",
                    exit_code=1,
                    stderr=str(exc),
                ) from exc

        return _gen()
