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

"""Translate DeepAgents / LangGraph state and messages into HarnessMessage types."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

from langchain_core.messages import (
    AIMessage,
    ToolMessage,
)
from pydantic import BaseModel

from vvaharness.util.tokens import TOKENS
from vvaharness.backends.harness.contract.messages import (
    HarnessAssistantText,
    HarnessMessage,
    HarnessResult,
    HarnessToolResult,
    HarnessToolUse,
    OneShotResult,
)


def _extract_text(msg: AIMessage) -> str:
    if isinstance(msg.content, str):
        return msg.content
    parts: list[str] = []
    for block in msg.content:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
    return "".join(parts)


def _tool_calls(msg: AIMessage) -> list[dict]:
    return [dict(c) for c in msg.tool_calls]


def translate_final_state(state: dict, *, oneshot: bool = False) -> OneShotResult:
    """Convert a terminal LangGraph state into a OneShotResult."""
    structured = state.get("structured_response")
    if structured is not None:
        if hasattr(structured, "model_dump_json"):
            result_text = structured.model_dump_json()
        elif hasattr(structured, "model_dump"):
            result_text = structured.model_dump()
        else:
            result_text = str(structured)
        return OneShotResult(
            result_text=None,
            structured=result_text,
        )
    messages = state.get("messages", [])
    for msg in reversed(messages):
        if isinstance(msg, AIMessage):
            text = _extract_text(msg)
            if text.strip():
                return OneShotResult(result_text=text.strip())
    return OneShotResult()


def _messages_from_event(payload: dict) -> list:
    """Collect new messages from a LangGraph ``stream_mode='updates'`` payload."""
    messages: list = []
    for update in payload.values():
        if not isinstance(update, dict):
            continue
        msgs = update.get("messages")
        if isinstance(msgs, Sequence):
            messages.extend(msgs)
    return messages


async def translate_stream_events(
    event: tuple | dict,
    seen_tool_call_ids: set[str],
    ns_to_agent: dict[tuple, str] | None = None,
) -> AsyncIterator[HarnessMessage]:
    """Yield HarnessMessage variants for one LangGraph stream event.

    With ``subgraphs=True`` each event is ``(namespace, payload)`` (namespace is
    ``()`` for the parent, non-empty for a persona). Messages are tagged by persona
    from ``AIMessage.name``; tool results inherit it via ``ns_to_agent``.
    """
    if ns_to_agent is None:
        ns_to_agent = {}
    ns, payload = event if isinstance(event, tuple) else ((), event)
    tag = tuple(ns) if ns else None
    for msg in _messages_from_event(payload):
        if isinstance(msg, AIMessage):
            name = getattr(msg, "name", None)
            if name:
                ns_to_agent[ns] = name
            agent = name or ns_to_agent.get(ns)
            text = _extract_text(msg)
            if text.strip():
                yield HarnessAssistantText(text=text, agent=agent, namespace=tag)
            for call in _tool_calls(msg):
                tid = call.get("id", "")
                if not tid:
                    continue
                if tid in seen_tool_call_ids:
                    continue
                seen_tool_call_ids.add(tid)
                yield HarnessToolUse(
                    tool_id=tid,
                    name=call.get("name", ""),
                    input=call.get("args", {}),
                    agent=agent,
                    namespace=tag,
                )
        elif isinstance(msg, ToolMessage):
            yield HarnessToolResult(
                content=msg.content,
                is_error=getattr(msg, "status", "success") == "error",
                agent=ns_to_agent.get(ns),
                namespace=tag,
            )


def make_terminal_result(
    state: dict, session_id: str | None = None
) -> HarnessResult:
    """Synthesize a terminal HarnessResult from the final LangGraph state."""
    messages = state.get("messages", [])
    final_text = ""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage):
            text = _extract_text(msg)
            if text.strip():
                final_text = text.strip()
                break
    structured = state.get("structured_response")
    if isinstance(structured, BaseModel):
        structured = structured.model_dump()
    # Mirror the Claude backend token counter hook when usage metadata is present.
    usage = state.get("usage")
    if isinstance(usage, dict):
        TOKENS.add(usage)

    return HarnessResult(
        subtype="success",
        session_id=session_id,
        result_text=final_text or None,
        structured=structured,
        usage=usage,
        total_cost_usd=None,
        state=state,
    )


__all__ = ["translate_final_state", "translate_stream_events", "make_terminal_result"]
