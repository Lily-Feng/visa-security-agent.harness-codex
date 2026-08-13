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

"""Per-file tree-sitter scanner. Emits a :class:`FileIndex` containing:

    * imports        — local-name → fully-qualified-name
    * functions      — (name, start_line, end_line) for scope resolution
    * source_hits    — CallSite records matching a source rule
    * sink_hits      — CallSite records matching a sink rule

Language support is pluggable via ``LANG_PLUGINS`` — a dict keyed by
vvaharness language keys (see vvaharness.lang.hints.EXT_TO_LANG). Each plugin
provides tree-sitter queries + a per-node extractor.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Callable
import sys

try:
    from tree_sitter_language_pack import get_parser
except Exception as _e:  # noqa: BLE001
    get_parser = None  # type: ignore[assignment]
    _TS_ERR = repr(_e)
else:
    _TS_ERR = ""

from vvaharness.pipeline.stages.callgraph_engine._rules import MatchSpec
from vvaharness.models import (
    CFG, CFGNode, ReflectionFact,
    FrameworkMarkerFact, RouteTaintFact, ResponseDataflowFact,
)


# ── parser caching (Iteration F) ─────────────────────────────────────────────
# Cache tree-sitter parser instances per language to avoid redundant O(n)
# re-instantiation when scanning n files of the same language.
_PARSERS: dict[str, object] = {}


def _get_cached_parser(ts_language: str):
    """Return cached parser for the given tree-sitter language.
    
    First call instantiates via get_parser(); subsequent calls return the cached
    instance. This eliminates per-file parser allocation overhead and enforces
    the "one parser per language" invariant.
    """
    if ts_language not in _PARSERS:
        _PARSERS[ts_language] = get_parser(ts_language)
    return _PARSERS[ts_language]


# ── record types ────────────────────────────────────────────────────────────

@dataclass
class CallSite:
    file: str                    # repo-relative path
    line: int                    # 1-based
    receiver: str                # leftmost identifier of the call expression
    method: str                  # attribute name (or bare function name)
    containing_fn: str           # nearest enclosing function name ("" = module)
    snippet: str                 # ~120 chars
    matched_rule: str            # MatchSpec.rule_id
    cwe: str                     # from MatchSpec.cwe
    role: str                    # "source" | "sink"
    kind: str                    # ep_kind / sink_kind
    semantic_family: str = ""
    owasp_top10_2025: tuple[str, ...] = ()


@dataclass
class FuncDef:
    name: str                    # bare function name (no class scope for MVP)
    start_line: int              # 1-based
    end_line: int
    class_name: str = ""         # enclosing class name for methods


@dataclass
class ObservedCall:
    """A call site observed by tree-sitter, regardless of rule matches.

    Used by LLM annotator mode to derive source/sink specs from actual
    repository call fingerprints.
    """
    file: str
    language: str
    line: int
    receiver: str
    resolved_receiver: str
    method: str
    containing_fn: str
    snippet: str


@dataclass
class VarAssignFact:
    function_qnode: str
    line: int
    dst_symbol: str
    src_symbol: str | None = None
    src_call: str | None = None


@dataclass
class ReturnFact:
    function_qnode: str
    line: int
    symbol: str | None = None


@dataclass
class CallArgFact:
    function_qnode: str
    line: int
    callee_name: str
    receiver: str
    arg_symbols: list[str] = field(default_factory=list)
    target_symbol: str | None = None


@dataclass
class FieldWriteFact:
    function_qnode: str
    line: int
    receiver: str        # "self", "this", or variable name
    field: str           # attribute/property/field name
    src_symbol: str | None = None  # RHS identifier if simple assignment


@dataclass
class FieldReadFact:
    function_qnode: str
    line: int
    receiver: str
    field: str
    dst_symbol: str | None = None  # LHS identifier if assigned


@dataclass
class ContainerWriteFact:
    function_qnode: str
    line: int
    container_symbol: str    # the list/dict/array variable
    element_symbol: str | None = None  # the value being written


@dataclass
class FileIndex:
    file: str
    language: str
    imports: dict[str, str]      # local-name → fully-qualified module/class name
    functions: list[FuncDef]
    source_hits: list[CallSite] = field(default_factory=list)
    sink_hits:   list[CallSite] = field(default_factory=list)
    # All call edges in the file, whether or not they matched a rule. Used
    # by the graph module to build true reachability.
    # (containing_fn_name, receiver_name, called_method_name)
    call_edges: list[tuple[str, str, str]] = field(default_factory=list)
    # All observed calls with snippets, for LLM-based spec derivation.
    observed_calls: list[ObservedCall] = field(default_factory=list)
    # Lightweight intra-procedural facts for interprocedural taint.
    assigns: list[VarAssignFact] = field(default_factory=list)
    returns: list[ReturnFact] = field(default_factory=list)
    call_args: list[CallArgFact] = field(default_factory=list)
    # Field and container extractor facts.
    field_writes: list[FieldWriteFact] = field(default_factory=list)
    field_reads: list[FieldReadFact] = field(default_factory=list)
    container_writes: list[ContainerWriteFact] = field(default_factory=list)
    # Control-flow graphs and reflection facts.
    cfgs: dict[str, CFG] = field(default_factory=dict)  # function_qnode → CFG
    reflection_facts: list[ReflectionFact] = field(default_factory=list)
    # Framework detection facts.
    framework_markers: list[FrameworkMarkerFact] = field(default_factory=list)
    route_facts: list[RouteTaintFact] = field(default_factory=list)
    response_dataflow: list[ResponseDataflowFact] = field(default_factory=list)


# ── language plugin protocol ────────────────────────────────────────────────

@dataclass
class LangPlugin:
    """Per-language extraction rules. `extract` walks the parsed tree and
    populates a fresh FileIndex + returns (call_list) for matching."""
    ts_language: str
    extract: Callable[[bytes, "object"], tuple[
        dict[str, str],           # imports
        list[FuncDef],            # function defs
        list[tuple[int, str, str, str, str]],  # calls: (line, receiver, method, containing_fn, snippet)
        list[VarAssignFact],      # local alias/call assignment facts
        list[ReturnFact],         # return identifier facts
        list[CallArgFact],        # call argument identifier facts
    ]]


# ── CFG and Reflection Fact Extraction ────────────────────────────────────

def _build_cfg_for_function(func_node, func_name: str, src: bytes) -> CFG | None:
    """Build a one-block CFG scaffold when given a function AST node.

    The current scanner does not call this helper with a node and therefore
    leaves ``FileIndex.cfgs`` empty. The schema/helper are reserved for future
    control-flow refinement; no branch- or path-sensitive analysis is claimed.
    
    Args:
        func_node: tree-sitter function_definition/method_declaration node
        func_name: function name for reference
        src: source code bytes
        
    Returns:
        CFG with blocks and successors, or None if parsing fails
    """
    if func_node is None:
        return None
    try:
        cfg = CFG(
            blocks={},
            entry="B0",
            exit="",
            function_name=func_name,
        )
        cfg.blocks["B0"] = CFGNode(
            block_id="B0",
            stmts=[func_node],
            successors=[],
            condition=None,
        )
        cfg.exit = "B0"
        return cfg
    except Exception:
        return None


def _extract_control_flow_nodes(node) -> list[tuple[int, str, str]]:
    """Recursively extract all control-flow statement nodes.

    Finds if/while/for/switch/try nodes and returns their start line,
    condition text, and node type.

    Returns:
        list of (start_line, condition_text, node_type) tuples
    """
    cf_nodes: list[tuple[int, str, str]] = []

    def _walk(n):
        if n is None:
            return
        t = n.type
        if t in ("if_statement", "if_expression"):
            # Try to extract condition text
            cond_text = ""
            for c in n.children:
                if c.type in ("comparison_operator", "binary_operator", "condition", "parenthesized_expression"):
                    cond_text = n.type
                    break
            cf_nodes.append((n.start_point[0] + 1, cond_text, t))
        elif t in ("while_statement", "for_statement", "for_in_statement"):
            cf_nodes.append((n.start_point[0] + 1, "", t))
        elif t in ("switch_statement", "switch_expression"):
            cf_nodes.append((n.start_point[0] + 1, "", t))
        elif t in ("try_statement", "try_catch_statement", "try_expression"):
            cf_nodes.append((n.start_point[0] + 1, "", t))
        # Recurse into children
        for child in n.children:
            _walk(child)

    _walk(node)
    return cf_nodes


def _py_extract_reflection_facts(src: bytes, tree) -> list[ReflectionFact]:
    """Extract Python reflection facts (getattr, setattr, __import__).
    
    Detects patterns like:
    - getattr(obj, name)
    - setattr(obj, name, val)
    - __import__(module)
    - importlib.import_module(...)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ReflectionFact records
    """
    root = tree.root_node
    facts: list[ReflectionFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type == "function_definition":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _py_text(n, src)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "call":
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                return
            # Check for bare function calls: getattr, setattr, __import__
            if fn_node.type == "identifier":
                fname = _py_text(fn_node, src)
                if fname in ("getattr", "setattr", "__import__",
                              "vars", "type", "eval", "exec", "compile"):
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        # Extract 2nd arg (name) for getattr/setattr, 1st arg for __import__
                        # and 1st arg for vars/type/eval/exec/compile
                        target_symbols: list[str] = []
                        for i, arg in enumerate(args_node.named_children):
                            if fname == "__import__" and i == 0:
                                if arg.type == "string":
                                    target_symbols.append(
                                        _py_text(arg, src).strip("\"'"))
                                elif arg.type == "identifier":
                                    target_symbols.append(_py_text(arg, src))
                                break
                            elif fname in ("getattr", "setattr") and i == 1:
                                if arg.type == "string":
                                    target_symbols.append(
                                        _py_text(arg, src).strip("\"'"))
                                elif arg.type == "identifier":
                                    target_symbols.append(_py_text(arg, src))
                                break
                            elif fname in ("vars", "type", "eval", "exec", "compile") and i == 0:
                                if arg.type == "string":
                                    target_symbols.append(
                                        _py_text(arg, src).strip("\"'"))
                                elif arg.type == "identifier":
                                    target_symbols.append(_py_text(arg, src))
                                break
                        if target_symbols:
                            _call_type = (
                                "getattr" if fname in ("getattr", "vars")
                                else "invoke" if fname in ("eval", "exec")
                                else "construct"
                            )
                            facts.append(ReflectionFact(
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                call_type=_call_type,
                                target_symbols=target_symbols,
                                receiver="",
                                language="python",
                            ))
            # Check for importlib.import_module
            elif fn_node.type == "attribute":
                attr_node = fn_node.child_by_field_name("attribute")
                if attr_node is not None:
                    method = _py_text(attr_node, src)
                    if method == "import_module":
                        receiver = _py_leftmost_identifier(fn_node, src)
                        if receiver == "importlib":
                            args_node = node.child_by_field_name("arguments")
                            if args_node is not None:
                                for arg in args_node.named_children:
                                    if arg.type == "string":
                                        target_symbols = [
                                            _py_text(arg, src).strip("\"'")]
                                        facts.append(ReflectionFact(
                                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                                            line=node.start_point[0] + 1,
                                            call_type="construct",
                                            target_symbols=target_symbols,
                                            receiver="importlib",
                                            language="python",
                                        ))
                                        break
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


def _java_extract_reflection_facts(src: bytes, tree) -> list[ReflectionFact]:
    """Extract Java reflection facts (getMethod, forName, invoke, newInstance).
    
    Detects patterns like:
    - Class.getMethod(name)
    - Class.forName(name)
    - method.invoke(...)
    - Class.newInstance()
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ReflectionFact records
    """
    root = tree.root_node
    facts: list[ReflectionFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type in ("method_declaration", "constructor_declaration"):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            obj_node = node.child_by_field_name("object")
            if name_node is None:
                return
            method = _text_of(src, name_node)
            receiver = _java_leftmost(obj_node, src) if obj_node is not None else ""
            
            # getMethod(name), forName(name), getDeclaredMethod(name),
            # getDeclaredField(name), getField(name)
            if method in ("getMethod", "forName", "getDeclaredMethod",
                          "getDeclaredField", "getField"):
                args_node = node.child_by_field_name("arguments")
                if args_node is not None:
                    target_symbols: list[str] = []
                    for arg in args_node.named_children:
                        if arg.type == "string_literal":
                            target_symbols.append(_text_of(src, arg).strip("\""))
                        elif arg.type == "identifier":
                            target_symbols.append(_text_of(src, arg))
                    if target_symbols:
                        facts.append(ReflectionFact(
                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                            line=node.start_point[0] + 1,
                            call_type="getmethod",
                            target_symbols=target_symbols,
                            receiver=receiver,
                            language="java",
                        ))
            # invoke(...) 
            elif method == "invoke":
                facts.append(ReflectionFact(
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    call_type="invoke",
                    target_symbols=[],
                    receiver=receiver,
                    language="java",
                ))
            # newInstance(), getDeclaredConstructor(...), getConstructor(...)
            elif method in ("newInstance", "getDeclaredConstructor", "getConstructor"):
                facts.append(ReflectionFact(
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    call_type="construct",
                    target_symbols=[],
                    receiver=receiver,
                    language="java",
                ))
            # MethodHandles.lookup() — method handle lookup
            elif method == "lookup" and "MethodHandles" in receiver:
                facts.append(ReflectionFact(
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    call_type="getmethod",
                    target_symbols=[],
                    receiver=receiver,
                    language="java",
                ))
            # Activator receiver — dynamic instantiation pattern
            elif receiver == "Activator":
                facts.append(ReflectionFact(
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    call_type="construct",
                    target_symbols=[],
                    receiver=receiver,
                    language="java",
                ))
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


def _cs_extract_reflection_facts(src: bytes, tree) -> list[ReflectionFact]:
    """Extract C# reflection facts (GetMethod, GetType, CreateDelegate, etc.).
    
    Detects patterns like:
    - type.GetMethod(name)
    - Type.GetType(name)
    - Delegate.CreateDelegate(...)
    - Assembly.LoadFrom(...)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ReflectionFact records
    """
    root = tree.root_node
    facts: list[ReflectionFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type in ("method_declaration", "constructor_declaration"):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "invocation_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                return
            if fn_node.type == "member_access_expression":
                name_node = fn_node.child_by_field_name("name")
                expr_node = fn_node.child_by_field_name("expression")
                if name_node is None:
                    return
                method = _text_of(src, name_node)
                receiver = _cs_leftmost(expr_node, src) if expr_node is not None else ""

                # GetMethod(name), GetType(name), GetMethods(), GetConstructor(...),
                # GetConstructors()
                if method in ("GetMethod", "GetType", "GetMethods",
                              "GetConstructor", "GetConstructors"):
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        target_symbols: list[str] = []
                        for arg in args_node.named_children:
                            if arg.type in ("string", "string_literal"):
                                target_symbols.append(
                                    _text_of(src, arg).strip("\""))
                            elif arg.type == "identifier":
                                target_symbols.append(_text_of(src, arg))
                            elif arg.type == "argument":
                                e = arg.child_by_field_name("expression")
                                if e is not None:
                                    if e.type in ("string", "string_literal"):
                                        target_symbols.append(
                                            _text_of(src, e).strip("\""))
                                    elif e.type == "identifier":
                                        target_symbols.append(_text_of(src, e))
                        if target_symbols:
                            facts.append(ReflectionFact(
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                call_type="getmethod",
                                target_symbols=target_symbols,
                                receiver=receiver,
                                language="csharp",
                            ))
                        elif method in ("GetMethods", "GetConstructor", "GetConstructors"):
                            # No string arg required — emit fact on the call itself
                            facts.append(ReflectionFact(
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                call_type="getmethod",
                                target_symbols=[],
                                receiver=receiver,
                                language="csharp",
                            ))
                # CreateDelegate(...) or Invoke() on a delegate
                elif method in ("CreateDelegate", "Invoke"):
                    facts.append(ReflectionFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        call_type="delegate" if method == "CreateDelegate" else "invoke",
                        target_symbols=[],
                        receiver=receiver,
                        language="csharp",
                    ))
                # LoadFrom(...), Load(...), LoadFile(...) for Assembly
                elif method in ("LoadFrom", "Load", "LoadFile"):
                    facts.append(ReflectionFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        call_type="construct",
                        target_symbols=[],
                        receiver=receiver,
                        language="csharp",
                    ))
                # Activator.CreateInstance(type) — dynamic instantiation
                elif method == "CreateInstance":
                    facts.append(ReflectionFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        call_type="construct",
                        target_symbols=[],
                        receiver=receiver,
                        language="csharp",
                    ))
                # Type.InvokeMember(name, ...) — reflective invocation
                elif method == "InvokeMember":
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        target_symbols = []
                        for arg in args_node.named_children:
                            if arg.type in ("string", "string_literal"):
                                target_symbols.append(
                                    _text_of(src, arg).strip("\""))
                            elif arg.type == "argument":
                                e = arg.child_by_field_name("expression")
                                if e is not None and e.type in ("string", "string_literal"):
                                    target_symbols.append(
                                        _text_of(src, e).strip("\""))
                            break  # only first arg (member name)
                    facts.append(ReflectionFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        call_type="invoke",
                        target_symbols=target_symbols if args_node is not None else [],
                        receiver=receiver,
                        language="csharp",
                    ))
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


# ── Framework Marker and Response Dataflow Extraction ────────────────────

def _py_extract_framework_markers(src: bytes, tree) -> tuple[list[FrameworkMarkerFact], list[RouteTaintFact]]:
    """Extract Python framework markers (Django views, request patterns).
    
    Detects:
    - Django view functions with 'request' parameter
    - request.GET/POST/META/FILES access patterns
    - View function naming patterns (*_view, handle*, process*)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        tuple of (marker_facts, route_facts)
    """
    root = tree.root_node
    markers: list[FrameworkMarkerFact] = []
    routes: list[RouteTaintFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type == "function_definition":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _py_text(n, src)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        # Detect function definitions with 'request' parameter
        if node.type == "function_definition":
            fn_name_node = node.child_by_field_name("name")
            if fn_name_node is None:
                return
            fn_name = _py_text(fn_name_node, src)
            params_node = node.child_by_field_name("parameters")
            if params_node is None:
                return
            
            # Extract parameter names
            param_names = []
            for param in params_node.named_children:
                if param.type in ("identifier", "parameter"):
                    pname = _py_text(param, src) if param.type == "identifier" else (
                        _py_text(param.child_by_field_name("name"), src) if param.child_by_field_name("name") else "")
                    if pname:
                        param_names.append(pname)
            
            # Treat any function that takes `request` as a Django view marker.
            # Naming heuristics miss common handlers (e.g., `profile(request)`).
            if "request" in param_names:
                markers.append(FrameworkMarkerFact(
                    function_qnode=fn_name,
                    line=node.start_point[0] + 1,
                    marker_type="django_view",
                    marker_name="request",
                    parameter_names=["request"],
                    framework="django",
                    confidence="high",
                ))
            
            # Detect request.GET/POST/META access patterns
            for child in node.children:
                _check_request_access(child, fn_name, src, markers, fn_ranges)
        
        for c in node.children:
            _visit(c)

    def _check_request_access(node, fn_name: str, src: bytes, markers: list, fn_ranges):
        """Recursively check for request.GET/POST/META patterns."""
        if node.type == "attribute":
            obj_node = node.child_by_field_name("object")
            # Python grammar uses "attribute"; keep legacy "attr" fallback
            # for compatibility with older/alternate grammars.
            attr_node = (node.child_by_field_name("attribute")
                         or node.child_by_field_name("attr"))
            if obj_node and attr_node:
                obj_text = _py_text(obj_node, src)
                attr_text = _py_text(attr_node, src)
                if obj_text == "request" and attr_text in ("GET", "POST", "META", "FILES"):
                    markers.append(FrameworkMarkerFact(
                        function_qnode=fn_name,
                        line=node.start_point[0] + 1,
                        marker_type="django_dict_access",
                        marker_name=f"request.{attr_text}",
                        parameter_names=["result"],
                        framework="django",
                        confidence="high",
                    ))
        
        for c in node.children:
            _check_request_access(c, fn_name, src, markers, fn_ranges)

    _visit(root)
    return markers, routes


def _java_extract_framework_markers(src: bytes, tree) -> tuple[list[FrameworkMarkerFact], list[RouteTaintFact]]:
    """Extract Java framework markers (Spring annotations, servlet types).
    
    Detects:
    - @RequestParam, @PathVariable, @RequestBody, @RequestHeader annotations
    - @GetMapping, @PostMapping with path patterns
    - ServletRequest, HttpServletRequest parameter types
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        tuple of (marker_facts, route_facts)
    """
    root = tree.root_node
    markers: list[FrameworkMarkerFact] = []
    routes: list[RouteTaintFact] = []
    
    def _visit(node):
        # Detect method with Spring annotations
        if node.type == "method_declaration":
            method_name_node = node.child_by_field_name("name")
            if method_name_node is None:
                return
            method_name = _text_of(src, method_name_node)
            
            # Collect annotations on the method (check direct children for modifiers)
            for child in node.children:
                if child.type == "modifiers":
                    for mod_child in child.children:
                        if mod_child.type in ("annotation", "marker_annotation"):
                            _process_spring_annotation(mod_child, method_name, node, src, markers, routes)
            
            # Check method parameters for annotations
            params_node = node.child_by_field_name("parameters")
            if params_node is not None:
                for param in params_node.named_children:
                    if param.type == "formal_parameter":
                        _process_parameter_annotations(param, method_name, src, markers)
        
        for c in node.children:
            _visit(c)

    def _process_spring_annotation(annotation_node, method_name: str, method_node, src: bytes, 
                                   markers: list, routes: list):
        """Process Spring annotations on a method."""
        name_node = annotation_node.child_by_field_name("name")
        if name_node is None:
            return
        
        annotation_name = _text_of(src, name_node)
        
        # @GetMapping("/path/{id}"), @PostMapping, etc.
        if annotation_name in ("GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "RequestMapping"):
            # Extract route pattern
            args = annotation_node.child_by_field_name("arguments")
            if args is not None:
                for arg in args.named_children:
                    if arg.type == "string_literal":
                        route_path = _text_of(src, arg).strip("\"")
                        # Extract path parameters
                        import re as re_module
                        params = re_module.findall(r'\{(\w+)\}', route_path)
                        for param in params:
                            routes.append(RouteTaintFact(
                                function_qnode=method_name,
                                line=method_node.start_point[0] + 1,
                                route_pattern=route_path,
                                parameter_name=param,
                                is_tainted=True,
                                framework="spring",
                            ))

    def _process_parameter_annotations(param_node, method_name: str, src: bytes, markers: list):
        """Process annotations on a parameter."""
        param_name_node = param_node.child_by_field_name("name")
        if param_name_node is None:
            return
        param_name = _text_of(src, param_name_node)
        
        # Check for annotations (inside modifiers node on parameter, iterate direct children)
        for child in param_node.children:
            if child.type == "modifiers":
                for mod_child in child.children:
                    if mod_child.type in ("annotation", "marker_annotation"):
                        ann_name_node = mod_child.child_by_field_name("name")
                        if ann_name_node is not None:
                            ann_name = _text_of(src, ann_name_node)
                            if ann_name in ("RequestParam", "PathVariable", "RequestBody", "RequestHeader"):
                                markers.append(FrameworkMarkerFact(
                                    function_qnode=method_name,
                                    line=param_node.start_point[0] + 1,
                                    marker_type="spring_annotation",
                                    marker_name=f"@{ann_name}",
                                    parameter_names=[param_name],
                                    framework="spring",
                                    confidence="high",
                                ))
        
        # Check for ServletRequest/HttpServletRequest types
        type_node = param_node.child_by_field_name("type")
        if type_node is not None:
            type_text = _text_of(src, type_node)
            if "ServletRequest" in type_text or "HttpServletRequest" in type_text:
                markers.append(FrameworkMarkerFact(
                    function_qnode=method_name,
                    line=param_node.start_point[0] + 1,
                    marker_type="spring_implicit",
                    marker_name=type_text,
                    parameter_names=[param_name],
                    framework="spring",
                    confidence="medium",
                ))

    _visit(root)
    return markers, routes


def _cs_extract_framework_markers(src: bytes, tree) -> tuple[list[FrameworkMarkerFact], list[RouteTaintFact]]:
    """Extract C# framework markers (ASP.NET annotations, binding parameters).
    
    Detects:
    - [FromQuery], [FromRoute], [FromBody], [FromHeader] annotations
    - [HttpGet], [HttpPost] with route patterns
    - ControllerBase inheritance + [ApiController]
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        tuple of (marker_facts, route_facts)
    """
    root = tree.root_node
    markers: list[FrameworkMarkerFact] = []
    routes: list[RouteTaintFact] = []
    
    def _visit(node):
        # Detect method with ASP.NET attributes
        if node.type == "method_declaration":
            method_name_node = node.child_by_field_name("name")
            if method_name_node is None:
                return
            method_name = _text_of(src, method_name_node)
            
            # Check method attributes (inside attribute_list)
            for child in node.children:
                if child.type == "attribute_list":
                    for attr_node in child.children:
                        if attr_node.type == "attribute":
                            _process_aspnet_attribute(attr_node, method_name, node, src, markers, routes)
            
            # Check parameters for attributes
            params_node = node.child_by_field_name("parameters")
            if params_node is not None:
                for param in params_node.named_children:
                    if param.type == "parameter":
                        _process_parameter_attributes(param, method_name, src, markers)
        
        for c in node.children:
            _visit(c)

    def _process_aspnet_attribute(attr_node, method_name: str, method_node, src: bytes,
                                 markers: list, routes: list):
        """Process ASP.NET attributes on a method."""
        attr_name_node = attr_node.child_by_field_name("name")
        if attr_name_node is None:
            return
        
        attr_name = _text_of(src, attr_name_node)
        
        # [HttpGet("/path/{id}")] etc.
        if attr_name in ("HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch"):
            args = attr_node.child_by_field_name("arguments")
            if args is not None:
                for arg in args.named_children:
                    if arg.type in ("string", "string_literal"):
                        route_path = _text_of(src, arg).strip("\"")
                        # Extract path parameters {id}
                        import re as re_module
                        params = re_module.findall(r'\{(\w+)\}', route_path)
                        for param in params:
                            routes.append(RouteTaintFact(
                                function_qnode=method_name,
                                line=method_node.start_point[0] + 1,
                                route_pattern=route_path,
                                parameter_name=param,
                                is_tainted=True,
                                framework="aspnet",
                            ))

    def _process_parameter_attributes(param_node, method_name: str, src: bytes, markers: list):
        """Process attributes on a parameter."""
        param_name_node = param_node.child_by_field_name("name")
        if param_name_node is None:
            return
        param_name = _text_of(src, param_name_node)
        
        # Check for parameter attributes [FromQuery], [FromRoute], etc. (inside attribute_list)
        for child in param_node.children:
            if child.type == "attribute_list":
                for attr_node in child.children:
                    if attr_node.type == "attribute":
                        attr_name_node = attr_node.child_by_field_name("name")
                        if attr_name_node is not None:
                            attr_name = _text_of(src, attr_name_node)
                            if attr_name in ("FromQuery", "FromRoute", "FromBody", "FromHeader"):
                                markers.append(FrameworkMarkerFact(
                                    function_qnode=method_name,
                                    line=param_node.start_point[0] + 1,
                                    marker_type="aspnet_annotation",
                                    marker_name=f"[{attr_name}]",
                                    parameter_names=[param_name],
                                    framework="aspnet",
                                    confidence="high",
                                ))

    _visit(root)
    return markers, routes


def _py_extract_response_dataflow(src: bytes, tree) -> list[ResponseDataflowFact]:
    """Extract Python response dataflow (JsonResponse, HttpResponse, render).
    
    Detects patterns like:
    - JsonResponse(data)
    - HttpResponse(content)
    - render(request, template, context=)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ResponseDataflowFact records
    """
    root = tree.root_node
    facts: list[ResponseDataflowFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type == "function_definition":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _py_text(n, src)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "call":
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                return
            
            # Detect bare function calls: JsonResponse, HttpResponse, render
            if fn_node.type == "identifier":
                fname = _py_text(fn_node, src)
                if fname in ("JsonResponse", "HttpResponse", "render"):
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        # Extract first argument as the data flowing into response
                        for i, arg in enumerate(args_node.named_children):
                            if fname == "render" and i == 2:  # context= parameter
                                if arg.type == "keyword_argument":
                                    val_node = arg.child_by_field_name("value")
                                    if val_node is not None:
                                        from_sym = _py_text(val_node, src)
                                        facts.append(ResponseDataflowFact(
                                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                                            line=node.start_point[0] + 1,
                                            from_symbol=from_sym,
                                            to_sink="render",
                                            framework="django",
                                            response_type="html",
                                        ))
                            elif fname in ("JsonResponse", "HttpResponse") and i == 0:
                                from_sym = _py_text(arg, src)
                                response_type = "json" if fname == "JsonResponse" else "html"
                                facts.append(ResponseDataflowFact(
                                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                                    line=node.start_point[0] + 1,
                                    from_symbol=from_sym,
                                    to_sink=fname,
                                    framework="django",
                                    response_type=response_type,
                                ))
                                break
        
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


def _java_extract_response_dataflow(src: bytes, tree) -> list[ResponseDataflowFact]:
    """Extract Java response dataflow (ResponseEntity, model.addAttribute).
    
    Detects patterns like:
    - ResponseEntity<...> return values
    - model.addAttribute(name, value)
    - new ResponseEntity<>(body, status)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ResponseDataflowFact records
    """
    root = tree.root_node
    facts: list[ResponseDataflowFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type == "method_declaration":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        # Detect ResponseEntity<...> constructor calls
        if node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                type_text = _text_of(src, type_node)
                if "ResponseEntity" in type_text:
                    args = node.child_by_field_name("arguments")
                    if args is not None:
                        for i, arg in enumerate(args.named_children):
                            if i == 0:  # First argument is body
                                from_sym = _text_of(src, arg)
                                facts.append(ResponseDataflowFact(
                                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                                    line=node.start_point[0] + 1,
                                    from_symbol=from_sym,
                                    to_sink="ResponseEntity",
                                    framework="spring",
                                    response_type="json",
                                ))
                                break
        
        # Detect model.addAttribute(...) calls
        if node.type == "method_invocation":
            fn_node = node.child_by_field_name("name")
            if fn_node is not None:
                method_name = _text_of(src, fn_node)
                if method_name == "addAttribute":
                    args = node.child_by_field_name("arguments")
                    if args is not None:
                        # Second argument is the value being added
                        children = list(args.named_children)
                        if len(children) >= 2:
                            from_sym = _text_of(src, children[1])
                            facts.append(ResponseDataflowFact(
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                from_symbol=from_sym,
                                to_sink="addAttribute",
                                framework="spring",
                                response_type="html",
                            ))
        
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


def _cs_extract_response_dataflow(src: bytes, tree) -> list[ResponseDataflowFact]:
    """Extract C# response dataflow (Ok, BadRequest, Created, JSON serialization).
    
    Detects patterns like:
    - Ok(model)
    - BadRequest(error)
    - Created(location, resource)
    - Json(data)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ResponseDataflowFact records
    """
    root = tree.root_node
    facts: list[ResponseDataflowFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type == "method_declaration":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "invocation_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                return
            
            # Detect bare method calls: Ok, BadRequest, Created, Json
            if fn_node.type == "identifier":
                method_name = _text_of(src, fn_node)
                if method_name in ("Ok", "BadRequest", "Created", "Json"):
                    args = node.child_by_field_name("arguments")
                    if args is not None:
                        for i, arg in enumerate(args.named_children):
                            # Map method name to response type
                            response_type_map = {
                                "Ok": "json",
                                "BadRequest": "json",
                                "Created": "json",
                                "Json": "json",
                            }
                            response_type = response_type_map.get(method_name, "json")
                            
                            # Skip location argument in Created()
                            if method_name == "Created" and i == 0:
                                continue
                            
                            from_sym = _text_of(src, arg)
                            facts.append(ResponseDataflowFact(
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                from_symbol=from_sym,
                                to_sink=method_name,
                                framework="aspnet",
                                response_type=response_type,
                            ))
                            break  # Only process first data argument
        
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


# ── Python plugin ───────────────────────────────────────────────────────────
# Uses tree-sitter-python's node types (call, attribute, identifier,
# import_statement, import_from_statement, function_definition, class_definition).


def _py_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _py_leftmost_identifier(node, src: bytes) -> str:
    """Walk a call/attribute expression to its leftmost identifier — that's
    what we treat as the receiver root for import resolution."""
    cur = node
    while cur is not None:
        if cur.type == "identifier":
            return _py_text(cur, src)
        # attribute has children [object, ".", attribute]; recurse into object
        if cur.type == "attribute":
            cur = cur.child_by_field_name("object") or cur.children[0]
            continue
        if cur.type == "call":
            cur = cur.child_by_field_name("function")
            continue
        # subscript, parenthesized, etc. — take first child and keep walking
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _py_snippet(src: bytes, node) -> str:
    """Grab a compact single-line snippet at the call site."""
    line_start = src.rfind(b"\n", 0, node.start_byte) + 1
    line_end = src.find(b"\n", node.end_byte)
    if line_end == -1:
        line_end = len(src)
    return src[line_start:line_end].decode("utf-8", errors="ignore").strip()[:120]


def _py_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    # Precompute function ranges so we can attribute each call to a scope.
    fn_ranges: list[tuple[int, int, str]] = []  # (start, end, name)
    calls: list[tuple[int, str, str, str, str]] = []
    assigns: list[VarAssignFact] = []
    returns: list[ReturnFact] = []
    call_args: list[CallArgFact] = []

    def _py_call_parts(call_node) -> tuple[str, str]:
        fn_node = call_node.child_by_field_name("function")
        if fn_node is None:
            return "", ""
        if fn_node.type == "attribute":
            method_node = fn_node.child_by_field_name("attribute")
            method = _py_text(method_node, src) if method_node else ""
            receiver = _py_leftmost_identifier(fn_node, src)
            return receiver, method
        if fn_node.type == "identifier":
            return "", _py_text(fn_node, src)
        return "", ""

    def _py_assignment_target_for_call(call_node) -> str | None:
        parent = call_node.parent
        if parent is None or parent.type != "assignment":
            return None
        right = parent.child_by_field_name("right")
        left = parent.child_by_field_name("left")
        if right is call_node and left is not None and left.type == "identifier":
            return _py_text(left, src)
        return None

    def _py_identifier_args(call_node) -> list[str]:
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            return []
        out: list[str] = []
        for arg in args_node.named_children:
            if arg.type == "identifier":
                out.append(_py_text(arg, src))
            elif arg.type == "keyword_argument":
                val = arg.child_by_field_name("value")
                if val is not None and val.type == "identifier":
                    out.append(_py_text(val, src))
        return out

    def _py_return_identifier(ret_node) -> str | None:
        val = ret_node.child_by_field_name("value")
        if val is None:
            for c in ret_node.named_children:
                if c.type != "return":
                    val = c
                    break
        if val is not None and val.type == "identifier":
            return _py_text(val, src)
        return None

    def _visit(node):
        t = node.type
        if t == "import_statement":
            # import foo   |   import foo.bar   |   import foo as f, baz
            for name_node in node.children:
                if name_node.type != "dotted_name" and name_node.type != "aliased_import":
                    continue
                if name_node.type == "aliased_import":
                    mod_node = name_node.child_by_field_name("name")
                    alias_node = name_node.child_by_field_name("alias")
                    if mod_node and alias_node:
                        imports[_py_text(alias_node, src)] = _py_text(mod_node, src)
                else:
                    mod = _py_text(name_node, src)
                    imports[mod.split(".")[0]] = mod
        elif t == "import_from_statement":
            mod_node = node.child_by_field_name("module_name")
            mod = _py_text(mod_node, src) if mod_node else ""
            # Children after module_name are the imported symbols
            for c in node.children:
                if c.type in ("dotted_name", "aliased_import") and c is not mod_node:
                    if c.type == "aliased_import":
                        name_node = c.child_by_field_name("name")
                        alias_node = c.child_by_field_name("alias")
                        if name_node and alias_node:
                            imports[_py_text(alias_node, src)] = (
                                f"{mod}.{_py_text(name_node, src)}"
                                if mod else _py_text(name_node, src)
                            )
                    else:
                        sym = _py_text(c, src)
                        imports[sym] = f"{mod}.{sym}" if mod else sym
        elif t == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _py_text(name_node, src)
                functions.append(FuncDef(
                    name=fname,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                ))
                fn_ranges.append((node.start_byte, node.end_byte, fname))
        elif t == "call":
            fn_node = node.child_by_field_name("function")
            if fn_node is not None:
                receiver, method = _py_call_parts(node)
                if method:
                    line = node.start_point[0] + 1
                    scope = _scope_for(node.start_byte, fn_ranges)
                    snippet = _py_snippet(src, node)
                    calls.append((line, receiver, method, scope, snippet))
                    call_args.append(CallArgFact(
                        function_qnode=scope,
                        line=line,
                        callee_name=method,
                        receiver=receiver,
                        arg_symbols=_py_identifier_args(node),
                        target_symbol=_py_assignment_target_for_call(node),
                    ))
        elif t == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "identifier" and right is not None:
                dst = _py_text(left, src)
                src_symbol: str | None = None
                src_call: str | None = None
                if right.type == "identifier":
                    src_symbol = _py_text(right, src)
                elif right.type == "call":
                    _r, m = _py_call_parts(right)
                    src_call = m or None
                if src_symbol is not None or src_call is not None:
                    assigns.append(VarAssignFact(
                        function_qnode=_scope_for(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        dst_symbol=dst,
                        src_symbol=src_symbol,
                        src_call=src_call,
                    ))
        elif t == "return_statement":
            returns.append(ReturnFact(
                function_qnode=_scope_for(node.start_byte, fn_ranges),
                line=node.start_point[0] + 1,
                symbol=_py_return_identifier(node),
            ))
        # Recurse into children (function_definition scopes contain calls too).
        for child in node.children:
            _visit(child)

    def _scope_for(offset: int, ranges: list[tuple[int, int, str]]) -> str:
        # Innermost enclosing function wins — walk in reverse so nested
        # defs override outer ones.
        for s, e, name in reversed(ranges):
            if s <= offset < e:
                return name
        return ""

    _visit(root)
    return imports, functions, calls, assigns, returns, call_args


# ── shared byte-level helpers (used by all non-Python plugins) ──────────────

def _text_of(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _snippet_at(src: bytes, node) -> str:
    line_start = src.rfind(b"\n", 0, node.start_byte) + 1
    line_end = src.find(b"\n", node.end_byte)
    if line_end == -1:
        line_end = len(src)
    return src[line_start:line_end].decode("utf-8", errors="ignore").strip()[:120]


def _scope_at(offset: int, ranges: list[tuple[int, int, str]]) -> str:
    """Innermost enclosing function name for a byte offset, "" if module-level."""
    for s, e, name in reversed(ranges):
        if s <= offset < e:
            return name
    return ""


# ── Java plugin ─────────────────────────────────────────────────────────────
# tree-sitter-java node types: import_declaration, scoped_identifier,
# method_declaration, constructor_declaration, class_declaration,
# method_invocation (fields: object?, name), object_creation_expression
# (field: type), field_access (field: object, field).

def _java_leftmost(node, src: bytes) -> str:
    cur = node
    while cur is not None:
        if cur.type == "identifier":
            return _text_of(src, cur)
        if cur.type == "field_access":
            cur = cur.child_by_field_name("object") or (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.type == "method_invocation":
            obj = cur.child_by_field_name("object")
            if obj is None:
                return ""
            cur = obj
            continue
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _java_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    fn_ranges: list[tuple[int, int, str]] = []
    calls: list[tuple[int, str, str, str, str]] = []
    assigns: list[VarAssignFact] = []
    returns: list[ReturnFact] = []
    call_args: list[CallArgFact] = []
    class_stack: list[str] = []
    package_name = ""
    local_types: dict[str, str] = {}

    def _normalize_type_name(raw: str) -> str:
        # Strip generics/arrays/annotations so lookups stay stable.
        t = re.sub(r"<[^>]*>", "", raw)
        t = t.replace("[]", "").strip()
        t = t.split()[-1] if t else ""
        return t

    def _resolve_type(raw: str) -> str:
        t = _normalize_type_name(raw)
        if not t:
            return ""
        if "." in t:
            return t
        if t in imports:
            return imports[t]
        if package_name:
            return f"{package_name}.{t}"
        return t

    def _ctor_type_from_node(node) -> str:
        """Best-effort concrete type extraction from Java expressions.

        Supports:
        - `new Foo(...)`
        - cast expressions like `(Foo) value`
        """
        if node is None:
            return ""
        if node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                return _resolve_type(_text_of(src, type_node))
            return ""
        if node.type == "cast_expression":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                return _resolve_type(_text_of(src, type_node))
            return ""
        return ""

    def _java_call_target(node) -> str | None:
        parent = node.parent
        if parent is None:
            return None
        if parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            right = parent.child_by_field_name("right")
            if right is node and left is not None and left.type == "identifier":
                return _text_of(src, left)
        if parent.type == "variable_declarator":
            val = parent.child_by_field_name("value")
            name = parent.child_by_field_name("name")
            if val is node and name is not None and name.type == "identifier":
                return _text_of(src, name)
        return None

    def _java_identifier_args(call_node) -> list[str]:
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            return []
        out: list[str] = []
        for c in args_node.named_children:
            if c.type == "identifier":
                out.append(_text_of(src, c))
        return out

    def _java_invocation_parts(node) -> tuple[str, str]:
        name_node = node.child_by_field_name("name")
        method = _text_of(src, name_node) if name_node else ""
        obj_node = node.child_by_field_name("object")
        receiver = _java_leftmost(obj_node, src) if obj_node is not None else ""
        return receiver, method

    def _java_return_identifier(ret_node) -> str | None:
        val = ret_node.child_by_field_name("value")
        if val is None:
            for c in ret_node.named_children:
                if c.type == "identifier":
                    val = c
                    break
        if val is not None and val.type == "identifier":
            return _text_of(src, val)
        return None

    def _visit(node):
        nonlocal package_name
        t = node.type
        if t == "package_declaration":
            for c in node.children:
                if c.type == "scoped_identifier":
                    package_name = _text_of(src, c)
                    break
        elif t == "import_declaration":
            qname = ""
            is_wildcard = False
            for c in node.children:
                if c.type == "scoped_identifier":
                    qname = _text_of(src, c)
                elif c.type == "asterisk":
                    is_wildcard = True
            if qname and not is_wildcard:
                imports[qname.split(".")[-1]] = qname
        elif t == "class_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                cls = _text_of(src, name_node)
                if cls:
                    imports[cls] = f"{package_name}.{cls}" if package_name else cls
                    class_stack.append(cls)
                    for c in node.children:
                        _visit(c)
                    class_stack.pop()
                    return
        elif t in ("method_declaration", "constructor_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                functions.append(FuncDef(
                    name=fname,
                    class_name=class_stack[-1] if class_stack else "",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1))
                fn_ranges.append((node.start_byte, node.end_byte, fname))
        elif t in ("formal_parameter", "catch_formal_parameter"):
            name_node = node.child_by_field_name("name")
            type_node = node.child_by_field_name("type")
            if name_node is not None and type_node is not None:
                local_types[_text_of(src, name_node)] = _resolve_type(_text_of(src, type_node))
        elif t == "local_variable_declaration":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                resolved_type = _resolve_type(_text_of(src, type_node))
                if resolved_type:
                    for c in node.children:
                        if c.type == "variable_declarator":
                            n = c.child_by_field_name("name")
                            if n is not None:
                                name = _text_of(src, n)
                                # Prefer concrete initializer types when available:
                                # `Iface x = new Impl()` should resolve `x` to `Impl`
                                # for call matching, not only `Iface`.
                                init = c.child_by_field_name("value")
                                narrowed = _ctor_type_from_node(init)
                                local_types[name] = narrowed or resolved_type
                                # Emit assign fact from the same declarator.
                                val_node = init
                                if val_node is not None:
                                    src_sym_lv: str | None = None
                                    src_call_lv: str | None = None
                                    if val_node.type == "identifier":
                                        src_sym_lv = _text_of(src, val_node)
                                    elif val_node.type == "method_invocation":
                                        _recv_lv, method_lv = _java_invocation_parts(val_node)
                                        src_call_lv = method_lv or None
                                    elif val_node.type == "object_creation_expression":
                                        tn_lv = val_node.child_by_field_name("type")
                                        if tn_lv is not None:
                                            src_call_lv = _text_of(src, tn_lv).split(".")[-1].strip() or None
                                    if src_sym_lv is not None or src_call_lv is not None:
                                        assigns.append(VarAssignFact(
                                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                                            line=node.start_point[0] + 1,
                                            dst_symbol=name,
                                            src_symbol=src_sym_lv,
                                            src_call=src_call_lv,
                                        ))
        elif t == "assignment_expression":
            # Track reassignments that narrow variable types, e.g.:
            # `conn = new HttpURLConnection(...)` or `x = (Foo) y`.
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "identifier" and right is not None:
                narrowed = _ctor_type_from_node(right)
                if narrowed:
                    local_types[_text_of(src, left)] = narrowed
                src_symbol: str | None = None
                src_call: str | None = None
                if right.type == "identifier":
                    src_symbol = _text_of(src, right)
                elif right.type == "method_invocation":
                    _recv, method = _java_invocation_parts(right)
                    src_call = method or None
                elif right.type == "object_creation_expression":
                    type_node = right.child_by_field_name("type")
                    if type_node is not None:
                        src_call = _text_of(src, type_node).split(".")[-1].strip() or None
                if src_symbol is not None or src_call is not None:
                    assigns.append(VarAssignFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        dst_symbol=_text_of(src, left),
                        src_symbol=src_symbol,
                        src_call=src_call,
                    ))
        elif t == "method_invocation":
            receiver, method = _java_invocation_parts(node)
            if method:
                line = node.start_point[0] + 1
                scope = _scope_at(node.start_byte, fn_ranges)
                calls.append((
                    line, receiver, method,
                    scope,
                    _snippet_at(src, node)))
                call_args.append(CallArgFact(
                    function_qnode=scope,
                    line=line,
                    callee_name=method,
                    receiver=receiver,
                    arg_symbols=_java_identifier_args(node),
                    target_symbol=_java_call_target(node),
                ))
        elif t == "object_creation_expression":
            # `new Foo(...)` — receiver empty, method = short class name.
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                cls = _text_of(src, type_node).split(".")[-1].strip()
                if cls:
                    line = node.start_point[0] + 1
                    scope = _scope_at(node.start_byte, fn_ranges)
                    calls.append((
                        line, "", cls,
                        scope,
                        _snippet_at(src, node)))
                    call_args.append(CallArgFact(
                        function_qnode=scope,
                        line=line,
                        callee_name=cls,
                        receiver="",
                        arg_symbols=_java_identifier_args(node),
                        target_symbol=_java_call_target(node),
                    ))
        elif t == "return_statement":
            returns.append(ReturnFact(
                function_qnode=_scope_at(node.start_byte, fn_ranges),
                line=node.start_point[0] + 1,
                symbol=_java_return_identifier(node),
            ))
        for c in node.children:
            _visit(c)

    _visit(root)
    # Lightweight type hints for variable receivers: let matcher resolve
    # receiver variables through inferred declaration/parameter types.
    imports.update({k: v for k, v in local_types.items() if v})
    return imports, functions, calls, assigns, returns, call_args


# ── JavaScript / TypeScript plugin ──────────────────────────────────────────
# tree-sitter-javascript / tree-sitter-typescript node types:
# import_statement (import_clause, source), variable_declarator,
# function_declaration, method_definition, arrow_function,
# call_expression (fields: function, arguments),
# member_expression (fields: object, property).

def _js_leftmost(node, src: bytes) -> str:
    cur = node
    while cur is not None:
        if cur.type in ("identifier", "property_identifier"):
            return _text_of(src, cur)
        if cur.type == "member_expression":
            cur = cur.child_by_field_name("object") or (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.type == "call_expression":
            cur = cur.child_by_field_name("function")
            continue
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _js_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    fn_ranges: list[tuple[int, int, str]] = []
    calls: list[tuple[int, str, str, str, str]] = []
    class_stack: list[str] = []

    def _visit(node):
        t = node.type
        if t == "import_statement":
            src_node = node.child_by_field_name("source")
            src_txt = _text_of(src, src_node).strip("\"'") if src_node else ""
            for c in node.children:
                if c.type != "import_clause":
                    continue
                for gc in c.children:
                    if gc.type == "identifier":
                        imports[_text_of(src, gc)] = src_txt
                    elif gc.type == "namespace_import":
                        for ggc in gc.children:
                            if ggc.type == "identifier":
                                imports[_text_of(src, ggc)] = src_txt
                    elif gc.type == "named_imports":
                        for spec in gc.children:
                            if spec.type != "import_specifier":
                                continue
                            n = spec.child_by_field_name("name")
                            a = spec.child_by_field_name("alias")
                            if n is None:
                                continue
                            local = _text_of(src, a) if a else _text_of(src, n)
                            imports[local] = (
                                f"{src_txt}.{_text_of(src, n)}"
                                if src_txt else _text_of(src, n))
        elif t == "variable_declarator":
            # const x = require('y')  — CommonJS shape
            n = node.child_by_field_name("name")
            v = node.child_by_field_name("value")
            if (n is not None and v is not None
                    and v.type == "call_expression"):
                fn = v.child_by_field_name("function")
                if (fn is not None and fn.type == "identifier"
                        and _text_of(src, fn) == "require"):
                    args = v.child_by_field_name("arguments")
                    if args is not None:
                        for arg in args.children:
                            if arg.type == "string":
                                imports[_text_of(src, n)] = (
                                    _text_of(src, arg).strip("\"'"))
        elif t == "class_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                cls = _text_of(src, name_node)
                if cls:
                    class_stack.append(cls)
                    for c in node.children:
                        _visit(c)
                    class_stack.pop()
                    return
        elif t in ("function_declaration", "method_definition",
                   "generator_function_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                functions.append(FuncDef(
                    name=fname,
                    class_name=class_stack[-1] if class_stack else "",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1))
                fn_ranges.append((node.start_byte, node.end_byte, fname))
        elif t == "call_expression":
            fn = node.child_by_field_name("function")
            method = ""
            receiver = ""
            if fn is not None:
                if fn.type == "member_expression":
                    prop = fn.child_by_field_name("property")
                    method = _text_of(src, prop) if prop else ""
                    receiver = _js_leftmost(fn, src)
                elif fn.type == "identifier":
                    method = _text_of(src, fn)
            if method:
                calls.append((
                    node.start_point[0] + 1, receiver, method,
                    _scope_at(node.start_byte, fn_ranges),
                    _snippet_at(src, node)))
        for c in node.children:
            _visit(c)

    _visit(root)
    return imports, functions, calls, [], [], []


# ── Go plugin ───────────────────────────────────────────────────────────────
# tree-sitter-go node types: import_declaration, import_spec_list, import_spec
# (fields: name?, path), function_declaration, method_declaration,
# call_expression (fields: function, arguments),
# selector_expression (fields: operand, field).

def _go_leftmost(node, src: bytes) -> str:
    cur = node
    while cur is not None:
        if cur.type == "identifier":
            return _text_of(src, cur)
        if cur.type == "selector_expression":
            cur = cur.child_by_field_name("operand") or (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.type == "call_expression":
            cur = cur.child_by_field_name("function")
            continue
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _go_import_spec(spec, src: bytes, imports: dict[str, str]) -> None:
    path_node = spec.child_by_field_name("path")
    name_node = spec.child_by_field_name("name")
    if path_node is None:
        return
    path = _text_of(src, path_node).strip("\"`")
    alias = _text_of(src, name_node) if name_node else path.rsplit("/", 1)[-1]
    if alias and alias not in (".", "_"):
        imports[alias] = path


def _go_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    fn_ranges: list[tuple[int, int, str]] = []
    calls: list[tuple[int, str, str, str, str]] = []

    def _visit(node):
        t = node.type
        if t == "import_declaration":
            for c in node.children:
                if c.type == "import_spec":
                    _go_import_spec(c, src, imports)
                elif c.type == "import_spec_list":
                    for gc in c.children:
                        if gc.type == "import_spec":
                            _go_import_spec(gc, src, imports)
        elif t in ("function_declaration", "method_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                functions.append(FuncDef(
                    name=fname,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1))
                fn_ranges.append((node.start_byte, node.end_byte, fname))
        elif t == "call_expression":
            fn = node.child_by_field_name("function")
            method = ""
            receiver = ""
            if fn is not None:
                if fn.type == "selector_expression":
                    field = fn.child_by_field_name("field")
                    method = _text_of(src, field) if field else ""
                    receiver = _go_leftmost(fn, src)
                elif fn.type == "identifier":
                    method = _text_of(src, fn)
            if method:
                calls.append((
                    node.start_point[0] + 1, receiver, method,
                    _scope_at(node.start_byte, fn_ranges),
                    _snippet_at(src, node)))
        for c in node.children:
            _visit(c)

    _visit(root)
    return imports, functions, calls, [], [], []


# ── C# plugin ───────────────────────────────────────────────────────────────
# tree-sitter-c-sharp node types: using_directive (field: name),
# method_declaration, constructor_declaration, local_function_statement,
# invocation_expression (fields: function, arguments),
# member_access_expression (fields: expression, name),
# object_creation_expression (field: type).

def _cs_leftmost(node, src: bytes) -> str:
    cur = node
    while cur is not None:
        if cur.type == "identifier":
            return _text_of(src, cur)
        if cur.type == "member_access_expression":
            cur = cur.child_by_field_name("expression") or (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.type in ("invocation_expression", "element_access_expression"):
            fn = cur.child_by_field_name("function")
            cur = fn if fn is not None else (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _cs_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    fn_ranges: list[tuple[int, int, str]] = []
    calls: list[tuple[int, str, str, str, str]] = []
    assigns: list[VarAssignFact] = []
    returns: list[ReturnFact] = []
    call_args: list[CallArgFact] = []
    class_stack: list[str] = []

    def _cs_invocation_parts(node) -> tuple[str, str]:
        fn = node.child_by_field_name("function")
        if fn is None and node.child_count:
            fn = node.children[0]
        method = ""
        receiver = ""
        if fn is not None:
            if fn.type == "member_access_expression":
                n = fn.child_by_field_name("name")
                method = _text_of(src, n) if n else ""
                receiver = _cs_leftmost(fn, src)
            elif fn.type == "identifier":
                method = _text_of(src, fn)
        return receiver, method

    def _cs_identifier_args(call_node) -> list[str]:
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            return []
        out: list[str] = []
        for c in args_node.named_children:
            if c.type == "identifier":
                out.append(_text_of(src, c))
            elif c.type == "argument":
                expr = c.child_by_field_name("expression")
                if expr is not None and expr.type == "identifier":
                    out.append(_text_of(src, expr))
        return out

    def _cs_call_target(node) -> str | None:
        parent = node.parent
        if parent is None:
            return None
        if parent.type in ("assignment_expression", "simple_assignment_expression"):
            left = parent.child_by_field_name("left")
            right = parent.child_by_field_name("right")
            if right is node and left is not None and left.type == "identifier":
                return _text_of(src, left)
        if parent.type == "equals_value_clause":
            gp = parent.parent
            if gp is not None and gp.type == "variable_declarator":
                name = gp.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    return _text_of(src, name)
        if parent.type == "variable_declarator":
            name = parent.child_by_field_name("name")
            value = parent.child_by_field_name("value")
            if value is node and name is not None and name.type == "identifier":
                return _text_of(src, name)
        return None

    def _cs_return_identifier(ret_node) -> str | None:
        expr = ret_node.child_by_field_name("expression")
        if expr is None:
            for c in ret_node.named_children:
                if c.type == "identifier":
                    expr = c
                    break
        if expr is not None and expr.type == "identifier":
            return _text_of(src, expr)
        return None

    def _cs_assignment_parts(node) -> tuple[str | None, str | None, str | None]:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or left.type != "identifier" or right is None:
            return None, None, None
        src_symbol: str | None = None
        src_call: str | None = None
        if right.type == "identifier":
            src_symbol = _text_of(src, right)
        elif right.type == "invocation_expression":
            _recv, method = _cs_invocation_parts(right)
            src_call = method or None
        elif right.type == "object_creation_expression":
            type_node = right.child_by_field_name("type")
            if type_node is not None:
                src_call = _text_of(src, type_node).split(".")[-1].strip() or None
        return _text_of(src, left), src_symbol, src_call

    def _visit(node):
        t = node.type
        if t == "using_directive":
            name_node = node.child_by_field_name("name")
            if name_node is None:
                for c in node.children:
                    if c.type in ("qualified_name", "identifier"):
                        name_node = c
                        break
            if name_node is not None:
                qname = _text_of(src, name_node)
                imports[qname.split(".")[-1]] = qname
        elif t in ("class_declaration", "struct_declaration", "interface_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                cls = _text_of(src, name_node)
                if cls:
                    class_stack.append(cls)
                    for c in node.children:
                        _visit(c)
                    class_stack.pop()
                    return
        elif t in ("method_declaration", "constructor_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                functions.append(FuncDef(
                    name=fname,
                    class_name=class_stack[-1] if class_stack else "",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1))
                fn_ranges.append((node.start_byte, node.end_byte, fname))
        elif t == "local_function_statement":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                functions.append(FuncDef(
                    name=fname,
                    class_name="",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1))
                fn_ranges.append((node.start_byte, node.end_byte, fname))
        elif t == "invocation_expression":
            receiver, method = _cs_invocation_parts(node)
            if method:
                line = node.start_point[0] + 1
                scope = _scope_at(node.start_byte, fn_ranges)
                calls.append((
                    line, receiver, method,
                    scope,
                    _snippet_at(src, node)))
                call_args.append(CallArgFact(
                    function_qnode=scope,
                    line=line,
                    callee_name=method,
                    receiver=receiver,
                    arg_symbols=_cs_identifier_args(node),
                    target_symbol=_cs_call_target(node),
                ))
        elif t == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                cls = _text_of(src, type_node).split(".")[-1].strip()
                if cls:
                    line = node.start_point[0] + 1
                    scope = _scope_at(node.start_byte, fn_ranges)
                    calls.append((
                        line, "", cls,
                        scope,
                        _snippet_at(src, node)))
                    call_args.append(CallArgFact(
                        function_qnode=scope,
                        line=line,
                        callee_name=cls,
                        receiver="",
                        arg_symbols=_cs_identifier_args(node),
                        target_symbol=_cs_call_target(node),
                    ))
        elif t in ("assignment_expression", "simple_assignment_expression"):
            dst, src_symbol, src_call = _cs_assignment_parts(node)
            if dst is not None and (src_symbol is not None or src_call is not None):
                assigns.append(VarAssignFact(
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    dst_symbol=dst,
                    src_symbol=src_symbol,
                    src_call=src_call,
                ))
        elif t == "variable_declarator":
            name_node = node.child_by_field_name("name")
            # C# grammar: variable_declarator has a 'name' field but no 'value'
            # field — the initialiser is an unnamed child after '='.  Walk
            # named_children to find the first child that is not the name.
            value_node = node.child_by_field_name("value")
            if value_node is None and name_node is not None:
                for _vc in node.named_children:
                    if _vc is not name_node:
                        value_node = _vc
                        break
            if name_node is not None and name_node.type == "identifier" and value_node is not None:
                src_symbol: str | None = None
                src_call: str | None = None
                if value_node.type == "identifier":
                    src_symbol = _text_of(src, value_node)
                elif value_node.type == "invocation_expression":
                    _recv, method = _cs_invocation_parts(value_node)
                    src_call = method or None
                elif value_node.type == "object_creation_expression":
                    type_node = value_node.child_by_field_name("type")
                    if type_node is not None:
                        src_call = _text_of(src, type_node).split(".")[-1].strip() or None
                if src_symbol is not None or src_call is not None:
                    assigns.append(VarAssignFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        dst_symbol=_text_of(src, name_node),
                        src_symbol=src_symbol,
                        src_call=src_call,
                    ))
        elif t == "return_statement":
            returns.append(ReturnFact(
                function_qnode=_scope_at(node.start_byte, fn_ranges),
                line=node.start_point[0] + 1,
                symbol=_cs_return_identifier(node),
            ))
        for c in node.children:
            _visit(c)

    _visit(root)
    return imports, functions, calls, assigns, returns, call_args


LANG_PLUGINS: dict[str, LangPlugin] = {
    "python":     LangPlugin(ts_language="python",     extract=_py_extract),
    "java":       LangPlugin(ts_language="java",       extract=_java_extract),
    "javascript": LangPlugin(ts_language="javascript", extract=_js_extract),
    "typescript": LangPlugin(ts_language="typescript", extract=_js_extract),
    "go":         LangPlugin(ts_language="go",         extract=_go_extract),
    "csharp":     LangPlugin(ts_language="csharp",     extract=_cs_extract),
}


_REFLECTION_FACT_EXTRACTORS: dict[str, Callable[[bytes, "object"], list[ReflectionFact]]] = {
    "python": _py_extract_reflection_facts,
    "java": _java_extract_reflection_facts,
    "csharp": _cs_extract_reflection_facts,
}


_FRAMEWORK_MARKER_EXTRACTORS: dict[
    str,
    "Callable[[bytes, object], tuple[list[FrameworkMarkerFact], list[RouteTaintFact]]]",
] = {
    "python": _py_extract_framework_markers,
    "java": _java_extract_framework_markers,
    "csharp": _cs_extract_framework_markers,
}


_RESPONSE_DATAFLOW_EXTRACTORS: dict[
    str,
    "Callable[[bytes, object], list[ResponseDataflowFact]]",
] = {
    "python": _py_extract_response_dataflow,
    "java": _java_extract_response_dataflow,
    "csharp": _cs_extract_response_dataflow,
}


def _semantic_sink_override(language: str,
                            receiver: str,
                            method: str,
                            snippet: str) -> tuple[str, str, str, tuple[str, ...]] | None:
    """Repo-agnostic semantic sink detection (Iteration B).

    This covers framework response-render paths that are not always captured by
    API-call signature rules.
    """
    low = (snippet or "").lower()
    m = (method or "").lower()
    r = (receiver or "").lower()

    if language == "python":
        if m in {"response", "htmlresponse", "httpresponse", "render_template", "templateresponse"}:
            if "html" in low and ("{" in snippet or ".format(" in low or "+" in snippet):
                return (
                    "xss",
                    "CWE-79",
                    "html-response",
                    ("A03:2025-Injection",),
                )
            if m in {"render_template", "templateresponse"}:
                return (
                    "xss",
                    "CWE-79",
                    "html-response",
                    ("A03:2025-Injection",),
                )

    if language == "java":
        if m in {"print", "println", "write"} and (
                r in {"response", "writer", "out"}
                or "httpservletresponse" in low):
            if "<" in snippet or "format(" in low or "+" in snippet:
                return (
                    "xss",
                    "CWE-79",
                    "html-response",
                    ("A03:2025-Injection",),
                )

    return None


# ── matching ────────────────────────────────────────────────────────────────

def _match_call(receiver: str, method: str, imports: dict[str, str],
                specs: list[MatchSpec], language: str) -> MatchSpec | None:
    """Return the first spec whose fingerprint matches this call. `receiver`
    is "" for bare-name calls."""
    resolved = imports.get(receiver, "") if receiver else ""
    for spec in specs:
        if language not in spec.languages:
            continue
        # ── qualified match (codeql / fsb) ─────────────────────────────
        if spec.has_qualified():
            if spec.is_constructor:
                # Constructor call: in Python, `Foo(...)` is the ctor.
                if receiver == "" and method in spec.methods:
                    if imports.get(method, "").startswith(spec.package):
                        return spec
                continue
            if method not in spec.methods:
                continue
            # Receiver's resolved import must live under the modeled package.
            if not resolved:
                continue
            if resolved.startswith(spec.package + ".") or resolved == spec.package:
                return spec
            # Gap 1 recall guard: when we only have a narrowed class tail,
            # accept `...<ClassName>` for JVM-style qualified rules.
            if language in {"java", "csharp", "kotlin", "scala"}:
                cls_tail = spec.class_name.split(".")[-1] if spec.class_name else ""
                if cls_tail and (resolved == cls_tail or resolved.endswith("." + cls_tail)):
                    return spec
            # Handle `from java.sql import Statement; s = Statement(); s.executeQuery(...)`
            # — the receiver is a variable, not an import. For MVP skip this
            # case (requires type inference).
            continue
        # ── module_attr match (semgrep-lifted) ─────────────────────────
        if spec.has_module_attr():
            if method not in spec.module_attr_names:
                continue
            if receiver == spec.module_attr_module:
                return spec
            if (resolved == spec.module_attr_module
                    or resolved.startswith(spec.module_attr_module + ".")
                    or resolved.endswith("." + spec.module_attr_module)):
                return spec
    return None


def _build_spec_index(specs: list[MatchSpec]) -> dict[str, dict[str, list[MatchSpec]]]:
    """Build language -> method -> specs index once per scan.

    Includes fallback buckets:
    - language "*" for specs that do not declare languages
    - method "*" for specs that do not declare methods
    """
    idx: dict[str, dict[str, list[MatchSpec]]] = defaultdict(lambda: defaultdict(list))
    for spec in specs:
        langs = list(spec.languages) if spec.languages else ["*"]
        if spec.methods:
            methods = list(spec.methods)
        elif spec.module_attr_names:
            methods = list(spec.module_attr_names)
        else:
            methods = ["*"]
        for lang in langs:
            for method in methods:
                idx[lang][method].append(spec)
    return idx


# ── Field/container fact extractors ────────────────────────────────────────
# Each function takes (src, tree) and returns
# (field_writes, field_reads, container_writes).  They do a separate tree
# walk so the LangPlugin 6-tuple return signature stays unchanged.


def _py_extract_field_facts(
    src: bytes, tree
) -> tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]:
    """Python-specific extraction of FieldWriteFact, FieldReadFact, ContainerWriteFact."""
    root = tree.root_node
    field_writes: list[FieldWriteFact] = []
    field_reads: list[FieldReadFact] = []
    container_writes: list[ContainerWriteFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_ranges(node):
        if node.type == "function_definition":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _py_text(n, src)))
        for c in node.children:
            _collect_ranges(c)

    _collect_ranges(root)

    def _visit(node):
        t = node.type
        if t == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)

            # FieldWriteFact: self.x = val  (LHS is attribute node)
            if left is not None and left.type == "attribute":
                obj = left.child_by_field_name("object")
                attr = left.child_by_field_name("attribute")
                recv = _py_text(obj, src) if obj is not None else ""
                fname = _py_text(attr, src) if attr is not None else ""
                if recv and fname:
                    src_sym = (
                        _py_text(right, src)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    field_writes.append(FieldWriteFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

            # ContainerWriteFact: d[k] = x  (LHS is subscript node)
            elif left is not None and left.type == "subscript":
                val_node = left.child_by_field_name("value")
                container = (
                    _py_text(val_node, src)
                    if val_node is not None and val_node.type == "identifier"
                    else ""
                )
                if container:
                    elem = (
                        _py_text(right, src)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    container_writes.append(ContainerWriteFact(
                        function_qnode=scope, line=line,
                        container_symbol=container, element_symbol=elem,
                    ))

            # FieldReadFact: x = self.y  (RHS is attribute node)
            if right is not None and right.type == "attribute":
                obj = right.child_by_field_name("object")
                attr = right.child_by_field_name("attribute")
                recv = _py_text(obj, src) if obj is not None else ""
                fname = _py_text(attr, src) if attr is not None else ""
                if recv and fname:
                    dst = (
                        _py_text(left, src)
                        if left is not None and left.type == "identifier"
                        else None
                    )
                    field_reads.append(FieldReadFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, dst_symbol=dst,
                    ))

        elif t == "augmented_assignment":
            # self.x += tainted  →  FieldWriteFact
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "attribute":
                obj = left.child_by_field_name("object")
                attr = left.child_by_field_name("attribute")
                recv = _py_text(obj, src) if obj is not None else ""
                fname = _py_text(attr, src) if attr is not None else ""
                if recv and fname:
                    src_sym = (
                        _py_text(right, src)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    field_writes.append(FieldWriteFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

        elif t == "call":
            # ContainerWriteFact: container.append(x) / container.add(x)
            fn_node = node.child_by_field_name("function")
            if fn_node is not None and fn_node.type == "attribute":
                method_node = fn_node.child_by_field_name("attribute")
                obj_node = fn_node.child_by_field_name("object")
                method = _py_text(method_node, src) if method_node is not None else ""
                if (
                    method in ("append", "add")
                    and obj_node is not None
                    and obj_node.type == "identifier"
                ):
                    container = _py_text(obj_node, src)
                    args_node = node.child_by_field_name("arguments")
                    elem: str | None = None
                    if args_node is not None:
                        for _a in args_node.named_children:
                            if _a.type == "identifier":
                                elem = _py_text(_a, src)
                            break
                    container_writes.append(ContainerWriteFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        container_symbol=container,
                        element_symbol=elem,
                    ))

        for c in node.children:
            _visit(c)

    _visit(root)
    return field_writes, field_reads, container_writes


def _java_extract_field_facts(
    src: bytes, tree
) -> tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]:
    """Java-specific extraction of FieldWriteFact, FieldReadFact, ContainerWriteFact."""
    root = tree.root_node
    field_writes: list[FieldWriteFact] = []
    field_reads: list[FieldReadFact] = []
    container_writes: list[ContainerWriteFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_ranges(node):
        if node.type in ("method_declaration", "constructor_declaration"):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_ranges(c)

    _collect_ranges(root)

    def _assign_target_of(node) -> str | None:
        """LHS identifier name if node is directly assigned."""
        parent = node.parent
        if parent is None:
            return None
        if parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            right = parent.child_by_field_name("right")
            if right is node and left is not None and left.type == "identifier":
                return _text_of(src, left)
        if parent.type == "variable_declarator":
            val = parent.child_by_field_name("value")
            name = parent.child_by_field_name("name")
            if val is node and name is not None and name.type == "identifier":
                return _text_of(src, name)
        return None

    def _visit(node):
        t = node.type
        if t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)

            # FieldWriteFact: obj.field = val  (LHS is field_access)
            if left is not None and left.type == "field_access":
                obj = left.child_by_field_name("object")
                fld = left.child_by_field_name("field")
                recv = _text_of(src, obj) if obj is not None else ""
                fname = _text_of(src, fld) if fld is not None else ""
                if recv and fname:
                    src_sym = (
                        _text_of(src, right)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    field_writes.append(FieldWriteFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

            # FieldReadFact: x = obj.field  (RHS is field_access)
            if right is not None and right.type == "field_access":
                obj = right.child_by_field_name("object")
                fld = right.child_by_field_name("field")
                recv = _text_of(src, obj) if obj is not None else ""
                fname = _text_of(src, fld) if fld is not None else ""
                if recv and fname:
                    dst = (
                        _text_of(src, left)
                        if left is not None and left.type == "identifier"
                        else None
                    )
                    field_reads.append(FieldReadFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, dst_symbol=dst,
                    ))

        elif t == "local_variable_declaration":
            # FieldReadFact: Type x = obj.field
            scope = _scope_at(node.start_byte, fn_ranges)
            line = node.start_point[0] + 1
            for c in node.children:
                if c.type == "variable_declarator":
                    name_n = c.child_by_field_name("name")
                    val_n = c.child_by_field_name("value")
                    if name_n is not None and val_n is not None and val_n.type == "field_access":
                        obj = val_n.child_by_field_name("object")
                        fld = val_n.child_by_field_name("field")
                        recv = _text_of(src, obj) if obj is not None else ""
                        fname = _text_of(src, fld) if fld is not None else ""
                        if recv and fname:
                            field_reads.append(FieldReadFact(
                                function_qnode=scope, line=line,
                                receiver=recv, field=fname,
                                dst_symbol=_text_of(src, name_n),
                            ))

        elif t == "method_invocation":
            name_n = node.child_by_field_name("name")
            obj_n = node.child_by_field_name("object")
            method = _text_of(src, name_n) if name_n is not None else ""
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)

            # ContainerWriteFact: list.add(x) / map.put(k, v)
            if method in ("add", "put") and obj_n is not None:
                recv = _java_leftmost(obj_n, src)
                if recv:
                    args_n = node.child_by_field_name("arguments")
                    elem: str | None = None
                    if args_n is not None:
                        for _a in args_n.named_children:
                            if _a.type == "identifier":
                                elem = _text_of(src, _a)
                                break
                    container_writes.append(ContainerWriteFact(
                        function_qnode=scope, line=line,
                        container_symbol=recv, element_symbol=elem,
                    ))

            # Setter convention: obj.setField(val)  →  FieldWriteFact
            elif re.match(r"^set[A-Z]", method) and obj_n is not None:
                recv = _java_leftmost(obj_n, src)
                fname = method[3].lower() + method[4:] if len(method) > 3 else ""
                if recv and fname:
                    args_n = node.child_by_field_name("arguments")
                    src_sym: str | None = None
                    if args_n is not None:
                        for _a in args_n.named_children:
                            if _a.type == "identifier":
                                src_sym = _text_of(src, _a)
                                break
                    field_writes.append(FieldWriteFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

            # Getter convention: obj.getField()  →  FieldReadFact
            elif re.match(r"^get[A-Z]", method) and obj_n is not None:
                recv = _java_leftmost(obj_n, src)
                fname = method[3].lower() + method[4:] if len(method) > 3 else ""
                args_n = node.child_by_field_name("arguments")
                zero_args = args_n is None or len(args_n.named_children) == 0
                if recv and fname and zero_args:
                    field_reads.append(FieldReadFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname,
                        dst_symbol=_assign_target_of(node),
                    ))

        for c in node.children:
            _visit(c)

    _visit(root)
    return field_writes, field_reads, container_writes


def _cs_extract_field_facts(
    src: bytes, tree
) -> tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]:
    """C#-specific extraction of FieldWriteFact, FieldReadFact, ContainerWriteFact."""
    root = tree.root_node
    field_writes: list[FieldWriteFact] = []
    field_reads: list[FieldReadFact] = []
    container_writes: list[ContainerWriteFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_ranges(node):
        if node.type in (
            "method_declaration",
            "constructor_declaration",
            "local_function_statement",
        ):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_ranges(c)

    _collect_ranges(root)

    def _mae_parts(node) -> tuple[str, str]:
        """(receiver, field_name) from a member_access_expression."""
        expr = node.child_by_field_name("expression")
        name = node.child_by_field_name("name")
        recv = _cs_leftmost(expr, src) if expr is not None else ""
        fname = _text_of(src, name) if name is not None else ""
        return recv, fname

    def _visit(node):
        t = node.type
        if t in ("assignment_expression", "simple_assignment_expression"):
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)

            # FieldWriteFact: obj.Field = val  (LHS is member_access_expression)
            if left is not None and left.type == "member_access_expression":
                recv, fname = _mae_parts(left)
                if recv and fname:
                    src_sym = (
                        _text_of(src, right)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    field_writes.append(FieldWriteFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

            # ContainerWriteFact: container[key] = val  (LHS is element_access_expression)
            elif left is not None and left.type == "element_access_expression":
                expr = left.child_by_field_name("expression")
                container = (
                    _text_of(src, expr)
                    if expr is not None and expr.type == "identifier"
                    else ""
                )
                if container:
                    elem = (
                        _text_of(src, right)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    container_writes.append(ContainerWriteFact(
                        function_qnode=scope, line=line,
                        container_symbol=container, element_symbol=elem,
                    ))

            # FieldReadFact: x = obj.Field  (RHS is member_access_expression)
            if right is not None and right.type == "member_access_expression":
                recv, fname = _mae_parts(right)
                if recv and fname:
                    dst = (
                        _text_of(src, left)
                        if left is not None and left.type == "identifier"
                        else None
                    )
                    field_reads.append(FieldReadFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, dst_symbol=dst,
                    ))

        elif t == "variable_declarator":
            # Type x = obj.Field;  (initialiser may be inside equals_value_clause)
            name_n = node.child_by_field_name("name")
            val_n: object = None
            for _vc in node.named_children:
                if _vc is not name_n:
                    if _vc.type == "equals_value_clause":
                        for _gvc in _vc.named_children:
                            val_n = _gvc
                            break
                    else:
                        val_n = _vc
                    break
            if (
                name_n is not None
                and val_n is not None
                and val_n.type == "member_access_expression"
            ):
                recv, fname = _mae_parts(val_n)
                if recv and fname:
                    field_reads.append(FieldReadFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        receiver=recv, field=fname,
                        dst_symbol=(
                            _text_of(src, name_n)
                            if name_n.type == "identifier"
                            else None
                        ),
                    ))

        elif t == "invocation_expression":
            fn_n = node.child_by_field_name("function")
            if fn_n is not None and fn_n.type == "member_access_expression":
                name_n = fn_n.child_by_field_name("name")
                method = _text_of(src, name_n) if name_n is not None else ""
                # ContainerWriteFact: container.Add(x)
                if method == "Add":
                    expr = fn_n.child_by_field_name("expression")
                    container = _cs_leftmost(expr, src) if expr is not None else ""
                    if container:
                        args_n = node.child_by_field_name("arguments")
                        elem: str | None = None
                        if args_n is not None:
                            for _a in args_n.named_children:
                                if _a.type == "identifier":
                                    elem = _text_of(src, _a)
                                    break
                                if _a.type == "argument":
                                    e = _a.child_by_field_name("expression")
                                    if e is not None and e.type == "identifier":
                                        elem = _text_of(src, e)
                                    break
                        container_writes.append(ContainerWriteFact(
                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                            line=node.start_point[0] + 1,
                            container_symbol=container,
                            element_symbol=elem,
                        ))

        for c in node.children:
            _visit(c)

    _visit(root)
    return field_writes, field_reads, container_writes


_FIELD_FACT_EXTRACTORS: dict[
    str,
    "Callable[[bytes, object], tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]]",
] = {
    "python": _py_extract_field_facts,
    "java": _java_extract_field_facts,
    "csharp": _cs_extract_field_facts,
}


# ── public scan_file ────────────────────────────────────────────────────────

def scan_file(abs_path: Path, rel: str, language: str,
              source_specs: list[MatchSpec],
              sink_specs:   list[MatchSpec],
              collect_observed: bool = False,
              source_index: dict[str, dict[str, list[MatchSpec]]] | None = None,
              sink_index: dict[str, dict[str, list[MatchSpec]]] | None = None) -> FileIndex | None:
    plugin = LANG_PLUGINS.get(language)
    if not plugin:
        return None
    if get_parser is None:
        print(
            f"  [s0/callgraph] tree-sitter backend unavailable ({_TS_ERR}); "
            "re-run 'pip install .' (or 'pipx install .') and then "
            "'vvaharness doctor' to verify dependencies",
            file=sys.stderr,
        )
        return None
    try:
        src = abs_path.read_bytes()
    except OSError:
        return None
    if not src:
        return None
    parser = _get_cached_parser(plugin.ts_language)  # Iteration F: use cached parser
    tree = parser.parse(src)
    imports, functions, calls, assigns, returns, call_args = plugin.extract(src, tree)
    idx = FileIndex(file=rel, language=language,
                    imports=imports, functions=functions,
                    assigns=assigns, returns=returns, call_args=call_args)
    # Populate field/container facts from a separate tree walk.
    _ff_extractor = _FIELD_FACT_EXTRACTORS.get(language)
    if _ff_extractor is not None:
        _fw, _fr, _cw = _ff_extractor(src, tree)
        idx.field_writes = _fw
        idx.field_reads = _fr
        idx.container_writes = _cw
    # CFG population is reserved for a future path-sensitive pass; the current
    # scanner deliberately leaves ``idx.cfgs`` empty rather than presenting a
    # one-block skeleton as control-flow analysis.
    for func_def in functions:
        cfg = _build_cfg_for_function(None, func_def.name, src)
        if cfg is not None:
            idx.cfgs[func_def.name] = cfg
    # Extract reflection facts (getattr, getMethod, invoke, etc.)
    _refl_extractor = _REFLECTION_FACT_EXTRACTORS.get(language)
    if _refl_extractor is not None:
        idx.reflection_facts = _refl_extractor(src, tree)
    # Extract framework markers, route facts, and response dataflow.
    _fm_extractor = _FRAMEWORK_MARKER_EXTRACTORS.get(language)
    if _fm_extractor is not None:
        idx.framework_markers, idx.route_facts = _fm_extractor(src, tree)
    _resp_extractor = _RESPONSE_DATAFLOW_EXTRACTORS.get(language)
    if _resp_extractor is not None:
        idx.response_dataflow = _resp_extractor(src, tree)
    for line, receiver, method, scope, snippet in calls:
        if source_index:
            src_lang = source_index.get(language, {})
            src_any = source_index.get("*", {})
            src_specs_lang = (
                src_lang.get(method, []) + src_lang.get("*", [])
                + src_any.get(method, []) + src_any.get("*", [])
            )
        else:
            src_specs_lang = source_specs
        if sink_index:
            snk_lang = sink_index.get(language, {})
            snk_any = sink_index.get("*", {})
            snk_specs_lang = (
                snk_lang.get(method, []) + snk_lang.get("*", [])
                + snk_any.get(method, []) + snk_any.get("*", [])
            )
        else:
            snk_specs_lang = sink_specs

        # Record the edge for BFS regardless of match status.
        idx.call_edges.append((scope, receiver, method))
        # Record full call fingerprint for annotator-style LLM mode.
        if collect_observed:
            idx.observed_calls.append(ObservedCall(
                file=rel,
                language=language,
                line=line,
                receiver=receiver,
                resolved_receiver=imports.get(receiver, ""),
                method=method,
                containing_fn=scope,
                snippet=snippet,
            ))
        src_spec = _match_call(receiver, method, imports, src_specs_lang, language)
        if src_spec:
            idx.source_hits.append(CallSite(
                file=rel, line=line, receiver=receiver, method=method,
                containing_fn=scope, snippet=snippet,
                matched_rule=src_spec.rule_id, cwe=src_spec.cwe,
                role="source", kind=src_spec.kind,
                semantic_family=src_spec.semantic_family,
                owasp_top10_2025=tuple(src_spec.owasp_top10_2025),
            ))
            # A call can be BOTH a source and a sink (rare but valid).
        snk_spec = _match_call(receiver, method, imports, snk_specs_lang, language)
        if snk_spec:
            idx.sink_hits.append(CallSite(
                file=rel, line=line, receiver=receiver, method=method,
                containing_fn=scope, snippet=snippet,
                matched_rule=snk_spec.rule_id, cwe=snk_spec.cwe,
                role="sink", kind=snk_spec.kind,
                semantic_family=snk_spec.semantic_family,
                owasp_top10_2025=tuple(snk_spec.owasp_top10_2025),
            ))
            continue

        # Iteration B semantic fallback: keep framework response sinks even if
        # the rule is not representable as module.attr signature.
        semantic = _semantic_sink_override(language, receiver, method, snippet)
        if semantic:
            sem_kind, sem_cwe, sem_family, sem_owasp = semantic
            idx.sink_hits.append(CallSite(
                file=rel, line=line, receiver=receiver, method=method,
                containing_fn=scope, snippet=snippet,
                matched_rule="vvah.semantic.sink",
                cwe=sem_cwe,
                role="sink",
                kind=sem_kind,
                semantic_family=sem_family,
                owasp_top10_2025=sem_owasp,
            ))
    return idx
