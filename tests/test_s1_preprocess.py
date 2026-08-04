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

"""Unit tests for the pure helpers in s1_preprocess.

These cover the deterministic, offline pieces: exclusion-set resolution,
the root-relative ``**`` glob predicate, config-shape dedup helpers, the
config-secret/insecure safety nets, and the call-graph qualification
helpers. No network, no LLM, no subprocess.
"""
from __future__ import annotations

import types

import pytest

from vvaharness.pipeline.stages import s1_preprocess as s1


# ─── tiny config doubles ──────────────────────────────────────────────────
def _step1(**kw):
    """A minimal stand-in for cfg.step1 — only attributes accessed via
    getattr(..., None) matter, so a SimpleNamespace is enough."""
    return types.SimpleNamespace(**kw)


def _cfg(step1):
    return types.SimpleNamespace(step1=step1)


# ─── _exclusion_sets ──────────────────────────────────────────────────────
def test_exclusion_sets_defaults_present_and_lowercased():
    dirs, exts, globs = s1._exclusion_sets(_cfg(_step1()))
    # built-in dirs are lower-cased
    assert "node_modules" in dirs
    assert "tests" in dirs
    assert "checkpoints" in dirs
    # built-in exts and globs survive
    assert ".png" in exts
    assert "**/test_*.py" in globs
    assert "**/LICENSE" in globs
    # spec/specs intentionally NOT excluded as a dir
    assert "spec" not in dirs
    assert "specs" not in dirs


def test_exclusion_sets_appends_config_values_and_lowercases_dirs():
    step1 = _step1(
        exclude_dirs=["MyVendorDir"],
        exclude_exts=[".weird"],
        exclude_globs=["**/*.custom"],
    )
    dirs, exts, globs = s1._exclusion_sets(_cfg(step1))
    # user dir is lower-cased and unioned with defaults
    assert "myvendordir" in dirs
    assert "node_modules" in dirs
    assert ".weird" in exts
    assert ".png" in exts
    # user globs are appended (defaults still first)
    assert globs[0] == s1._DEFAULT_EXCLUDE_GLOBS[0]
    assert "**/*.custom" in globs


def test_exclusion_sets_none_config_is_safe():
    # exclude_* explicitly None must not blow up (the `or []` guards it)
    step1 = _step1(exclude_dirs=None, exclude_exts=None, exclude_globs=None)
    dirs, exts, globs = s1._exclusion_sets(_cfg(step1))
    assert dirs == {d.lower() for d in s1._DEFAULT_EXCLUDE_DIRS}
    assert exts == s1._DEFAULT_EXCLUDE_EXTS
    assert globs == list(s1._DEFAULT_EXCLUDE_GLOBS)


# ─── glob_hit ─────────────────────────────────────────────────────────────
def test_glob_hit_matches_nested_path():
    globs = ["**/test_*.py"]
    assert s1.glob_hit("pkg/sub/test_foo.py", globs) == "**/test_*.py"


def test_glob_hit_matches_root_file_via_double_star():
    # The whole point of the helper: a ROOT-level file must also match a
    # `**/x` pattern even though fnmatch's `**` normally requires a slash.
    globs = ["**/LICENSE"]
    assert s1.glob_hit("LICENSE", globs) == "**/LICENSE"


def test_glob_hit_root_test_file_excluded():
    globs = list(s1._DEFAULT_EXCLUDE_GLOBS)
    assert s1.glob_hit("test_main.py", globs) == "**/test_*.py"


def test_glob_hit_no_match_returns_none():
    globs = ["**/test_*.py", "**/LICENSE"]
    assert s1.glob_hit("src/app/handler.py", globs) is None


def test_glob_hit_returns_first_matching_glob():
    # Both could conceptually match a name; the first in iteration order wins.
    globs = ["**/*.spec.ts", "**/handler.ts"]
    assert s1.glob_hit("a/b/handler.ts", globs) == "**/handler.ts"


def test_glob_hit_direct_pattern_without_double_star():
    # A bare (non-`**/`) pattern matches via full-path fnmatch. Note fnmatch's
    # `*` is NOT path-segment-aware, so it spans `/` too.
    globs = ["src/*.py"]
    assert s1.glob_hit("src/main.py", globs) == "src/*.py"
    # A path that does not share the `src/...py` shape is not matched.
    assert s1.glob_hit("lib/main.py", globs) is None


# ─── _norm_rel ────────────────────────────────────────────────────────────
def test_norm_rel_strips_backslashes_and_dot_slash():
    assert s1._norm_rel("repo", "./a\\b/c.py") == "a/b/c.py"


def test_norm_rel_strips_repo_root_prefix():
    assert s1._norm_rel("myrepo", "myrepo/src/app.py") == "src/app.py"


def test_norm_rel_passthrough_when_no_prefix():
    assert s1._norm_rel("myrepo", "other/app.py") == "other/app.py"


def test_norm_rel_empty():
    assert s1._norm_rel("repo", "") == ""


# ─── _resolve_scope_path (collision-aware in-scope resolution) ──────────────
# repo_root="app" with two repos sharing src/config.py; only repo-a has util.py.
_KEEP = {"repo-a/src/config.py", "repo-b/src/config.py", "repo-a/src/util.py"}
_TOPS = ["repo-a", "repo-b"]


def test_resolve_exact_prefixed_hit():
    # A correctly-qualified path resolves directly, never touching the fallback.
    assert s1._resolve_scope_path("repo-b/src/config.py", "app", _KEEP, _TOPS) \
        == ("repo-b/src/config.py", False)


def test_resolve_unprefixed_unique_match():
    # Exists under exactly ONE top dir -> resolved, not ambiguous.
    assert s1._resolve_scope_path("src/util.py", "app", _KEEP, _TOPS) \
        == ("repo-a/src/util.py", False)


def test_resolve_unprefixed_ambiguous_is_dropped_not_guessed():
    # Exists under BOTH repos -> must NOT bind to the alphabetically-first repo.
    hit, amb = s1._resolve_scope_path("src/config.py", "app", _KEEP, _TOPS)
    assert hit is None and amb is True
    assert hit != "repo-a/src/config.py"     # the old silent-first-match bug


def test_resolve_no_match():
    assert s1._resolve_scope_path("src/missing.py", "app", _KEEP, _TOPS) \
        == (None, False)


def test_resolve_single_repo_top_dir_ambiguity():
    # Same defect/fix in single-repo mode: bare name under src/ AND lib/.
    keep = {"src/config.py", "lib/config.py", "src/only.py"}
    tops = ["lib", "src"]
    assert s1._resolve_scope_path("config.py", "repo", keep, tops) == (None, True)
    assert s1._resolve_scope_path("only.py", "repo", keep, tops) \
        == ("src/only.py", False)


# ─── _flatten_keys ────────────────────────────────────────────────────────
def test_flatten_keys_nested_dict():
    obj = {"a": {"b": 1, "c": 2}, "d": 3}
    assert set(s1._flatten_keys(obj)) == {"a.b", "a.c", "d"}


def test_flatten_keys_list_uses_bracket_marker():
    obj = {"items": [{"x": 1}, {"y": 2}]}
    keys = set(s1._flatten_keys(obj))
    assert keys == {"items[].x", "items[].y"}


def test_flatten_keys_scalar_returns_prefix():
    assert s1._flatten_keys("scalar", prefix="root") == ["root"]


# ─── _shape_hash ──────────────────────────────────────────────────────────
def test_shape_hash_same_yaml_shape_different_values_equal():
    a = "host: prod.example.com\nport: 443\n"
    b = "host: stage.example.test\nport: 8080\n"
    ha = s1._shape_hash(a, ".yaml")
    hb = s1._shape_hash(b, ".yaml")
    assert ha is not None and ha == hb


def test_shape_hash_different_keys_differ():
    a = "host: x\nport: 1\n"
    b = "host: x\ntimeout: 1\n"
    assert s1._shape_hash(a, ".yaml") != s1._shape_hash(b, ".yaml")


def test_shape_hash_json_value_insensitive():
    a = '{"a": {"b": 1}}'
    b = '{"a": {"b": 999}}'
    ha = s1._shape_hash(a, ".json")
    assert ha is not None
    assert ha == s1._shape_hash(b, ".json")


def test_shape_hash_invalid_json_returns_none():
    assert s1._shape_hash("{not valid json", ".json") is None


def test_shape_hash_empty_returns_none():
    assert s1._shape_hash("", ".yaml") is None


def test_shape_hash_ini_sections():
    text = "[server]\nhost = a\nport = 1\n"
    h = s1._shape_hash(text, ".ini")
    assert h is not None
    # same structure, different values -> same hash
    text2 = "[server]\nhost = z\nport = 9\n"
    assert h == s1._shape_hash(text2, ".ini")


def test_shape_hash_env_kv_lines():
    a = "FOO=1\nBAR=two\n"
    b = "FOO=9\nBAR=other\n"
    ha = s1._shape_hash(a, ".env")
    assert ha is not None and ha == s1._shape_hash(b, ".env")


# ─── gap_fill escalation policy ──────────────────────────────────────────
def _seed(ep_count: int, sink_count: int, *, kind: str = "network"):
    eps = [types.SimpleNamespace(kind=kind, reachable_from_unauth=False)
           for _ in range(ep_count)]
    sinks = [types.SimpleNamespace() for _ in range(sink_count)]
    return types.SimpleNamespace(entry_points=eps, unsafe_sinks=sinks)


def test_should_escalate_gap_fill_for_large_web_api_with_sparse_sinks():
    files = [f"src/f{i}.py" for i in range(501)]
    escalate, reason = s1._should_escalate_gap_fill(_seed(10, 4), files)
    assert escalate is True
    assert "source_files=501" in reason
    assert "entry_points=10" in reason
    assert "sinks=4" in reason


def test_should_not_escalate_gap_fill_when_sinks_are_sufficient():
    files = [f"src/f{i}.py" for i in range(700)]
    escalate, reason = s1._should_escalate_gap_fill(_seed(12, 5), files)
    assert escalate is False
    assert reason == "sinks=5 >= 5"


def test_should_not_escalate_gap_fill_for_small_repo():
    files = [f"src/f{i}.py" for i in range(500)]
    escalate, reason = s1._should_escalate_gap_fill(_seed(20, 0), files)
    assert escalate is False
    assert reason == "source_files=500 <= 500"


def test_should_not_escalate_gap_fill_for_library_repo():
    files = [f"src/f{i}.py" for i in range(800)]
    escalate, reason = s1._should_escalate_gap_fill(_seed(20, 0, kind="file"), files)
    assert escalate is False
    assert reason == "repo_kind=['library']"


# ─── _suspicious_set (security-relevant: secrets never silently dropped) ───
def test_suspicious_set_detects_literal_password():
    text = "password: hunter2supersecret\n"
    hits = s1._suspicious_set(text, want_secret=True, want_insecure=False)
    assert any(h.startswith("secret:") for h in hits)


def test_suspicious_set_skips_templated_secret():
    # ${VAR} / {{var}} / vault: references are NOT real credential material.
    for templated in (
        "password: ${DB_PASS}\n",
        "password: {{db_pass}}\n",
        "password: vault:secret/data/db\n",
    ):
        hits = s1._suspicious_set(templated, want_secret=True, want_insecure=False)
        assert not any(h.startswith("secret:") for h in hits), templated


def test_suspicious_set_detects_aws_access_key():
    text = "key = AKIAIOSFODNN7EXAMPLE\n"
    hits = s1._suspicious_set(text, want_secret=True, want_insecure=False)
    assert any(h.startswith("secret:") for h in hits)


def test_suspicious_set_detects_insecure_value():
    text = "ssl_verify: false\n"
    hits = s1._suspicious_set(text, want_secret=False, want_insecure=True)
    assert any(h.startswith("insecure:") for h in hits)


def test_suspicious_set_respects_flags():
    text = "password: hunter2supersecret\nssl_verify: false\n"
    # both off -> nothing
    assert s1._suspicious_set(text, want_secret=False, want_insecure=False) == set()
    # only secret
    only_sec = s1._suspicious_set(text, want_secret=True, want_insecure=False)
    assert only_sec and all(h.startswith("secret:") for h in only_sec)


# ─── _rep_score (prod > cert/stage > perf/qa > other; bigger file wins) ────
def test_rep_score_prod_beats_other():
    prod = s1._rep_score("svc/prod/config.yml", 100)
    other = s1._rep_score("svc/dev/config.yml", 100)
    assert prod < other  # lower tuple sorts first => chosen as representative


def test_rep_score_stage_between_prod_and_other():
    prod = s1._rep_score("svc/prod/c.yml", 10)
    stage = s1._rep_score("svc/staging/c.yml", 10)
    other = s1._rep_score("svc/dev/c.yml", 10)
    assert prod < stage < other


def test_rep_score_larger_file_preferred_within_same_env():
    big = s1._rep_score("svc/prod/c.yml", 5000)
    small = s1._rep_score("svc/prod/c.yml", 10)
    assert big < small  # -size makes larger sort first


# ─── q_join / q_split / q_name / q_file ────────────────────────────────────
def test_q_join_and_split_roundtrip():
    q = s1.q_join("a/b/File.java", "method")
    assert q == "a/b/File.java::method"
    assert s1.q_split(q) == ("a/b/File.java", "method")
    assert s1.q_file(q) == "a/b/File.java"
    assert s1.q_name(q) == "method"


def test_q_split_unqualified_name():
    assert s1.q_split("bareName") == ("", "bareName")
    assert s1.q_file("bareName") == ""
    assert s1.q_name("bareName") == "bareName"


def test_q_split_uses_rpartition_last_sep():
    # File path itself contains no QSEP, but ensure rpartition picks last sep.
    q = "pkg::sub::fn"
    assert s1.q_split(q) == ("pkg::sub", "fn")


# ─── _resolve_callee_files ─────────────────────────────────────────────────
def test_resolve_callee_prefers_same_file():
    def_files = {"foo": {"a/x.py", "b/y.py"}}
    out = s1._resolve_callee_files("foo", "a/x.py", def_files, max_targets=3)
    assert out == ["a/x.py"]


def test_resolve_callee_unique_def():
    def_files = {"foo": {"only/here.py"}}
    out = s1._resolve_callee_files("foo", "elsewhere/z.py", def_files, max_targets=3)
    assert out == ["only/here.py"]


def test_resolve_callee_unknown_name_empty():
    assert s1._resolve_callee_files("nope", "a/x.py", {}, max_targets=3) == []


def test_resolve_callee_prefix_scoring_and_cap():
    def_files = {
        "foo": {"a/b/c/x.py", "a/b/q/y.py", "z/w.py"},
    }
    out = s1._resolve_callee_files("foo", "a/b/c/caller.py", def_files, max_targets=2)
    # longest shared dir prefix wins; capped at max_targets
    assert len(out) == 2
    assert out[0] == "a/b/c/x.py"


def test_resolve_callee_prefers_import_aware_match_over_proximity():
    def_files = {
        "validate": {
            "pkg/sub/services.py",          # correct import target
            "pkg/sub/nearby/validate.py",   # closer but wrong
            "pkg/other/validate.py",
        },
    }
    caller_imports = {"validate": "pkg.sub.services"}
    out = s1._resolve_callee_files(
        "validate",
        "pkg/sub/handler.py",
        def_files,
        max_targets=3,
        caller_imports=caller_imports,
    )
    assert out[0] == "pkg/sub/services.py"


def test_scan_imports_python_ast_handles_multiline_alias_and_relative():
    lines = [
        "from .services import (",
        "    validate as v,",
        ")",
        "from ..common import sanitize",
        "import os.path as osp",
    ]
    got = s1._scan_imports(lines, ".py", "pkg/sub/handler.py")
    # Relative imports resolve against caller package path.
    assert got["v"] == "pkg.sub.services"
    assert got["sanitize"] == "pkg.common"
    assert got["osp"] == "os.path"


def test_file_matches_import_python_init_package():
    assert s1._file_matches_import("pkg/sub/__init__.py", "pkg.sub", ".py")


# ─── _scan_defs ────────────────────────────────────────────────────────────
def test_scan_defs_python_function():
    lines = ["import os", "def handler(req):", "    pass"]
    assert s1._scan_defs(lines) == [(2, "handler")]


def test_scan_defs_async_python():
    lines = ["async def fetch(x):", "    return x"]
    assert s1._scan_defs(lines) == [(1, "fetch")]


def test_scan_defs_js_function_keyword():
    lines = ["export function doThing(a) {", "}"]
    assert s1._scan_defs(lines) == [(1, "doThing")]


def test_scan_defs_ignores_control_keywords():
    # `if (...)` / `for (...)` must not be mistaken for definitions.
    lines = ["if (x) {", "for (i=0; i<n; i++) {", "while (true) {"]
    assert s1._scan_defs(lines) == []


def test_scan_defs_go_func():
    lines = ["func Handler(w http.ResponseWriter) {"]
    assert s1._scan_defs(lines) == [(1, "Handler")]


def test_walk_repo_drops_offroot_symlink_keeps_intree(tmp_path):
    """A symlinked file whose target resolves OUTSIDE the repo is dropped
    (and recorded), while an in-tree symlink (e.g. a monorepo link) is kept —
    closing the off-host read without losing legitimate coverage."""
    from pathlib import Path
    secret = tmp_path / "secret.txt"          # lives OUTSIDE the repo
    secret.write_text("host-only data", encoding="utf-8")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    try:
        Path(repo / "link_in.py").symlink_to(repo / "a.py")     # in-tree → keep
        Path(repo / "link_out.txt").symlink_to(secret)          # off-root → drop
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")

    out, excluded = s1._walk_repo(str(repo), _cfg(_step1(max_file_kb=1024)))

    assert "a.py" in out
    assert "link_in.py" in out                 # in-tree symlink preserved
    assert "link_out.txt" not in out           # off-root symlink not scanned
    assert "link_out.txt" in (excluded.get("symlinks") or {})   # and audited


def test_walk_repo_offroot_symlink_dropped_even_with_follow_symlinks_true(tmp_path):
    """The off-root containment guard is UNCONDITIONAL: setting
    step1.follow_symlinks: true (e.g. via a shared/CI config) must NOT re-open
    host-file reads through a committed off-repo symlink. In-tree links are still
    followed. Regression guard for the disclosure path."""
    from pathlib import Path
    secret = tmp_path / "secret.txt"           # lives OUTSIDE the repo
    secret.write_text("host-only data", encoding="utf-8")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    try:
        Path(repo / "link_in.py").symlink_to(repo / "a.py")     # in-tree → keep
        Path(repo / "link_out.txt").symlink_to(secret)          # off-root → drop
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")

    out, excluded = s1._walk_repo(
        str(repo), _cfg(_step1(max_file_kb=1024, follow_symlinks=True)))

    assert "a.py" in out
    assert "link_in.py" in out                 # in-tree symlink still followed
    assert "link_out.txt" not in out           # off-root STILL dropped despite flag
    assert "link_out.txt" in (excluded.get("symlinks") or {})   # and audited


# ─── F36 fix 1: S0 reuse gated on language coverage ───────────────────────
def test_seed_covered_languages_from_all_three_artifacts():
    data = {
        "def_spans": {"app.py::handle": [1, 5]},
        "call_graph": {"svc.go::Serve": ["db.go::Query"]},
        "call_graph_files": {"login": ["auth.java:12"]},
    }
    covered = s1._seed_covered_languages(data)
    assert covered == {"python", "go", "java"}
    # A language present only in the inventory (e.g. Ruby) is NOT covered, so
    # the dispatch would route its files through the residual rebuild.
    assert "ruby" not in covered


def test_seed_covered_languages_empty_when_no_artifacts():
    assert s1._seed_covered_languages({}) == set()


def test_merge_graph_artifacts_unions_without_dropping_residual():
    # data holds the residual (Ruby) rebuild; seed_* is S0's Python graph.
    data = {
        "call_graph": {"app.rb::handle": ["app.rb::render"]},
        "call_graph_files": {"handle": ["app.rb:3"]},
        "def_spans": {"app.rb::handle": [1, 9]},
    }
    seed_cg = {"svc.py::serve": ["svc.py::query"]}
    seed_cgf = {"handle": ["svc.py:20"]}      # bare-name collision across langs
    seed_spans = {"svc.py::serve": [4, 40]}

    s1._merge_graph_artifacts(data, seed_cg, seed_cgf, seed_spans)

    # both languages survive in the merged call graph
    assert data["call_graph"]["app.rb::handle"] == ["app.rb::render"]
    assert data["call_graph"]["svc.py::serve"] == ["svc.py::query"]
    # colliding bare name unions both def-sites rather than overwriting
    assert data["call_graph_files"]["handle"] == ["app.rb:3", "svc.py:20"]
    # spans from both languages are present
    assert data["def_spans"]["app.rb::handle"] == [1, 9]
    assert data["def_spans"]["svc.py::serve"] == [4, 40]


def test_merge_graph_artifacts_seed_span_wins_on_qnode_collision():
    data = {"call_graph": {}, "call_graph_files": {},
            "def_spans": {"a.py::f": [1, 2]}}
    s1._merge_graph_artifacts(data, {}, {}, {"a.py::f": [1, 99]})
    assert data["def_spans"]["a.py::f"] == [1, 99]   # S0 AST span authoritative


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
