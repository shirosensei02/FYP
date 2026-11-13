from pathlib import Path

import repo_graph
from locator import (
    _locations_with_bodies,
    _parse_action,
    _render_trace,
    _system_prompt,
    locator_node,
    route_after_locator,
)
from repo_graph import repo_graph_node, route_after_repo_graph


def _package(tmp_path: Path) -> Path:
    source = tmp_path / "pkg"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "b.js").write_text("function helper(input) {\n  return input;\n}\n", encoding="utf-8")
    return source


def _state(source: Path) -> dict:
    return {
        "source_dir": str(source),
        "package_name": "demo",
        "package_version": "1.0.0",
        "model_provider": "mock",
        "current_vulnerabilities": [{
            "id": "CVE-1",
            "description": "helper passes input through unchanged",
        }],
    }


def test_locator_searches_twice_and_ranks_the_function(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_graph, "INDEX_ROOT", tmp_path / "index")
    monkeypatch.setattr(repo_graph, "_CACHE", {})
    state = _state(_package(tmp_path))

    state.update(repo_graph_node(state))
    assert route_after_repo_graph(state) == "locator"

    state.update(locator_node(state))
    assert state["graph_request"]["tool"] == "SearchEntity"
    assert route_after_locator(state) == "repo_graph"

    state.update(repo_graph_node(state))
    assert route_after_repo_graph(state) == "locator"
    state.update(locator_node(state))
    assert state["locate_sample"] == 1
    assert route_after_locator(state) == "locator"

    state.update(locator_node(state))
    assert state["graph_request"]["caller"] == "locator"
    state.update(repo_graph_node(state))
    state.update(locator_node(state))

    assert state["locate_status"] == "ranked"
    assert state["debug_locations"][0]["function"] == "helper"
    assert state["debug_locations"][0]["path"] == "lib/b.js"
    assert "return input" in state["debug_locations"][0]["body"]
    assert state["located_entities"][0]["score"] == 2
    assert route_after_locator(state) == "generation"


def test_generation_fetch_returns_to_patch_generation(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_graph, "INDEX_ROOT", tmp_path / "index")
    monkeypatch.setattr(repo_graph, "_CACHE", {})
    state = _state(_package(tmp_path))
    state.update(repo_graph_node(state))
    state["graph_request"] = {
        "caller": "patch_generation",
        "tool": "RetrieveEntity",
        "arguments": {"entity_ids": ["lib/b.js:helper"]},
    }

    state.update(repo_graph_node(state))

    assert state["graph_request"] is None
    assert state["graph_return"] == "patch_generation"
    assert route_after_repo_graph(state) == "generation"
    assert "return input" in state["graph_result"]["entities"][0]["code"]


def test_prompt_keeps_the_enriched_brief_and_the_tool_contract():
    prompt = _system_prompt({"package_name": "demo"})

    assert "in the 'demo' package" in prompt
    assert "CWE ID:" in prompt
    assert "SearchEntity" in prompt
    assert '"action":"locate"' in prompt

    cot = _system_prompt({"package_name": "demo", "prompt_suffix": "_CoT"})
    assert "Step 1: Categorize and Extract Key Problem Information" in cot
    assert "modules in the 'demo' package" in cot


def test_final_locations_accept_the_locator_block():
    parsed = _parse_action(
        "```\n"
        "lib/client.js\n"
        "line: 10\n"
        "class: Client\n"
        "function: query\n"
        "lib/util.js\n"
        "line: 24\n"
        "function: escape\n"
        "```\n"
    )

    assert parsed["action"] == "locate"
    assert parsed["locations"][0] == {
        "path": "lib/client.js",
        "lines": ["10"],
        "line": "10",
        "class": "Client",
        "function": "query",
    }
    assert parsed["locations"][1]["path"] == "lib/util.js"
    assert parsed["locations"][1]["function"] == "escape"


def test_named_module_export_resolves_when_the_model_says_module_exports(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_graph, "INDEX_ROOT", tmp_path / "index")
    monkeypatch.setattr(repo_graph, "_CACHE", {})
    source = tmp_path / "pkg"
    source.mkdir()
    (source / "quote.js").write_text(
        "module.exports = function quote(xs) {\n"
        "  return xs.map(function (s) {\n"
        "    return s;\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )
    state = {
        "source_dir": str(source),
        "package_name": "demo",
        "package_version": "1.0.0",
    }
    kept = _locations_with_bodies(state, [{
        "id": "quote.js:module.exports",
        "path": "quote.js",
        "function": "module.exports",
        "line": 8,
        "class": "",
        "rank": 1,
    }])
    assert kept[0]["id"] == "quote.js:quote"
    assert kept[0]["function"] == "quote"
    assert "return s" in kept[0]["body"]


def test_anonymous_export_and_a_functionless_file_stay_locations(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_graph, "INDEX_ROOT", tmp_path / "index")
    monkeypatch.setattr(repo_graph, "_CACHE", {})
    source = tmp_path / "pkg"
    source.mkdir()
    (source / "verify.js").write_text(
        "module.exports = function (value) {\n  return value;\n};\n",
        encoding="utf-8",
    )
    (source / "notes.js").write_text("const marker = 1;\n", encoding="utf-8")
    state = {
        "source_dir": str(source),
        "package_name": "demo",
        "package_version": "1.0.0",
    }

    kept = _locations_with_bodies(state, [
        {
            "id": "verify.js:module.exports",
            "path": "verify.js",
            "function": "module.exports",
            "line": 2,
            "class": "",
            "rank": 1,
        },
        {"id": "notes.js", "path": "notes.js", "function": "", "line": 1, "class": "", "rank": 2},
    ])

    assert kept[0]["id"] == "verify.js:default"
    assert kept[0]["function"] == "default"
    assert "return value" in kept[0]["body"]
    assert kept[1]["path"] == "notes.js"
    assert kept[1]["function"] == ""
    assert "marker" in kept[1]["body"]


def test_long_retrieve_keeps_its_cursor_inside_the_prompt_result():
    code = "x" * 20_000
    rendered = _render_trace([{
        "tool": "RetrieveEntity",
        "arguments": {"entity_ids": ["long.js:huge"]},
        "result": {
            "tool": "RetrieveEntity",
            "entities": [{
                "id": "long.js:huge",
                "cursor": 3000,
                "stopped_at_line": 4,
                "code": code,
            }],
        },
    }])

    assert "cursor" in rendered
    assert "stopped_at_line" in rendered
