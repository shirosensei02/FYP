from pathlib import Path

import repo_graph
from locator import _parse_action, _system_prompt, locator_node, route_after_locator
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


def test_prompt_keeps_the_chain_of_thought_and_the_tool_contract():
    prompt = _system_prompt({"package_name": "demo"})

    assert "Step 1: Categorize and Extract Key Problem Information" in prompt
    assert "modules in the 'demo' package" in prompt
    assert "SearchEntity" in prompt
    assert '"action":"locate"' in prompt


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
