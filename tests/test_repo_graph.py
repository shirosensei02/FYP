from pathlib import Path

import repo_graph
from repo_graph import build_graph, retrieve_entity, search_entity, traverse_graph


LIBRARY = """
class Parser {
  parse(input) {
    return input;
  }
}
class Child extends Parser {
  parse(input) {
    return input;
  }
}
"""

CALLER = """
const { helper } = require("./b");
function run(input) {
  return helper(input);
}
"""

CALLEE = """
function helper(input) {
  return input;
}
"""


def _package(tmp_path: Path) -> Path:
    source = tmp_path / "pkg"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "types.js").write_text(LIBRARY, encoding="utf-8")
    (lib / "a.js").write_text(CALLER, encoding="utf-8")
    (lib / "b.js").write_text(CALLEE, encoding="utf-8")
    return source


def test_graph_links_contain_import_invoke_and_inherit(tmp_path):
    graph = build_graph(_package(tmp_path))
    ids = {node["id"] for node in graph["nodes"]}
    edges = {(edge["source"], edge["type"], edge["target"]) for edge in graph["edges"]}

    assert "lib/b.js:helper" in ids
    assert "lib/types.js:Parser.parse" in ids
    assert ("lib/a.js", "import", "lib/b.js:helper") in edges
    assert ("lib/a.js:run", "invoke", "lib/b.js:helper") in edges
    assert ("lib/types.js:Child", "inherit", "lib/types.js:Parser") in edges
    assert ("lib/types.js:Parser", "contain", "lib/types.js:Parser.parse") in edges


def test_search_traverse_and_retrieve_round_trip_the_called_function(tmp_path):
    graph = build_graph(_package(tmp_path))

    found = search_entity(graph, ["helper"])
    assert found["entities"][0]["id"] == "lib/b.js:helper"
    assert "return input" in found["entities"][0]["snippet"]

    walked = traverse_graph(
        graph,
        ["lib/a.js:run"],
        direction="out",
        hops=1,
        entity_types=["function"],
        relation_types=["invoke"],
    )
    assert {item["id"] for item in walked["entities"]} >= {"lib/a.js:run", "lib/b.js:helper"}
    assert walked["relations"] == [{"source": "lib/a.js:run", "target": "lib/b.js:helper", "type": "invoke"}]

    loaded = retrieve_entity(graph, ["lib/b.js:helper"])
    assert loaded["entities"][0]["code"].startswith("function helper")


def test_name_index_finds_a_callee_outside_the_caller_directory(tmp_path):
    source = tmp_path / "pkg"
    (source / "src" / "api").mkdir(parents=True)
    (source / "lib" / "security").mkdir(parents=True)
    (source / "src" / "api" / "handler.js").write_text(
        "function handle(input) {\n  return sanitize(input);\n}\n",
        encoding="utf-8",
    )
    (source / "lib" / "security" / "clean.js").write_text(
        "class Clean {\n  scrub(input) {\n    const noncevalue = input;\n    return noncevalue;\n  }\n}\n"
        "function sanitize(input) {\n  return input;\n}\n",
        encoding="utf-8",
    )
    (source / "lib" / "security" / "note.js").write_text(
        "function format(input) {\n  // sanitize is mentioned only in this comment\n  return input;\n}\n",
        encoding="utf-8",
    )
    graph = build_graph(source)
    edges = {(edge["source"], edge["type"], edge["target"]) for edge in graph["edges"]}

    assert ("src/api/handler.js:handle", "invoke", "lib/security/clean.js:sanitize") in edges

    by_name = search_entity(graph, ["sanitize"])
    assert [item["id"] for item in by_name["entities"]] == ["lib/security/clean.js:sanitize"]

    by_qualified = search_entity(graph, ["Clean.scrub"])
    assert [item["id"] for item in by_qualified["entities"]] == ["lib/security/clean.js:Clean.scrub"]

    by_body = search_entity(graph, ["noncevalue"])
    assert by_body["entities"][0]["id"] == "lib/security/clean.js:Clean.scrub"


def test_nested_function_is_contained_and_owns_its_call(tmp_path):
    source = tmp_path / "pkg"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "a.js").write_text(
        "function run(input) {\n"
        "  function inner(value) {\n"
        "    return helper(value);\n"
        "  }\n"
        "  return inner(input);\n"
        "}\n"
        "function helper(value) {\n"
        "  return value;\n"
        "}\n",
        encoding="utf-8",
    )
    graph = build_graph(source)
    edges = {(edge["source"], edge["type"], edge["target"]) for edge in graph["edges"]}

    assert ("lib/a.js:run", "contain", "lib/a.js:run.inner") in edges
    assert ("lib/a.js:run.inner", "invoke", "lib/a.js:helper") in edges


def test_new_expression_invokes_an_imported_class(tmp_path):
    source = tmp_path / "pkg"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "types.js").write_text(
        "class Parser {\n  parse(input) {\n    return input;\n  }\n}\n",
        encoding="utf-8",
    )
    (lib / "a.js").write_text(
        'const { Parser } = require("./types");\n'
        "function make() {\n"
        "  return new Parser();\n"
        "}\n",
        encoding="utf-8",
    )
    graph = build_graph(source)
    edges = {(edge["source"], edge["type"], edge["target"]) for edge in graph["edges"]}

    assert ("lib/a.js", "import", "lib/types.js:Parser") in edges
    assert ("lib/a.js:make", "invoke", "lib/types.js:Parser") in edges


def test_object_method_is_a_function_whose_body_can_be_retrieved(tmp_path):
    source = tmp_path / "pkg"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "api.js").write_text(
        "const api = {\n"
        "  stat(input) {\n"
        "    return input;\n"
        "  }\n"
        "};\n",
        encoding="utf-8",
    )
    graph = build_graph(source)
    edges = {(edge["source"], edge["type"], edge["target"]) for edge in graph["edges"]}

    assert ("lib/api.js", "contain", "lib/api.js:api.stat") in edges
    loaded = retrieve_entity(graph, ["lib/api.js:api.stat"])
    assert "return input" in loaded["entities"][0]["code"]


def test_file_scope_global_is_found_from_the_code_index(tmp_path):
    source = tmp_path / "pkg"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "config.js").write_text(
        "const noncevalue = 1;\n"
        "function other() {\n"
        "  return 1;\n"
        "}\n",
        encoding="utf-8",
    )
    graph = build_graph(source)
    found = search_entity(graph, ["noncevalue"])
    assert found["entities"][0]["id"] == "lib/config.js"
    assert "noncevalue" in found["entities"][0]["snippet"]


def test_side_effect_import_links_the_file_when_no_entity_is_named(tmp_path):
    source = tmp_path / "pkg"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "b.js").write_text("function helper(input) {\n  return input;\n}\n", encoding="utf-8")
    (lib / "a.js").write_text(
        'require("./b");\n'
        "function run() {\n"
        "  return 1;\n"
        "}\n",
        encoding="utf-8",
    )
    graph = build_graph(source)
    edges = {(edge["source"], edge["type"], edge["target"]) for edge in graph["edges"]}
    assert ("lib/a.js", "import", "lib/b.js") in edges


def test_regex_fallback_imports_a_class_and_records_instantiation(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_graph, "parse_javascript", lambda relative, text: None)
    source = tmp_path / "pkg"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "types.js").write_text(
        "class Parser {\n  parse(input) {\n    return input;\n  }\n}\n",
        encoding="utf-8",
    )
    (lib / "a.js").write_text(
        'const { Parser } = require("./types");\n'
        "function make() {\n"
        "  return new Parser();\n"
        "}\n",
        encoding="utf-8",
    )
    graph = build_graph(source)
    edges = {(edge["source"], edge["type"], edge["target"]) for edge in graph["edges"]}

    assert ("lib/a.js", "import", "lib/types.js:Parser") in edges
    assert ("lib/a.js:make", "invoke", "lib/types.js:Parser") in edges
