from pathlib import Path

from js_ast import parse_javascript
from repo_graph import build_graph


def test_parser_binds_a_renamed_require_to_the_imported_function(tmp_path: Path):
    source = tmp_path / "pkg"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "b.js").write_text("function helper(input) {\n  return input;\n}\n", encoding="utf-8")
    (lib / "a.js").write_text(
        'const { helper: scrub } = require("./b");\n'
        "function run(input) {\n"
        "  return scrub(input);\n"
        "}\n",
        encoding="utf-8",
    )

    facts = parse_javascript("lib/a.js", (lib / "a.js").read_text(encoding="utf-8"))
    assert facts is not None
    assert facts.bindings[0].local == "scrub"
    assert facts.bindings[0].imported == "helper"

    graph = build_graph(source)
    edges = {(edge["source"], edge["type"], edge["target"]) for edge in graph["edges"]}
    assert ("lib/a.js", "import", "lib/b.js:helper") in edges
    assert ("lib/a.js:run", "invoke", "lib/b.js:helper") in edges


def test_parser_binds_a_namespace_member_call():
    facts = parse_javascript(
        "lib/a.js",
        'import * as security from "./clean.js";\n'
        "function run(input) {\n"
        "  return security.scrub(input);\n"
        "}\n",
    )
    assert facts is not None
    assert facts.bindings[0].imported == "*"
    assert facts.calls[0].object == "security"
    assert facts.calls[0].name == "scrub"


def test_parser_qualifies_a_nested_function_and_an_object_method():
    facts = parse_javascript(
        "lib/a.js",
        "function run(input) {\n"
        "  function inner(value) {\n"
        "    return helper(value);\n"
        "  }\n"
        "  return inner(input);\n"
        "}\n"
        "const api = {\n"
        "  stat(input) {\n"
        "    return helper(input);\n"
        "  }\n"
        "};\n",
    )
    assert facts is not None
    qualified = {symbol.qualified for symbol in facts.symbols}
    assert "run.inner" in qualified
    assert "api.stat" in qualified
    owners = {call.owner for call in facts.calls}
    assert "run.inner" in owners
    assert "api.stat" in owners
