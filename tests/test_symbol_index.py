from pathlib import Path

import symbol_index
from symbol_index import apply_lookup, catalog_path, ensure_index, render_catalog, scan_source


SOURCE = """
function declared(input) {
  return input;
}
const expressed = function (input) {
  return input;
}
const arrow = (input) => {
  return input;
}
class Parser {
  parse(input) {
    return input;
  }
}
exports.legacy = function (input) {
  return input;
}
"""


def _package(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "parse.js").write_text(SOURCE, encoding="utf-8")
    return source


def test_scan_records_function_const_arrow_class_and_export(tmp_path):
    names = {(symbol.name, symbol.exported) for symbol in scan_source(_package(tmp_path))}

    assert ("declared", False) in names
    assert ("expressed", False) in names
    assert ("arrow", False) in names
    assert ("Parser", False) in names
    assert ("parse", False) in names
    assert ("legacy", True) in names


def test_prompt_catalog_marks_advisory_names_without_writing_them(tmp_path, monkeypatch):
    monkeypatch.setattr(symbol_index, "INDEX_ROOT", tmp_path / "index")
    source = _package(tmp_path)
    symbols = ensure_index(source, "secret-pkg", "9.9.9-secret")
    disk = catalog_path("secret-pkg", "9.9.9-secret").read_text(encoding="utf-8")
    prompt = render_catalog(symbols, {"normalize", "arrow"})

    assert "[advisory]" not in disk
    assert "arrow [advisory]" in prompt
    assert "secret-pkg" not in prompt
    assert "9.9.9-secret" not in prompt


def test_lookup_drop_does_not_change_the_disk_catalog(tmp_path, monkeypatch):
    monkeypatch.setattr(symbol_index, "INDEX_ROOT", tmp_path / "index")
    source = _package(tmp_path)
    (source / "lib" / "parse.js").write_text(
        "function normalize(input) {\n  return input;\n}\n"
        "function join(parts) {\n  return parts;\n}\n",
        encoding="utf-8",
    )
    symbols = ensure_index(source, "pkg", "1.0.0")
    disk = catalog_path("pkg", "1.0.0").read_text(encoding="utf-8")
    loaded = apply_lookup(
        source, symbols,
        request=["lib/parse.js:normalize", "missing"],
        drop=[], in_prompt=[], retrieved=[], body_loads=0,
    )
    dropped = apply_lookup(
        source, symbols,
        request=["lib/parse.js:join"],
        drop=["lib/parse.js:normalize"],
        in_prompt=loaded["debug_in_prompt"],
        retrieved=loaded["debug_retrieved"],
        body_loads=loaded["debug_body_loads"],
    )

    assert catalog_path("pkg", "1.0.0").read_text(encoding="utf-8") == disk
    assert [item["name"] for item in dropped["debug_in_prompt"]] == ["join"]
    assert "return input" in loaded["debug_in_prompt"][0]["body"]
    statuses = {item["key"]: item["status"] for item in dropped["debug_retrieved"]}
    assert statuses["lib/parse.js:normalize"] == "dropped"
    assert statuses["missing"] == "not_found"
    assert statuses["lib/parse.js:join"] == "in_prompt"


def test_lookup_adds_every_requested_function(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    source.joinpath("index.js").write_text(
        "\n".join(f"function f{i}() {{ return {i}; }}" for i in range(5)),
        encoding="utf-8",
    )
    symbols = scan_source(source)
    loaded = apply_lookup(
        source, symbols,
        request=[f"f{i}" for i in range(5)],
        drop=[], in_prompt=[], retrieved=[], body_loads=0,
    )

    assert [item["name"] for item in loaded["debug_in_prompt"]] == [f"f{i}" for i in range(5)]
    assert loaded["debug_body_loads"] == 5


def test_lookup_skips_a_body_that_would_overflow_the_prompt(tmp_path, monkeypatch):
    import debugger

    source = tmp_path / "src"
    source.mkdir()
    source.joinpath("index.js").write_text(
        "function f0() { return 0; }\nfunction f1() { return 1; }\n",
        encoding="utf-8",
    )
    symbols = scan_source(source)
    state = {
        "symbol_catalog": render_catalog(symbols, set()),
        "debug_actions": [],
        "current_vulnerabilities": [],
    }
    first = apply_lookup(
        source, symbols,
        request=["f0"],
        drop=[], in_prompt=[], retrieved=[], body_loads=0,
        state=state,
    )
    used = debugger._prompt_chars(debugger.build_messages({
        **state,
        "debug_in_prompt": first["debug_in_prompt"],
        "debug_retrieved": first["debug_retrieved"],
    }))
    monkeypatch.setattr(debugger, "MAX_DEBUG_PROMPT_CHARS", used)
    loaded = apply_lookup(
        source, symbols,
        request=["f0", "f1"],
        drop=[], in_prompt=[], retrieved=[], body_loads=0,
        state=state,
    )

    assert [item["name"] for item in loaded["debug_in_prompt"]] == ["f0"]
    assert "index.js:f1" not in {item["key"] for item in loaded["debug_retrieved"]}
