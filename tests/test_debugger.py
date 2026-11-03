import symbol_index
from debugger import build_messages, debugger_node
from patch_generation import patch_generation
from symbol_index import index_node


def _source(tmp_path):
    source = tmp_path / "src"
    lib = source / "lib"
    lib.mkdir(parents=True)
    (lib / "parse.js").write_text(
        "function normalize(input) {\n  return input;\n}\nfunction join(parts) {\n  return parts;\n}\n",
        encoding="utf-8",
    )
    (source / "package.json").write_text('{"name":"secret-pkg","version":"9.9.9-secret"}', encoding="utf-8")
    return source


def _state(source):
    return {
        "source_dir": str(source),
        "package_manifest_path": str(source / "package.json"),
        "package_name": "secret-pkg",
        "package_version": "9.9.9-secret",
        "model_provider": "mock",
        "current_vulnerabilities": [{
            "id": "GHSA-test",
            "severity": "high",
            "description": "normalize does not check the path",
            "package": "secret-pkg",
            "installed_version": "9.9.9-secret",
        }],
        "errors": [],
        "patch_attempts": [],
        "retry_count": 0,
    }


def test_history_keeps_advisory_and_catalog_while_bodies_change(tmp_path, monkeypatch):
    monkeypatch.setattr(symbol_index, "INDEX_ROOT", tmp_path / "index")
    state = _state(_source(tmp_path))
    state.update(index_node(state))
    first = build_messages(state)
    catalog_message = first[1]["content"]

    assert "GHSA-test" in catalog_message
    assert "normalize [advisory]" in catalog_message
    assert "secret-pkg" not in catalog_message
    assert "9.9.9-secret" not in catalog_message
    assert "Function bodies:" in first[2]["content"]

    state.update(debugger_node(state))
    state.update(index_node(state))
    second = build_messages(state)

    assert second[1]["content"] == catalog_message
    assert "return input" in second[2]["content"]
    assert state["debug_in_prompt"][0]["name"] == "normalize"


def test_mock_loop_locates_the_advisory_function(tmp_path, monkeypatch):
    monkeypatch.setattr(symbol_index, "INDEX_ROOT", tmp_path / "index")
    state = _state(_source(tmp_path))
    state.update(index_node(state))
    state.update(debugger_node(state))
    state.update(index_node(state))
    state.update(debugger_node(state))

    assert state["debug_status"] == "located"
    assert state["debug_request"] is None
    assert state["debug_locations"][0]["function"] == "normalize"
    assert state["debug_locations"][0]["path"] == "lib/parse.js"
    assert "return input" in state["debug_locations"][0]["body"]


def test_debugger_stops_when_the_round_cap_is_reached(tmp_path, monkeypatch):
    monkeypatch.setattr(symbol_index, "INDEX_ROOT", tmp_path / "index")
    state = _state(_source(tmp_path))
    state.update(index_node(state))
    state["debug_rounds"] = 4
    result = debugger_node(state)

    assert result["debug_status"] == "capped"
    assert result["debug_request"] is None


def test_generation_uses_located_bodies(tmp_path, monkeypatch):
    monkeypatch.setattr(symbol_index, "INDEX_ROOT", tmp_path / "index")
    source = _source(tmp_path)
    (source / "other.js").write_text("function other(){ return 1 }\n", encoding="utf-8")
    state = _state(source)
    state["localized_context_files"] = [{"path": "other.js", "content": "function other(){ return 1 }\n"}]
    state["debug_locations"] = [{
        "path": "lib/parse.js",
        "function": "normalize",
        "body": "function normalize(input) {\n  return input;\n}\n",
    }]
    result = patch_generation(state)

    assert result["context_file_paths"] == ["lib/parse.js"]
