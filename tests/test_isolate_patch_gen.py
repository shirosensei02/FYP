from pathlib import Path

import pytest
import repo_graph

from abalation.mongodb_parser import categorise
from isolated_runners.isolate_patch_gen import LOCKED_ROOT, apply_answer_key_locations, load_locked_oracle


LOCKED = {
    ("drizzle-orm", "0.45.1"): ("drizzle-orm_0.45.1_1", 4),
    ("next", "15.2.2"): ("next_15.2.2_2", 2),
    ("lodash", "4.17.11"): ("lodash_4.17.11_1", 6),
    ("form-data", "4.0.3"): ("form-data_4.0.3_1", 1),
    ("jsonwebtoken", "8.5.1"): ("jsonwebtoken_8.5.1_2", 1),
    ("minimatch", "3.0.4"): ("minimatch_3.0.4_2", 2),
    ("shell-quote", "1.8.3"): ("shell-quote_1.8.3_1", 3),
}


def test_locked_oracle_uses_the_accepted_script():
    for (package, version), (source_run, attempt) in LOCKED.items():
        oracle = load_locked_oracle(package, version)
        script = Path(LOCKED_ROOT / f"{package}_{version}" / "oracle.js").read_text(encoding="utf-8")
        assert oracle["status"] == "accepted"
        assert oracle["source"] == script
        assert oracle["source"].strip()
        assert oracle["source_run"] == source_run
        assert oracle["attempt_number"] == attempt
    with pytest.raises(FileNotFoundError):
        load_locked_oracle("axios", "1.7.3")


def test_answer_key_locations_carry_the_function_body(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_graph, "INDEX_ROOT", tmp_path / "index")
    monkeypatch.setattr(repo_graph, "_CACHE", {})
    source = tmp_path / "pkg"
    source.mkdir()
    (source / "quote.js").write_text("function quote(value) {\n  return value;\n}\n", encoding="utf-8")
    state = {
        "package_name": "shell-quote",
        "package_version": "1.8.3",
        "source_dir": str(source),
    }
    key = {
        ("shell-quote", "1.8.3"): [
            {"path": "quote.js", "function": "quote", "lines": [1, 2]},
        ],
    }

    state.update(apply_answer_key_locations(state, key))

    location = state["debug_locations"][0]
    assert location["path"] == "quote.js"
    assert location["function"] == "quote"
    assert location["line"] == 1
    assert "return value" in location["body"]
    with pytest.raises(FileNotFoundError):
        apply_answer_key_locations(
            {"package_name": "axios", "package_version": "1.7.3", "source_dir": str(source)},
            key,
        )


def test_patch_outcome_uses_the_oracle_buckets():
    assert categorise("patch", "max_5") == (None, None, "pass")
    assert categorise("patch", "max_10") == (None, None, "partial")
    assert categorise("patch", "failed") == (None, None, "fail")
    assert categorise("locator", "1/1") == (1, 1, "pass")
