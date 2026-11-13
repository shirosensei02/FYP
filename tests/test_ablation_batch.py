import copy

import ablation_cost
from ablation_cost import finish, loop_outcome, record_loop
from isolated_runners.batch_runner import ANSWER_KEY_PATH, load_config, run_batch
from locator_answer import load_answer_key, located_file_ratio, match_locations
from prompt_variant import prompt_path


class _Usage:
    def __init__(self, prompt, completion, cost):
        self.prompt_tokens = prompt
        self.completion_tokens = completion
        self.total_tokens = prompt + completion
        self.cost = cost


class _Response:
    def __init__(self, prompt, completion, cost, content=""):
        self.usage = _Usage(prompt, completion, cost)
        self.choices = [type("Choice", (), {"message": type("Message", (), {"content": content})()})()]


class _AblationCollection:
    def __init__(self):
        self.docs = {}

    def find_one(self, filt, projection=None):
        document = self.docs.get(filt["ablation_id"])
        if document is None:
            return None
        return copy.deepcopy(document)

    def replace_one(self, filt, document, upsert=False):
        self.docs[filt["ablation_id"]] = copy.deepcopy(document)


def test_prompt_suffix_maps_onto_the_existing_files():
    assert prompt_path("locator", "_generic").name == "locator_generic.txt"
    assert prompt_path("locator", "_enriched").name == "locator_enriched.txt"
    assert prompt_path("locator", "_CoT").name == "locator.txt"
    assert prompt_path("oracle", "_generic").name == "oracle_generic.txt"
    assert prompt_path("oracle", "_enriched").name == "oracle.txt"
    assert prompt_path("oracle", "_CoT").name == "oracle_CoT.txt"
    assert prompt_path("patch", "_CoT").name == "patch_CoT.txt"
    assert prompt_path("locator", None).name == "locator_enriched.txt"
    assert prompt_path("oracle", None).name == "oracle.txt"
    assert prompt_path("patch", "").name == "patch_enriched.txt"


def test_loop_buckets_count_five_and_ten():
    assert loop_outcome(1) == "max_5"
    assert loop_outcome(5) == "max_5"
    assert loop_outcome(6) == "max_10"
    assert loop_outcome(10) == "max_10"
    assert loop_outcome(11) == "failed"
    assert loop_outcome(None) == "failed"


def test_locator_file_ratio_counts_expected_files():
    expected = [
        {"path": "mysql-core/dialect.js", "function": "escapeName", "lines": [56]},
        {"path": "pg-core/dialect.js", "function": "escapeName", "lines": [73]},
        {"path": "sqlite-core/dialect.js", "function": "escapeName", "lines": [29]},
    ]
    state = {"located_entities": [
        {"path": "mysql-core/dialect.js", "function": "module.exports", "line": 1},
        {"path": "pg-core/dialect.js", "function": "other", "line": 4},
        {"path": "test/dialect.js", "function": "escapeName", "line": 1},
    ]}
    assert located_file_ratio(state, expected) == "2/3"
    assert located_file_ratio({"debug_locations": []}, expected) == "0/3"
    assert located_file_ratio(state, []) is None


def test_locator_match_uses_file_and_function_not_the_diff_body():
    predicted = [
        {"path": "src/quote.js", "function": "quote", "line": 12},
        {"path": "src/other.js", "function": "parse", "line": 4},
    ]
    assert match_locations(predicted, [{"path": "quote.js", "function": "quote", "lines": [40]}]) is True
    assert match_locations(predicted, [{"path": "quote.js", "function": "parse"}]) is False
    assert match_locations(predicted, [{"path": "quote.js", "lines": [12]}]) is True
    assert match_locations(predicted, []) is None


def test_answer_key_lists_the_ten_packages_without_bodies():
    key = load_answer_key(ANSWER_KEY_PATH)
    assert len(key) == 10
    assert key[("shell-quote", "1.8.3")] == [{"path": "quote.js", "function": "quote", "lines": [8, 9]}]
    assert all(isinstance(locations, list) for locations in key.values())


def test_batch_config_selects_suffix_loop_and_all_packages():
    config = load_config()
    assert config["prompt_suffix"] in {"_generic", "_enriched", "_CoT"}
    assert config["max_loop"] == 5
    assert config["node"] in {"locator", "oracle", "patch"}
    assert len(config["packages"]) == 10
    assert config["packages"][0]["package_name"] == "shell-quote"
    assert config["packages"][0]["package_version"] == "1.8.3"


def test_ablation_log_records_each_loop_and_the_bucket(monkeypatch):
    collection = _AblationCollection()
    monkeypatch.setattr(ablation_cost, "_collection", lambda: collection)
    state = {
        "ablation_id": "oracle-run",
        "ablation_node": "oracle",
        "prompt_suffix": "_generic",
        "package_name": "shell-quote",
        "package_version": "1.8.3",
        "vulnerability_id": "CVE-2026-9277",
        "model_name": "anthropic/claude-sonnet-5",
    }
    record_loop(state, node="oracle_generation", call="generate", model=state["model_name"], response=_Response(10, 4, 0.2, '{"source":"a"}'))
    record_loop(state, node="oracle_generation", call="generate", model=state["model_name"], response=_Response(12, 5, 0.3, '{"source":"b"}'))
    document = finish(state, success_loop=2, max_loop=10)

    assert [item["loop"] for item in document["loops"]] == [1, 2]
    assert document["loops"][0]["response"] == '{"source":"a"}'
    assert document["loops"][0]["token_in"] == 10
    assert document["loops"][0]["token_out"] == 4
    assert document["loops"][0]["lines_added"] is None
    assert document["totals"]["total_loops"] == 2
    assert document["totals"]["token_in"] == 22
    assert document["totals"]["token_out"] == 9
    assert document["totals"]["total_tokens"] == 31
    assert document["totals"]["cost"] == 0.5
    assert document["totals"]["lines_added"] is None
    assert document["totals"]["lines_removed"] is None
    assert document["totals"]["outcome"] == "max_5"
    assert document["totals"]["success_loop"] == 2

    later = finish({**state, "ablation_id": "late"}, success_loop=8, max_loop=10)
    assert later["totals"]["outcome"] == "max_10"


def test_batch_runs_every_package_and_keeps_going_after_a_failure(monkeypatch):
    collection = _AblationCollection()
    monkeypatch.setattr(ablation_cost, "_collection", lambda: collection)
    seen = []

    def run_oracle(config):
        seen.append(config["package_name"])
        if config["package_name"] == "minimatch":
            raise RuntimeError("registry down")
        state = {
            "ablation_id": config["ablation_id"],
            "ablation_node": "oracle",
            "prompt_suffix": config["prompt_suffix"],
            "package_name": config["package_name"],
            "package_version": config["package_version"],
            "vulnerability_id": config["vulnerability_id"],
            "model_name": config["model_name"],
        }
        record_loop(
            state,
            node="oracle_generation",
            call="generate",
            model=config["model_name"],
            response=_Response(3, 1, 0.0, "ok"),
        )
        return {"ok": True, "error": None, "state": state, "success_loop": 6}

    config = {
        "node": "oracle",
        "prompt_suffix": "_generic",
        "max_loop": 10,
        "model_provider": "openrouter",
        "model_name": "anthropic/claude-sonnet-5",
        "packages": [
            {"package_name": "shell-quote", "package_version": "1.8.3", "vulnerability_id": "CVE-2026-9277"},
            {"package_name": "minimatch", "package_version": "3.0.4", "vulnerability_id": "CVE-2022-3517"},
        ],
    }
    results = run_batch(config, run_locator=lambda config: {}, run_oracle=run_oracle, answer_key={})

    assert seen == ["shell-quote", "minimatch"]
    assert results[0]["outcome"] == "max_10"
    assert results[1]["outcome"] == "failed"
    assert config["packages"][0].get("max_oracle_attempts") is None


def test_locator_batch_records_the_file_ratio(monkeypatch):
    collection = _AblationCollection()
    monkeypatch.setattr(ablation_cost, "_collection", lambda: collection)

    def run_locator(config):
        state = {
            "ablation_id": config["ablation_id"],
            "ablation_node": "locator",
            "prompt_suffix": config["prompt_suffix"],
            "package_name": config["package_name"],
            "package_version": config["package_version"],
            "vulnerability_id": config["vulnerability_id"],
            "model_name": config["model_name"],
            "located_entities": [{
                "path": "quote.js",
                "function": "module.exports",
                "line": 8,
            }],
        }
        record_loop(
            state,
            node="locator",
            call="locate",
            model=config["model_name"],
            response=_Response(3, 1, 0.0, "ok"),
        )
        return {"ok": True, "error": None, "state": state}

    config = {
        "node": "locator",
        "prompt_suffix": "_CoT",
        "max_loop": 10,
        "model_provider": "openrouter",
        "model_name": "anthropic/claude-sonnet-5",
        "packages": [
            {"package_name": "shell-quote", "package_version": "1.8.3", "vulnerability_id": "CVE-2026-9277"},
        ],
    }
    results = run_batch(
        config,
        run_locator=run_locator,
        run_oracle=lambda package: {},
        answer_key={("shell-quote", "1.8.3"): [{"path": "quote.js", "function": "quote", "lines": [8, 9]}]},
    )
    assert results[0]["outcome"] == "1/1"


def test_patch_batch_records_an_early_pass(monkeypatch):
    collection = _AblationCollection()
    monkeypatch.setattr(ablation_cost, "_collection", lambda: collection)
    seen = []

    def run_patch(config):
        seen.append(config)
        state = {
            "ablation_id": config["ablation_id"],
            "ablation_node": "patch",
            "prompt_suffix": config["prompt_suffix"],
            "package_name": config["package_name"],
            "package_version": config["package_version"],
            "vulnerability_id": config["vulnerability_id"],
            "model_name": config["model_name"],
        }
        record_loop(
            state,
            node="patch_generation",
            call="generate",
            model=config["model_name"],
            response=_Response(3, 1, 0.0, "ok"),
        )
        return {"ok": True, "error": None, "state": state, "success_loop": 2}

    config = {
        "node": "patch",
        "prompt_suffix": "_generic",
        "max_loop": 10,
        "model_provider": "openrouter",
        "model_name": "anthropic/claude-sonnet-5",
        "packages": [
            {"package_name": "form-data", "package_version": "4.0.3", "vulnerability_id": "CVE-2025-7783"},
        ],
    }
    results = run_batch(config, run_patch=run_patch, answer_key={})

    assert seen[0]["ablation_node"] == "patch"
    assert seen[0]["max_patch_attempts"] == 10
    assert seen[0]["ablation_id"].startswith("patch-_generic-form-data-4.0.3-")
    assert results[0]["outcome"] == "max_5"
    document = collection.docs[seen[0]["ablation_id"]]
    assert len(document["loops"]) == 1
    assert document["node"] == "patch"
    assert document["totals"]["outcome"] == "max_5"
    assert document["totals"]["success_loop"] == 2
