import json

import cost_log
from maintainer_eval import maintainer_eval
from run_cost import response_usage


class _Usage:
    def __init__(self, prompt, completion, cost):
        self.prompt_tokens = prompt
        self.completion_tokens = completion
        self.total_tokens = prompt + completion
        self.cost = cost


class _Response:
    def __init__(self, prompt, completion, cost):
        self.usage = _Usage(prompt, completion, cost)


def _state(**overrides):
    state = {
        "run_attempt_id": "pidusage-fc111",
        "retry_count": 0,
        "package_name": "pidusage",
        "package_version": "1.1.4",
        "model_name": "anthropic/claude-sonnet-5",
    }
    state.update(overrides)
    return state


def _documents():
    return list(cost_log._collection().find())


def _read(key):
    matches = [document for document in _documents() if document.get("key") == key]
    assert len(matches) == 1
    return matches[0]


def test_response_usage_reads_tokens_and_cost():
    usage = response_usage(_Response(11, 7, 0.125))

    assert usage == {
        "prompt_tokens": 11,
        "completion_tokens": 7,
        "total_tokens": 18,
        "cost": 0.125,
    }
    assert response_usage(object())["prompt_tokens"] is None
    assert response_usage(object())["cost"] == 0.0


def test_response_usage_sums_token_counts_when_the_total_is_absent():
    class _Partial:
        prompt_tokens = 4
        completion_tokens = 6

    class _PartialResponse:
        usage = _Partial()

    usage = response_usage(_PartialResponse())

    assert usage["total_tokens"] == 10
    assert usage["cost"] == 0.0


def test_attempt_log_appends_requests_and_separates_retries():
    state = _state()
    cost_log.record_request(
        state,
        node="patch_generation",
        call="generate",
        model="anthropic/claude-sonnet-5",
        response=_Response(10, 4, 0.25),
    )
    cost_log.note_written_lines(state, "--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-old\n+new\n")
    cost_log.record_request(
        state,
        node="patch_generation",
        call="repair",
        model="anthropic/claude-sonnet-5",
        response=_Response(8, 3, 0.125),
    )
    cost_log.note_written_lines(
        state,
        "--- a/a.js\n+++ b/a.js\n@@ -1,2 +1,3 @@\n-old\n-also\n+new\n+extra\n",
    )
    cost_log.record_request(
        state,
        node="adversarial_evaluation",
        call="evaluate",
        model="openai/gpt-5.3-codex",
        response=_Response(3, 2, 0.125),
    )
    cost_log.note_written_lines(state, "--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-should\n+not-attach\n")

    document = _read("pidusage-fc111-1")
    assert document["key"] == "pidusage-fc111-1"
    assert document["package_name"] == "pidusage"
    assert document["package_version"] == "1.1.4"
    assert document["model"] == "anthropic/claude-sonnet-5"
    assert document["requests"][0]["lines_added"] == 1
    assert document["requests"][0]["lines_removed"] == 1
    assert document["requests"][1]["call"] == "repair"
    assert document["requests"][1]["lines_added"] == 2
    assert document["requests"][1]["lines_removed"] == 2
    assert document["requests"][2]["model"] == "openai/gpt-5.3-codex"
    assert document["requests"][2]["lines_added"] is None
    assert document["totals"]["prompt_tokens"] == 21
    assert document["totals"]["completion_tokens"] == 9
    assert document["totals"]["total_tokens"] == 30
    assert document["totals"]["cost"] == 0.5
    assert document["totals"]["lines_added"] == 3
    assert document["totals"]["lines_removed"] == 3
    assert document["totals"]["outcome"] is None

    cost_log.record_attempt_outcome(state, passed=False)
    assert _read("pidusage-fc111-1")["totals"]["outcome"] == "failed"
    cost_log.record_request(
        state,
        node="maintainer_eval",
        call="evaluate",
        model="openai/gpt-5.3-codex",
        response=_Response(1, 1, 0.0),
    )
    assert _read("pidusage-fc111-1")["totals"]["outcome"] == "failed"

    cost_log.record_request(
        _state(retry_count=1),
        node="patch_generation",
        call="generate",
        model="anthropic/claude-sonnet-5",
        response=_Response(1, 1, 0.125),
    )
    assert _read("pidusage-fc111-2")["attempt_number"] == 2
    assert len(_documents()) == 2


def test_scoped_package_keeps_its_attempt_key():
    cost_log.record_request(
        _state(run_attempt_id="@scope/pkg-abc", package_name="@scope/pkg"),
        node="patch_generation",
        call="generate",
        model="anthropic/claude-sonnet-5",
        error="timed out",
    )

    document = _read("@scope/pkg-abc-1")
    assert document["key"] == "@scope/pkg-abc-1"
    assert document["package_name"] == "@scope/pkg"
    assert document["requests"][0]["cost"] == 0.0
    assert document["requests"][0]["prompt_tokens"] is None
    assert document["requests"][0]["error"] == "timed out"


def test_missing_attempt_id_and_storage_errors_do_not_raise(monkeypatch):
    cost_log.record_request({}, node="patch_generation", call="generate", model="m")
    cost_log.note_written_lines({}, "--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-old\n+new\n")
    assert _documents() == []

    def fail(document):
        raise OSError("disk full")

    monkeypatch.setattr(cost_log, "_save", fail)
    cost_log.record_request(_state(), node="patch_generation", call="generate", model="m")


def test_diff_line_counts_ignore_file_headers():
    diff = (
        "diff --git a/a.js b/a.js\n"
        "--- a/a.js\n+++ b/a.js\n@@ -1,2 +1,3 @@\n-old\n+new\n+extra\n"
        "diff --git a/b.js b/b.js\n"
        "--- a/b.js\n+++ b/b.js\n@@ -1 +0,0 @@\n-gone\n"
    )

    assert cost_log.diff_line_counts(diff) == {"lines_added": 2, "lines_removed": 2}


def test_maintainer_eval_appends_its_request(monkeypatch):
    class _EvalUsage:
        prompt_tokens = 20
        completion_tokens = 5
        total_tokens = 25
        cost = 0.125

    class _EvalResponse:
        usage = _EvalUsage()
        choices = [
            type(
                "Choice",
                (),
                {
                    "message": type(
                        "Message",
                        (),
                        {
                            "content": json.dumps(
                                {
                                    "verdict": "PARTIAL",
                                    "root_cause_identified": True,
                                    "same_fix_strategy": False,
                                    "summary": "Different strategy.",
                                    "differences": [],
                                    "missing_from_generated": [],
                                    "extra_in_generated": [],
                                }
                            )
                        },
                    )()
                },
            )()
        ]

    class _Client:
        def __init__(self, **kwargs):
            self.chat = type("Chat", (), {"completions": self})()

        def create(self, **kwargs):
            return _EvalResponse()

    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr("maintainer_eval.OpenAI", _Client)
    monkeypatch.setattr("maintainer_eval.save_pipeline_result", lambda state: (None, None))

    diff = "--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-old\n+new\n"
    result = maintainer_eval(
        _state(
            current_patch={"diff": diff},
            answer_key={"diff": diff},
            adversarial_evaluation={"evaluator_model": "openai/gpt-5.3-codex"},
            vulnerabilities=[{"id": "CVE-1", "severity": "high", "description": "bug"}],
        )
    )

    assert result["maintainer_eval"]["verdict"] == "PARTIAL"
    assert result["run_cost"] == 0.125
    document = _read("pidusage-fc111-1")
    assert document["model"] == "anthropic/claude-sonnet-5"
    request = document["requests"][0]
    assert request["node"] == "maintainer_eval"
    assert request["call"] == "evaluate"
    assert request["model"] == "openai/gpt-5.3-codex"
    assert request["prompt_tokens"] == 20
    assert request["cost"] == 0.125
    assert request["lines_added"] is None


def test_concurrent_sampled_requests_are_all_recorded():
    from concurrent.futures import ThreadPoolExecutor

    def record(index):
        cost_log.record_request(
            _state(), node="patch_generation", call="sample", model="m", response=_Response(1, 1, 0.01)
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(record, range(40)))

    document = _read("pidusage-fc111-1")
    assert len(document["requests"]) == 40
    assert round(document["totals"]["cost"], 2) == 0.40
