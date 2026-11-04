import json

from batch_runner import (
    load_batch_config,
    oracle_failure_summaries,
    parse_package,
    run_batch,
    should_start_run,
)
from run_cost import response_cost


def test_parse_package_accepts_scoped_names():
    assert parse_package("lodash@4.17.15") == ("lodash", "4.17.15")
    assert parse_package("@scope/pkg@1.2.3") == ("@scope/pkg", "1.2.3")


def test_first_sample_starts_and_later_samples_stop_on_the_average():
    assert should_start_run(0, 0, 0) is True
    assert should_start_run(1.0, 1, 2.5) is True
    assert should_start_run(2.0, 2, 2.5) is False
    assert should_start_run(2.5, 2, 2.5) is False


def test_response_cost_reads_provider_usage():
    class _Usage:
        cost = 0.125

    class _Response:
        usage = _Usage()

    assert response_cost(_Response()) == 0.125
    assert response_cost(object()) == 0.0


def test_batch_runs_each_package_the_requested_number_of_times_then_stops_at_the_cap():
    seen = []

    def invoke(state):
        seen.append((state["package_name"], state["package_version"], state["model_name"], state["retry_count"]))
        assert "retry_feedback" not in state
        return {"run_cost": 1.0, "classification": "fail", "retry_count": state["retry_count"]}

    summary = run_batch(
        [
            {"package_name": "left-pad", "package_version": "1.0.0", "num_runs": 3, "model": "openai/gpt-5.3-codex"},
            {"package_name": "semver", "package_version": "7.5.1", "num_runs": 3, "model": "openai/gpt-5.3-codex"},
        ],
        cost_cap=2.5,
        invoke=invoke,
    )

    assert seen == [
        ("left-pad", "1.0.0", "openai/gpt-5.3-codex", 0),
        ("left-pad", "1.0.0", "openai/gpt-5.3-codex", 0),
    ]
    assert summary["scheduled"] == 6
    assert summary["spent"] == 2.0
    assert summary["stopped_reason"] == "cost_cap"
    assert [run["classification"] for run in summary["runs"]] == ["fail", "fail"]


def test_oracle_failure_summary_keeps_rejected_attempts_and_a_failed_patch_check():
    lines = oracle_failure_summaries({
        "oracle_attempts": [
            {
                "attempt_number": 1,
                "generation": {"status": "generated"},
                "validation": {
                    "status": "INVALID",
                    "reason": "Expected vulnerable=EXPLOIT_SUCCEEDED and fixed=EXPLOIT_BLOCKED.",
                    "vulnerable": {"status": "OPERATION_FAILED"},
                    "fixed": {"status": "EXPLOIT_BLOCKED"},
                },
            },
            {
                "attempt_number": 2,
                "generation": {"status": "invalid", "explanation": "model response was not JSON"},
                "validation": {"status": "INVALID", "reason": "model response was not JSON"},
            },
            {
                "attempt_number": 3,
                "generation": {"status": "generated"},
                "validation": {"status": "VALID", "reason": "accepted"},
            },
        ],
        "generated_patch_oracle_validation": {
            "status": "SECURITY_FAIL",
            "reason": "The accepted exploit still succeeds against the generated patch.",
        },
    })
    assert lines == [
        "oracle attempt 1: INVALID vulnerable=OPERATION_FAILED fixed=EXPLOIT_BLOCKED "
        "— Expected vulnerable=EXPLOIT_SUCCEEDED and fixed=EXPLOIT_BLOCKED.",
        "oracle attempt 2: INVALID — model response was not JSON",
        "patch oracle: SECURITY_FAIL — The accepted exploit still succeeds against the generated patch.",
    ]
    summary = run_batch(
        [{"package_name": "pidusage", "package_version": "1.1.4", "num_runs": 1, "model": "mock"}],
        cost_cap=1,
        invoke=lambda state: {
            "run_cost": 0.0,
            "classification": "inconclusive",
            "retry_count": 0,
            "oracle_attempts": [{
                "attempt_number": 1,
                "generation": {"status": "failed", "explanation": "Docker image build failed."},
                "validation": {"status": "ERROR", "reason": "Docker image build failed."},
            }],
        },
    )
    assert summary["runs"][0]["oracle_failures"] == [
        "oracle attempt 1: ERROR — Docker image build failed.",
    ]


def test_oracle_failure_summary_includes_the_full_sandbox_log():
    lines = oracle_failure_summaries({
        "oracle_attempts": [{
            "attempt_number": 1,
            "generation": {"status": "generated"},
            "validation": {
                "status": "ERROR",
                "reason": "Oracle infrastructure failed.",
                "vulnerable": {
                    "status": "INFRA_ERROR",
                    "evidence": "Docker image build failed.",
                    "stdout": "",
                    "stderr": "ERROR: dockerDesktopLinuxEngine/_ping Internal Server Error\n" * 3,
                },
                "fixed": None,
            },
        }],
    })
    assert lines[0].startswith("oracle attempt 1: ERROR")
    assert lines[1] == "vulnerable log:"
    assert lines[2:].count("ERROR: dockerDesktopLinuxEngine/_ping Internal Server Error") == 3


def test_batch_uses_a_fresh_state_for_every_sample():
    def invoke(state):
        assert state["errors"] == []
        assert state["run_cost"] == 0.0
        assert state["max_retries"] == 1
        return {"run_cost": 0.0, "classification": "pass", "retry_count": 0}

    summary = run_batch(
        [{"package_name": "demo", "package_version": "1.0.0", "num_runs": 2, "model": "mock-diff-v1"}],
        cost_cap=5,
        model_provider="mock",
        invoke=invoke,
    )

    assert summary["stopped_reason"] is None
    assert len(summary["runs"]) == 2
    assert summary["spent"] == 0.0


def test_config_runs_each_package_with_its_model(tmp_path):
    path = tmp_path / "batch.json"
    path.write_text(
        json.dumps(
            {
                "cost_cap": 10,
                "model_provider": "mock",
                "packages": [
                    {"package": "left-pad@1.0.0", "num_runs": 2, "model": "model-a"},
                    {"package": "left-pad@1.0.0", "num_runs": 1, "model": "model-b"},
                    {"package": "@scope/pkg@2.0.0", "num_runs": 1, "model": "model-b"},
                ],
            }
        ),
        encoding="utf-8",
    )
    config = load_batch_config(path)
    seen = []

    def invoke(state):
        seen.append((state["package_name"], state["package_version"], state["model_name"]))
        return {"run_cost": 0.0, "classification": "pass", "retry_count": 0}

    summary = run_batch(
        config["jobs"],
        config["cost_cap"],
        model_provider=config["model_provider"],
        invoke=invoke,
    )

    assert seen == [
        ("left-pad", "1.0.0", "model-a"),
        ("left-pad", "1.0.0", "model-a"),
        ("left-pad", "1.0.0", "model-b"),
        ("@scope/pkg", "2.0.0", "model-b"),
    ]
    assert summary["scheduled"] == 4
    assert summary["stopped_reason"] is None


def test_config_rejects_an_unknown_openrouter_model(tmp_path):
    path = tmp_path / "batch.json"
    path.write_text(
        json.dumps(
            {
                "cost_cap": 1,
                "packages": [
                    {"package": "left-pad@1.0.0", "num_runs": 1, "model": "not-a-catalog-model"}
                ],
            }
        ),
        encoding="utf-8",
    )

    try:
        load_batch_config(path)
    except ValueError as exc:
        assert "left-pad@1.0.0" in str(exc)
    else:
        raise AssertionError("expected an unknown model to be rejected")
