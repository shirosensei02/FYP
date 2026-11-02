import json

from batch_runner import load_batch_config, parse_package, run_batch, should_start_run
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
