from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, START, StateGraph

import chat_graph
from chat_graph import _parse_request, _parse_targets, _select_vulnerability, chat_input


def test_parse_request_reads_package_advisory_and_model():
    assert _parse_request("jszip@3.7.1 GHSA-36fh-84j7-cv5h codex") == {
        "package_name": "jszip",
        "package_version": "3.7.1",
        "vulnerability_id": "GHSA-36fh-84j7-cv5h",
        "model_name": "openai/gpt-5.3-codex",
    }
    assert _parse_request("please patch @actions/artifact@2.1.1 with anthropic/claude-sonnet-5") == {
        "package_name": "@actions/artifact",
        "package_version": "2.1.1",
        "model_name": "anthropic/claude-sonnet-5",
    }
    assert _parse_request("hello there") == {}


def test_parse_targets_splits_segments_and_shares_models(monkeypatch):
    monkeypatch.setenv("MODEL_NAME", "openai/gpt-5.3-codex")

    targets = _parse_targets(
        "jszip@3.7.1 GHSA-36fh-84j7-cv5h, tar-fs@3.0.8 GHSA-8cj5-5rvv-wf4v sonnet\njoi@18.2.5 codex; pm2@6.0.14"
    )

    assert [(t["package_name"], t["model_name"]) for t in targets] == [
        ("jszip", "anthropic/claude-sonnet-5"),  # no model before it: first model named anywhere
        ("tar-fs", "anthropic/claude-sonnet-5"),
        ("joi", "openai/gpt-5.3-codex"),
        ("pm2", "openai/gpt-5.3-codex"),  # inherits the nearest model named before it
    ]
    assert targets[1]["vulnerability_id"] == "GHSA-8cj5-5rvv-wf4v"
    assert [t["model_name"] for t in _parse_targets("jszip@3.7.1")] == ["openai/gpt-5.3-codex"]


def test_chat_input_reads_only_the_newest_message():
    result = chat_input(
        {
            "messages": [
                HumanMessage(content="jszip@3.7.1 codex"),
                AIMessage(content="🏁 done"),
                HumanMessage(content="tar-fs@3.0.8 sonnet"),
            ],
            "targets": [{"package_name": "jszip"}],
            "results": [{"package": "jszip@3.7.1"}],
        }
    )

    assert [t["package_name"] for t in result["targets"]] == ["tar-fs"]
    assert result["results"] == [] and result["run"] == {} and result["target_index"] == 0


def test_chat_input_explains_usage_when_message_has_no_package():
    result = chat_input({"messages": [HumanMessage(content="patch something")]})

    assert result["input_error"]
    assert "jszip@3.7.1" in result["messages"][0].content
    assert chat_graph.route_after_input(result) == "end"


def test_chat_input_caps_the_number_of_targets():
    text = ", ".join(f"pkg{i}@1.0.{i}" for i in range(chat_graph.MAX_TARGETS + 2))

    result = chat_input({"messages": [HumanMessage(content=text)]})

    assert len(result["targets"]) == chat_graph.MAX_TARGETS
    assert "Only the first" in result["messages"][0].content


def test_select_vulnerability_pins_by_id_or_alias():
    found = [{"id": "GHSA-a", "aliases": ["CVE-1"]}, {"id": "GHSA-b", "aliases": ["CVE-2"]}]

    assert _select_vulnerability({"vulnerability_id": "cve-2"}, {"current_vulnerabilities": found})["current_vulnerabilities"] == [found[1]]
    assert _select_vulnerability({"vulnerability_id": "GHSA-z"}, {"current_vulnerabilities": found})["current_vulnerabilities"] == []
    assert _select_vulnerability({}, {"current_vulnerabilities": found})["current_vulnerabilities"] == found


def test_chat_graph_has_exactly_the_pipeline_steps_plus_chat_steps():
    import graph as main_graph

    main_nodes = set(main_graph.graph.get_graph().nodes) - {"__start__", "__end__"}
    chat_nodes = set(chat_graph.graph.get_graph().nodes) - {"__start__", "__end__"}
    assert chat_nodes == main_nodes | {"chat_input", "start_target", "finish_target", "batch_summary"}


def test_sandbox_summary_reports_stage_statuses_and_regression():
    summary = chat_graph._summary(
        "package_validation_node",
        {
            "validation": {"docker_status": "PASS", "installation_status": "PASS", "build_status": "SKIPPED",
                           "test_status": "FAIL", "failure_stage": "tests"},
            "regression_status": "REGRESSION",
        },
    )

    assert "Docker ✅" in summary and "build –" in summary and "tests ❌" in summary
    assert "Failed at: tests" in summary and "REGRESSION" in summary


def test_tool_loop_steps_stay_quiet():
    assert chat_graph._summary("repo_graph_node", {}) is None
    assert chat_graph._summary("locator_node", {"locate_status": "running"}) is None
    assert chat_graph._summary("patch_generation_node", {"graph_request": {"tool": "x"}}) is None
    assert "Locator ranked" in chat_graph._summary(
        "locator_node", {"locate_status": "ranked", "debug_locations": [{"path": "lib/load.js", "function": "load"}]}
    )


def _fake_pipeline(seen_states):
    """A three-step stand-in for graph.py with the same node names the chat graph relies on."""

    def package_input_node(state):
        seen_states.append(dict(state))
        return {"source_dir": f"/tmp/{state['package_name']}"}

    def vulnerability_detection_node(state):
        return {"current_vulnerabilities": [{"id": "GHSA-aaaa-aaaa-aaaa", "aliases": []}, {"id": "GHSA-bbbb-bbbb-bbbb", "aliases": []}]}

    def patch_validation_node(state):
        return {"classification": "pass", "classification_reason": "ok", "run_cost": 0.25}

    builder = StateGraph(dict)
    builder.add_node("package_input_node", package_input_node)
    builder.add_node("vulnerability_detection_node", vulnerability_detection_node)
    builder.add_node("patch_validation_node", patch_validation_node)
    builder.add_edge(START, "package_input_node")
    builder.add_edge("package_input_node", "vulnerability_detection_node")
    builder.add_edge("vulnerability_detection_node", "patch_validation_node")
    builder.add_edge("patch_validation_node", END)
    return builder.compile()


def test_several_targets_run_one_after_another_with_fresh_state(monkeypatch):
    monkeypatch.setenv("MODEL_NAME", "openai/gpt-5.3-codex")
    seen = []
    chat = chat_graph.build_chat_graph(_fake_pipeline(seen))

    final = chat.invoke({"messages": [HumanMessage(content="jszip@3.7.1 GHSA-bbbb-bbbb-bbbb codex, tar-fs@3.0.8 GHSA-zzzz-zzzz-zzzz sonnet")]})

    assert [s["package_name"] for s in seen] == ["jszip", "tar-fs"]
    assert "source_dir" not in seen[1] and "classification" not in seen[1]  # nothing leaked from jszip
    first, second = final["results"]
    assert (first["advisory"], first["classification"], first["cost"]) == ("GHSA-bbbb-bbbb-bbbb", "pass", 0.25)
    assert second["classification"] == "not run" and "not detected" in second["reason"]
    texts = [m.content for m in final["messages"] if m.type == "ai"]
    assert any(t.startswith("**[1/2 jszip]**") for t in texts)
    assert "📊 **Summary**" in texts[-1] and "| tar-fs@3.0.8 |" in texts[-1]


def test_every_pipeline_step_has_a_named_summary():
    import graph as main_graph

    steps = set(main_graph.graph.get_graph().nodes) - {"__start__", "__end__"}
    assert steps - set(chat_graph.STEP_TITLES) <= {"repo_graph_node"}  # quiet tool-loop step
