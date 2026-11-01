from langchain_core.messages import HumanMessage

import demo_graph
from demo_graph import _parse_request, _select_vulnerability, demo_input


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
    assert _parse_request("tar-fs@3.0.8 CVE-2025-48387 sonnet")["vulnerability_id"] == "CVE-2025-48387"
    assert _parse_request("hello there") == {}


def test_demo_input_from_chat_message(monkeypatch):
    monkeypatch.setenv("MODEL_NAME", "openai/gpt-5.3-codex")
    monkeypatch.delenv("MAX_RETRIES", raising=False)

    result = demo_input({"messages": [HumanMessage(content="joi@18.2.5 GHSA-6h2x-m376-mqjq sonnet")]})

    assert result["package_name"] == "joi"
    assert result["package_version"] == "18.2.5"
    assert result["vulnerability_id"] == "GHSA-6h2x-m376-mqjq"
    assert result["model_name"] == "anthropic/claude-sonnet-5"
    assert result["retry_count"] == 0 and result["max_retries"] == 0
    assert result["progress"][0]["step"] == "demo_input"


def test_demo_input_prefers_form_fields_and_falls_back_to_env_model(monkeypatch):
    monkeypatch.setenv("MODEL_NAME", "openai/gpt-5.3-codex")

    result = demo_input({"package_name": "pm2", "package_version": "6.0.14", "vulnerability_id": "GHSA-x5gf-qvw8-r2rm"})

    assert (result["package_name"], result["model_name"]) == ("pm2", "openai/gpt-5.3-codex")


def test_demo_input_explains_usage_when_message_has_no_package():
    result = demo_input({"messages": [HumanMessage(content="patch something")]})

    assert result["input_error"]
    assert "jszip@3.7.1" in result["messages"][0].content
    assert demo_graph.route_after_input({**result}) == "end"


def test_select_vulnerability_pins_by_id_or_alias():
    found = [{"id": "GHSA-a", "aliases": ["CVE-1"]}, {"id": "GHSA-b", "aliases": ["CVE-2"]}]

    assert _select_vulnerability({"vulnerability_id": "cve-2"}, {"current_vulnerabilities": found})["current_vulnerabilities"] == [found[1]]
    assert _select_vulnerability({"vulnerability_id": "GHSA-z"}, {"current_vulnerabilities": found})["current_vulnerabilities"] == []
    assert _select_vulnerability({}, {"current_vulnerabilities": found})["current_vulnerabilities"] == found


def test_progress_wrapper_keeps_node_output_and_adds_summary():
    wrapped = demo_graph._with_progress("patch_validation_node", lambda state: {"classification": "pass", "classification_reason": "ok", "mongo_id": None})

    result = wrapped({"package_name": "x"})

    assert result["classification"] == "pass"
    assert "PASS" in result["messages"][0].content and "not saved" in result["messages"][0].content
    assert result["progress"][0]["step"] == "patch_validation_node"


def test_demo_graph_has_same_pipeline_nodes_as_main_graph():
    import graph as main_graph

    main_nodes = set(main_graph.graph.get_graph().nodes) - {"__start__", "__end__"}
    demo_nodes = set(demo_graph.graph.get_graph().nodes) - {"__start__", "__end__", "demo_input"}
    assert demo_nodes == main_nodes
