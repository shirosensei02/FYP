from graph import increment_retry, route_after_classification, route_after_patch_generation


def test_generation_failure_skips_docker_and_goes_to_validation():
    assert route_after_patch_generation({"generation_status": "failed", "current_patch": None}) == "validation"


def test_generated_patch_goes_to_docker():
    assert route_after_patch_generation({"generation_status": "generated", "current_patch": {"diff": "..."}}) == "application"


def test_route_sends_a_successful_validation_to_maintainer_eval():
    assert route_after_classification({"classification": "pass", "retry_count": 0, "max_retries": 1}) == "eval"


def test_route_respects_zero_allowed_retries():
    assert route_after_classification({"classification": "fail", "retry_count": 0, "max_retries": 0}) == "eval"


def test_route_does_not_retry_infrastructure_failures():
    assert route_after_classification({
        "classification": "fail",
        "retry_count": 0,
        "max_retries": 1,
        "validation": {"failure_stage": "setup"},
    }) == "eval"


def test_route_retries_while_attempts_remain():
    assert route_after_classification({"classification": "fail", "retry_count": 0, "max_retries": 1}) == "retry"


def test_patch_generation_routes_a_graph_fetch_before_validation():
    assert route_after_patch_generation({
        "graph_request": {"caller": "patch_generation", "tool": "RetrieveEntity"},
        "generation_status": None,
        "current_patch": None,
    }) == "repo_graph"


def test_locator_and_generation_meet_the_package_graph():
    from graph import graph as compiled

    edges = {(edge.source, edge.target) for edge in compiled.get_graph().edges}
    assert ("og_patch_resolution_node", "repo_graph_node") in edges
    assert ("repo_graph_node", "locator_node") in edges
    assert ("locator_node", "repo_graph_node") in edges
    assert ("locator_node", "patch_generation_node") in edges
    assert ("patch_generation_node", "repo_graph_node") in edges
    assert ("repo_graph_node", "patch_generation_node") in edges


def test_increment_retry_only_advances_the_counter():
    update = increment_retry({"retry_count": 1, "classification_reason": "npm test failed"})
    assert update == {"retry_count": 2}
