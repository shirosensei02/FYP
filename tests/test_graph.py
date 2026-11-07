from graph import (
    increment_retry,
    route_after_apply,
    route_after_classification,
    route_after_generated_oracle,
    route_after_oracle_validation,
    route_after_patch_generation,
)


def test_generation_failure_skips_docker_and_goes_to_validation():
    assert route_after_patch_generation({"generation_status": "failed", "current_patch": None}) == "validation"


def test_generated_patch_goes_to_docker():
    assert route_after_patch_generation({"generation_status": "generated", "current_patch": {"diff": "..."}}) == "application"


def test_route_sends_a_successful_validation_to_maintainer_eval():
    assert route_after_classification({"classification": "pass", "retry_count": 0, "max_retries": 1}) == "eval"


def test_route_does_not_retry_inconclusive_or_unverified_security():
    for classification in ("inconclusive", "pass_unverified"):
        assert route_after_classification({
            "classification": classification,
            "retry_count": 0,
            "max_retries": 3,
        }) == "eval"


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


def test_locator_oracle_and_generation_meet():
    from graph import graph as compiled

    edges = {(edge.source, edge.target) for edge in compiled.get_graph().edges}
    assert ("og_patch_resolution_node", "repo_graph_node") in edges
    assert ("repo_graph_node", "locator_node") in edges
    assert ("locator_node", "repo_graph_node") in edges
    assert ("locator_node", "vulnerability_localization_node") in edges
    assert ("vulnerability_localization_node", "oracle_generation_node") in edges
    assert ("oracle_generation_node", "oracle_validation_node") in edges
    assert ("oracle_validation_node", "oracle_generation_node") in edges
    assert ("oracle_validation_node", "patch_generation_node") in edges
    assert ("patch_generation_node", "repo_graph_node") in edges
    assert ("repo_graph_node", "patch_generation_node") in edges
    assert ("patch_generation_node", "candidate_selection_node") in edges
    assert ("candidate_selection_node", "apply_patch_node") in edges
    assert ("apply_patch_node", "generated_patch_oracle_validation_node") in edges


def test_increment_retry_advances_counter_and_clears_stale_oracle_verdict():
    update = increment_retry({
        "retry_count": 1,
        "classification_reason": "npm test failed",
        "generated_patch_oracle_validation": {"status": "SECURITY_PASS"},
    })
    assert update == {"retry_count": 2, "generated_patch_oracle_validation": None}


def test_invalid_oracle_retries_within_its_budget():
    assert route_after_oracle_validation({
        "oracle_validation": {"status": "INVALID"},
        "oracle_attempt_count": 2,
        "max_oracle_attempts": 5,
    }) == "retry"


def test_applied_patch_goes_to_the_oracle_before_package_tests():
    assert route_after_apply({"patch_applied": True}) == "oracle"
    assert route_after_apply({"patch_applied": False}) == "validation"


def test_locked_oracle_failure_retries_before_package_tests():
    failing = {
        "generated_patch_oracle_validation": {"status": "SECURITY_FAIL"},
        "retry_count": 0,
        "max_retries": 2,
    }
    assert route_after_generated_oracle(failing) == "retry"
    assert route_after_generated_oracle({
        **failing,
        "generated_patch_oracle_validation": {"status": "REGRESSION"},
    }) == "retry"
    assert route_after_generated_oracle({**failing, "retry_count": 2}) == "terminal"


def test_inconclusive_oracle_still_runs_package_tests():
    for status in ("SECURITY_PASS", "INCONCLUSIVE", "SKIPPED"):
        assert route_after_generated_oracle({
            "generated_patch_oracle_validation": {"status": status},
            "retry_count": 0,
            "max_retries": 2,
        }) == "package_tests"


def test_oracle_stops_retrying_at_budget_or_on_error():
    assert route_after_oracle_validation({
        "oracle_validation": {"status": "INVALID"},
        "oracle_attempt_count": 5,
        "max_oracle_attempts": 5,
    }) == "continue"
    assert route_after_oracle_validation({
        "oracle_validation": {"status": "ERROR"},
        "oracle_attempt_count": 1,
        "max_oracle_attempts": 5,
    }) == "continue"
