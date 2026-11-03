from debugger import route_after_debugger, route_after_index
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


def test_index_routes_a_running_debug_loop_to_the_debugger():
    assert route_after_index({"debug_status": "running"}) == "debugger"


def test_index_routes_a_finished_debug_loop_to_generation():
    assert route_after_index({"debug_status": "located"}) == "generation"
    assert route_after_index({"debug_status": "cannot_locate"}) == "generation"
    assert route_after_index({"debug_status": "capped"}) == "generation"


def test_debugger_routes_a_lookup_back_to_the_index():
    assert route_after_debugger({"debug_request": {"request": ["lib/parse.js:normalize"]}}) == "index"
    assert route_after_debugger({"debug_request": None, "debug_status": "located"}) == "generation"


def test_increment_retry_only_advances_the_counter():
    update = increment_retry({"retry_count": 1, "classification_reason": "npm test failed"})
    assert update == {"retry_count": 2}
