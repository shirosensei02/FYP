from graph import route_after_classification, route_after_patch_generation


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
