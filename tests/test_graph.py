from graph import (
    increment_retry,
    route_after_classification,
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
