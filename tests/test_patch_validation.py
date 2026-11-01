import patch_validation as patch_validation_module
from patch_validation import patch_validation


def _stub_persistence(monkeypatch, attempt_id="fake_attempt_id", result_id="fake_result_id"):
    calls = {"attempt": [], "result": []}

    def fake_save_attempt(state, passed):
        calls["attempt"].append({"state": state, "passed": passed})
        return attempt_id

    def fake_save_result(state, passed, all_attempts_id=None):
        calls["result"].append(
            {"state": state, "passed": passed, "all_attempts_id": all_attempts_id}
        )
        return result_id if passed else None

    monkeypatch.setattr(patch_validation_module, "save_patch_attempt", fake_save_attempt)
    monkeypatch.setattr(patch_validation_module, "save_patch_result", fake_save_result)
    return calls


def _state(**overrides):
    state = {
        "package_name": "demo",
        "package_version": "1.0.0",
        "current_patch": {"model_used": "generator", "diff": "patch"},
        "regression_status": "NO_REGRESSION",
        "validation": {
            "validation_mode": "published_package",
            "build_status": "SKIPPED",
            "test_status": "SKIPPED",
            "consumer_smoke_status": "PASS",
        },
        "adversarial_evaluation": {"genuine_fix": "true"},
        "maintainer_eval": {"status": "evaluated", "verdict": "COMPLETE"},
    }
    state.update(overrides)
    return state


def test_confirmed_fix_is_the_only_successful_patch(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(_state())

    assert result["compatibility_status"] == "PASS"
    assert result["security_fix_status"] == "PASS"
    assert result["final_patch_status"] == "PASS"
    assert result["classification"] == "pass"
    assert "confirmed" in result["classification_reason"]
    assert calls["attempt"][0]["passed"] is True
    assert calls["attempt"][0]["state"]["final_patch_status"] == "PASS"
    assert calls["result"][0]["passed"] is True
    assert calls["result"][0]["all_attempts_id"] == "fake_attempt_id"


def test_compatibility_only_result_is_partial_and_not_successful(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(
        _state(
            adversarial_evaluation={"genuine_fix": "uncertain"},
            maintainer_eval={"status": "skipped"},
        )
    )

    assert result["compatibility_status"] == "PASS"
    assert result["security_fix_status"] == "UNCERTAIN"
    assert result["final_patch_status"] == "PARTIAL"
    assert result["classification"] == "fail"
    assert "not considered successful" in result["classification_reason"]
    assert calls["attempt"][0]["passed"] is False
    assert calls["result"] == []


def test_false_adversarial_verdict_fails_compatible_patch(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(
        _state(adversarial_evaluation={"genuine_fix": "false"})
    )

    assert result["compatibility_status"] == "PASS"
    assert result["security_fix_status"] == "FAIL"
    assert result["final_patch_status"] == "FAIL"
    assert "did not fix" in result["classification_reason"]
    assert calls["result"] == []


def test_incomplete_maintainer_verdict_fails_compatible_patch(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(
        _state(
            adversarial_evaluation={"genuine_fix": "true"},
            maintainer_eval={"status": "evaluated", "verdict": "INCOMPLETE"},
        )
    )

    assert result["security_fix_status"] == "FAIL"
    assert result["final_patch_status"] == "FAIL"
    assert calls["result"] == []


def test_partial_maintainer_verdict_remains_uncertain(monkeypatch):
    _stub_persistence(monkeypatch)

    result = patch_validation(
        _state(maintainer_eval={"status": "evaluated", "verdict": "PARTIAL"})
    )

    assert result["security_fix_status"] == "UNCERTAIN"
    assert result["final_patch_status"] == "PARTIAL"


def test_regression_fails_even_with_confirmed_security_evidence(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(_state(regression_status="REGRESSION"))

    assert result["compatibility_status"] == "FAIL"
    assert result["security_fix_status"] == "PASS"
    assert result["final_patch_status"] == "FAIL"
    assert "baseline passed" in result["classification_reason"]
    assert calls["result"] == []


def test_failed_baseline_is_inconclusive_and_not_successful(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(_state(regression_status="INCONCLUSIVE"))

    assert result["compatibility_status"] == "INCONCLUSIVE"
    assert result["final_patch_status"] == "FAIL"
    assert "could not be determined" in result["classification_reason"]
    assert calls["result"] == []


def test_generation_failure_reason_takes_priority(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(
        {
            "generation_status": "failed",
            "generation_error": "Model returned no diff",
            "validation": {},
        }
    )

    assert result["classification"] == "fail"
    assert result["security_fix_status"] == "FAIL"
    assert result["classification_reason"] == "Model returned no diff"
    assert calls["attempt"][0]["passed"] is False
    assert calls["result"] == []


def test_legacy_compatibility_flags_still_work(monkeypatch):
    _stub_persistence(monkeypatch)

    result = patch_validation(
        _state(
            regression_status=None,
            validation={"build_succeeded": True, "tests_passed": True},
        )
    )

    assert result["compatibility_status"] == "PASS"
    assert result["final_patch_status"] == "PASS"


def test_attempt_save_failure_does_not_block_success_evaluation(monkeypatch):
    monkeypatch.setattr(patch_validation_module, "save_patch_attempt", lambda state, passed: None)
    result_calls = []

    def fake_save_result(state, passed, all_attempts_id=None):
        result_calls.append(all_attempts_id)
        return None

    monkeypatch.setattr(patch_validation_module, "save_patch_result", fake_save_result)

    result = patch_validation(_state())

    assert result["classification"] == "pass"
    assert result["mongo_id"] is None
    assert result_calls == [None]


def test_db_rejects_non_final_pass_even_when_caller_passes_true(monkeypatch):
    import db

    monkeypatch.setattr(db, "_get_db", lambda: (_ for _ in ()).throw(AssertionError("must not write")))

    assert db.save_patch_result({"final_patch_status": "PARTIAL"}, passed=True) is None
