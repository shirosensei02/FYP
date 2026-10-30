import patch_validation as patch_validation_module
from patch_validation import patch_validation


def _stub_persistence(monkeypatch, attempt_id="fake_attempt_id", result_id="fake_result_id"):
    calls = {"attempt": [], "result": []}

    def fake_save_attempt(state, passed):
        calls["attempt"].append({"passed": passed})
        return attempt_id

    def fake_save_result(state, passed, all_attempts_id=None):
        calls["result"].append({"passed": passed, "all_attempts_id": all_attempts_id})
        return result_id if passed else None

    monkeypatch.setattr(patch_validation_module, "save_patch_attempt", fake_save_attempt)
    monkeypatch.setattr(patch_validation_module, "save_patch_result", fake_save_result)
    return calls


def test_patch_validation_pass_persists_attempt_and_result(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(
        {
            "validation": {"build_succeeded": True, "tests_passed": True},
            "package_name": "lodash",
            "package_version": "4.17.15",
            "current_patch": {"model_used": "mock-diff-v1"},
        }
    )

    assert result["classification"] == "pass"
    assert result["classification_reason"] == "Docker build succeeded and package validation passed."
    assert result["mongo_id"] == "fake_attempt_id"
    assert calls["attempt"] == [{"passed": True}]
    assert calls["result"] == [{"passed": True, "all_attempts_id": "fake_attempt_id"}]


def test_no_regression_is_the_only_comparison_success(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(
        {
            "regression_status": "NO_REGRESSION",
            "validation": {"build_succeeded": True, "tests_passed": True},
        }
    )

    assert result["classification"] == "pass"
    assert result["classification_reason"] == (
        "Baseline and patched package validation passed; no regression was detected."
    )
    assert calls["result"] == [{"passed": True, "all_attempts_id": "fake_attempt_id"}]


def test_published_package_no_regression_explains_compatibility_scope(monkeypatch):
    _stub_persistence(monkeypatch)

    result = patch_validation(
        {
            "regression_status": "NO_REGRESSION",
            "validation": {
                "validation_mode": "published_package",
                "build_status": "SKIPPED",
                "test_status": "SKIPPED",
                "consumer_smoke_status": "PASS",
            },
        }
    )

    assert result["classification"] == "pass"
    assert "no compatibility regression" in result["classification_reason"]
    assert "does not independently confirm" in result["classification_reason"]


def test_regression_fails_even_when_patched_flags_are_true(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(
        {
            "regression_status": "REGRESSION",
            "validation": {"build_succeeded": True, "tests_passed": True},
        }
    )

    assert result["classification"] == "fail"
    assert result["classification_reason"] == (
        "The baseline passed, but the patched package failed validation."
    )
    assert calls["result"] == []


def test_inconclusive_baseline_is_not_saved_as_success(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(
        {
            "regression_status": "INCONCLUSIVE",
            "validation": {"build_succeeded": False, "tests_passed": False},
        }
    )

    assert result["classification"] == "fail"
    assert "could not be determined" in result["classification_reason"]
    assert calls["result"] == []


def test_patched_only_pass_remains_inconclusive(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation(
        {
            "regression_status": "PATCHED_ONLY_PASS",
            "validation": {"build_succeeded": True, "tests_passed": True},
        }
    )

    assert result["classification"] == "fail"
    assert "failed baseline" in result["classification_reason"]
    assert calls["result"] == []


def test_patch_validation_fail_on_build_skips_result_save(monkeypatch):
    calls = _stub_persistence(monkeypatch)

    result = patch_validation({"validation": {"build_succeeded": False, "tests_passed": False}})

    assert result["classification"] == "fail"
    assert result["classification_reason"] == "Docker build failed — patch could not be applied."
    assert calls["attempt"] == [{"passed": False}]
    assert calls["result"] == []


def test_patch_validation_fail_on_tests_only(monkeypatch):
    _stub_persistence(monkeypatch)

    result = patch_validation({"validation": {"build_succeeded": True, "tests_passed": False}})

    assert result["classification"] == "fail"
    assert result["classification_reason"] == "Build succeeded but npm test failed — patch broke the package."


def test_patch_validation_generation_failed_reason_takes_priority(monkeypatch):
    _stub_persistence(monkeypatch)

    result = patch_validation(
        {
            "generation_status": "failed",
            "generation_error": "Model returned no diff",
            "validation": {},
        }
    )

    assert result["classification"] == "fail"
    assert result["classification_reason"] == "Model returned no diff"


def test_patch_validation_generation_failed_default_reason(monkeypatch):
    _stub_persistence(monkeypatch)

    result = patch_validation({"generation_status": "failed", "validation": {}})

    assert result["classification_reason"] == "Patch generation failed before sandbox validation."


def test_patch_validation_missing_validation_defaults_to_fail(monkeypatch):
    _stub_persistence(monkeypatch)

    result = patch_validation({})

    assert result["classification"] == "fail"


def test_patch_validation_continues_when_attempt_save_fails(monkeypatch):
    monkeypatch.setattr(patch_validation_module, "save_patch_attempt", lambda state, passed: None)
    result_calls = []

    def fake_save_result(state, passed, all_attempts_id=None):
        result_calls.append(all_attempts_id)
        return None

    monkeypatch.setattr(patch_validation_module, "save_patch_result", fake_save_result)

    result = patch_validation({"validation": {"build_succeeded": True, "tests_passed": True}})

    assert result["classification"] == "pass"
    assert result["mongo_id"] is None
    assert result_calls == [None]
