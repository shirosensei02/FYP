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
