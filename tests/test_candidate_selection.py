from pathlib import Path

import candidate_selection as selection

FIX = "--- a/lib/x.js\n+++ b/lib/x.js\n@@ -1 +1 @@\n-bad\n+good\n"
BIG_FIX = "--- a/lib/x.js\n+++ b/lib/x.js\n@@ -1 +1,3 @@\n-bad\n+good\n+extra1\n+extra2\n"
NOOP = "--- a/lib/x.js\n+++ b/lib/x.js\n@@ -1 +1 @@\n-bad\n+bad // checked\n"


def _state(*diffs, **extra):
    candidates = [{"diff": diff, "raw_output": {"diff": diff}, "target_files": ["lib/x.js"]} for diff in diffs]
    primary = {"diff": diffs[0], "raw_output": {"diff": diffs[0]}, "model_used": "m", "attempt_number": 1}
    return {
        "candidate_patches": candidates,
        "accepted_oracle": {"status": "accepted", "source": "..."},
        "generation_status": "generated",
        "current_patch": dict(primary),
        "patch_attempts": [dict(primary)],
        **extra,
    }


def _verdicts(monkeypatch, by_diff):
    calls = []

    def fake_evaluate(state, candidate):
        calls.append(candidate["diff"])
        return by_diff[candidate["diff"]], f"stub {by_diff[candidate['diff']]}"

    monkeypatch.setattr(selection, "_evaluate", fake_evaluate)
    return calls


def test_identical_samples_are_clustered_ignoring_trailing_whitespace():
    candidates = [{"diff": FIX}, {"diff": FIX.replace("+good", "+good   ")}, {"diff": NOOP}, {"diff": FIX}]

    assert selection.cluster_candidates(candidates) == [[0, 1, 3], [2]]


def test_nothing_to_choose_between_is_a_no_op(monkeypatch):
    calls = _verdicts(monkeypatch, {})

    assert selection.candidate_selection(_state(FIX)) == {}
    assert selection.candidate_selection({**_state(FIX, NOOP), "accepted_oracle": None}) == {}
    assert selection.candidate_selection({**_state(FIX, NOOP), "generation_status": "failed"}) == {}
    assert calls == []


def test_identical_samples_skip_the_oracle_entirely(monkeypatch):
    calls = _verdicts(monkeypatch, {})

    update = selection.candidate_selection(_state(FIX, FIX, FIX))

    assert calls == []
    assert update["candidate_selection"]["status"] == "skipped"
    assert update["candidate_selection"]["unique"] == 1
    assert "current_patch" not in update


def test_a_patch_that_blocks_the_exploit_beats_the_primary(monkeypatch):
    _verdicts(monkeypatch, {NOOP: "SECURITY_FAIL", FIX: "SECURITY_PASS"})
    state = _state(NOOP, FIX)

    update = selection.candidate_selection(state)

    summary = update["candidate_selection"]
    assert summary["chosen_index"] == 1
    assert summary["chosen_is_primary"] is False
    assert summary["primary_status"] == "SECURITY_FAIL"
    assert summary["oracle_passes"] == 1
    assert update["current_patch"]["diff"] == FIX
    assert update["current_patch"]["model_used"] == "m"
    assert update["current_patch"]["target_files"] == ["lib/x.js"]
    assert update["patch_attempts"][-1] is update["current_patch"]
    assert state["current_patch"]["diff"] == NOOP


def test_the_primary_stays_when_it_is_already_the_best(monkeypatch):
    _verdicts(monkeypatch, {FIX: "SECURITY_PASS", NOOP: "SECURITY_FAIL"})

    update = selection.candidate_selection(_state(FIX, NOOP))

    assert update["candidate_selection"]["chosen_is_primary"] is True
    assert "current_patch" not in update and "patch_attempts" not in update


def test_ties_go_to_the_larger_cluster_then_the_smaller_diff_then_the_primary(monkeypatch):
    _verdicts(monkeypatch, {FIX: "SECURITY_PASS", BIG_FIX: "SECURITY_PASS", NOOP: "SECURITY_PASS"})

    majority = selection.candidate_selection(_state(BIG_FIX, FIX, FIX))
    smaller = selection.candidate_selection(_state(BIG_FIX, FIX))
    primary = selection.candidate_selection(_state(NOOP, FIX))

    assert majority["current_patch"]["diff"] == FIX
    assert smaller["current_patch"]["diff"] == FIX
    assert primary["candidate_selection"]["chosen_index"] == 0


def test_status_ranking_prefers_inconclusive_to_failing_and_broken_patches(monkeypatch):
    _verdicts(monkeypatch, {
        FIX: "SECURITY_FAIL", BIG_FIX: "REGRESSION", NOOP: "INCONCLUSIVE",
        "--- a/y.js\n+++ b/y.js\n@@ -1 +1 @@\n-a\n+b\n": "APPLY_FAILED",
    })
    apply_failed = "--- a/y.js\n+++ b/y.js\n@@ -1 +1 @@\n-a\n+b\n"

    update = selection.candidate_selection(_state(apply_failed, BIG_FIX, FIX, NOOP))

    assert update["candidate_selection"]["chosen_index"] == 3
    statuses = {entry["index"]: entry["oracle_status"] for entry in update["candidate_selection"]["entries"]}
    assert statuses == {0: "APPLY_FAILED", 1: "REGRESSION", 2: "SECURITY_FAIL", 3: "INCONCLUSIVE"}


def test_a_failed_evaluation_is_inconclusive_and_never_aborts_selection(monkeypatch, tmp_path):
    def broken_seed(source_dir, work_dir):
        raise FileNotFoundError("source vanished")

    monkeypatch.setattr(selection, "PATCH_WORKSPACE_ROOT", tmp_path / "work")
    monkeypatch.setattr(selection, "_seed_workspace_from_source", broken_seed)

    status, reason = selection._evaluate({"accepted_oracle": {}}, {"diff": FIX})

    assert status == "INCONCLUSIVE"
    assert "source vanished" in reason
    assert list((tmp_path / "work").iterdir()) == []


def test_evaluate_applies_the_candidate_runs_the_oracle_and_cleans_up(monkeypatch, tmp_path):
    seen = {}

    def fake_apply(work_dir, name, version, patch):
        seen["applied"] = (name, version, patch["diff"], Path(work_dir).is_dir())
        return True

    def fake_run(work_dir, oracle, label):
        seen["label"] = label
        seen["workspace"] = Path(work_dir)
        return {"status": "EXPLOIT_BLOCKED"}

    monkeypatch.setattr(selection, "PATCH_WORKSPACE_ROOT", tmp_path / "work")
    monkeypatch.setattr(selection, "_seed_workspace_from_source", lambda source, work: None)
    monkeypatch.setattr(selection, "_write_patched_package", fake_apply)
    monkeypatch.setattr(selection, "_run_oracle", fake_run)

    status, _ = selection._evaluate(
        {"package_name": "demo", "package_version": "1.0.0", "accepted_oracle": {"source": "x"}}, {"diff": FIX}
    )

    assert status == "SECURITY_PASS"
    assert seen["applied"] == ("demo", "1.0.0", FIX, True)
    assert seen["label"] == "candidate"
    assert not seen["workspace"].exists()


def test_a_candidate_that_does_not_apply_is_reported_without_running_the_oracle(monkeypatch, tmp_path):
    monkeypatch.setattr(selection, "PATCH_WORKSPACE_ROOT", tmp_path / "work")
    monkeypatch.setattr(selection, "_seed_workspace_from_source", lambda source, work: None)
    monkeypatch.setattr(selection, "_write_patched_package", lambda *args: False)
    monkeypatch.setattr(selection, "_run_oracle", lambda *args: (_ for _ in ()).throw(AssertionError("ran")))

    status, _ = selection._evaluate({"accepted_oracle": {}}, {"diff": FIX})

    assert status == "APPLY_FAILED"
