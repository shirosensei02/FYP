from datetime import datetime, timedelta, timezone

import metrics_report as metrics

NOW = datetime(2026, 11, 7, tzinfo=timezone.utc)

PIDUSAGE_DIFF = (
    "--- a/lib/stats.js\n+++ b/lib/stats.js\n@@ -1,2 +1,3 @@\n"
    "-old1\n+new1\n+new2\n context\n"
)
LARGE_DIFF = "--- a/lib/a.js\n+++ b/lib/a.js\n@@ -1 +1 @@\n" + "".join(f"-x{i}\n+y{i}\n" for i in range(15))


def _doc(run, *, attempt=1, passed=False, model="anthropic/claude-sonnet-5", regression=None,
         oracle=None, judge=None, accepted=False, baseline=None, diff=PIDUSAGE_DIFF,
         vendor_files=("lib/stats.js", "test/test.js"), shown=("lib/stats.js",),
         summary="Command injection in pid via child_process.exec", generation_status="generated"):
    return {
        "attempt_id": run,
        "attempt_number": attempt,
        "timestamp": NOW + timedelta(minutes=attempt),
        "passed": passed,
        "model_used": model,
        "regression_status": regression,
        "generation_status": generation_status,
        "generated_patch_oracle_validation": {"status": oracle} if oracle else {},
        "oracle_validation": {"status": baseline} if baseline else {},
        "accepted_oracle": {"status": "accepted"} if accepted else {},
        "adversarial_evaluation": {"genuine_fix": judge} if judge else {},
        "answer_key": {"summary": summary, "files": list(vendor_files), "diff": diff},
        "context_file_paths": list(shown),
        "vulnerabilities": [],
    }


def test_final_attempt_per_run_is_selected():
    docs = [
        _doc("run-a", attempt=1, oracle="SECURITY_FAIL"),
        _doc("run-a", attempt=2, passed=True, oracle="SECURITY_PASS"),
        _doc("run-b", attempt=1),
    ]

    runs = metrics.final_attempts(docs)

    assert len(runs) == 2
    assert {doc["attempt_id"]: doc["attempt_number"] for doc in runs} == {"run-a": 2, "run-b": 1}


def test_documents_without_a_run_id_are_each_their_own_run():
    docs = [{"passed": True}, {"passed": False}]

    assert len(metrics.final_attempts(docs)) == 2


def test_outcome_classification_mirrors_patch_validation():
    assert metrics.classify_outcome(_doc("a", passed=True)) == "pass"
    assert metrics.classify_outcome(_doc("a", regression="NO_REGRESSION")) == "inconclusive"
    assert metrics.classify_outcome(_doc("a", regression="NO_REGRESSION", oracle="INCONCLUSIVE")) == "inconclusive"
    assert metrics.classify_outcome(_doc("a", regression="NO_REGRESSION", oracle="SECURITY_FAIL")) == "fail"
    assert metrics.classify_outcome(_doc("a", regression="REGRESSION")) == "fail"
    assert metrics.classify_outcome(_doc("a", regression="NO_REGRESSION", generation_status="failed")) == "fail"


def test_headline_rates_and_oracle_coverage():
    docs = [
        _doc("r1", passed=True, regression="NO_REGRESSION", oracle="SECURITY_PASS", accepted=True, baseline="VALID"),
        _doc("r2", oracle="SECURITY_FAIL", accepted=True, baseline="VALID"),
        _doc("r3", regression="NO_REGRESSION", oracle="INCONCLUSIVE", baseline="SKIPPED"),
        _doc("legacy"),
    ]

    overall = metrics.compute_metrics(docs)["overall"]

    assert overall["runs"] == 4
    assert overall["outcomes"] == {"pass": 1, "inconclusive": 1, "fail": 2}
    assert overall["pass_rate_all_runs"] == 0.25
    assert overall["legacy_runs"] == 1
    assert overall["poc_verified_rate"] == 1 / 3
    assert overall["compatible_not_verified"] == 1
    assert overall["oracle"]["runs_with_oracle_data"] == 3
    assert overall["oracle"]["acceptance_rate"] == 2 / 3
    assert overall["oracle"]["generated_patch_status"] == {"SECURITY_PASS": 1, "SECURITY_FAIL": 1, "INCONCLUSIVE": 1}


def test_judge_agreement_counts_only_decided_pairs():
    docs = [
        _doc("r1", oracle="SECURITY_PASS", judge="true"),
        _doc("r2", oracle="SECURITY_FAIL", judge="true"),
        _doc("r3", oracle="SECURITY_FAIL", judge="false"),
        _doc("r4", oracle="SECURITY_FAIL", judge="uncertain"),
        _doc("r5", oracle="INCONCLUSIVE", judge="true"),
        _doc("r6", judge="true"),
    ]

    judge = metrics.compute_metrics(docs)["overall"]["judge_vs_oracle"]

    assert judge == {"decided_pairs": 3, "agreement": 2 / 3, "uncertain_verdicts": 1}


def test_repair_rate_by_vendor_patch_size():
    docs = [
        _doc("small-pass", passed=True),
        _doc("small-fail"),
        _doc("large-fail", diff=LARGE_DIFF),
        _doc("no-diff", diff=None),
    ]

    sizes = metrics.compute_metrics(docs)["overall"]["by_vendor_patch_size"]

    assert sizes["1-5 lines"] == {"runs": 2, "passes": 1, "repair_rate": 0.5}
    assert sizes[">20 lines"]["runs"] == 1
    assert sizes["unknown"]["runs"] == 1


def test_vulnerability_class_is_keyword_derived():
    assert metrics.classify_vulnerability({"answer_key": {"summary": "Prototype pollution in merge"}}) == "prototype pollution"
    assert metrics.classify_vulnerability({"answer_key": {"summary": "Regular Expression Denial of Service"}}) == "ReDoS"
    assert metrics.classify_vulnerability(
        {"answer_key": {}, "vulnerabilities": [{"description": "allows path traversal via filename"}]}
    ) == "path traversal"
    assert metrics.classify_vulnerability({"answer_key": {"summary": "something else"}}) == "other"


def test_context_hit_ignores_test_files_and_normalises_paths():
    docs = [
        _doc("hit", vendor_files=("lib/stats.js", "test/test.js"), shown=("lib/stats.js",)),
        _doc("miss", vendor_files=("lib/stats.js",), shown=("lib/helpers.js",)),
        _doc("prefixed", vendor_files=("./lib/stats.js",), shown=("package/lib/stats.js",)),
        _doc("tests-only", vendor_files=("test/test.js",), shown=()),
    ]

    context = metrics.compute_metrics(docs)["overall"]["context_hit"]

    assert context["runs_with_vendor_source_files"] == 3
    assert context["any_vendor_file_shown"] == 2 / 3
    assert context["mean_vendor_file_recall"] == 2 / 3


def test_cost_per_verified_pass_uses_all_attempts_of_a_run():
    docs = [
        _doc("r1", attempt=1, passed=False),
        _doc("r1", attempt=2, passed=True),
        _doc("r2", passed=False),
        _doc("r3", passed=True),
    ]
    costs = [
        {"run_attempt_id": "r1", "attempt_number": 1, "totals": {"cost": 0.10}},
        {"run_attempt_id": "r1", "attempt_number": 2, "totals": {"cost": 0.20}},
        {"run_attempt_id": "r2", "attempt_number": 1, "totals": {"cost": 0.30}},
    ]

    cost = metrics.compute_metrics(docs, costs)["overall"]["cost"]

    assert cost["runs_with_cost_data"] == 2
    assert round(cost["total_usd"], 2) == 0.60
    assert round(cost["per_run_usd"], 2) == 0.30
    assert round(cost["per_verified_pass_usd"], 2) == 0.60


def test_metrics_are_split_by_model():
    docs = [
        _doc("a", passed=True, model="openai/gpt-5.3-codex"),
        _doc("b", model="openai/gpt-5.3-codex"),
        _doc("c", passed=True, model="anthropic/claude-sonnet-5"),
        {**_doc("d"), "model_used": None},
    ]

    report = metrics.compute_metrics(docs)

    assert report["by_model"]["openai/gpt-5.3-codex"]["pass_rate_all_runs"] == 0.5
    assert report["by_model"]["anthropic/claude-sonnet-5"]["pass_rate_all_runs"] == 1.0
    assert report["by_model"]["unknown"]["runs"] == 1


def test_oracle_only_drops_legacy_runs_from_every_rate():
    docs = [
        _doc("legacy-pass", passed=True),
        _doc("legacy-fail"),
        _doc("modern-pass", passed=True, oracle="SECURITY_PASS", accepted=True, baseline="VALID"),
        _doc("modern-fail", oracle="SECURITY_FAIL", accepted=True, baseline="VALID"),
    ]

    overall = metrics.compute_metrics(docs, oracle_only=True)["overall"]

    assert overall["runs"] == 2
    assert overall["legacy_runs"] == 0
    assert overall["pass_rate_all_runs"] == 0.5
    assert overall["poc_verified_rate"] == 0.5


def test_empty_inputs_do_not_divide_by_zero_and_render():
    report = metrics.compute_metrics([_doc("only")])
    text = metrics.render(report)

    assert report["overall"]["judge_vs_oracle"]["agreement"] is None
    assert report["overall"]["cost"]["per_verified_pass_usd"] is None
    assert "n/a" in text
    assert "PoC-verified repair rate" in text


def test_candidate_sampling_metrics_show_what_sampling_bought():
    def sampled(run, **selection):
        doc = _doc(run, oracle="SECURITY_PASS", baseline="VALID")
        doc["candidate_selection"] = {"status": "selected", "unique": 3, **selection}
        return doc

    docs = [
        sampled("a", primary_status="SECURITY_PASS", oracle_passes=2, chosen_is_primary=True),
        sampled("b", primary_status="SECURITY_FAIL", oracle_passes=1, chosen_is_primary=False),
        sampled("c", primary_status="SECURITY_FAIL", oracle_passes=0, chosen_is_primary=True),
        {**_doc("d"), "candidate_selection": {"status": "skipped"}},
        _doc("e"),
    ]

    report = metrics.compute_metrics(docs)
    sampling = report["overall"]["candidate_selection"]

    assert sampling == {
        "runs_with_selection": 3,
        "mean_distinct_candidates": 3.0,
        "primary_passed_oracle": 1,
        "any_candidate_passed_oracle": 2,
        "chosen_not_primary": 1,
    }
    assert "any sampled candidate blocked it" in metrics.render(report)


def test_report_without_sampling_omits_the_section():
    assert "Candidate sampling" not in metrics.render(metrics.compute_metrics([_doc("only")]))
