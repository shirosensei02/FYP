import json

import pytest

import failure_context as context
import patch_generation as generation
from graph import increment_retry, route_after_classification


@pytest.fixture(autouse=True)
def isolated_history(tmp_path, monkeypatch):
    monkeypatch.setattr(context, 'ROOT', tmp_path)


def state(**extra):
    return dict(package_name='semver', package_version='5.0.0',
                vulnerabilities=[{'id': 'GHSA-example'}], **extra)


def test_locked_oracle_output_reaches_the_writer_without_the_maintainer_result():
    record = context.record_failure(state(
        generated_patch_oracle_validation={
            "status": "REGRESSION",
            "reason": "The relevant package operation failed.",
            "execution": {
                "status": "OPERATION_FAILED",
                "operation_completed": False,
                "exploit_succeeded": False,
                "evidence": "ordinary call threw",
                "stdout": "ORACLE_RESULT {\"operation_completed\":false}",
                "stderr": "TypeError: ps is not a function",
            },
        },
        oracle_validation={"fixed": {"evidence": "maintainer-secret-pass"}},
    ), "ordinary call failed", stage="security_oracle")
    feedback = context.load_feedback(state(retry_feedback=record))
    assert "ordinary call threw" in feedback
    assert "TypeError: ps is not a function" in feedback
    assert "maintainer-secret-pass" not in feedback


SINK_LINE = (
    'SINK_TRACE {"sink":"child_process.exec","argument":"ps -o pcpu,rss -p 1; touch /tmp/pwn",'
    '"frames":["Object.ps (pidusage/lib/stats.js:104:5)","Object.<anonymous> (pidusage/index.js:9:3)"]}'
)


def _security_fail_state(**extra):
    return state(
        generated_patch_oracle_validation={
            "status": "SECURITY_FAIL",
            "reason": "The accepted exploit still succeeds against the generated patch.",
            "execution": {
                "status": "EXPLOIT_SUCCEEDED",
                "operation_completed": True,
                "exploit_succeeded": True,
                "evidence": "marker file created",
                "stdout": "ORACLE_RESULT {}",
                "stderr": "warning: something\n\n" + SINK_LINE + "\n",
            },
        },
        accepted_oracle={
            "status": "accepted",
            "explanation": "Passes a pid string containing a shell metacharacter to the ps method.",
            "source": "const SECRET_ORACLE_SOURCE = require('pidusage');",
        },
        **extra,
    )


def test_security_fail_feedback_names_the_sink_and_describes_the_exploit():
    record = context.record_failure(_security_fail_state(), "exploit still works", stage="security_oracle")
    feedback = context.load_feedback(state(retry_feedback=record))

    assert "exploit description: Passes a pid string containing a shell metacharacter" in feedback
    assert "sink calls reached through the package" in feedback
    assert "child_process.exec(" in feedback
    assert "Object.ps (pidusage/lib/stats.js:104:5)" in feedback
    assert "marker file created" in feedback


def test_oracle_source_and_raw_trace_lines_stay_out_of_the_feedback():
    record = context.record_failure(_security_fail_state(), "exploit still works", stage="security_oracle")
    feedback = context.load_feedback(state(retry_feedback=record))

    assert "SECRET_ORACLE_SOURCE" not in feedback
    assert "SINK_TRACE {" not in feedback
    assert "warning: something" in feedback


def test_security_fail_without_a_trace_still_reports_the_evidence():
    plain = _security_fail_state()
    plain["generated_patch_oracle_validation"]["execution"]["stderr"] = ""
    plain["accepted_oracle"] = {}

    record = context.record_failure(plain, "exploit still works", stage="security_oracle")
    feedback = context.load_feedback(state(retry_feedback=record))

    assert "marker file created" in feedback
    assert "sink calls reached" not in feedback
    assert "exploit description" not in feedback


def test_sink_trace_parser_skips_malformed_lines_and_keeps_the_latest_events():
    lines = ["SINK_TRACE not-json", 'SINK_TRACE {"sink":"fs.open"}', 'SINK_TRACE {"sink":"x","frames":[]}']
    lines += [
        'SINK_TRACE ' + json.dumps({"sink": f"fs.open{n}", "argument": "a", "frames": [f"f{n} (p/x.js:1:1)"]})
        for n in range(10)
    ]

    events = context.parse_sink_trace("\n".join(lines))

    assert len(events) == context.MAX_SINK_EVENTS
    assert events[-1]["sink"] == "fs.open9"
    assert all(event["frames"] for event in events)


def _patch(name, new):
    return {"diff": f"--- a/lib/{name}.js\n+++ b/lib/{name}.js\n@@ -1 +1 @@\n-old\n+{new}\n",
            "target_files": [f"lib/{name}.js"]}


def _entry(index, status, reason, cluster_size=1):
    return {"index": index, "cluster_size": cluster_size, "lines_changed": 2,
            "oracle_status": status, "reason": reason}


def _selection_state(**extra):
    # Four samples: the primary, two identical ones, and one that did not apply.
    patches = [_patch("a", "x"), _patch("b", "z"), _patch("b", "z"), _patch("c", "w")]
    selection = {
        "status": "selected", "candidates": 4, "unique": 3, "chosen_index": 0,
        "chosen_is_primary": True, "primary_status": "SECURITY_FAIL", "oracle_passes": 0,
        "entries": [
            _entry(0, "SECURITY_FAIL", "The accepted exploit still succeeds against the generated patch."),
            _entry(1, "REGRESSION", "The exploit did not succeed, but the relevant package operation failed.", 2),
            _entry(3, "APPLY_FAILED", "The candidate did not apply cleanly."),
        ],
    }
    return state(candidate_patches=patches, candidate_selection=selection,
                 current_patch={"diff": patches[0]["diff"]}, **extra)


def test_retry_feedback_lists_the_other_samples_of_the_failed_attempt():
    record = context.record_failure(_selection_state(), "exploit still works", stage="security_oracle")
    feedback = context.load_feedback(state(retry_feedback=record))

    assert "Other samples from this attempt" in feedback
    assert "4 samples gave 3 distinct patches" in feedback
    assert "The patch above (primary) was chosen" in feedback
    assert "- sample 1: REGRESSION, produced 2 times." in feedback
    assert "Changed 2 lines in lib/b.js." in feedback
    single = context.render_candidates({
        "status": "selected", "samples": 2, "distinct": 2, "chosen_index": 1, "chosen_status": "SECURITY_FAIL",
        "items": [{"index": 0, "cluster_size": 1, "oracle_status": "SECURITY_FAIL", "reason": "r",
                   "lines_changed": 1, "target_files": ["lib/a.js"], "diff": ""}],
    })
    assert "Changed 1 line in lib/a.js." in single
    assert "- sample 3: APPLY_FAILED." in feedback
    assert "+z" in feedback
    assert "- primary:" not in feedback


def test_identical_samples_are_reported_as_one_patch():
    only = state(candidate_selection={"status": "skipped", "candidates": 4, "unique": 1},
                 candidate_patches=[_patch("a", "x")] * 4, current_patch={"diff": _patch("a", "x")["diff"]})

    record = context.record_failure(only, "exploit still works", stage="security_oracle")

    assert "All 4 samples produced the same patch." in context.load_feedback(state(retry_feedback=record))


def test_no_sampling_means_no_samples_section():
    record = context.record_failure(state(current_patch={"diff": "d"}), "failed", stage="security_oracle")

    assert record["candidates"] is None
    assert "Other samples" not in context.load_feedback(state(retry_feedback=record))


def test_the_samples_section_is_bounded():
    patches = [_patch(f"f{n}", "q" * 5_000) for n in range(7)]
    selection = {
        "status": "selected", "candidates": 7, "unique": 7, "chosen_index": 0,
        "entries": [_entry(n, "SECURITY_FAIL", "still succeeds") for n in range(7)],
    }
    record = context.record_failure(
        state(candidate_patches=patches, candidate_selection=selection, current_patch=patches[0]),
        "exploit still works", stage="security_oracle",
    )

    items = record["candidates"]["items"]
    assert [item["index"] for item in items] == [1, 2, 3]
    assert record["candidates"]["omitted"] == 3
    assert all(len(item["diff"]) <= context.CANDIDATE_DIFF_CHARS + 20 for item in items)
    assert "[3 more distinct patches omitted.]" in context.load_feedback(state(retry_feedback=record))


def test_a_selection_entry_without_a_stored_patch_does_not_break_feedback():
    broken = _selection_state()
    broken["candidate_patches"] = broken["candidate_patches"][:2]
    record = context.record_failure(broken, "exploit still works", stage="security_oracle")

    feedback = context.load_feedback(state(retry_feedback=record))

    assert "- sample 3: APPLY_FAILED." in feedback
    assert "unknown files" in feedback


def test_a_failed_locked_oracle_hands_the_other_samples_to_the_next_attempt():
    from patch_validation import record_locked_oracle_failure

    failed = _selection_state(
        generated_patch_oracle_validation={
            "status": "SECURITY_FAIL", "reason": "The accepted exploit still succeeds against the generated patch.",
            "execution": {"status": "EXPLOIT_SUCCEEDED", "evidence": "marker file created"},
        },
        accepted_oracle={"status": "accepted", "explanation": "shell metacharacter in pid"},
    )

    update = record_locked_oracle_failure(failed)
    retry = {**state(), **update}
    prompt = generation._build_openrouter_prompt(retry, retry["vulnerabilities"], [])

    assert update["retry_feedback"]["candidates"]["items"][0]["index"] == 1
    assert "Other samples from this attempt" in prompt
    assert "sample 1: REGRESSION" in prompt
    assert "marker file created" in prompt


def test_missing_oracle_is_journaled_but_not_shown_to_the_writer():
    record = context.record_failure(state(), "security validation was skipped", writer_visible=False)
    assert record["writer_visible"] is False
    journal = (context.package_directory("semver") / "failures.jsonl").read_text()
    assert "security validation was skipped" in journal
    assert context.context_paths(state())[0].exists() is False
    assert context.load_feedback(state(retry_feedback=record)) == ""


def test_history_is_persisted_filtered_and_deduplicated():
    failed = state(attempt_record_id='first', current_patch={'diff': 'bad diff'},
                   validation={'logs': 'actual apply error'})
    context.record_failure(failed, 'did not apply')
    context.record_failure(failed, 'did not apply')
    directory = context.package_directory('semver')
    assert len((directory / 'failures.jsonl').read_text().splitlines()) == 1
    assert 'bad diff' in context.context_paths(state())[0].read_text()
    feedback = context.load_feedback(state())
    assert 'actual apply error' in feedback
    assert not context.load_feedback({**state(), 'package_version': '6.0.0'})
    assert not context.load_feedback({**state(), 'package_name': 'other'})
    assert not context.load_feedback({**state(), 'vulnerabilities': [{'id': 'other'}]})


def test_final_failure_and_retry_reach_both_prompt_formats():
    from patch_validation import patch_validation
    from unittest.mock import patch
    initial = state(retry_count=0, max_retries=0, generation_status='failed',
                    generation_error='invalid candidate', current_patch=None)
    with patch('patch_validation.save_patch_attempt', return_value=None):
        result = patch_validation(initial)
    initial.update(result)
    assert route_after_classification(initial) == 'eval'
    initial.update(increment_retry(initial))
    for messages in [generation._build_messages(initial, initial['vulnerabilities'], [])]:
        assert 'invalid candidate' in messages[1]['content']
    assert 'invalid candidate' in generation._build_openrouter_prompt(initial, initial['vulnerabilities'], [])
    # A fresh run obtains the same evidence from disk.
    assert 'invalid candidate' in context.load_feedback(state())


def test_generation_failure_clears_previous_validation():
    result = generation.patch_generation(state(validation={'build_succeeded': True, 'tests_passed': True},
                                              adversarial_evaluation={'genuine_fix': 'true'}))
    assert result['generation_status'] == 'failed'
    assert result['validation'] is None
    assert result['adversarial_evaluation'] == {}
    assert result['current_patch'] is None


def test_history_budget_corruption_and_scoped_names():
    context.record_failure(state(current_patch={'diff': 'x' * 100_000}), 'bad patch')
    path = context.package_directory('semver') / 'failures.jsonl'
    with path.open('a') as stream:
        stream.write('broken json\n')
    assert len(context.load_feedback(state())) <= context.MAX_FEEDBACK_CHARS + 20
    assert context.package_directory('@scope/pkg') != context.package_directory('_scope_pkg')


def test_storage_error_does_not_discard_retry_evidence(monkeypatch):
    monkeypatch.setattr(context, 'ROOT', context.ROOT / 'file')
    context.ROOT.write_text('not a directory')
    record = context.record_failure(state(), 'apply failed')
    assert 'apply failed' in context.load_feedback(state(retry_feedback=record))


def test_retry_history_survives_internal_repair(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'package.json').write_text('{"name":"semver","main":"index.js"}')
    (source / 'index.js').write_text('module.exports = 1;\n')
    record = context.record_failure(state(current_patch={'diff': 'old failed candidate'}), 'tests failed')
    calls = []

    def generate(provider, current, findings, files, repair_feedback=None):
        messages = generation._build_messages(current, findings, files, repair_feedback)
        payload = json.loads(messages[1]['content'])
        assert 'old failed candidate' in payload['previous_failure_context']
        calls.append(payload)
        if len(calls) == 1:
            return {'edits': [{'path': 'index.js', 'old_text': 'missing source', 'new_text': 'fixed'}]}
        assert 'occurs exactly once' in payload['repair_feedback']
        return {'edits': [{'path': 'index.js', 'old_text': 'module.exports = 1;',
                           'new_text': 'module.exports = 2;'}]}

    monkeypatch.setattr(generation, '_generate_patch_payload', generate)
    result = generation.patch_generation(state(source_dir=str(source), retry_feedback=record, retry_count=1))
    assert result['generation_status'] == 'generated'
    assert result['current_patch']['attempt_number'] == 2
    assert len(calls) == 2
    assert 'missing source' in (context.package_directory('semver') / 'failures.jsonl').read_text()
    assert (source / 'index.js').read_text() == 'module.exports = 1;\n'


def test_markdown_uses_fences_and_prioritizes_error_evidence():
    logs = 'Docker progress\n' * 500 + 'npm error syscall spawn git\n' + 'noise\n' * 500 + 'sh: evalmd: not found'
    record = context.record_failure(state(
        current_patch={'diff': '--- a/quote.js\n+++ b/quote.js\n-old\n+new\n'},
        errors=['npm install step reported errors (continuing to test)'],
        validation={'build_succeeded': True, 'install_succeeded': False,
                    'tests_passed': False, 'logs': logs},
        adversarial_evaluation={'genuine_fix': 'false', 'reasoning': 'Unrelated advisory opinion'},
    ), 'patch broke the package')
    markdown = context.render([record])
    assert '## Attempt 1 — Dependency setup failure' in markdown
    assert '```diff\n--- a/quote.js\n+++ b/quote.js' in markdown
    assert 'npm error syscall spawn git' in markdown
    assert 'sh: evalmd: not found' in markdown
    assert 'patch broke the package' not in markdown
    assert 'Unrelated advisory opinion' not in markdown
    assert 'Evaluator opinion (unverified)' in markdown
    assert '\\n+++' not in markdown


def test_redaction_and_provider_error_summary():
    record = context.record_failure(state(
        generation_status='failed',
        errors=['Request blocked: prompt injection patterns detected org_private123'],
    ), 'HTTP 403 Request blocked: prompt injection patterns detected org_private123')
    raw = (context.package_directory('semver') / 'failures.jsonl').read_text()
    assert 'org_private123' not in raw
    markdown = context.render([record])
    assert 'Generation request rejected (HTTP 403)' in markdown
    assert 'org_private123' not in markdown
    assert 'No candidate patch was generated.' in markdown


def test_markdown_budget_keeps_complete_code_fences():
    records = [context.record_failure(state(
        current_patch={'diff': 'a' * 20000}, validation={'logs': 'error ' * 10000},
    ), 'failure') for _ in range(5)]
    markdown = context.render(records)
    assert len(markdown) <= context.MAX_FEEDBACK_CHARS
    assert markdown.count('```') % 2 == 0


def test_manual_markdown_is_the_prompt_source_and_survives_new_failures():
    context.record_failure(state(attempt_record_id='first'), 'original failure')
    path = context.context_paths(state())[0]
    manual = '# My reviewed memory\n\nKeep Git available. This is a setup issue.\n'
    path.write_text(manual)
    # Archive still contains the old failure, but it must not be regenerated into the prompt.
    assert 'original failure' not in context.load_feedback(state())
    assert 'Keep Git available' in context.load_feedback(state())
    context.record_failure(state(attempt_record_id='second'), 'another failure')
    assert path.read_text().startswith(manual)
    assert 'another failure' in path.read_text()
    assert 'original failure' not in path.read_text()
    archive = context.read_records(context.package_directory('semver') / 'failures.jsonl')
    assert len(archive) == 2


def test_current_run_feedback_is_separate_and_not_duplicated():
    context.record_failure(state(run_attempt_id='previous', attempt_record_id='old'), 'prior run failure')
    latest = context.record_failure(state(run_attempt_id='current', attempt_record_id='new'), 'current unique failure')
    feedback = context.load_feedback(state(run_attempt_id='current', retry_feedback=latest))
    persistent, immediate = feedback.split('# Latest attempt failure (current run)')
    assert 'prior run failure' in persistent
    assert 'current unique failure' not in persistent
    assert 'current unique failure' in immediate
    assert feedback.count('current unique failure') == 1
    assert 'current unique failure' in context.load_feedback(state(run_attempt_id='next'))


def test_all_scope_aliases_deduplicate_records_and_include_manual_notes():
    findings = [{'id': 'GHSA-example', 'aliases': ['CVE-123']}, {'id': 'GHSA-second'}]
    context.record_failure({**state(), 'vulnerabilities': findings, 'patch_scope': 'all'}, 'shared failure')
    target = {**state(), 'vulnerabilities': findings, 'patch_scope': 'all'}
    paths = context.context_paths(target)
    assert len(paths) == 3
    with paths[-1].open('a') as stream:
        stream.write('\nManual advice for this advisory.\n')
    feedback = context.load_feedback(target)
    assert feedback.count('shared failure') == 1
    assert 'Manual advice for this advisory.' in feedback
    assert not context.load_feedback({**target, 'package_version': 'other'})


def test_large_manual_memory_leaves_room_for_immediate_failure():
    context.record_failure(state(), 'old failure')
    path = context.context_paths(state())[0]
    path.write_text('manual notes\n' * 10000)
    latest = context.record_failure(state(run_attempt_id='current'), 'latest important failure')
    feedback = context.load_feedback(state(run_attempt_id='current', retry_feedback=latest))
    assert len(feedback) <= context.MAX_FEEDBACK_CHARS
    assert 'latest important failure' in feedback
