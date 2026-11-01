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
    assert route_after_classification(initial) == 'end'
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
