"""The resolved runner must retain locator and oracle stages in graph order."""
from argparse import Namespace

import pytest

import test_local_pipeline as runner


@pytest.mark.parametrize("tool_requests", [0, 1, 3])
def test_runner_preserves_localization_and_oracle_retry_loop(tmp_path, monkeypatch, tool_requests):
    import og_patch_resolution
    (tmp_path / 'package.json').write_text('{"name":"demo"}')
    calls = []
    monkeypatch.setattr(og_patch_resolution, 'og_patch_resolution', lambda state: {'answer_key': {}})

    def locate(state):
        calls.append('locator')
        return {'debug_locations': [{'function': 'target'}]}

    def localize(state):
        assert state['debug_locations'][0]['function'] == 'target'
        calls.append('localization')
        return {'localized_context_files': [{'path': 'index.js', 'content': 'source'}]}

    def generate_oracle(state):
        assert state['localized_context_files']
        calls.append('oracle_generation')
        return {'oracle_attempt_count': state.get('oracle_attempt_count', 0) + 1}

    def validate_oracle(state):
        calls.append('oracle_validation')
        if state['oracle_attempt_count'] == 1:
            return {'oracle_validation': {'status': 'INVALID'}}
        return {'oracle_validation': {'status': 'VALID'}, 'accepted_oracle': {'status': 'accepted'}}

    def generate_patch(state):
        calls.append('patch_generation')
        assert state['accepted_oracle']['status'] == 'accepted'
        assert state['debug_locations']
        requested = state.get('generation_graph_fetches', 0)
        assert state['retry_count'] == 0
        if requested < tool_requests:
            return {'graph_request': {'caller': 'patch_generation', 'tool': 'RetrieveEntity',
                                      'arguments': {'entity_ids': ['index.js:target']}},
                    'generation_graph_fetches': requested + 1, 'current_patch': None}
        if tool_requests:
            assert state['graph_result']['entities'][0]['code'] == 'fetched source'
        return {'current_patch': {'diff': 'candidate'}}

    def execute_tool(state):
        calls.append('graph_tool')
        assert state['graph_request']['caller'] == 'patch_generation'
        return {'graph_request': None, 'graph_return': 'patch_generation',
                'graph_result': {'entities': [{'code': 'fetched source'}]}}

    import repo_graph
    monkeypatch.setattr(repo_graph, 'repo_graph_node', execute_tool)

    monkeypatch.setattr(runner, 'localize', locate)
    monkeypatch.setattr(runner, 'vulnerability_localization', localize)
    monkeypatch.setattr(runner, 'oracle_generation', generate_oracle)
    monkeypatch.setattr(runner, 'oracle_validation', validate_oracle)
    monkeypatch.setattr(runner, 'patch_generation', generate_patch)
    runner.run_pipeline(Namespace(
        package_name='demo', package_version='1.0.0', model_provider='mock', model_name=None,
        patch_scope='single', max_retries=1, max_oracle_attempts=5,
        source_dir=str(tmp_path), skip_vuln_detection=True, list_vulnerabilities=False,
        vulnerability_id=None, stop_after_patch=True, dump_state=False,
    ))
    assert calls == ['locator', 'localization', 'oracle_generation', 'oracle_validation',
                     'oracle_generation', 'oracle_validation'] + ['patch_generation', 'graph_tool'] * tool_requests + ['patch_generation']
