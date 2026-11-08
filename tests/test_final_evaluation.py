import pytest

from final_evaluation import final_evaluation


@pytest.mark.parametrize('oracle,expected', [
    ('SECURITY_PASS', ['supported_fix', 'needs_verification', 'needs_verification', 'needs_verification']),
    ('SECURITY_FAIL', ['security_failure'] * 4),
    ('REGRESSION', ['functional_failure'] * 4),
    ('INCONCLUSIVE', ['inconclusive'] * 4),
    ('SKIPPED', ['inconclusive'] * 4),
    (None, ['inconclusive'] * 4),
])
@pytest.mark.parametrize('index,verdict', list(enumerate(['true', 'false', 'uncertain', None])))
def test_category_matrix(oracle, expected, index, verdict):
    result = final_evaluation({
        'accepted_oracle': {'status': 'accepted'},
        'current_patch': {'diff': 'candidate'}, 'generation_status': 'generated', 'patch_applied': True,
        'generated_patch_oracle_validation': {'status': oracle},
        'adversarial_evaluation': {'status': 'evaluated', 'genuine_fix': verdict},
        'compatibility_classification': 'pass',
    })['final_evaluation']
    assert result['category'] == expected[index]
    assert result['compatibility_status'] == 'pass'
    assert result['reason']


def candidate():
    return {
        'accepted_oracle': {'status': 'accepted'},
        'current_patch': {'diff': 'candidate'}, 'patch_applied': True,
        'generated_patch_oracle_validation': {'status': 'SECURITY_PASS'},
        'adversarial_evaluation': {'status': 'evaluated', 'genuine_fix': 'true'},
    }


@pytest.mark.parametrize('changes', [
    {'accepted_oracle': None}, {'current_patch': None}, {'patch_applied': False},
    {'generation_status': 'failed'},
])
def test_unusable_or_stale_oracle_cannot_support_fix(changes):
    state = {**candidate(), **changes}
    result = final_evaluation(state)['final_evaluation']
    assert result['category'] == 'inconclusive'
    assert result['oracle_applicable'] is False


def test_evaluator_error_cannot_count_as_agreement():
    state = candidate()
    state['adversarial_evaluation']['evaluation_error'] = 'API failure'
    result = final_evaluation(state)['final_evaluation']
    assert result['category'] == 'needs_verification'
    assert result['adversarial_verdict'] == 'unavailable'
    assert result['adversarial_reported_verdict'] == 'true'


def test_security_assessment_preserves_compatibility_and_classification():
    state = {**candidate(), 'classification': 'fail', 'compatibility_classification': 'fail'}
    updates = final_evaluation(state)
    assert updates['final_evaluation']['category'] == 'supported_fix'
    assert updates['final_evaluation']['compatibility_status'] == 'fail'
    assert set(updates) == {'final_evaluation'}
    assert state['classification'] == 'fail'


def test_final_node_precedes_persistence_and_is_in_graph():
    from graph import graph
    edges = {(edge.source, edge.target) for edge in graph.get_graph().edges}
    assert ('patch_scoring_node', 'final_evaluation_node') in edges
    assert ('final_evaluation_node', 'maintainer_eval_node') in edges
    from db import _build_doc
    state = candidate()
    state.update(final_evaluation(state))
    assert _build_doc(state, passed=False)['final_evaluation'] == state['final_evaluation']


def test_maintainer_persistence_receives_final_evaluation(monkeypatch):
    import maintainer_eval as module
    saved = []
    monkeypatch.setattr(module, 'save_pipeline_result', lambda state: (saved.append(state) or 'attempt', None))
    state = candidate()
    state.update(final_evaluation(state))
    # Missing answer key follows the skipped-evaluation path, which must still persist.
    module.maintainer_eval(state)
    assert saved[0]['final_evaluation']['category'] == 'supported_fix'
