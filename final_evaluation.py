"""Combine locked-oracle evidence and the independent evaluator's verdict.

This assessment does not change execution classification, retries, or the
success collection policy. Compatibility remains a separate result.
"""
from state import GraphState, FinalEvaluation


def final_evaluation(state: GraphState) -> dict:
    oracle_status = (state.get('generated_patch_oracle_validation') or {}).get('status')
    evaluator = state.get('adversarial_evaluation') or {}
    raw_verdict = evaluator.get('genuine_fix')
    available = (evaluator.get('status') == 'evaluated'
                 and not evaluator.get('evaluation_error')
                 and raw_verdict in {'true', 'false', 'uncertain'})
    verdict = raw_verdict if available else 'unavailable'
    # Only the current candidate tested with an accepted oracle can establish
    # success or failure. Missing generation/application evidence is inconclusive.
    trusted_oracle = (state.get('accepted_oracle') or {}).get('status') == 'accepted'
    current_candidate = bool(state.get('current_patch')) and state.get('generation_status') != 'failed'
    applicable = trusted_oracle and current_candidate and state.get('patch_applied') is True
    effective_status = oracle_status if applicable else 'SKIPPED'

    if effective_status == 'SECURITY_PASS' and verdict == 'true':
        category = 'supported_fix'
        reason = 'The accepted oracle was blocked and the independent evaluator supports the fix.'
    elif effective_status == 'SECURITY_PASS':
        category = 'needs_verification'
        reason = ('The accepted oracle was blocked, but the evaluator rejected the fix.' if verdict == 'false'
                  else 'The accepted oracle was blocked, but independent evaluation is uncertain or unavailable.')
    elif effective_status == 'SECURITY_FAIL':
        category = 'security_failure'
        reason = 'The accepted exploit still succeeds, regardless of the evaluator opinion.'
    elif effective_status == 'REGRESSION':
        category = 'functional_failure'
        reason = 'The oracle operation failed; this does not establish that the exploit was blocked correctly.'
    else:
        category = 'inconclusive'
        reason = 'No conclusive accepted-oracle result establishes the security outcome for this candidate.'

    result = FinalEvaluation(
        category=category,
        oracle_status=oracle_status or 'SKIPPED',
        oracle_applicable=applicable,
        adversarial_verdict=verdict,
        adversarial_reported_verdict=raw_verdict,
        compatibility_status=state.get('compatibility_classification') or 'unknown',
        reason=reason,
    )
    return {'final_evaluation': result}
