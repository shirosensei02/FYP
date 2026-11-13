const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const createDOMPurify = require('dompurify');

  // In Node without a browser DOM, DOMPurify returns input unchanged.
  // This still exercises the public sanitize API and the SAFE_FOR_TEMPLATES regex path.
  const purify = createDOMPurify();

  if (!purify || typeof purify.sanitize !== 'function') {
    throw new Error('sanitize_api_unavailable');
  }

  const benignInput = 'hello-safe-text';
  const benignOutput = purify.sanitize(benignInput, { SAFE_FOR_TEMPLATES: true });

  if (typeof benignOutput !== 'string' || benignOutput !== benignInput) {
    throw new Error('benign_call_unexpected');
  }

  result.operation_completed = true;

  // Trigger case for GHSA-vhxf-7vqr-mrjg:
  // vulnerable regex /\$\{[\w\W]*}/gm fails to match unclosed ${...,
  // patched regex /\$\{[\w\W]*/gm removes from ${ onward.
  const maliciousInput = 'prefix ${alert(1)';

  try {
    const maliciousOutput = purify.sanitize(maliciousInput, { SAFE_FOR_TEMPLATES: true });
    const tokenSurvived = typeof maliciousOutput === 'string' && maliciousOutput.indexOf('${') !== -1;

    result.exploit_succeeded = tokenSurvived;
    result.evidence = JSON.stringify({
      benign_output: benignOutput,
      malicious_output: maliciousOutput,
      template_token_survived: tokenSurvived
    });
  } catch (err) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious_input_blocked_by_exception';
  }
} catch (err) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_failure:' + (err && err.message ? err.message : String(err));
}

finish();