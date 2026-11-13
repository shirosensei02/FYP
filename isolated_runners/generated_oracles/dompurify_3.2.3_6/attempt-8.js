const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const createDOMPurify = require('dompurify');

  // Minimal DOM stubs just enough for DOMPurify initialization in Node.
  const fakeDocument = { nodeType: 9 };
  function Element() {}

  const fakeWindow = {
    document: fakeDocument,
    Element,
  };

  const DOMPurify = createDOMPurify(fakeWindow);
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('sanitize_not_available');
  }

  // Benign call first: SAFE_FOR_TEMPLATES should strip template markers.
  const benignInput = 'Hello ${name}!';
  const benignOut = DOMPurify.sanitize(benignInput, { SAFE_FOR_TEMPLATES: true });
  if (typeof benignOut !== 'string') {
    throw new Error('benign_non_string_output');
  }
  if (benignOut.includes('${')) {
    throw new Error('benign_template_marker_not_removed');
  }

  result.operation_completed = true;

  // Malicious case: unclosed template literal marker.
  const maliciousInput = 'AA ${<img src=x onerror=alert(1)';
  try {
    const maliciousOut = DOMPurify.sanitize(maliciousInput, { SAFE_FOR_TEMPLATES: true });
    const leakedTemplateLiteral = typeof maliciousOut === 'string' && maliciousOut.includes('${');
    result.exploit_succeeded = leakedTemplateLiteral;
    result.evidence = JSON.stringify({
      benign_out: benignOut,
      malicious_out: maliciousOut,
      leaked_template_literal: leakedTemplateLiteral,
    });
  } catch (err) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious_call_blocked';
  }
} catch (err) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_failure:' + (err && err.message ? err.message : String(err));
}

finish();