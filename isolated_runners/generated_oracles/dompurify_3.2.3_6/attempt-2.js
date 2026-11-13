const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const createDOMPurify = require('dompurify');

  const fakeDocument = {
    nodeType: 9
  };

  const fakeWindow = {
    document: fakeDocument,
    Element: function Element() {}
  };

  const purify = createDOMPurify(fakeWindow);

  if (!purify || typeof purify.sanitize !== 'function') {
    throw new Error('dompurify instance missing sanitize');
  }

  const benignInput = 'plain-safe-text';
  const benignOutput = purify.sanitize(benignInput, { SAFE_FOR_TEMPLATES: true });

  if (typeof benignOutput !== 'string' || benignOutput !== benignInput) {
    throw new Error('benign sanitize mismatch');
  }

  result.operation_completed = true;

  const maliciousInput = 'greeting ${alert(1) unfinished';
  try {
    const maliciousOutput = purify.sanitize(maliciousInput, { SAFE_FOR_TEMPLATES: true });
    const leakedTemplateStart = typeof maliciousOutput === 'string' && maliciousOutput.includes('${');

    result.exploit_succeeded = leakedTemplateStart;
    result.evidence = JSON.stringify({
      benignOutput,
      maliciousOutput,
      leakedTemplateStart
    });
  } catch (err) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious_call_blocked:' + (err && err.message ? err.message : String(err));
  }
} catch (err) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_failure:' + (err && err.message ? err.message : String(err));
}

done();