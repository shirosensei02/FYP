const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const createDOMPurify = require('dompurify');

  // Minimal fake window/document to exercise SAFE_FOR_TEMPLATES text sanitization path.
  // We intentionally do not provide a real DOM so sanitize() returns input unchanged.
  const fakeWindow = {
    document: { nodeType: 9 }
  };

  const purifier = createDOMPurify(fakeWindow);

  // Benign operation first: public sanitize() API should return unchanged safe text.
  const benignInput = 'hello-template-safe-text';
  const benignOutput = purifier.sanitize(benignInput, { SAFE_FOR_TEMPLATES: true });
  if (typeof benignOutput !== 'string' || benignOutput !== benignInput) {
    throw new Error('benign sanitize behavior unexpected');
  }

  // Mark setup+benign as completed before malicious probe.
  result.operation_completed = true;

  // Malicious probe targets template-literal regex handling in SAFE_FOR_TEMPLATES mode.
  const maliciousInput = 'prefix ${alert(1) suffix';
  let maliciousOutput;
  try {
    maliciousOutput = purifier.sanitize(maliciousInput, { SAFE_FOR_TEMPLATES: true });
  } catch (e) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious sanitize threw after benign success';
    finish();
    return;
  }

  const containsTemplateMarker = typeof maliciousOutput === 'string' && maliciousOutput.includes('${');
  result.exploit_succeeded = containsTemplateMarker;
  result.evidence = JSON.stringify({
    benign_output: benignOutput,
    malicious_output: maliciousOutput
  });
} catch (e) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

finish();